use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::Instant;
use xmtp_proto::mls_v1::{GroupMessage, GroupMessageInput, group_message, group_message_input};

use super::auth::{self, HelloSigner};
use super::frames::{
    self, Auth, Hello, IdentityLog, Interest, MAX_MESSAGES_PER_FRAME, Pending, Sequenced,
    WelcomeAck, frame::Body,
};
use super::membership::GroupMembership;
use super::transport::{MeshTransport, PeerId};
use crate::MeshError;
use crate::link::LinkRole;
use crate::link::tx::LinkTx;
use crate::node::{
    MAX_PEER_IDENTITY_LOG, MAX_RELAYED_IDENTITY_LOGS, MeshNode, NodeEvent, Resolution,
};

/// What the radio delivered to a session.
pub(crate) enum Inbound {
    /// Bytes off the air: handshake messages, then sealed records (§B14.3).
    Wire(Vec<u8>),
    /// Test only: a frame as if it had just been decrypted on this link.
    #[cfg(any(test, feature = "test-utils"))]
    Plain(Vec<u8>),
}

/// How a session's link was opened.
pub(crate) struct LinkSetup {
    pub(crate) role: LinkRole,
    /// Test-only cleartext link (no Noise); see `MeshNode::inject_plain_for_test`.
    pub(crate) plain: bool,
}

pub(crate) struct SessionHandle {
    /// Distinguishes this session from earlier/later ones for the same peer.
    pub(crate) id: u64,
    pub(crate) tx: mpsc::UnboundedSender<Inbound>,
    /// The link's sending half, shared with the relay engine.
    pub(crate) link: Arc<LinkTx>,
    /// Set (and `_wake` dropped) when this handle leaves the registry, i.e. the
    /// peer was lost or the entry replaced. A tokio mpsc receiver keeps draining
    /// buffered frames after its senders drop, so the session task checks this
    /// before every frame and every send: after a reconnect under the same
    /// `PeerId` a stale session must never talk to the peer's new session.
    cancelled: Arc<AtomicBool>,
    _wake: oneshot::Sender<()>,
}

impl SessionHandle {
    pub(crate) fn new(
        id: u64,
        tx: mpsc::UnboundedSender<Inbound>,
        link: Arc<LinkTx>,
        cancelled: Arc<AtomicBool>,
    ) -> (Self, oneshot::Receiver<()>) {
        let (wake, wake_rx) = oneshot::channel();
        (
            Self {
                id,
                tx,
                link,
                cancelled,
                _wake: wake,
            },
            wake_rx,
        )
    }
}

/// A registry entry whose session never runs (node registry tests).
#[cfg(test)]
pub(crate) fn test_handle(id: u64) -> SessionHandle {
    struct Nowhere;
    impl MeshTransport for Nowhere {
        fn send(&self, _: &PeerId, _: Vec<u8>) {}
        fn disconnect(&self, _: &PeerId) {}
    }
    let (tx, _rx) = mpsc::unbounded_channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let link = Arc::new(LinkTx::new(
        "p".into(),
        Arc::new(Nowhere),
        cancelled.clone(),
        true,
        None,
    ));
    SessionHandle::new(id, tx, link, cancelled).0
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

/// Handshake: each side sends `Hello{its key, a fresh challenge}` and answers
/// the other's Hello with `Auth{signature, echoed challenge}`, the signature
/// over `hello_text(their challenge, own key, their key)`. A Hello carrying our
/// own key is rejected (reflection). Every Hello from the same key is answered,
/// in any state, and an Auth echoing another challenge is ignored: when a
/// `PeerId` reconnects, one frame from the previous connection's session may
/// still arrive (it passed its cancel check just before the relink) and must
/// not break the new handshake.
///
/// A Hello received before we are authenticated also makes us send our own
/// Hello again (at most [`MAX_HELLO_RESENDS`] times per session), so the two
/// sides converge even when one side's first Hello was lost (e.g. it went out
/// before the radio reported the connection). A session not authenticated
/// within the node's handshake timeout disconnects the peer.
///
/// Authenticated means a live holder of installation key K answered through
/// this pipe; it does not bind the PeerId to K against a relaying
/// man-in-the-middle (channel binding arrives with the planned Noise upgrade).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    AwaitHello,
    AwaitAuth,
    Authenticated,
}

/// How many times a session re-sends its Hello in answer to the peer's.
pub(crate) const MAX_HELLO_RESENDS: u8 = 3;

/// How often a session re-checks the membership of groups it deferred.
pub(crate) const MEMBERSHIP_RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// How long a deferred group is re-checked before the session gives up on it
/// (a later frame about the group defers it again).
pub(crate) const MEMBERSHIP_RETRY_WINDOW: Duration = Duration::from_secs(60);
/// Most groups one session keeps deferred at a time.
pub(crate) const MAX_DEFERRED_GROUPS: usize = 64;

/// Whether the verified peer's inbox is a member of a group, per the local
/// libxmtp client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Membership {
    Member,
    /// The client knows the group and the peer is not in it (or the peer is
    /// another installation of our own inbox).
    NotMember,
    /// The client does not know the group yet (or could not say).
    Unknown,
}

/// What the peer asked about a group whose membership check has not passed
/// yet, so it can be acted on once it does.
#[derive(Debug, Clone, Copy, Default)]
struct Ask {
    /// The peer claimed to sequence the group.
    claimed: bool,
    /// The peer showed interest (Interest or Pending): it gets pushes.
    interested: bool,
    /// The high id of the peer's latest Interest.
    high: Option<u64>,
}

impl Ask {
    fn merge(&mut self, other: Ask) {
        self.claimed |= other.claimed;
        self.interested |= other.interested;
        if other.high.is_some() {
            self.high = other.high;
        }
    }
}

struct Deferred {
    since: Instant,
    ask: Ask,
}

pub(crate) struct Session {
    pub(crate) id: u64,
    cancelled: Arc<AtomicBool>,
    pub(crate) node: MeshNode,
    pub(crate) peer: PeerId,
    pub(crate) transport: Arc<dyn MeshTransport>,
    /// How the radio opened this link (§B14.2).
    pub(crate) role: LinkRole,
    /// Test-only cleartext link.
    pub(crate) plain: bool,
    /// The link's sending half; every frame goes out through it.
    pub(crate) link: Arc<LinkTx>,
    pub(crate) signer: Arc<dyn HelloSigner>,
    pub(crate) membership: Arc<dyn GroupMembership>,
    pub(crate) challenge: [u8; 32],
    pub(crate) state: State,
    pub(crate) peer_installation: Option<Vec<u8>>,
    pub(crate) peer_inbox: Option<String>,
    /// The peer proved (via its identity log) that its installation belongs to its inbox.
    pub(crate) verified: bool,
    /// Armed at authentication while unverified: a peer that has not proven
    /// membership by then is dropped as `PeerNotMember`.
    pub(crate) verify_deadline: Option<Instant>,
    /// Armed at start: the peer must authenticate by then.
    pub(crate) handshake_deadline: Option<Instant>,
    pub(crate) hello_resends: u8,
    pub(crate) peer_interest: HashSet<Vec<u8>>,
    /// The peer's Hello offered relay v1.
    pub(crate) peer_relay: bool,
    /// Our last Hello to this peer offered relay v1.
    pub(crate) self_relay: bool,
    /// Groups whose membership check for this peer has not passed yet, with
    /// what the peer asked; re-checked every [`MEMBERSHIP_RETRY_INTERVAL`]
    /// (and on `GroupKnown`) for up to [`MEMBERSHIP_RETRY_WINDOW`].
    deferred: HashMap<Vec<u8>, Deferred>,
    /// When the deferred groups are next re-checked.
    retry_at: Option<Instant>,
    /// Inboxes an `IdentityConflict` reply was already sent for this
    /// session: at most one per inbox per session,
    /// so a peer can't flood the link. Cleared for an inbox once our log
    /// of it actually changes.
    conflict_sent: HashSet<String>,
}

pub(crate) fn spawn(
    runtime: &tokio::runtime::Handle,
    node: MeshNode,
    peer: PeerId,
    transport: Arc<dyn MeshTransport>,
    signer: Arc<dyn HelloSigner>,
    membership: Arc<dyn GroupMembership>,
    setup: LinkSetup,
) -> SessionHandle {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = mpsc::unbounded_channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    // Cleartext until the Noise handshake is wired in (§B14.3).
    let link = Arc::new(LinkTx::new(
        peer.clone(),
        transport.clone(),
        cancelled.clone(),
        true,
        node.frame_tap(),
    ));
    let (handle, wake) = SessionHandle::new(id, tx, link.clone(), cancelled.clone());
    let events = node.subscribe_events();
    let session = Session {
        id,
        cancelled,
        node,
        peer,
        transport,
        role: setup.role,
        plain: setup.plain,
        link,
        signer,
        membership,
        challenge: rand::random(),
        state: State::AwaitHello,
        peer_installation: None,
        peer_inbox: None,
        verified: false,
        verify_deadline: None,
        handshake_deadline: None,
        hello_resends: 0,
        peer_interest: HashSet::new(),
        peer_relay: false,
        self_relay: false,
        deferred: HashMap::new(),
        retry_at: None,
        conflict_sent: HashSet::new(),
    };
    runtime.spawn(session.run(rx, events, wake));
    handle
}

impl Session {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn send(&self, body: Body) {
        self.try_send(body);
    }

    /// Frames over [`frames::MAX_FRAME_LEN`] are refused (logged), never sent.
    /// Returns whether the frame went out.
    fn try_send(&self, body: Body) -> bool {
        if self.is_cancelled() {
            return false;
        }
        self.link.send(body)
    }

    async fn run(
        mut self,
        mut rx: mpsc::UnboundedReceiver<Inbound>,
        mut events: broadcast::Receiver<NodeEvent>,
        mut wake: oneshot::Receiver<()>,
    ) {
        self.run_loop(&mut rx, &mut events, &mut wake).await;
        self.node.session_ended(&self.peer, self.id);
    }

    async fn run_loop(
        &mut self,
        rx: &mut mpsc::UnboundedReceiver<Inbound>,
        events: &mut broadcast::Receiver<NodeEvent>,
        wake: &mut oneshot::Receiver<()>,
    ) {
        if self.is_cancelled() {
            return;
        }
        self.handshake_deadline = Some(Instant::now() + self.node.handshake_timeout());
        self.send_hello();
        loop {
            let deadline = match self.state {
                State::Authenticated if self.verified => None,
                State::Authenticated => self.verify_deadline,
                State::AwaitHello | State::AwaitAuth => self.handshake_deadline,
            };
            let retry_at = self.retry_at;
            tokio::select! {
                biased;
                _ = &mut *wake => break,
                _ = until(deadline) => {
                    if self.state == State::Authenticated {
                        tracing::warn!(peer = %self.peer, "peer did not prove inbox membership in time");
                    } else {
                        tracing::warn!(peer = %self.peer, "peer did not complete the handshake in time");
                    }
                    if !self.is_cancelled() {
                        self.transport.disconnect(&self.peer);
                    }
                    break;
                }
                frame = rx.recv() => {
                    let Some(inbound) = frame else { break };
                    if self.is_cancelled() {
                        break;
                    }
                    if let Err(e) = self.on_inbound(inbound).await {
                        tracing::warn!(peer = %self.peer, error = %e, "mesh frame rejected");
                        if e.is_fatal() {
                            if !self.is_cancelled() {
                                self.transport.disconnect(&self.peer);
                            }
                            break;
                        }
                    }
                }
                event = events.recv() => match event {
                    Ok(event) => {
                        if let Err(e) = self.on_event(event).await {
                            tracing::warn!(peer = %self.peer, error = %e, "mesh event failed");
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if let Err(e) = self.on_lagged().await {
                            tracing::warn!(peer = %self.peer, error = %e, "mesh resync failed");
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = until(retry_at) => {
                    if let Err(e) = self.retry_deferred().await {
                        tracing::warn!(peer = %self.peer, error = %e, "mesh membership retry failed");
                    }
                }
            }
        }
    }

    async fn on_inbound(&mut self, inbound: Inbound) -> Result<(), MeshError> {
        match inbound {
            Inbound::Wire(bytes) => self.on_frame(&bytes).await,
            #[cfg(any(test, feature = "test-utils"))]
            Inbound::Plain(frame) => self.on_frame(&frame).await,
        }
    }

    async fn on_frame(&mut self, bytes: &[u8]) -> Result<(), MeshError> {
        let body = frames::decode(bytes)?;
        match (self.state, body) {
            (_, Body::Hello(hello)) => self.on_hello(hello),
            (State::AwaitAuth, Body::Auth(auth)) => self.on_auth(auth).await,
            (State::Authenticated, Body::Auth(_)) => Ok(()),
            (State::Authenticated, body) => self.on_authenticated_frame(body).await,
            // Anything else before authentication is dropped silently.
            _ => Ok(()),
        }
    }

    fn send_hello(&mut self) {
        self.self_relay = self.node.relay_enabled();
        self.send(Body::Hello(Hello {
            installation_key: self.signer.installation_key(),
            inbox_id: self.node.local_inbox().ok().flatten().unwrap_or_default(),
            challenge: self.challenge.to_vec(),
            relay: if self.self_relay { frames::RELAY_V1 } else { 0 },
            seq: frames::SEQ_V1,
        }));
    }

    fn on_hello(&mut self, hello: Hello) -> Result<(), MeshError> {
        if hello.installation_key.len() != 32 || hello.challenge.len() != 32 {
            return Err(MeshError::AuthFailed("malformed hello".into()));
        }
        if hello.seq < frames::SEQ_V1 {
            self.node.seq_counters().count_rejected_version();
            return Err(MeshError::IncompatibleVersion(format!(
                "peer speaks signed sequencing {} (this node needs {})",
                hello.seq,
                frames::SEQ_V1
            )));
        }
        let own_key = self.signer.installation_key();
        if hello.installation_key == own_key {
            return Err(MeshError::AuthFailed(
                "hello carries our own installation key".into(),
            ));
        }
        if self
            .peer_installation
            .as_ref()
            .is_some_and(|k| *k != hello.installation_key)
        {
            return Err(MeshError::AuthFailed(
                "peer changed installation key".into(),
            ));
        }
        let text = auth::hello_text(&hello.challenge, &own_key, &hello.installation_key);
        let signature = self.signer.sign(&text)?;
        let handshaking = self.state != State::Authenticated;
        if self.state == State::AwaitHello {
            self.peer_installation = Some(hello.installation_key);
            self.peer_inbox = Some(hello.inbox_id);
            self.peer_relay = hello.relay >= frames::RELAY_V1;
            self.state = State::AwaitAuth;
        }
        self.send(Body::Auth(Auth {
            signature,
            challenge: hello.challenge,
        }));
        // The peer may never have seen our Hello: say it again (bounded).
        if handshaking && self.hello_resends < MAX_HELLO_RESENDS {
            self.hello_resends += 1;
            self.send_hello();
        }
        Ok(())
    }

    async fn on_auth(&mut self, auth_frame: Auth) -> Result<(), MeshError> {
        if auth_frame.challenge != self.challenge {
            return Ok(()); // answers some other (stale) Hello of ours
        }
        let peer_key = self.peer_installation.clone().expect("set by hello");
        let text = auth::hello_text(&self.challenge, &peer_key, &self.signer.installation_key());
        auth::verify(&text, &auth_frame.signature, &peer_key)?;
        self.state = State::Authenticated;
        self.handshake_deadline = None;
        self.node.session_authenticated(&self.peer, self.id);
        self.on_authenticated().await
    }

    fn send_own_identity(&self) -> Result<(), MeshError> {
        if let Some(log) = self.node.own_identity_log()? {
            self.send(Body::IdentityLog(log));
        }
        if let Some(kp) = self.node.own_key_package()? {
            self.send(Body::KeyPackage(kp));
        }
        Ok(())
    }

    /// Runs once when the handshake completes. Arms the verification
    /// deadline, then verifies at once if the log we already hold for the
    /// claimed inbox lists the peer's installation. If it does not, the peer
    /// still gets until the deadline to send its log: ours may be stale (the
    /// installation added after our copy), and rejecting now would drop an
    /// honest peer before its newer log is read, on every reconnect.
    async fn on_authenticated(&mut self) -> Result<(), MeshError> {
        self.verify_deadline = Some(Instant::now() + self.node.peer_verify_timeout());
        self.send_own_identity()?;
        let Some(inbox_id) = self.peer_inbox.clone() else {
            return Ok(());
        };
        if self.is_member(&inbox_id).await? {
            self.mark_verified().await?;
        }
        Ok(())
    }

    async fn is_member(&self, inbox_id: &str) -> Result<bool, MeshError> {
        let claimed = self.peer_installation.as_ref().expect("set by hello");
        Ok(self
            .node
            .installations_of(inbox_id)
            .await?
            .contains(claimed))
    }

    async fn mark_verified(&mut self) -> Result<(), MeshError> {
        self.verified = true;
        self.verify_deadline = None;
        let inbox_id = self.peer_inbox.clone().unwrap_or_default();
        self.node
            .session_verified(&self.peer, self.id, inbox_id, self.peer_installation());
        self.on_verified().await
    }

    /// The peer's identity log for `log.inbox_id`. The log of the inbox the
    /// peer claimed in its Hello proves (or disproves) its membership. Any
    /// other inbox's log is a relay (§C4.2), which only ever reconciles a log
    /// we already hold. When the two copies differ, the one with the earlier
    /// update at their first difference wins on every node (§C4.1,
    /// D25): ours is replaced, or the peer is sent ours in an
    /// IdentityConflict and stays unverified until the verification deadline
    /// (an owner re-bases meanwhile, §C4.4) instead of being dropped. PeerNotMember stays fatal when the logs agree and
    /// the peer is still not a member.
    async fn on_identity_log(&mut self, log: IdentityLog) -> Result<(), MeshError> {
        if self.node.legacy_identity() {
            return self.on_identity_log_legacy(log).await;
        }
        if self.peer_inbox.as_deref() != Some(log.inbox_id.as_str()) {
            return self.on_relayed_identity_log(log).await;
        }
        let inbox_id = log.inbox_id.clone();
        let resolved = self.node.resolve_identity_log(&inbox_id, log.updates).await;
        if let Ok(Resolution::OursWins(candidate_state)) = &resolved {
            // D27: the peer's own submitted, fully
            // verified log for its claimed inbox must actually list the
            // installation it just authenticated as, before it gets our
            // log back -- the restoring-owner bootstrap proof. A stranger
            // whose later-ranked (but genuinely signed) claim doesn't list
            // its own installation gets nothing. Either way, a losing
            // claimed-inbox submission never proceeds to the membership
            // check below: our own (unchanged, winning) log is what the
            // peer needs to catch up to first.
            if candidate_state
                .installation_ids()
                .contains(&self.peer_installation())
            {
                self.send_identity_conflict(&inbox_id)?;
                return Ok(());
            }
            // A failed proof must
            // disconnect exactly like the "we hold nothing for this inbox"
            // case below (fatal `PeerNotMember`), not linger connected
            // until the verification deadline -- otherwise how long a
            // stranger stays connected (immediately dropped vs. 10 s)
            // itself reveals whether we hold the inbox, through
            // disconnect timing alone even though no frame is ever sent
            // (D27).
            return Err(MeshError::PeerNotMember);
        }
        if !self.verified {
            if !self.is_member(&inbox_id).await? {
                return Err(MeshError::PeerNotMember);
            }
            self.mark_verified().await?;
        }
        resolved.map(|_| ())
    }

    /// Before restore convergence (and in tests that emulate such a node):
    /// only the claimed inbox's log counts; ingest, then require membership.
    async fn on_identity_log_legacy(&mut self, log: IdentityLog) -> Result<(), MeshError> {
        if self.peer_inbox.as_deref() != Some(log.inbox_id.as_str()) {
            return Ok(());
        }
        let ingested = self
            .node
            .ingest_identity_log(&log.inbox_id, log.updates)
            .await;
        if !self.verified {
            if !self.is_member(&log.inbox_id).await? {
                return Err(MeshError::PeerNotMember);
            }
            self.mark_verified().await?;
        }
        ingested.map(|_| ())
    }

    /// A verified peer relayed its copy of another inbox's log (§C4.2): it
    /// reconciles a log we hold (extends it, replaces it, or gets ours
    /// back). Authorized only under [`Self::may_consider`]
    /// (D27), checked *before* `holds_identity_log` so an
    /// unauthorized inbox looks the same (silence) whether or not we hold
    /// it. A log we do not hold is ignored, as before.
    async fn on_relayed_identity_log(&mut self, log: IdentityLog) -> Result<(), MeshError> {
        if !self.may_consider(&log.inbox_id).await?
            || !self.node.holds_identity_log(&log.inbox_id)?
        {
            return Ok(());
        }
        let resolution = self
            .node
            .resolve_identity_log(&log.inbox_id, log.updates)
            .await?;
        if matches!(resolution, Resolution::OursWins(_)) {
            self.send_identity_conflict(&log.inbox_id)?;
        }
        Ok(())
    }

    /// The peer says its copy of `log.inbox_id`'s log beats ours (§C4.2).
    /// Checked, never trusted: we replace only if it verifies and wins
    /// (§C4.3), and a same-origin log is ingested like any other. If ours
    /// wins, the peer gets ours; the winner rule is the same on both sides,
    /// so this never ping-pongs.
    ///
    /// Authorized the same way as a relay ([`Self::may_consider`]), or, on
    /// the claimed-inbox path (`inbox_id` is the peer's own claimed
    /// inbox), the same proof [`Self::on_identity_log`] uses: the peer's
    /// own submitted candidate fully verifies and lists the installation
    /// it authenticated as (D27). Checked before
    /// `holds_identity_log`.
    async fn on_identity_conflict(&mut self, log: IdentityLog) -> Result<(), MeshError> {
        if self.node.legacy_identity() {
            return Ok(());
        }
        let IdentityLog { inbox_id, updates } = log;
        let authorized = if self.may_consider(&inbox_id).await? {
            true
        } else if self.peer_inbox.as_deref() == Some(inbox_id.as_str()) {
            self.node
                .claimed_log_proves_installation(&inbox_id, &updates, &self.peer_installation())
                .await?
        } else {
            false
        };
        if !authorized || !self.node.holds_identity_log(&inbox_id)? {
            return Ok(());
        }
        let resolution = self.node.resolve_identity_log(&inbox_id, updates).await?;
        if matches!(resolution, Resolution::OursWins(_)) {
            self.send_identity_conflict(&inbox_id)?;
        }
        Ok(())
    }

    /// Whether the peer may have their claim about `inbox_id` looked at,
    /// and, if we hold a winning log for it, get it back
    /// (§C4.2, D27). True when either:
    /// - `inbox_id` is our own local inbox: never sensitive (we already
    ///   send our own log to every authenticated peer, verified or not, in
    ///   `send_own_identity`), and this is how a restored owner's contacts
    ///   help it converge before it can prove membership of anything.
    /// - the peer is verified and shares a group with `inbox_id`, the same
    ///   scope [`Self::relay_identity_logs`] uses to send it in the first
    ///   place.
    /// Checked before `holds_identity_log`, so an unauthorized inbox looks
    /// the same (silence) whether or not we hold it.
    async fn may_consider(&self, inbox_id: &str) -> Result<bool, MeshError> {
        if self.node.local_inbox()?.as_deref() == Some(inbox_id) {
            return Ok(true);
        }
        if !self.verified {
            return Ok(false);
        }
        let peer_inbox = self.peer_inbox.clone().unwrap_or_default();
        Ok(self
            .inboxes_sharing_a_group_with(&peer_inbox)
            .await?
            .contains(inbox_id))
    }

    /// At most one reply per inbox per session, so a
    /// peer that keeps sending a losing (or forged, if authorized) log
    /// can't flood the link with a fresh full log every time. Cleared for
    /// an inbox by [`Self::on_event`] once our log of it actually changes.
    fn send_identity_conflict(&mut self, inbox_id: &str) -> Result<(), MeshError> {
        if !self.conflict_sent.insert(inbox_id.to_string()) {
            return Ok(());
        }
        let mut updates = self.node.identity_log(inbox_id)?;
        updates.truncate(MAX_PEER_IDENTITY_LOG as usize);
        tracing::info!(
            peer = %self.peer,
            inbox_id,
            "identity conflict: our log of this inbox has the earlier origin; sending it"
        );
        self.send(Body::IdentityConflict(IdentityLog {
            inbox_id: inbox_id.to_string(),
            updates,
        }));
        Ok(())
    }

    /// §C4.2 relay: the logs we hold of inboxes that share a group with the
    /// peer, so that a peer holding a losing copy of one converges from us
    /// even when the owner is not here. A log
    /// of inbox X goes to the peer only if the peer's verified inbox and X
    /// are both members of some group this node knows, per the local
    /// client. Never to strangers: a nearby phone must not learn which
    /// inboxes this phone has met. At most [`MAX_RELAYED_IDENTITY_LOGS`].
    async fn relay_identity_logs(&self) -> Result<(), MeshError> {
        if self.node.legacy_identity() {
            return Ok(());
        }
        let Some(peer_inbox) = self.peer_inbox.clone().filter(|i| !i.is_empty()) else {
            return Ok(());
        };
        let own_inbox = self.node.local_inbox()?.unwrap_or_default();
        let shared = self.inboxes_sharing_a_group_with(&peer_inbox).await?;
        let relayable: Vec<String> = self
            .node
            .relayable_inboxes(&[peer_inbox.as_str(), own_inbox.as_str()])?
            .into_iter()
            .filter(|inbox| shared.contains(inbox))
            .take(MAX_RELAYED_IDENTITY_LOGS)
            .collect();
        for inbox_id in relayable {
            let mut updates = self.node.identity_log(&inbox_id)?;
            updates.truncate(MAX_PEER_IDENTITY_LOG as usize);
            self.send(Body::IdentityLog(IdentityLog { inbox_id, updates }));
        }
        Ok(())
    }

    /// Every inbox that is a member, together with `peer_inbox`, of some
    /// group this node knows (the local client's member lists). A group the
    /// client cannot report is skipped: when in doubt, relay nothing. Runs
    /// no store lock across the lookups.
    async fn inboxes_sharing_a_group_with(
        &self,
        peer_inbox: &str,
    ) -> Result<HashSet<String>, MeshError> {
        let mut shared = HashSet::new();
        for group_id in self.node.known_group_ids()? {
            match self.membership.member_inboxes(&group_id).await {
                Ok(Some(members)) if members.iter().any(|m| m == peer_inbox) => {
                    shared.extend(members);
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(peer = %self.peer, error = %e, "group membership unavailable; not relaying for it");
                }
            }
        }
        Ok(shared)
    }

    /// Our log of the verified peer's own inbox changed (a replace, or an
    /// update relayed by someone else, such as a revocation). If the peer's
    /// installation is no longer a member, it loses its verification: it
    /// is sent our log (§C4.2) and gets the verification deadline to prove
    /// membership again (an owner re-bases, §C4.4). Until then none of its
    /// group traffic is accepted (§C4.7 "no split brain").
    ///
    /// A security gate fails closed. If
    /// `is_member` itself errors (we can't tell), demote anyway rather
    /// than leave the peer verified on an unknown answer.
    async fn recheck_membership(&mut self) -> Result<(), MeshError> {
        let inbox_id = self.peer_inbox.clone().unwrap_or_default();
        match self.is_member(&inbox_id).await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(
                    peer = %self.peer,
                    inbox_id,
                    error = %e,
                    "membership check failed; demoting the peer to be safe"
                );
            }
        }
        tracing::info!(
            peer = %self.peer,
            inbox_id,
            "peer installation left its inbox's log; unverified until it proves membership again"
        );
        self.verified = false;
        self.verify_deadline = Some(Instant::now() + self.node.peer_verify_timeout());
        self.peer_interest.clear();
        self.deferred.clear();
        self.retry_at = None;
        self.node.session_unverified(&self.peer, self.id);
        self.send_identity_conflict(&inbox_id)
    }

    /// Runs once the peer's membership is proven: deliver the welcomes queued
    /// for it, announce every group it may hear about, and relay the
    /// identity logs of inboxes that share a group with it (§C4.2). Every step always runs; the first error
    /// is returned for logging.
    async fn on_verified(&mut self) -> Result<(), MeshError> {
        // Both Hellos must have offered relay: a session that did not
        // advertise it never links up, even if relay was enabled since.
        if self.peer_relay && self.self_relay {
            self.node.relay_session_link_up(
                &self.peer,
                self.id,
                self.peer_installation(),
                self.peer_inbox.clone().unwrap_or_default(),
            );
        }
        let welcomes = self.send_welcomes();
        let announced = self.announce_all().await;
        let relayed = self.relay_identity_logs().await;
        welcomes.and(announced).and(relayed)
    }

    async fn on_authenticated_frame(&mut self, body: Body) -> Result<(), MeshError> {
        match body {
            Body::IdentityLog(log) => self.on_identity_log(log).await,
            Body::IdentityConflict(log) => self.on_identity_conflict(log).await,
            // Only the peer's own key package: relaying others' would let any
            // peer replace a stored package with an older genuine one.
            Body::KeyPackage(kp)
                if self.peer_installation.as_ref() == Some(&kp.installation_key) =>
            {
                self.node.ingest_peer_key_package(&kp)
            }
            Body::KeyPackage(_) => Ok(()),
            body if self.verified => self.on_verified_frame(body).await,
            // Everything else waits for membership to be proven.
            _ => Ok(()),
        }
    }

    /// Frames from a verified peer: welcomes and group sync. Rule A: only the
    /// pinned sequencer assigns order, and all group traffic is scoped to the
    /// group's members as our libxmtp client sees them (see the crate docs).
    async fn on_verified_frame(&mut self, body: Body) -> Result<(), MeshError> {
        match body {
            Body::Welcome(welcome) => {
                if let Some(envelope_hash) = self.node.ingest_welcome(welcome)? {
                    self.send(Body::WelcomeAck(WelcomeAck { envelope_hash }));
                }
                Ok(())
            }
            Body::WelcomeAck(ack) => {
                // The peer holds the welcome now: announce the groups it may
                // join (those it is already a member of, as we see them).
                if self
                    .node
                    .ack_outbound_welcome(&self.peer_installation(), &ack.envelope_hash)?
                {
                    self.announce_all().await?;
                }
                Ok(())
            }
            Body::Interest(interest) => self.on_interest(interest).await,
            Body::Sequenced(sequenced) => self.on_sequenced(sequenced).await,
            Body::Pending(pending) => self.on_pending(pending).await,
            body @ (Body::Relay(_)
            | Body::SpoolDigest(_)
            | Body::SpoolWant(_)
            | Body::RelayKeyOffer(_)
            | Body::RelayKeyAck(_)) => {
                // Relay errors are never fatal to a session: the engine logs them.
                if self.peer_relay {
                    self.node.on_relay_frame(&self.peer, body).await;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn local_installation(&self) -> Vec<u8> {
        self.signer.installation_key()
    }

    fn peer_installation(&self) -> Vec<u8> {
        self.peer_installation
            .clone()
            .expect("verified peer has an installation")
    }

    /// Whether the verified peer's inbox is a current member of `group_id`
    /// per the local client. Another installation of our own inbox is never
    /// treated as a member (D7). Runs no store lock across the lookup.
    async fn peer_membership(&self, group_id: &[u8]) -> Membership {
        let Some(peer_inbox) = self.peer_inbox.as_deref().filter(|i| !i.is_empty()) else {
            return Membership::NotMember;
        };
        match self.node.local_inbox() {
            Ok(Some(own)) if own == peer_inbox => return Membership::NotMember,
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(peer = %self.peer, error = %e, "local inbox unavailable");
                return Membership::Unknown;
            }
        }
        match self.membership.member_inboxes(group_id).await {
            Ok(Some(members)) if members.iter().any(|m| m == peer_inbox) => Membership::Member,
            Ok(Some(_)) => Membership::NotMember,
            Ok(None) => Membership::Unknown,
            Err(e) => {
                tracing::warn!(peer = %self.peer, error = %e, "group membership unavailable");
                Membership::Unknown
            }
        }
    }

    /// The membership gate for traffic about `gid`. Returns true when the
    /// caller may go on with its normal handling.
    ///
    /// When the peer is not (yet) a member, `ask` is remembered and the group
    /// re-checked later: libxmtp may not have processed the welcome yet
    /// (`Unknown`), or not yet merged the commit that added the peer
    /// (`NotMember`, deferred only when `defer_non_member`). When the peer is
    /// a member and something was deferred for the group, the merged request
    /// is resolved here instead (and false returned: it covered this call).
    async fn admit(
        &mut self,
        gid: &[u8],
        ask: Ask,
        defer_non_member: bool,
    ) -> Result<bool, MeshError> {
        match self.peer_membership(gid).await {
            Membership::Member => match self.deferred.remove(gid) {
                Some(mut deferred) => {
                    deferred.ask.merge(ask);
                    self.resolve(gid, deferred.ask).await?;
                    Ok(false)
                }
                None => Ok(true),
            },
            Membership::NotMember if !defer_non_member => Ok(false),
            Membership::NotMember | Membership::Unknown => {
                self.defer(gid, ask);
                Ok(false)
            }
        }
    }

    fn defer(&mut self, gid: &[u8], ask: Ask) {
        if let Some(deferred) = self.deferred.get_mut(gid) {
            deferred.ask.merge(ask);
            return;
        }
        if self.deferred.len() >= MAX_DEFERRED_GROUPS {
            tracing::warn!(peer = %self.peer, "too many groups awaiting membership; dropping one");
            return;
        }
        let now = Instant::now();
        self.deferred
            .insert(gid.to_vec(), Deferred { since: now, ask });
        self.retry_at.get_or_insert(now + MEMBERSHIP_RETRY_INTERVAL);
    }

    /// Re-check every deferred group; resolve those the peer is now a member
    /// of, and forget those deferred longer than [`MEMBERSHIP_RETRY_WINDOW`].
    async fn retry_deferred(&mut self) -> Result<(), MeshError> {
        self.retry_at = None;
        let now = Instant::now();
        self.deferred
            .retain(|_, d| now.duration_since(d.since) < MEMBERSHIP_RETRY_WINDOW);
        let gids: Vec<Vec<u8>> = self.deferred.keys().cloned().collect();
        let mut result = Ok(());
        for gid in gids {
            if self.peer_membership(&gid).await != Membership::Member {
                continue;
            }
            if let Some(deferred) = self.deferred.remove(&gid) {
                result = result.and(self.resolve(&gid, deferred.ask).await);
            }
        }
        if !self.deferred.is_empty() {
            self.retry_at = Some(Instant::now() + MEMBERSHIP_RETRY_INTERVAL);
        }
        result
    }

    /// Act on what a member peer asked while its membership was unknown:
    /// record its interest, pin it if it claimed the (still unpinned) group,
    /// then sync the group with it: serve it (we sequence), flush our pending
    /// to it (it sequences), or tell it what we hold.
    async fn resolve(&mut self, gid: &[u8], ask: Ask) -> Result<(), MeshError> {
        if !self.node.is_known_group(gid)? {
            return Ok(());
        }
        if ask.interested {
            self.peer_interest.insert(gid.to_vec());
        }
        let local = self.local_installation();
        let peer = self.peer_installation();
        let sequencer = match self.node.sequencer_of(gid)? {
            Some(s) => Some(s),
            None if ask.claimed => Some(self.node.pin_sequencer(gid, &peer)?),
            None => None,
        };
        match sequencer {
            Some(s) if s == local => match ask.high {
                Some(high) => self.serve_sequenced(gid, high as i64)?,
                None => self.send(Body::Interest(self.node.group_summary(gid)?)),
            },
            Some(s) if s == peer => {
                self.flush_pending(gid).await?;
                self.send(Body::Interest(self.node.group_summary(gid)?));
            }
            Some(_) => {}
            None => self.send(Body::Interest(self.node.group_summary(gid)?)),
        }
        Ok(())
    }

    /// Send our pending messages for the group to its sequencer (the peer),
    /// paged, if the peer is a member of the group.
    async fn flush_pending(&self, group_id: &[u8]) -> Result<(), MeshError> {
        let messages = self.node.pending_inputs(group_id)?;
        if messages.is_empty() || self.peer_membership(group_id).await != Membership::Member {
            return Ok(());
        }
        for messages in frames::pages(messages, input_len) {
            self.send(Body::Pending(Pending {
                group_id: group_id.to_vec(),
                messages,
            }));
        }
        Ok(())
    }

    /// Serve the group's sequenced messages after `high`, in pages of
    /// consecutive frames (one empty frame when there are none, which still
    /// tells the peer who sequences the group). A message too large for any
    /// frame ends the reply: sending the pages after it would only make the
    /// peer detect a gap and ask again, forever. Callers check membership.
    fn serve_sequenced(&self, group_id: &[u8], mut high: i64) -> Result<(), MeshError> {
        let mut first = true;
        loop {
            let batch = self
                .node
                .sequenced_after(group_id, high, MAX_MESSAGES_PER_FRAME)?;
            let full = batch.len() == MAX_MESSAGES_PER_FRAME;
            if batch.is_empty() && !first {
                return Ok(());
            }
            first = false;
            let pages = if batch.is_empty() {
                vec![vec![]]
            } else {
                frames::pages(batch, |(m, _)| message_len(m))
            };
            for page in pages {
                high = page.last().map_or(high, |(m, _)| message_id(m));
                let frame = frames::sequenced_frame(group_id, page);
                if !self.try_send(Body::Sequenced(frame)) {
                    return Ok(()); // oversized (logged) or cancelled
                }
            }
            if !full {
                return Ok(());
            }
        }
    }

    fn send_welcomes(&self) -> Result<(), MeshError> {
        for welcome in self.node.outbound_welcomes_for(&self.peer_installation())? {
            self.send(Body::Welcome(welcome));
        }
        Ok(())
    }

    /// Whether the peer may hear about `gid`: it is a member of the group
    /// (per our client) and the group is unpinned, or pinned to us or to the
    /// peer. A group our client does not know yet is deferred and announced
    /// once it does.
    async fn may_announce(&mut self, gid: &[u8]) -> Result<bool, MeshError> {
        let peer = self.peer_installation();
        let local = self.local_installation();
        if let Some(s) = self.node.sequencer_of(gid)?
            && s != peer
            && s != local
        {
            return Ok(false);
        }
        self.admit(gid, Ask::default(), false).await
    }

    async fn announce_all(&mut self) -> Result<(), MeshError> {
        let peer = self.peer_installation();
        for interest in self.node.group_summaries()? {
            let gid = interest.group_id.clone();
            if !self.may_announce(&gid).await? {
                continue;
            }
            self.send(Body::Interest(interest));
            if self.node.sequencer_of(&gid)?.as_deref() == Some(peer.as_slice()) {
                self.flush_pending(&gid).await?;
            }
        }
        Ok(())
    }

    /// The peer (a member of the group) wants `interest.group_id` from
    /// `high_id` on. A member claiming to sequence an unpinned group is
    /// pinned (trust-on-first-use among members). The sequencer answers with
    /// what it has; a member whose sequencer is the peer flushes its pending
    /// messages. Groups we have never seen locally are ignored.
    async fn on_interest(&mut self, interest: Interest) -> Result<(), MeshError> {
        let gid = interest.group_id.clone();
        if !self.node.is_known_group(&gid)? {
            return Ok(());
        }
        let ask = Ask {
            claimed: interest.i_am_sequencer,
            interested: true,
            high: Some(interest.high_id),
        };
        if !self.admit(&gid, ask, true).await? {
            return Ok(());
        }
        self.peer_interest.insert(gid.clone());
        let local = self.local_installation();
        let peer = self.peer_installation();
        let (sequencer, newly_pinned) = match self.node.sequencer_of(&gid)? {
            Some(s) => (s, false),
            None if interest.i_am_sequencer => (self.node.pin_sequencer(&gid, &peer)?, true),
            None => return Ok(()),
        };
        if sequencer == local {
            // Clamped to what we hold (relay_note_peer_high).
            self.node
                .relay_note_peer_high(&gid, i64::try_from(interest.high_id).unwrap_or(i64::MAX));
            self.serve_sequenced(&gid, interest.high_id as i64)?;
        } else if sequencer == peer {
            self.flush_pending(&gid).await?;
            // The sequencer holds rows we lack (e.g. a push lost to a lagged
            // event stream), or we just pinned it and it has not heard our
            // interest yet: ask from what we have.
            let ours = self.node.group_summary(&gid)?;
            if newly_pinned || interest.high_id > ours.high_id {
                self.send(Body::Interest(ours));
            }
        }
        Ok(())
    }

    /// Accepted only from the group's pinned sequencer (a member), and only
    /// if the whole frame passes the §B13 accept rule (a refused frame ends
    /// the session); on a gap, ask again from what we hold.
    async fn on_sequenced(&mut self, sequenced: Sequenced) -> Result<(), MeshError> {
        let gid = sequenced.group_id.clone();
        if !self.node.is_known_group(&gid)? {
            return Ok(());
        }
        let ask = Ask {
            claimed: sequenced.sender_is_sequencer,
            ..Ask::default()
        };
        if !self.admit(&gid, ask, true).await? {
            return Ok(());
        }
        let peer = self.peer_installation();
        let (sequencer, newly_pinned) = match self.node.sequencer_of(&gid)? {
            Some(s) => (s, false),
            None if sequenced.sender_is_sequencer => (self.node.pin_sequencer(&gid, &peer)?, true),
            None => return Ok(()),
        };
        if sequencer != peer {
            return Ok(());
        }
        let rows =
            crate::node::sequencing::rows_from_sequenced(sequenced.messages, sequenced.proofs)
                .map_err(|reason| self.node.reject_sequencing(reason))?;
        if let Some(have) = self
            .node
            .ingest_proven(&gid, rows, self.membership.as_ref())
            .await?
        {
            self.send(Body::Interest(Interest {
                group_id: gid.clone(),
                high_id: have as u64,
                i_am_sequencer: false,
            }));
        }
        if newly_pinned {
            self.flush_pending(&gid).await?;
        }
        Ok(())
    }

    /// Sequencer side: order the pending messages of a member.
    async fn on_pending(&mut self, pending: Pending) -> Result<(), MeshError> {
        let gid = pending.group_id.clone();
        if self.node.sequencer_of(&gid)?.as_deref() != Some(self.local_installation().as_slice()) {
            return Ok(());
        }
        let ask = Ask {
            interested: true,
            ..Ask::default()
        };
        if !self.admit(&gid, ask, true).await? {
            return Ok(());
        }
        self.peer_interest.insert(gid.clone());
        self.node.sequence_from_peer(&gid, pending.messages)
    }

    async fn on_event(&mut self, event: NodeEvent) -> Result<(), MeshError> {
        if self.state != State::Authenticated {
            return Ok(());
        }
        if let NodeEvent::IdentityLogChanged(inbox_id) | NodeEvent::IdentityLogReplaced(inbox_id) =
            &event
        {
            // Our log of this inbox actually changed, so a
            // fresh conflict reply is allowed again instead of throttled
            // for the rest of the session.
            self.conflict_sent.remove(inbox_id);
        }
        match event {
            NodeEvent::LocalIdentityChanged | NodeEvent::LocalKeyPackageChanged => {
                self.send_own_identity()
            }
            NodeEvent::IdentityLogChanged(inbox_id) | NodeEvent::IdentityLogReplaced(inbox_id)
                if !self.node.legacy_identity()
                    && self.peer_inbox.as_deref() == Some(inbox_id.as_str()) =>
            {
                if self.verified {
                    self.recheck_membership().await
                } else if self.is_member(&inbox_id).await? {
                    // A demoted (or never-verified)
                    // peer whose re-base reaches us through a third party
                    // re-verifies as soon as our log of its claimed inbox
                    // shows it, instead of waiting for its own IdentityLog
                    // frame or the deadline.
                    self.mark_verified().await
                } else {
                    Ok(())
                }
            }
            event if self.verified => self.on_verified_event(event).await,
            _ => Ok(()),
        }
    }

    /// Local changes a verified peer should hear about: newly sequenced
    /// messages (when we are the sequencer and the peer is an interested
    /// member), pending messages for a peer sequencer, welcomes for the
    /// peer, and groups our client just started using.
    async fn on_verified_event(&mut self, event: NodeEvent) -> Result<(), MeshError> {
        let local = self.local_installation();
        let peer = self.peer_installation();
        match event {
            NodeEvent::GroupSequenced(row) => {
                if !self.node.group_push_suppressed()
                    && self.peer_interest.contains(&row.group_id)
                    && self.node.sequencer_of(&row.group_id)?.as_deref() == Some(local.as_slice())
                    && self.peer_membership(&row.group_id).await == Membership::Member
                {
                    self.send(Body::Sequenced(frames::sequenced_frame(
                        &row.group_id,
                        vec![(row.to_proto(), row.proof())],
                    )));
                }
                Ok(())
            }
            NodeEvent::PendingAdded(gid) => {
                if self.node.sequencer_of(&gid)?.as_deref() == Some(peer.as_slice()) {
                    self.flush_pending(&gid).await?;
                }
                Ok(())
            }
            NodeEvent::WelcomeOutbound(installation) if installation == peer => {
                self.send_welcomes()
            }
            // Our client queried the group, so it knows the group and its
            // members now: announce it, or resolve what was deferred for it.
            NodeEvent::GroupKnown(gid) => {
                if self.may_announce(&gid).await? {
                    self.send(Body::Interest(self.node.group_summary(&gid)?));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Missed node events: resend everything a fresh verification would.
    async fn on_lagged(&mut self) -> Result<(), MeshError> {
        if self.verified {
            self.on_verified().await
        } else {
            Ok(())
        }
    }
}

fn message_len(m: &GroupMessage) -> usize {
    match &m.version {
        Some(group_message::Version::V1(v1)) => v1.data.len() + v1.sender_hmac.len(),
        None => 0,
    }
}

fn message_id(m: &GroupMessage) -> i64 {
    match &m.version {
        Some(group_message::Version::V1(v1)) => v1.id as i64,
        None => 0,
    }
}

fn input_len(m: &GroupMessageInput) -> usize {
    match &m.version {
        Some(group_message_input::Version::V1(v1)) => v1.data.len() + v1.sender_hmac.len(),
        None => 0,
    }
}

/// Completes at `deadline`, or never when there is none.
async fn until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}
