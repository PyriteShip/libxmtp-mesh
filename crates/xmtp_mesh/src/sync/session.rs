use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::Instant;

use super::auth::{self, HelloSigner};
use super::frames::{self, Auth, Hello, IdentityLog, Interest, Pending, Sequenced, WelcomeAck, frame::Body};
use super::transport::{MeshTransport, PeerId};
use crate::node::{MeshNode, NodeEvent};
use crate::MeshError;

pub(crate) struct SessionHandle {
    /// Distinguishes this session from earlier/later ones for the same peer.
    pub(crate) id: u64,
    pub(crate) tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Set (and `_wake` dropped) when this handle leaves the registry, i.e. the
    /// peer was lost or the entry replaced. A tokio mpsc receiver keeps draining
    /// buffered frames after its senders drop, so the session task checks this
    /// before every frame and every send: after a reconnect under the same
    /// `PeerId` a stale session must never talk to the peer's new session.
    cancelled: Arc<AtomicBool>,
    _wake: oneshot::Sender<()>,
}

impl SessionHandle {
    pub(crate) fn new(id: u64, tx: mpsc::UnboundedSender<Vec<u8>>) -> (Self, Arc<AtomicBool>, oneshot::Receiver<()>) {
        let cancelled = Arc::new(AtomicBool::new(false));
        let (wake, wake_rx) = oneshot::channel();
        (Self { id, tx, cancelled: cancelled.clone(), _wake: wake }, cancelled, wake_rx)
    }
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
/// Authenticated means a live holder of installation key K answered through
/// this pipe; it does not bind the PeerId to K against a relaying
/// man-in-the-middle (channel binding arrives with the planned Noise upgrade).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    AwaitHello,
    AwaitAuth,
    Authenticated,
}

pub(crate) struct Session {
    pub(crate) id: u64,
    cancelled: Arc<AtomicBool>,
    pub(crate) node: MeshNode,
    pub(crate) peer: PeerId,
    pub(crate) transport: Arc<dyn MeshTransport>,
    pub(crate) signer: Arc<dyn HelloSigner>,
    pub(crate) challenge: [u8; 32],
    pub(crate) state: State,
    pub(crate) peer_installation: Option<Vec<u8>>,
    pub(crate) peer_inbox: Option<String>,
    /// The peer proved (via its identity log) that its installation belongs to its inbox.
    pub(crate) verified: bool,
    /// Armed at authentication while unverified: a peer that has not proven
    /// membership by then is dropped as `PeerNotMember`.
    pub(crate) verify_deadline: Option<Instant>,
    pub(crate) peer_interest: HashSet<Vec<u8>>,
}

pub(crate) fn spawn(
    node: MeshNode,
    peer: PeerId,
    transport: Arc<dyn MeshTransport>,
    signer: Arc<dyn HelloSigner>,
) -> SessionHandle {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = mpsc::unbounded_channel();
    let (handle, cancelled, wake) = SessionHandle::new(id, tx);
    let events = node.subscribe_events();
    let session = Session {
        id,
        cancelled,
        node,
        peer,
        transport,
        signer,
        challenge: rand::random(),
        state: State::AwaitHello,
        peer_installation: None,
        peer_inbox: None,
        verified: false,
        verify_deadline: None,
        peer_interest: HashSet::new(),
    };
    tokio::spawn(session.run(rx, events, wake));
    handle
}

impl Session {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn send(&self, body: Body) {
        if self.is_cancelled() {
            return;
        }
        self.transport.send(&self.peer, frames::encode(body));
    }

    async fn run(
        mut self,
        mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
        mut events: broadcast::Receiver<NodeEvent>,
        mut wake: oneshot::Receiver<()>,
    ) {
        self.run_loop(&mut rx, &mut events, &mut wake).await;
        self.node.session_ended(&self.peer, self.id);
    }

    async fn run_loop(
        &mut self,
        rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
        events: &mut broadcast::Receiver<NodeEvent>,
        wake: &mut oneshot::Receiver<()>,
    ) {
        if self.is_cancelled() {
            return;
        }
        let hello = Hello {
            installation_key: self.signer.installation_key(),
            inbox_id: self.node.local_inbox().ok().flatten().unwrap_or_default(),
            challenge: self.challenge.to_vec(),
        };
        self.send(Body::Hello(hello));
        loop {
            let deadline = if self.verified { None } else { self.verify_deadline };
            tokio::select! {
                biased;
                _ = &mut *wake => break,
                _ = until(deadline) => {
                    tracing::warn!(peer = %self.peer, "peer did not prove inbox membership in time");
                    if !self.is_cancelled() {
                        self.transport.disconnect(&self.peer);
                    }
                    break;
                }
                frame = rx.recv() => {
                    let Some(bytes) = frame else { break };
                    if self.is_cancelled() {
                        break;
                    }
                    if let Err(e) = self.on_frame(&bytes).await {
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
                        if let Err(e) = self.on_event(event) {
                            tracing::warn!(peer = %self.peer, error = %e, "mesh event failed");
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if let Err(e) = self.on_lagged() {
                            tracing::warn!(peer = %self.peer, error = %e, "mesh resync failed");
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            }
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

    fn on_hello(&mut self, hello: Hello) -> Result<(), MeshError> {
        if hello.installation_key.len() != 32 || hello.challenge.len() != 32 {
            return Err(MeshError::AuthFailed("malformed hello".into()));
        }
        let own_key = self.signer.installation_key();
        if hello.installation_key == own_key {
            return Err(MeshError::AuthFailed("hello carries our own installation key".into()));
        }
        if self.peer_installation.as_ref().is_some_and(|k| *k != hello.installation_key) {
            return Err(MeshError::AuthFailed("peer changed installation key".into()));
        }
        let text = auth::hello_text(&hello.challenge, &own_key, &hello.installation_key);
        let signature = self.signer.sign(&text)?;
        if self.state == State::AwaitHello {
            self.peer_installation = Some(hello.installation_key);
            self.peer_inbox = Some(hello.inbox_id);
            self.state = State::AwaitAuth;
        }
        self.send(Body::Auth(Auth { signature, challenge: hello.challenge }));
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
        let Some(inbox_id) = self.peer_inbox.clone() else { return Ok(()) };
        if self.is_member(&inbox_id).await? {
            self.mark_verified()?;
        }
        Ok(())
    }

    async fn is_member(&self, inbox_id: &str) -> Result<bool, MeshError> {
        let claimed = self.peer_installation.as_ref().expect("set by hello");
        Ok(self.node.installations_of(inbox_id).await?.contains(claimed))
    }

    fn mark_verified(&mut self) -> Result<(), MeshError> {
        self.verified = true;
        self.verify_deadline = None;
        self.on_verified()
    }

    /// Ingest the log, then, if it is the log of the inbox the peer claimed in
    /// its Hello, require the peer's installation to be a member of it. The
    /// membership check runs even when ingestion failed part-way: a peer that
    /// cannot prove membership with what we hold is dropped.
    async fn on_identity_log(&mut self, log: IdentityLog) -> Result<(), MeshError> {
        let ingested = self.node.ingest_identity_log(&log.inbox_id, log.updates).await;
        if !self.verified && self.peer_inbox.as_deref() == Some(log.inbox_id.as_str()) {
            if !self.is_member(&log.inbox_id).await? {
                return Err(MeshError::PeerNotMember);
            }
            self.mark_verified()?;
        }
        ingested
    }

    /// Runs once the peer's membership is proven: deliver the welcomes queued
    /// for it and announce every group we know.
    /// Both steps always run; an error from either is returned for logging.
    fn on_verified(&mut self) -> Result<(), MeshError> {
        let welcomes = self.send_welcomes();
        let announced = self.announce_all();
        welcomes.and(announced)
    }

    async fn on_authenticated_frame(&mut self, body: Body) -> Result<(), MeshError> {
        match body {
            Body::IdentityLog(log) => self.on_identity_log(log).await,
            // Only the peer's own key package: relaying others' would let any
            // peer replace a stored package with an older genuine one.
            Body::KeyPackage(kp) if self.peer_installation.as_ref() == Some(&kp.installation_key) => {
                self.node.ingest_peer_key_package(&kp)
            }
            Body::KeyPackage(_) => Ok(()),
            body if self.verified => self.on_verified_frame(body),
            // Everything else waits for membership to be proven.
            _ => Ok(()),
        }
    }

    /// Frames from a verified peer: welcomes and group sync. Rule A: only the
    /// pinned sequencer assigns order, and a sequencer is pinned
    /// trust-on-first-use only from a verified peer's claim.
    fn on_verified_frame(&mut self, body: Body) -> Result<(), MeshError> {
        match body {
            Body::Welcome(welcome) => {
                if let Some(envelope_hash) = self.node.ingest_welcome(welcome)? {
                    self.send(Body::WelcomeAck(WelcomeAck { envelope_hash }));
                }
                Ok(())
            }
            Body::WelcomeAck(ack) => self.node.ack_outbound_welcome(&self.peer_installation(), &ack.envelope_hash),
            Body::Interest(interest) => self.on_interest(interest),
            Body::Sequenced(sequenced) => self.on_sequenced(sequenced),
            Body::Pending(pending) => self.on_pending(pending),
            _ => Ok(()),
        }
    }

    fn local_installation(&self) -> Vec<u8> {
        self.signer.installation_key()
    }

    fn peer_installation(&self) -> Vec<u8> {
        self.peer_installation.clone().expect("verified peer has an installation")
    }

    fn flush_pending(&self, group_id: &[u8]) -> Result<(), MeshError> {
        let messages = self.node.pending_inputs(group_id)?;
        if !messages.is_empty() {
            self.send(Body::Pending(Pending { group_id: group_id.to_vec(), messages }));
        }
        Ok(())
    }

    fn send_welcomes(&self) -> Result<(), MeshError> {
        for welcome in self.node.outbound_welcomes_for(&self.peer_installation())? {
            self.send(Body::Welcome(welcome));
        }
        Ok(())
    }

    fn announce_all(&self) -> Result<(), MeshError> {
        let peer = self.peer_installation();
        for interest in self.node.group_summaries()? {
            let gid = interest.group_id.clone();
            self.send(Body::Interest(interest));
            if self.node.sequencer_of(&gid)?.as_deref() == Some(peer.as_slice()) {
                self.flush_pending(&gid)?;
            }
        }
        Ok(())
    }

    /// The peer wants `interest.group_id` from `high_id` on. The sequencer
    /// answers with what it has; a member whose sequencer is the peer flushes
    /// its pending messages. Groups we have never seen locally are ignored.
    fn on_interest(&mut self, interest: Interest) -> Result<(), MeshError> {
        let gid = interest.group_id.clone();
        self.peer_interest.insert(gid.clone());
        if !self.node.is_known_group(&gid)? {
            return Ok(());
        }
        let local = self.local_installation();
        let peer = self.peer_installation();
        let sequencer = match self.node.sequencer_of(&gid)? {
            Some(s) => s,
            None if interest.i_am_sequencer => self.node.pin_sequencer(&gid, &peer)?,
            None => return Ok(()),
        };
        if sequencer == local {
            self.send(Body::Sequenced(Sequenced {
                group_id: gid.clone(),
                messages: self.node.sequenced_after(&gid, interest.high_id as i64)?,
                sender_is_sequencer: true,
            }));
        } else if sequencer == peer {
            self.flush_pending(&gid)?;
            // The sequencer holds rows we lack (e.g. a push lost to a lagged
            // event stream, or we just pinned it): ask from what we have.
            let ours = self.node.group_summary(&gid)?;
            if interest.high_id > ours.high_id {
                self.send(Body::Interest(ours));
            }
        }
        Ok(())
    }

    /// Accepted only from the group's pinned sequencer; on a gap, ask again
    /// from what we hold.
    fn on_sequenced(&mut self, sequenced: Sequenced) -> Result<(), MeshError> {
        let gid = sequenced.group_id.clone();
        if !self.node.is_known_group(&gid)? {
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
        if let Some(have) = self.node.ingest_sequenced(&gid, sequenced.messages)? {
            self.send(Body::Interest(Interest { group_id: gid.clone(), high_id: have as u64, i_am_sequencer: false }));
        }
        if newly_pinned {
            self.flush_pending(&gid)?;
        }
        Ok(())
    }

    /// Sequencer side: order the peer's pending messages.
    fn on_pending(&mut self, pending: Pending) -> Result<(), MeshError> {
        let gid = pending.group_id.clone();
        if self.node.sequencer_of(&gid)?.as_deref() != Some(self.local_installation().as_slice()) {
            return Ok(());
        }
        self.peer_interest.insert(gid.clone());
        self.node.sequence_from_peer(&gid, pending.messages)
    }

    fn on_event(&mut self, event: NodeEvent) -> Result<(), MeshError> {
        if self.state != State::Authenticated {
            return Ok(());
        }
        match event {
            NodeEvent::LocalIdentityChanged | NodeEvent::LocalKeyPackageChanged => self.send_own_identity(),
            event if self.verified => self.on_verified_event(event),
            _ => Ok(()),
        }
    }

    /// Local changes a verified peer should hear about: newly sequenced
    /// messages (when we are the sequencer and the peer is interested),
    /// pending messages for a peer sequencer, welcomes for the peer, and
    /// groups we just learned about.
    fn on_verified_event(&mut self, event: NodeEvent) -> Result<(), MeshError> {
        let local = self.local_installation();
        let peer = self.peer_installation();
        match event {
            NodeEvent::GroupSequenced(row) => {
                if !self.node.group_push_suppressed()
                    && self.peer_interest.contains(&row.group_id)
                    && self.node.sequencer_of(&row.group_id)?.as_deref() == Some(local.as_slice())
                {
                    self.send(Body::Sequenced(Sequenced {
                        group_id: row.group_id.clone(),
                        messages: vec![row.to_proto()],
                        sender_is_sequencer: true,
                    }));
                }
                Ok(())
            }
            NodeEvent::PendingAdded(gid) => {
                if self.node.sequencer_of(&gid)?.as_deref() == Some(peer.as_slice()) {
                    self.flush_pending(&gid)?;
                }
                Ok(())
            }
            NodeEvent::WelcomeOutbound(installation) if installation == peer => self.send_welcomes(),
            NodeEvent::GroupKnown(gid) => {
                self.send(Body::Interest(self.node.group_summary(&gid)?));
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Missed node events: resend everything a fresh verification would.
    fn on_lagged(&mut self) -> Result<(), MeshError> {
        if self.verified { self.on_verified() } else { Ok(()) }
    }
}

/// Completes at `deadline`, or never when there is none.
async fn until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}
