mod convergence;
mod group_messages;
mod handover;
mod identity;
mod key_packages;
mod links;
pub(crate) mod paths;
pub(crate) mod sequencing;
mod streams;
mod sync_api;
#[cfg(test)]
mod sync_api_tests;
#[cfg(test)]
pub(crate) mod test_logs;
mod welcomes;

pub(crate) use convergence::MAX_RELAYED_IDENTITY_LOGS;
pub use convergence::{Resolution, ResyncOutcome};
pub(crate) use sync_api::MAX_PEER_IDENTITY_LOG;

use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::time::Duration;

use bytes::Bytes;
use futures::Stream;
use http::{request, uri::PathAndQuery};
use parking_lot::Mutex;
use tokio::sync::broadcast;
use xmtp_api_grpc::error::GrpcError;
use xmtp_proto::api::{ApiClientError, Client, IsConnectedCheck};

use crate::MeshError;
use crate::link::LinkRole;
use crate::store::{MeshStore, StoredGroupMessage, StoredWelcome};
use crate::sync::session::{Inbound, LinkSetup};
use crate::sync::{GroupMembership, HelloSigner, MeshTransport, PeerId, session};

pub type MeshStream = Pin<Box<dyn Stream<Item = Result<Bytes, GrpcError>> + Send>>;

/// An in-process XMTP v3 node. Cheap to clone; all clones share state.
#[derive(Clone)]
pub struct MeshNode {
    pub(crate) inner: Arc<NodeInner>,
}

pub(crate) struct NodeInner {
    pub(crate) store: Mutex<MeshStore>,
    pub(crate) events: broadcast::Sender<NodeEvent>,
    pub(crate) sync: Mutex<Option<SyncConfig>>,
    pub(crate) sessions: Mutex<HashMap<PeerId, session::SessionHandle>>,
    pub(crate) authenticated: Mutex<HashSet<PeerId>>,
    pub(crate) verified: Mutex<HashMap<PeerId, VerifiedPeer>>,
    /// How long an authenticated peer has to prove inbox membership.
    pub(crate) peer_verify_timeout: Mutex<Duration>,
    /// How long a session has to complete its Noise handshake and Hello/Auth.
    pub(crate) handshake_timeout: Mutex<Duration>,
    /// How long an open relay link may go without a relayed envelope
    /// accepted as new.
    pub(crate) relay_idle_timeout: Mutex<Duration>,
    /// How long a relay link may stay open at all.
    pub(crate) relay_link_lifetime: Mutex<Duration>,
    /// How long a radio peer is refused as a stranger after its relay link
    /// was closed idle, at a cap or for a rejected frame (§B14.3).
    pub(crate) relay_backoff: Mutex<Duration>,
    /// Radio peers refused as strangers until the given instant.
    pub(crate) relay_backoffs: Mutex<HashMap<PeerId, std::time::Instant>>,
    /// How long an open pairing link waits for both people to confirm.
    pub(crate) pairing_timeout: Mutex<Duration>,
    /// Test only: never send our identity log to peers.
    pub(crate) suppress_identity_log: AtomicBool,
    /// Test only: sessions drop live GroupSequenced pushes (simulates a lagged stream).
    pub(crate) suppress_group_push: AtomicBool,
    /// When each inbox's identity log was last replaced (flap guard, §C4.3).
    pub(crate) replaced_at: Mutex<HashMap<String, std::time::Instant>>,
    pub(crate) replace_flap_window: Mutex<Duration>,
    /// Replaces so far (tests assert convergence settles).
    pub(crate) replacements: AtomicU64,
    /// The identity task (convergence.rs), alive between start_sync and stop_sync.
    pub(crate) identity_task: Mutex<Option<tokio::task::AbortHandle>>,
    /// Test only: behave like a node from before restore convergence.
    pub(crate) legacy_identity: AtomicBool,
    /// Test only: suppress the
    /// §C4.7 handover's automatic trigger (the identity task and
    /// `start_sync`), so a test can prove a gate other than the handover's
    /// own sequencer repin is what refuses a revoked installation's frames.
    /// `hand_over_sequencers` itself is never suppressed -- only its
    /// automatic callers are.
    pub(crate) suppress_handover: AtomicBool,
    /// Test only: the identity task never resyncs the
    /// client, as if the process died right after a replace committed.
    pub(crate) suppress_client_resync: AtomicBool,
    /// Serializes `start_sync`/`stop_sync`: they
    /// update `identity_task` and `sync` under separate locks, so a
    /// concurrent start and stop could otherwise interleave and leave
    /// `sync` set with no identity task, or an identity task running with
    /// no `sync`. Held for each method's whole critical section.
    pub(crate) sync_lifecycle: Mutex<()>,
    /// The relay engine while relay is enabled (DESIGN.md Part R).
    pub(crate) relay: Mutex<Option<Arc<crate::relay::engine::RelayEngine>>>,
    /// Verified live sessions whose Hellos both offered relay: peer ->
    /// (installation, inbox). Kept while relay is off, so re-enabling links
    /// them up (the peer still thinks we relay). Lock order: `sessions`,
    /// then this, then `relay`.
    pub(crate) relay_links: Mutex<HashMap<PeerId, (Vec<u8>, String)>>,
    /// Link keys, pairing mode, counters (DESIGN.md §B14).
    pub(crate) link: crate::link::LinkState,
    /// Test only: receives every frame the sessions send, before sealing.
    pub(crate) frame_tap: Mutex<Option<Arc<dyn MeshTransport>>>,
    /// Signed-sequencing counters, shared with the store (§B13).
    pub(crate) seq: Arc<crate::sync::seq::SeqCounters>,
    /// Test only: the order `stop_sync`'s teardown steps ran in.
    #[cfg(test)]
    pub(crate) stop_sync_order: Mutex<Vec<&'static str>>,
}

/// Default time an authenticated peer has to prove inbox membership.
pub(crate) const PEER_VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

/// Default time a session has to authenticate its peer (Hello/Auth) before
/// the node disconnects it. Bounds sessions created by stray frames and
/// devices that never speak the protocol.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Default time an open relay (stranger) link may go without receiving a
/// relay frame before the node closes it, so a stranger cannot hold one of
/// the radio's few connections forever (§B14.3).
pub(crate) const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Longest a relay (stranger) link stays open, busy or not (§B14.3).
pub(crate) const RELAY_LINK_LIFETIME: Duration = Duration::from_secs(600);

/// How long a phone refuses a radio peer as a stranger (accepting or
/// dialing a relay link) after it closed that peer's relay link for
/// idleness, at the lifetime cap, for a rejected frame or because relay
/// went off (§B14.3).
/// Half the idle bound: a stranger that keeps reconnecting to hold a slot
/// costs at most one handshake per 30 s, while a stranger with real
/// traffic waits less than the first DM retry (2 min) and far less than
/// an envelope's hold (10 min).
pub(crate) const RELAY_BACKOFF: Duration = Duration::from_secs(30);

/// How long an open pairing link waits for both people to compare and
/// confirm the code before it closes (§B14.4).
pub(crate) const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) struct SyncConfig {
    pub(crate) signer: Arc<dyn HelloSigner>,
    pub(crate) transport: Arc<dyn MeshTransport>,
    /// Group members per the local client: scopes all group traffic.
    pub(crate) membership: Arc<dyn GroupMembership>,
    /// Sessions and their timers run here, so the transport may call
    /// `on_peer_connected` / `on_frame` / `on_peer_lost` from any thread.
    pub(crate) runtime: tokio::runtime::Handle,
}

impl SyncConfig {
    fn spawn_session(
        &self,
        node: &MeshNode,
        peer: &str,
        setup: LinkSetup,
    ) -> session::SessionHandle {
        session::spawn(
            &self.runtime,
            node.clone(),
            peer.to_string(),
            self.transport.clone(),
            self.signer.clone(),
            self.membership.clone(),
            setup,
        )
    }
}

/// A connected peer whose installation proved membership of the inbox it
/// claims (presence, for the UI's "nearby").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPeer {
    pub peer: PeerId,
    pub inbox_id: String,
    pub installation: Vec<u8>,
}

/// Something changed in the node; sync sessions and subscriptions listen.
#[derive(Clone, Debug)]
pub enum NodeEvent {
    /// A peer's session verified it (see [`VerifiedPeer`]).
    PeerVerified {
        peer: PeerId,
        inbox_id: String,
        installation: Vec<u8>,
    },
    /// A peer reported by `PeerVerified` is gone (link lost, session
    /// replaced or ended, or sync stopped).
    PeerLost {
        peer: PeerId,
    },
    LocalIdentityChanged,
    LocalKeyPackageChanged,
    GroupSequenced(StoredGroupMessage),
    PendingAdded(Vec<u8>),
    GroupKnown(Vec<u8>),
    WelcomeStored(StoredWelcome),
    WelcomeOutbound(Vec<u8>),
    /// An update was appended to this inbox's identity log (local or a peer's).
    IdentityLogChanged(String),
    /// This inbox's identity log was replaced by one with an earlier origin
    /// (restore convergence §C4.3). The local client must drop its copy.
    ///
    /// A replace emits **only** this event, not
    /// `IdentityLogChanged` and not `LocalIdentityChanged` even for our own
    /// inbox. A listener that follows appends (e.g. the §C4.7 handover, or
    /// re-sending our own log to peers) must also handle this variant, or
    /// it will miss a replace.
    IdentityLogReplaced(String),
    /// The local client reloaded a replaced log (or, for our own inbox, the
    /// node refused a full winner): what the app should do next (§C4.4).
    IdentityResynced {
        inbox_id: String,
        outcome: ResyncOutcome,
    },
    /// The user confirmed a contact this phone added by itself during a
    /// restore window (§B14.7): it may now get our contact card.
    ContactConfirmed(String),
}

impl MeshNode {
    pub fn new(store: MeshStore) -> Self {
        let (events, _) = broadcast::channel(1024);
        let seq = store.seq_counters();
        let node = Self {
            inner: Arc::new(NodeInner {
                store: Mutex::new(store),
                events,
                sync: Mutex::new(None),
                sessions: Default::default(),
                authenticated: Default::default(),
                verified: Default::default(),
                peer_verify_timeout: Mutex::new(PEER_VERIFY_TIMEOUT),
                handshake_timeout: Mutex::new(HANDSHAKE_TIMEOUT),
                relay_idle_timeout: Mutex::new(RELAY_IDLE_TIMEOUT),
                relay_link_lifetime: Mutex::new(RELAY_LINK_LIFETIME),
                relay_backoff: Mutex::new(RELAY_BACKOFF),
                relay_backoffs: Mutex::new(HashMap::new()),
                pairing_timeout: Mutex::new(PAIRING_TIMEOUT),
                suppress_identity_log: AtomicBool::new(false),
                suppress_group_push: AtomicBool::new(false),
                replaced_at: Mutex::new(HashMap::new()),
                replace_flap_window: Mutex::new(convergence::REPLACE_FLAP_WINDOW),
                replacements: AtomicU64::new(0),
                identity_task: Mutex::new(None),
                legacy_identity: AtomicBool::new(false),
                suppress_handover: AtomicBool::new(false),
                suppress_client_resync: AtomicBool::new(false),
                sync_lifecycle: Mutex::new(()),
                relay: Mutex::new(None),
                relay_links: Mutex::new(HashMap::new()),
                link: Default::default(),
                frame_tap: Mutex::new(None),
                seq,
                #[cfg(test)]
                stop_sync_order: Mutex::new(Vec::new()),
            }),
        };
        node.refresh_allowed_dialers(&mut node.inner.store.lock());
        node
    }

    pub fn in_memory() -> Result<Self, MeshError> {
        Ok(Self::new(MeshStore::open_in_memory()?))
    }

    /// Open a persistent node. `key` is the SQLCipher key (recommended on device).
    ///
    /// The mesh database is bound to one installation for life: the first
    /// key package uploaded fixes the node's local installation. On logout or
    /// reset, delete and recreate it together with the libxmtp database.
    pub fn open(path: &str, key: Option<[u8; 32]>) -> Result<Self, MeshError> {
        Ok(Self::new(MeshStore::open(Some(path), key)?))
    }

    pub(crate) fn now_ns() -> i64 {
        xmtp_common::time::now_ns()
    }

    pub(crate) fn emit(&self, events: Vec<NodeEvent>) {
        for event in events {
            let _ = self.inner.events.send(event);
        }
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<NodeEvent> {
        self.inner.events.subscribe()
    }

    pub fn local_installation(&self) -> Result<Option<Vec<u8>>, MeshError> {
        self.inner.store.lock().local_installation()
    }

    pub fn local_inbox(&self) -> Result<Option<String>, MeshError> {
        self.inner.store.lock().local_inbox()
    }

    pub(crate) async fn route(&self, path: &str, body: Bytes) -> Result<Bytes, MeshError> {
        use xmtp_proto::mls_v1 as mls;
        use xmtp_proto::xmtp::identity::api::v1 as id;
        if paths::is::<id::PublishIdentityUpdateRequest>(path) {
            return Ok(encode(self.publish_identity_update(decode(body)?).await?));
        }
        if paths::is::<id::GetIdentityUpdatesRequest>(path) {
            return Ok(encode(self.get_identity_updates(decode(body)?)?));
        }
        if paths::is::<id::GetInboxIdsRequest>(path) {
            return Ok(encode(self.get_inbox_ids(decode(body)?)?));
        }
        if paths::is::<id::VerifySmartContractWalletSignaturesRequest>(path) {
            return Ok(encode(self.verify_scw_signatures(decode(body)?)));
        }
        if paths::is::<mls::UploadKeyPackageRequest>(path) {
            self.upload_key_package(decode(body)?)?;
            return Ok(Bytes::new()); // google.protobuf.Empty
        }
        if paths::is::<mls::FetchKeyPackagesRequest>(path) {
            return Ok(encode(self.fetch_key_packages(decode(body)?)?));
        }
        if paths::is::<mls::SendGroupMessagesRequest>(path) {
            self.send_group_messages(decode(body)?)?;
            return Ok(Bytes::new());
        }
        if paths::is::<mls::QueryGroupMessagesRequest>(path) {
            return Ok(encode(self.query_group_messages(decode(body)?)?));
        }
        if paths::is::<mls::SendWelcomeMessagesRequest>(path) {
            self.send_welcome_messages(decode(body)?)?;
            return Ok(Bytes::new());
        }
        if paths::is::<mls::QueryWelcomeMessagesRequest>(path) {
            return Ok(encode(self.query_welcome_messages(decode(body)?)?));
        }
        if paths::is::<mls::GetNewestGroupMessageRequest>(path) {
            return Ok(encode(self.get_newest_group_message(decode(body)?)?));
        }
        if paths::is::<mls::BatchPublishCommitLogRequest>(path) {
            self.publish_commit_log(decode(body)?);
            return Ok(Bytes::new());
        }
        if paths::is::<mls::BatchQueryCommitLogRequest>(path) {
            return Ok(encode(self.query_commit_log(decode(body)?)));
        }
        Err(MeshError::Unimplemented(path.to_string()))
    }

    pub(crate) async fn route_stream(
        &self,
        path: &str,
        body: Bytes,
    ) -> Result<MeshStream, MeshError> {
        use xmtp_proto::mls_v1 as mls;
        if paths::is::<mls::SubscribeGroupMessagesRequest>(path) {
            return self.subscribe_group_messages(decode(body)?);
        }
        if paths::is::<mls::SubscribeWelcomeMessagesRequest>(path) {
            return self.subscribe_welcome_messages(decode(body)?);
        }
        Err(MeshError::Unimplemented(path.to_string()))
    }
}

impl MeshNode {
    /// Begin syncing. The signer's installation must be this node's local one,
    /// and `membership` must report group members as that installation's
    /// libxmtp client sees them (production: [`crate::ClientGroupMembership`]
    /// over the same client as [`crate::ClientHelloSigner`]).
    ///
    /// Must be called from within a tokio runtime: the node captures that
    /// runtime's handle and runs every sync session on it, so the transport
    /// callbacks (`on_peer_connected`, `on_frame`, `on_peer_lost`) may then be
    /// called from any thread.
    ///
    /// Call `set_account_key` first (DESIGN.md §B14.1).
    pub fn start_sync(
        &self,
        signer: Arc<dyn HelloSigner>,
        transport: Arc<dyn MeshTransport>,
        membership: Arc<dyn GroupMembership>,
    ) -> Result<(), MeshError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| MeshError::NoRuntime)?;
        let local = self.local_installation()?.ok_or(MeshError::NotRegistered)?;
        if local != signer.installation_key() {
            return Err(MeshError::InvalidRequest(
                "signer is not this node's installation".into(),
            ));
        }
        if !self.has_account_key() {
            return Err(MeshError::NoAccountKey);
        }
        // Held for the whole critical section, so a
        // concurrent `stop_sync` can't interleave between the identity task
        // swap and the `sync` config write.
        let _lifecycle = self.inner.sync_lifecycle.lock();
        // §B13: sign rows as they are sequenced from now on, and sign every
        // stored row that has none (sequenced while sync was stopped, or
        // stored before signed sequencing) before a session, the relay or
        // the handover below can serve it; and attest, as ours, held rows
        // another installation signed in groups pinned to us (a §C4.7
        // re-pin that ran while no signer was set). If the backfill errors
        // (e.g. the signer fails), the signer is cleared before returning:
        // sync never started, so nothing must be left holding the
        // Client-backed signer's reference back to this node, and the next
        // `start_sync` retries the backfill from scratch (unsigned rows are
        // untouched by a failed attempt).
        {
            let mut store = self.inner.store.lock();
            store.set_seq_signer(signer.clone());
            let backfilled = store
                .sign_unsigned_rows()
                .and_then(|a| store.attest_foreign_rows(None).map(|b| a + b));
            let signed = match backfilled {
                Ok(signed) => signed,
                Err(e) => {
                    store.clear_seq_signer();
                    return Err(e);
                }
            };
            if signed > 0 {
                tracing::info!(
                    signed,
                    "signed stored rows that had no proof, or attested held rows of our groups (§B13)"
                );
            }
        }
        let task = self.spawn_identity_task(&runtime, membership.clone());
        if let Some(old) = self.inner.identity_task.lock().replace(task) {
            old.abort();
        }
        // Also run the §C4.7 handover once here, so
        // a restart retries it even if this node's own revocation of a dead
        // sequencer was ingested while sync was stopped (no identity-log
        // event fires for the identity task to react to after the fact).
        {
            let node = self.clone();
            let membership = membership.clone();
            runtime.spawn(async move { node.hand_over(membership.as_ref()).await });
        }
        *self.inner.sync.lock() = Some(SyncConfig {
            signer,
            transport,
            membership,
            runtime,
        });
        Ok(())
    }

    fn session_for(&self, peer: &str) -> Option<tokio::sync::mpsc::UnboundedSender<Inbound>> {
        let sync = self.inner.sync.lock();
        let config = sync.as_ref()?;
        let mut sessions = self.inner.sessions.lock();
        let handle = sessions.entry(peer.to_string()).or_insert_with(|| {
            config.spawn_session(
                self,
                peer,
                LinkSetup {
                    role: LinkRole::Accept,
                    plain: false,
                    implicit: true,
                },
            )
        });
        Some(handle.tx.clone())
    }

    /// The radio connected a new pipe `peer` (see [`MeshTransport`]) as
    /// `role`: start a fresh session, replacing (and cancelling) any session
    /// held for `peer`, e.g. one a stray frame created. Frames also create an
    /// accepting session implicitly when they arrive before this call.
    pub fn on_peer_connected(&self, peer: &str, role: LinkRole) {
        let sync = self.inner.sync.lock();
        let Some(config) = sync.as_ref() else { return };
        let mut sessions = self.inner.sessions.lock();
        // A frame of this connection arrived first and started the accepting
        // session (MeshTransport): it already holds the handshake. Keep it.
        if role == LinkRole::Accept
            && let Some(handle) = sessions.get_mut(peer)
            && handle.implicit
        {
            handle.implicit = false;
            return;
        }
        let handle = config.spawn_session(
            self,
            peer,
            LinkSetup {
                role,
                plain: false,
                implicit: false,
            },
        );
        let old = sessions.insert(peer.to_string(), handle);
        self.forget_peer(peer);
        drop(sessions);
        drop(sync);
        drop(old); // cancels the replaced session
    }

    pub fn on_frame(&self, peer: &str, frame: Vec<u8>) {
        if let Some(tx) = self.session_for(peer) {
            let _ = tx.send(Inbound::Wire(frame));
        }
    }

    pub fn on_peer_lost(&self, peer: &str) {
        let mut sessions = self.inner.sessions.lock();
        let old = sessions.remove(peer); // dropping the handle ends the session
        self.forget_peer(peer);
        drop(sessions);
        drop(old);
    }

    /// Stop syncing: cancel every session and forget the signer and
    /// transport. Frames and connections reported afterwards are ignored
    /// until the next `start_sync` (which may use a new transport).
    ///
    /// Also clears the store's sequencing signer (§B13): a Client-backed
    /// signer holds (through the client's API bundle) a reference back to
    /// this node, so keeping it past `stop_sync` would keep the node, and
    /// its database, from ever being dropped after logout. Rows sequenced
    /// while stopped stay unsigned until the next `start_sync`'s backfill.
    ///
    /// The signer is cleared last, after every session and the relay are
    /// torn down: a still-live session's push or the relay's `pack_sync`
    /// reads the signer to decide whether a row has a proof, and clearing it
    /// first would let a row sequenced in this window be served unsigned.
    pub fn stop_sync(&self) {
        // See `start_sync`.
        let _lifecycle = self.inner.sync_lifecycle.lock();
        if let Some(task) = self.inner.identity_task.lock().take() {
            task.abort();
        }
        let mut sync = self.inner.sync.lock();
        *sync = None;
        let mut sessions = self.inner.sessions.lock();
        let old: Vec<_> = sessions.drain().collect();
        for (peer, _) in &old {
            self.forget_peer(peer);
        }
        drop(sessions);
        drop(sync);
        self.disable_relay_locked();
        drop(old);
        #[cfg(test)]
        self.inner
            .stop_sync_order
            .lock()
            .push("sessions_and_relay_torn_down");
        self.inner.store.lock().clear_seq_signer();
        #[cfg(test)]
        self.inner.stop_sync_order.lock().push("signer_cleared");
    }

    pub fn authenticated_peers(&self) -> Vec<PeerId> {
        let mut peers: Vec<_> = self.inner.authenticated.lock().iter().cloned().collect();
        peers.sort();
        peers
    }

    /// Connected peers that proved inbox membership, sorted by `PeerId`.
    pub fn verified_peers(&self) -> Vec<VerifiedPeer> {
        let mut peers: Vec<_> = self.inner.verified.lock().values().cloned().collect();
        peers.sort_by(|a, b| a.peer.cmp(&b.peer));
        peers
    }

    /// Clear `peer`'s authentication and presence, emitting `PeerLost` if it
    /// was verified. Callers hold `sessions`.
    pub(crate) fn forget_peer(&self, peer: &str) {
        self.inner.link.contact_links.lock().remove(peer);
        self.inner.link.pairings.lock().remove(peer);
        self.relay_link_down(peer);
        self.inner.authenticated.lock().remove(peer);
        if self.inner.verified.lock().remove(peer).is_some() {
            self.emit(vec![NodeEvent::PeerLost {
                peer: peer.to_string(),
            }]);
        }
    }

    /// A session task may outlive its registry entry (its receiver still drains
    /// buffered frames after `on_peer_lost`), so only the peer's current session
    /// may change its state. Lock order: `sessions`, then `authenticated`,
    /// then `verified`.
    pub(crate) fn session_authenticated(&self, peer: &str, session_id: u64) {
        let sessions = self.inner.sessions.lock();
        if sessions.get(peer).is_some_and(|h| h.id == session_id) {
            self.inner.authenticated.lock().insert(peer.to_string());
        }
    }

    pub(crate) fn session_verified(
        &self,
        peer: &str,
        session_id: u64,
        inbox_id: String,
        installation: Vec<u8>,
    ) {
        let sessions = self.inner.sessions.lock();
        if sessions.get(peer).is_some_and(|h| h.id == session_id) {
            self.register_verified(peer, inbox_id, installation);
        }
    }

    /// Record `peer` as verified and emit `PeerVerified`. Callers hold
    /// `sessions` and checked the session is current.
    pub(crate) fn register_verified(&self, peer: &str, inbox_id: String, installation: Vec<u8>) {
        let verified = VerifiedPeer {
            peer: peer.to_string(),
            inbox_id,
            installation,
        };
        self.inner
            .verified
            .lock()
            .insert(peer.to_string(), verified.clone());
        let VerifiedPeer {
            peer,
            inbox_id,
            installation,
        } = verified;
        self.emit(vec![NodeEvent::PeerVerified {
            peer,
            inbox_id,
            installation,
        }]);
    }

    /// The session's peer lost its verification (its installation left its
    /// inbox's log): drop it from presence. Only the current session may.
    pub(crate) fn session_unverified(&self, peer: &str, session_id: u64) {
        let sessions = self.inner.sessions.lock();
        if sessions.get(peer).is_some_and(|h| h.id == session_id) {
            self.relay_link_down(peer);
            if self.inner.verified.lock().remove(peer).is_some() {
                self.emit(vec![NodeEvent::PeerLost {
                    peer: peer.to_string(),
                }]);
            }
        }
    }

    pub(crate) fn session_ended(&self, peer: &str, session_id: u64) {
        let mut sessions = self.inner.sessions.lock();
        if sessions.get(peer).is_some_and(|h| h.id == session_id) {
            let old = sessions.remove(peer);
            self.forget_peer(peer);
            drop(sessions);
            drop(old);
        }
    }
}

pub(crate) fn decode<M: prost::Message + Default>(body: Bytes) -> Result<M, MeshError> {
    Ok(M::decode(body)?)
}

pub(crate) fn encode<M: prost::Message>(message: M) -> Bytes {
    Bytes::from(message.encode_to_vec())
}

fn api_err(e: MeshError) -> ApiClientError<GrpcError> {
    ApiClientError::Client {
        source: GrpcError::Status(e.into_status()),
    }
}

#[xmtp_common::async_trait]
impl Client for MeshNode {
    type Error = GrpcError;
    type Stream = MeshStream;

    async fn request(
        &self,
        _request: request::Builder,
        path: PathAndQuery,
        body: Bytes,
    ) -> Result<http::Response<Bytes>, ApiClientError<GrpcError>> {
        self.route(path.path(), body)
            .await
            .map(http::Response::new)
            .map_err(api_err)
    }

    async fn stream(
        &self,
        _request: request::Builder,
        path: PathAndQuery,
        body: Bytes,
    ) -> Result<http::Response<MeshStream>, ApiClientError<GrpcError>> {
        self.route_stream(path.path(), body)
            .await
            .map(http::Response::new)
            .map_err(api_err)
    }

    fn fake_stream(&self) -> http::Response<MeshStream> {
        http::Response::new(Box::pin(futures::stream::pending()))
    }
}

#[xmtp_common::async_trait]
impl IsConnectedCheck for MeshNode {
    async fn is_connected(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod session_registry_tests {
    use super::*;

    fn handle(id: u64) -> session::SessionHandle {
        session::test_handle(id)
    }

    #[test]
    fn stale_session_cannot_touch_newer_session_state() {
        let node = MeshNode::in_memory().unwrap();
        node.inner.sessions.lock().insert("p".into(), handle(2));
        node.session_authenticated("p", 2);
        assert_eq!(node.authenticated_peers(), vec!["p".to_string()]);

        // Session 1 was replaced by session 2 (peer lost, then reconnected).
        node.session_authenticated("p", 1);
        node.session_ended("p", 1);
        assert_eq!(node.authenticated_peers(), vec!["p".to_string()]);
        assert!(node.inner.sessions.lock().contains_key("p"));

        // A session whose peer was already lost cannot re-authenticate it.
        node.session_authenticated("q", 3);
        assert!(node.authenticated_peers().iter().all(|p| p != "q"));

        // The live session ending clears its registry entry and auth.
        node.session_ended("p", 2);
        assert!(node.authenticated_peers().is_empty());
        assert!(!node.inner.sessions.lock().contains_key("p"));
    }
}

#[cfg(test)]
mod sync_lifecycle_tests {
    use async_trait::async_trait;

    use super::*;
    use crate::store::NewGroupMessage;
    use crate::sync::{GroupMembership, HelloSigner, LoopbackHub};

    struct NoGroups;

    #[async_trait]
    impl GroupMembership for NoGroups {
        async fn member_inboxes(&self, _group_id: &[u8]) -> Result<Option<Vec<String>>, MeshError> {
            Ok(None)
        }
    }

    /// §B13: `stop_sync` must clear the store's signer only after sessions
    /// and the relay are torn down, so nothing still live in that window
    /// can read the signer as already gone and serve or pack a row
    /// unsigned.
    #[test]
    fn stop_sync_clears_the_signer_after_sessions_and_relay_are_torn_down() {
        let node = MeshNode::in_memory().unwrap();
        node.stop_sync();
        assert_eq!(
            *node.inner.stop_sync_order.lock(),
            vec!["sessions_and_relay_torn_down", "signer_cleared"],
        );
    }

    struct FailingSigner(Vec<u8>);

    impl HelloSigner for FailingSigner {
        fn installation_key(&self) -> Vec<u8> {
            self.0.clone()
        }

        fn sign(&self, _text: &str) -> Result<Vec<u8>, MeshError> {
            Err(MeshError::AuthFailed("signer unavailable".into()))
        }
    }

    /// §B13: a `start_sync` whose backfill fails (the signer errors) must
    /// not leave the store holding that signer. If it did, a `Client`-backed
    /// signer would keep the node (and its database) alive past logout, and
    /// every row sequenced until the next `start_sync` would fail to store
    /// at all (this test's own row-append would fail too, since the same
    /// failing signer would still be asked to sign it).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_start_sync_clears_the_signer() {
        let node = MeshNode::in_memory().unwrap();
        let key = b"a-failing-installation-key".to_vec();
        node.inner
            .store
            .lock()
            .set_local_installation(&key)
            .unwrap();
        // Link keys, so start_sync gets as far as the backfill.
        node.inner.store.lock().set_local_inbox("inbox").unwrap();
        node.set_account_key(&[1; 32]).unwrap();
        // An unsigned row already stored, so the backfill actually reaches
        // the signer instead of returning early with nothing to sign.
        node.inner
            .store
            .lock()
            .append_sequenced(
                &NewGroupMessage {
                    group_id: b"g".to_vec(),
                    data: b"one".to_vec(),
                    sender_hmac: vec![],
                    should_push: true,
                    is_commit: false,
                },
                1,
            )
            .unwrap();

        let hub = LoopbackHub::new();
        let err = node.start_sync(
            Arc::new(FailingSigner(key)),
            hub.transport_for("a"),
            Arc::new(NoGroups),
        );
        assert!(err.is_err(), "the backfill's signing error must propagate");

        // If the signer were still held, this would fail too (signing "two"
        // with the same failing signer): it succeeds only because start_sync
        // cleared it.
        let (row, _) = node
            .inner
            .store
            .lock()
            .append_sequenced(
                &NewGroupMessage {
                    group_id: b"g".to_vec(),
                    data: b"two".to_vec(),
                    sender_hmac: vec![],
                    should_push: true,
                    is_commit: false,
                },
                2,
            )
            .unwrap();
        assert!(
            row.seq_signer.is_none(),
            "no signer means unsigned, not a signing error"
        );
    }
}
