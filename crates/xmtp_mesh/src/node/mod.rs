mod convergence;
mod group_messages;
mod handover;
mod identity;
mod key_packages;
pub(crate) mod paths;
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
use crate::store::{MeshStore, StoredGroupMessage, StoredWelcome};
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
    /// How long a session has to complete Hello/Auth.
    pub(crate) handshake_timeout: Mutex<Duration>,
    /// Test only: never send our identity log to peers.
    pub(crate) suppress_identity_log: AtomicBool,
    /// Test only: sessions drop live GroupSequenced pushes (simulates a lagged stream).
    pub(crate) suppress_group_push: AtomicBool,
    /// When each inbox's identity log was last replaced (flap guard, §4.3).
    pub(crate) replaced_at: Mutex<HashMap<String, std::time::Instant>>,
    pub(crate) replace_flap_window: Mutex<Duration>,
    /// Replaces so far (tests assert convergence settles).
    pub(crate) replacements: AtomicU64,
    /// The identity task (convergence.rs), alive between start_sync and stop_sync.
    pub(crate) identity_task: Mutex<Option<tokio::task::AbortHandle>>,
    /// Test only: behave like a node from before restore convergence.
    pub(crate) legacy_identity: AtomicBool,
    /// Test only (review I2, task-5-review.md fix round 1): suppress the
    /// §4.7 handover's automatic trigger (the identity task and
    /// `start_sync`), so a test can prove a gate other than the handover's
    /// own sequencer repin is what refuses a revoked installation's frames.
    /// `hand_over_sequencers` itself is never suppressed -- only its
    /// automatic callers are.
    pub(crate) suppress_handover: AtomicBool,
    /// Test only (final review I2): the identity task never resyncs the
    /// client, as if the process died right after a replace committed.
    pub(crate) suppress_client_resync: AtomicBool,
    /// Serializes `start_sync`/`stop_sync` (review M5, 2026-09-24): they
    /// update `identity_task` and `sync` under separate locks, so a
    /// concurrent start and stop could otherwise interleave and leave
    /// `sync` set with no identity task, or an identity task running with
    /// no `sync`. Held for each method's whole critical section.
    pub(crate) sync_lifecycle: Mutex<()>,
    /// The relay engine while relay is enabled (spec 2026-09-24 multi-hop).
    pub(crate) relay: Mutex<Option<Arc<crate::relay::engine::RelayEngine>>>,
}

/// Default time an authenticated peer has to prove inbox membership.
pub(crate) const PEER_VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

/// Default time a session has to authenticate its peer (Hello/Auth) before
/// the node disconnects it. Bounds sessions created by stray frames and
/// devices that never speak the protocol.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

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
    fn spawn_session(&self, node: &MeshNode, peer: &str) -> session::SessionHandle {
        session::spawn(
            &self.runtime,
            node.clone(),
            peer.to_string(),
            self.transport.clone(),
            self.signer.clone(),
            self.membership.clone(),
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
    /// (restore convergence §4.3). The local client must drop its copy.
    ///
    /// M3 (review 2026-09-24): a replace emits **only** this event, not
    /// `IdentityLogChanged` and not `LocalIdentityChanged` even for our own
    /// inbox. A listener that follows appends (e.g. the §4.7 handover, or
    /// re-sending our own log to peers) must also handle this variant, or
    /// it will miss a replace.
    IdentityLogReplaced(String),
    /// The local client reloaded a replaced log (or, for our own inbox, the
    /// node refused a full winner): what the app should do next (§4.4).
    IdentityResynced {
        inbox_id: String,
        outcome: ResyncOutcome,
    },
}

impl MeshNode {
    pub fn new(store: MeshStore) -> Self {
        let (events, _) = broadcast::channel(1024);
        Self {
            inner: Arc::new(NodeInner {
                store: Mutex::new(store),
                events,
                sync: Mutex::new(None),
                sessions: Default::default(),
                authenticated: Default::default(),
                verified: Default::default(),
                peer_verify_timeout: Mutex::new(PEER_VERIFY_TIMEOUT),
                handshake_timeout: Mutex::new(HANDSHAKE_TIMEOUT),
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
            }),
        }
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
        // M5 (review 2026-09-24): held for the whole critical section, so a
        // concurrent `stop_sync` can't interleave between the identity task
        // swap and the `sync` config write.
        let _lifecycle = self.inner.sync_lifecycle.lock();
        let task = self.spawn_identity_task(&runtime, membership.clone());
        if let Some(old) = self.inner.identity_task.lock().replace(task) {
            old.abort();
        }
        // Ruling F9 (progress.md): also run the §4.7 handover once here, so
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

    fn session_for(&self, peer: &str) -> Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>> {
        let sync = self.inner.sync.lock();
        let config = sync.as_ref()?;
        let mut sessions = self.inner.sessions.lock();
        let handle = sessions
            .entry(peer.to_string())
            .or_insert_with(|| config.spawn_session(self, peer));
        Some(handle.tx.clone())
    }

    /// The radio connected a new pipe `peer` (see [`MeshTransport`]): start a
    /// fresh session, replacing (and cancelling) any session held for `peer`,
    /// e.g. one a stray frame created. Frames also create a session implicitly
    /// when they arrive before this call.
    pub fn on_peer_connected(&self, peer: &str) {
        let sync = self.inner.sync.lock();
        let Some(config) = sync.as_ref() else { return };
        let handle = config.spawn_session(self, peer);
        let mut sessions = self.inner.sessions.lock();
        let old = sessions.insert(peer.to_string(), handle);
        self.forget_peer(peer);
        drop(sessions);
        drop(sync);
        drop(old); // cancels the replaced session
    }

    pub fn on_frame(&self, peer: &str, frame: Vec<u8>) {
        if let Some(tx) = self.session_for(peer) {
            let _ = tx.send(frame);
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
    pub fn stop_sync(&self) {
        // M5 (review 2026-09-24): see `start_sync`.
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
        self.disable_relay();
        drop(old);
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
    fn forget_peer(&self, peer: &str) {
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
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        session::SessionHandle::new(id, tx).0
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
