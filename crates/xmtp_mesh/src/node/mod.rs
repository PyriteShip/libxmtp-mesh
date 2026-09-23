mod group_messages;
mod identity;
mod key_packages;
pub(crate) mod paths;
mod streams;
mod sync_api;
#[cfg(test)]
mod sync_api_tests;
mod welcomes;

use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
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
use crate::sync::{HelloSigner, MeshTransport, PeerId, session};

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
    /// How long an authenticated peer has to prove inbox membership.
    pub(crate) peer_verify_timeout: Mutex<Duration>,
    /// Test only: never send our identity log to peers.
    pub(crate) suppress_identity_log: AtomicBool,
    /// Test only: sessions drop live GroupSequenced pushes (simulates a lagged stream).
    pub(crate) suppress_group_push: AtomicBool,
}

/// Default time an authenticated peer has to prove inbox membership.
pub(crate) const PEER_VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct SyncConfig {
    pub(crate) signer: Arc<dyn HelloSigner>,
    pub(crate) transport: Arc<dyn MeshTransport>,
}

/// Something changed in the node; sync sessions and subscriptions listen.
#[derive(Clone, Debug)]
pub enum NodeEvent {
    LocalIdentityChanged,
    LocalKeyPackageChanged,
    GroupSequenced(StoredGroupMessage),
    PendingAdded(Vec<u8>),
    GroupKnown(Vec<u8>),
    WelcomeStored(StoredWelcome),
    WelcomeOutbound(Vec<u8>),
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
                peer_verify_timeout: Mutex::new(PEER_VERIFY_TIMEOUT),
                suppress_identity_log: AtomicBool::new(false),
                suppress_group_push: AtomicBool::new(false),
            }),
        }
    }

    pub fn in_memory() -> Result<Self, MeshError> {
        Ok(Self::new(MeshStore::open_in_memory()?))
    }

    /// Open a persistent node. `key` is the SQLCipher key (recommended on device).
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

    pub(crate) async fn route_stream(&self, path: &str, body: Bytes) -> Result<MeshStream, MeshError> {
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
    /// Begin syncing. The signer's installation must be this node's local one.
    pub fn start_sync(&self, signer: Arc<dyn HelloSigner>, transport: Arc<dyn MeshTransport>) -> Result<(), MeshError> {
        let local = self.local_installation()?.ok_or(MeshError::NotRegistered)?;
        if local != signer.installation_key() {
            return Err(MeshError::InvalidRequest("signer is not this node's installation".into()));
        }
        *self.inner.sync.lock() = Some(SyncConfig { signer, transport });
        Ok(())
    }

    fn session_for(&self, peer: &str) -> Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>> {
        let sync = self.inner.sync.lock();
        let config = sync.as_ref()?;
        let mut sessions = self.inner.sessions.lock();
        let handle = sessions.entry(peer.to_string()).or_insert_with(|| {
            session::spawn(self.clone(), peer.to_string(), config.transport.clone(), config.signer.clone())
        });
        Some(handle.tx.clone())
    }

    /// The radio connected to `peer`. Frames also create the session implicitly.
    pub fn on_peer_connected(&self, peer: &str) {
        let _ = self.session_for(peer);
    }

    pub fn on_frame(&self, peer: &str, frame: Vec<u8>) {
        if let Some(tx) = self.session_for(peer) {
            let _ = tx.send(frame);
        }
    }

    pub fn on_peer_lost(&self, peer: &str) {
        let mut sessions = self.inner.sessions.lock();
        sessions.remove(peer); // dropping the sender ends the session
        self.inner.authenticated.lock().remove(peer);
    }

    pub fn authenticated_peers(&self) -> Vec<PeerId> {
        let mut peers: Vec<_> = self.inner.authenticated.lock().iter().cloned().collect();
        peers.sort();
        peers
    }

    /// A session task may outlive its registry entry (its receiver still drains
    /// buffered frames after `on_peer_lost`), so only the peer's current session
    /// may change its state. Lock order: `sessions`, then `authenticated`.
    pub(crate) fn session_authenticated(&self, peer: &str, session_id: u64) {
        let sessions = self.inner.sessions.lock();
        if sessions.get(peer).is_some_and(|h| h.id == session_id) {
            self.inner.authenticated.lock().insert(peer.to_string());
        }
    }

    pub(crate) fn session_ended(&self, peer: &str, session_id: u64) {
        let mut sessions = self.inner.sessions.lock();
        if sessions.get(peer).is_some_and(|h| h.id == session_id) {
            sessions.remove(peer);
            self.inner.authenticated.lock().remove(peer);
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
