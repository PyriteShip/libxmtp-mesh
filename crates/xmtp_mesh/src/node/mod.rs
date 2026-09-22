mod group_messages;
mod identity;
mod key_packages;
pub(crate) mod paths;
mod streams;
mod welcomes;

use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use futures::Stream;
use http::{request, uri::PathAndQuery};
use parking_lot::Mutex;
use tokio::sync::broadcast;
use xmtp_api_grpc::error::GrpcError;
use xmtp_proto::api::{ApiClientError, Client, IsConnectedCheck};

use crate::MeshError;
use crate::store::{MeshStore, StoredGroupMessage, StoredWelcome};

pub type MeshStream = Pin<Box<dyn Stream<Item = Result<Bytes, GrpcError>> + Send>>;

/// An in-process XMTP v3 node. Cheap to clone; all clones share state.
#[derive(Clone)]
pub struct MeshNode {
    pub(crate) inner: Arc<NodeInner>,
}

pub(crate) struct NodeInner {
    pub(crate) store: Mutex<MeshStore>,
    pub(crate) events: broadcast::Sender<NodeEvent>,
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
