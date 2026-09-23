#![allow(dead_code)]
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use xmtp_api_d14n::{ClientBundle, MessageBackendBuilder};
use xmtp_cryptography::utils::generate_local_wallet;
use xmtp_db::group_message::{GroupMessageKind, MsgQueryArgs};
use xmtp_db::{EncryptedMessageStore, NativeDb};
use xmtp_id::InboxOwner;
use xmtp_mesh::{EoaOnlyVerifier, MeshNode};
use xmtp_mls::builder::DeviceSyncMode;
use xmtp_mls::cursor_store::SqliteCursorStore;
use xmtp_mls::groups::MlsGroup;
use xmtp_mls::identity::IdentityStrategy;
use xmtp_mls::utils::test::register_client;
use xmtp_mls::{Client, MlsContext};
use xmtp_proto::api::ToBoxedClient;

pub type MeshClient = Client<MlsContext>;
pub type MeshGroup = MlsGroup<MlsContext>;

pub async fn build_client(node: &MeshNode) -> MeshClient {
    let wallet = generate_local_wallet();
    let ident = wallet.get_identifier().unwrap();
    let nonce = 1;
    let inbox_id = ident.inbox_id(nonce).unwrap();
    let strategy = IdentityStrategy::new(inbox_id, ident, nonce, None);

    let db = NativeDb::builder().ephemeral().build_unencrypted().unwrap();
    let store = EncryptedMessageStore::new(db).unwrap();

    let bundle = ClientBundle::v3(node.clone().arced());
    let mut backend = MessageBackendBuilder::default();
    backend.cursor_store(Arc::new(SqliteCursorStore::new(store.db())));
    let api = backend.clone().from_bundle(bundle.clone()).unwrap();
    let sync_api = backend.from_bundle(bundle).unwrap();

    let client = Client::builder(strategy)
        .api_clients(api, sync_api)
        .enable_api_stats()
        .unwrap()
        .enable_api_debug_wrapper()
        .unwrap()
        .with_scw_verifier(EoaOnlyVerifier)
        .store(store)
        .default_mls_store()
        .unwrap()
        .device_sync_worker_mode(DeviceSyncMode::Disabled)
        .build()
        .await
        .unwrap();
    register_client(&client, &wallet).await;
    client
}

/// Poll `check` every 50 ms for up to 20 s.
pub async fn eventually<F, Fut>(what: &str, check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    eventually_for(what, 20, check).await
}

/// Poll `check` every 50 ms for up to `secs` seconds.
pub async fn eventually_for<F, Fut>(what: &str, secs: u64, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        if check().await {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for: {what}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Application payloads in a group, ordered by sequencer timestamp.
pub fn app_payloads(group: &MeshGroup) -> Vec<Vec<u8>> {
    let mut messages = group.find_messages(&MsgQueryArgs::default()).unwrap();
    messages.retain(|m| m.kind == GroupMessageKind::Application);
    messages.sort_by_key(|m| m.sent_at_ns);
    messages
        .into_iter()
        .map(|m| m.decrypted_message_bytes)
        .collect()
}

use xmtp_mesh::LoopbackHub;
pub use xmtp_mesh::{ClientGroupMembership, ClientHelloSigner};

/// Start `node` syncing over `transport`, signing as `client` and scoping
/// group traffic by `client`'s group membership (the production wiring).
pub fn start_sync(node: &MeshNode, client: &MeshClient, transport: Arc<dyn MeshTransport>) {
    node.start_sync(
        Arc::new(ClientHelloSigner(client.clone())),
        transport,
        Arc::new(ClientGroupMembership(client.clone())),
    )
    .unwrap();
}

pub struct TestPeer {
    pub name: String,
    pub node: MeshNode,
    pub client: MeshClient,
}

impl TestPeer {
    pub fn installation(&self) -> Vec<u8> {
        self.client.installation_public_key().to_vec()
    }
}

/// A registered client on its own node, attached to `hub` under `name`, syncing.
pub async fn peer(hub: &LoopbackHub, name: &str) -> TestPeer {
    let node = MeshNode::in_memory().unwrap();
    hub.register(name, &node);
    let client = build_client(&node).await;
    start_sync(&node, &client, hub.transport_for(name));
    TestPeer {
        name: name.to_string(),
        node,
        client,
    }
}

/// Start `p`'s node syncing again (after `stop_sync`) over `transport`.
pub fn restart_sync(p: &TestPeer, transport: Arc<dyn MeshTransport>) {
    start_sync(&p.node, &p.client, transport);
}

use std::sync::Mutex;

use xmtp_mesh::frames::{self, frame::Body};
use xmtp_mesh::{MeshTransport, PeerId};

/// Forwards to another transport and records every frame sent through it.
pub struct Recording {
    inner: Arc<dyn MeshTransport>,
    sent: Mutex<Vec<(PeerId, Vec<u8>)>>,
}

impl Recording {
    pub fn new(inner: Arc<dyn MeshTransport>) -> Self {
        Self {
            inner,
            sent: Mutex::new(Vec::new()),
        }
    }

    /// Raw frames sent to `peer`, in order.
    pub fn raw_to(&self, peer: &str) -> Vec<Vec<u8>> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p == peer)
            .map(|(_, f)| f.clone())
            .collect()
    }

    /// Decoded frames sent to `peer`, in order.
    pub fn sent_to(&self, peer: &str) -> Vec<Body> {
        self.raw_to(peer)
            .iter()
            .map(|f| frames::decode(f).unwrap())
            .collect()
    }
}

impl MeshTransport for Recording {
    fn send(&self, peer: &PeerId, frame: Vec<u8>) {
        self.sent
            .lock()
            .unwrap()
            .push((peer.clone(), frame.clone()));
        self.inner.send(peer, frame);
    }
    fn disconnect(&self, peer: &PeerId) {
        self.inner.disconnect(peer);
    }
}

/// Like [`peer`], but every frame the node sends is also recorded.
pub async fn recorded_peer(hub: &LoopbackHub, name: &str) -> (TestPeer, Arc<Recording>) {
    let node = MeshNode::in_memory().unwrap();
    hub.register(name, &node);
    let client = build_client(&node).await;
    let recording = Arc::new(Recording::new(hub.transport_for(name)));
    start_sync(&node, &client, recording.clone());
    (
        TestPeer {
            name: name.to_string(),
            node,
            client,
        },
        recording,
    )
}

/// Query `group_id` through the node's v3 API (as a client would), which also
/// makes the group known to the node.
pub async fn query_group(
    node: &MeshNode,
    group_id: &[u8],
) -> Vec<xmtp_proto::mls_v1::GroupMessage> {
    use prost::Message;
    use xmtp_proto::api::Client as _;
    use xmtp_proto::mls_v1::{QueryGroupMessagesRequest, QueryGroupMessagesResponse};
    let req = QueryGroupMessagesRequest {
        group_id: group_id.to_vec(),
        paging_info: None,
    };
    let path = http::uri::PathAndQuery::try_from(
        xmtp_proto::path_and_query::<QueryGroupMessagesRequest>().as_ref(),
    )
    .unwrap();
    let res = node
        .request(
            http::request::Builder::new(),
            path,
            bytes::Bytes::from(req.encode_to_vec()),
        )
        .await
        .unwrap();
    QueryGroupMessagesResponse::decode(res.into_body())
        .unwrap()
        .messages
}

/// Welcomes `p`'s node holds for `p`, read through the node's own API.
pub async fn welcome_count(p: &TestPeer) -> usize {
    use prost::Message;
    use xmtp_proto::api::Client as _;
    use xmtp_proto::mls_v1::{QueryWelcomeMessagesRequest, QueryWelcomeMessagesResponse};
    let req = QueryWelcomeMessagesRequest {
        installation_key: p.installation(),
        paging_info: None,
    };
    let path = http::uri::PathAndQuery::try_from(
        xmtp_proto::path_and_query::<QueryWelcomeMessagesRequest>().as_ref(),
    )
    .unwrap();
    let res = p
        .node
        .request(
            http::request::Builder::new(),
            path,
            bytes::Bytes::from(req.encode_to_vec()),
        )
        .await
        .unwrap();
    QueryWelcomeMessagesResponse::decode(res.into_body())
        .unwrap()
        .messages
        .len()
}
