#![allow(dead_code)]
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use alloy::signers::local::PrivateKeySigner;
use prost::Message;
use tokio::sync::broadcast;
use xmtp_api_d14n::{ClientBundle, MessageBackendBuilder};
use xmtp_cryptography::utils::generate_local_wallet;
use xmtp_db::group::GroupQueryArgs;
use xmtp_db::group_message::{GroupMessageKind, MsgQueryArgs};
use xmtp_db::{EncryptedMessageStore, NativeDb};
use xmtp_id::InboxOwner;
use xmtp_id::associations::test_utils::add_wallet_signature;
use xmtp_id::associations::unverified::UnverifiedIdentityUpdate;
use xmtp_id::associations::{self, AssociationState};
use xmtp_mesh::{EoaOnlyVerifier, MeshNode, NodeEvent, ResyncOutcome};
use xmtp_mls::builder::DeviceSyncMode;
use xmtp_mls::cursor_store::SqliteCursorStore;
use xmtp_mls::groups::MlsGroup;
use xmtp_mls::groups::send_message_opts::SendMessageOpts;
use xmtp_mls::identity::IdentityStrategy;
use xmtp_mls::utils::test::register_client;
use xmtp_mls::{Client, MlsContext};
use xmtp_proto::api::ToBoxedClient;
use xmtp_proto::xmtp::identity::associations::IdentityUpdate as IdentityUpdateProto;

pub type MeshClient = Client<MlsContext>;
pub type MeshGroup = MlsGroup<MlsContext>;

pub async fn build_client(node: &MeshNode) -> MeshClient {
    build_client_for(node, &generate_local_wallet()).await
}

/// A client for `wallet`'s inbox (nonce 1) on `node`, registered with the
/// wallet's signature: a new inbox on a node that does not know it, or a new
/// installation of an inbox the node already holds (the reset case).
pub async fn build_client_for(node: &MeshNode, wallet: &PrivateKeySigner) -> MeshClient {
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
    register_client(&client, wallet).await;
    client
}

/// The verified association state built from `node`'s own stored identity
/// log for `inbox_id` (empty log -> `get_state` on no updates, which is an
/// error the caller is not expected to hit in these tests). Mirrors
/// `MeshNode::verified_state`, which is `pub(crate)` and not visible from
/// this integration-test crate.
pub async fn association_state(node: &MeshNode, inbox_id: &str) -> AssociationState {
    let mut verified = Vec::new();
    for row in node.identity_log(inbox_id).unwrap() {
        let unverified = UnverifiedIdentityUpdate::try_from(row.update.unwrap()).unwrap();
        verified.push(unverified.to_verified(EoaOnlyVerifier).await.unwrap());
    }
    associations::get_state(&verified).unwrap()
}

/// Re-base `peer`'s installation onto its inbox's current log (restore
/// convergence §4.4), signed by `wallet` as the app's phrase-derived signer
/// would. False when the log already lists the installation.
pub async fn rebase(peer: &TestPeer, wallet: &PrivateKeySigner) -> bool {
    let Some(mut request) = peer
        .client
        .identity_updates()
        .rebase_installation_signature_request()
        .await
        .unwrap()
    else {
        return false;
    };
    add_wallet_signature(&mut request, wallet).await;
    peer.client
        .identity_updates()
        .apply_signature_request(request)
        .await
        .unwrap();
    true
}

/// The next IdentityResynced for `inbox_id` on `events` (20 s at most).
pub async fn next_resync(
    events: &mut broadcast::Receiver<NodeEvent>,
    inbox_id: &str,
) -> ResyncOutcome {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match events.recv().await {
                Ok(NodeEvent::IdentityResynced {
                    inbox_id: i,
                    outcome,
                }) if i == inbox_id => {
                    return outcome;
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("event stream closed: {e}"),
            }
        }
    })
    .await
    .expect("no identity resync within 20 s")
}

/// The identity updates `peer`'s libxmtp client holds for `inbox_id`, oldest first.
pub fn client_log(peer: &TestPeer, inbox_id: &str) -> Vec<IdentityUpdateProto> {
    use xmtp_db::prelude::QueryIdentityUpdates;
    peer.client
        .db()
        .get_identity_updates(inbox_id, None, None)
        .unwrap()
        .into_iter()
        .map(|u| IdentityUpdateProto::decode(u.payload.as_slice()).unwrap())
        .collect()
}

/// `node`'s log of `inbox_id`, oldest first.
pub fn node_log(node: &MeshNode, inbox_id: &str) -> Vec<IdentityUpdateProto> {
    node.identity_log(inbox_id)
        .unwrap()
        .into_iter()
        .map(|u| u.update.unwrap())
        .collect()
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

/// Revoke every other live installation of `peer`'s inbox, signed by the
/// recovery wallet. Mirrors `revoke_all_other_installations_signature_request`
/// (`bindings/mobile/src/mls.rs:952-976`), the libxmtp call the app's
/// instance `client.revokeAllOtherInstallations(signer)` runs underneath
/// (Task 2b, `dm-after-reset-analysis.md` Option 1). Idempotent the same
/// way that FFI is: once `peer`'s own installation is the only one left,
/// this reads the inbox state, finds nothing to revoke, and returns without
/// building or submitting a signature request — it does not resubmit the
/// prior revoke, which the association state's replay protection
/// (`RevokeAssociation::replay_check`) would reject as a reused signature.
pub async fn revoke_all_other_installations(peer: &TestPeer, wallet: &PrivateKeySigner) {
    let own = peer.installation();
    let others: Vec<Vec<u8>> = peer
        .client
        .inbox_state(true)
        .await
        .unwrap()
        .installation_ids()
        .into_iter()
        .filter(|id| *id != own)
        .collect();
    if others.is_empty() {
        return;
    }

    let mut request = peer
        .client
        .identity_updates()
        .revoke_installations(others)
        .await
        .unwrap();
    add_wallet_signature(&mut request, wallet).await;
    peer.client
        .identity_updates()
        .apply_signature_request(request)
        .await
        .unwrap();
}

/// Revoke `installation` from `peer`'s inbox, signed by the recovery
/// wallet. Unlike `revoke_all_other_installations`, this can target any
/// installation, including `peer`'s own live one: a wallet holder can sign
/// a revoke for any installation of their inbox, live or not (spec R2).
pub async fn revoke_installation(
    peer: &TestPeer,
    wallet: &PrivateKeySigner,
    installation: Vec<u8>,
) {
    let mut request = peer
        .client
        .identity_updates()
        .revoke_installations(vec![installation])
        .await
        .unwrap();
    add_wallet_signature(&mut request, wallet).await;
    peer.client
        .identity_updates()
        .apply_signature_request(request)
        .await
        .unwrap();
}

/// A registered client on its own node, attached to `hub` under `name`, syncing.
pub async fn peer(hub: &LoopbackHub, name: &str) -> TestPeer {
    peer_on(
        hub,
        name,
        MeshNode::in_memory().unwrap(),
        &generate_local_wallet(),
    )
    .await
}

/// Like [`peer`], but on `node` and for `wallet` (a reset keeps the wallet).
pub async fn peer_on(
    hub: &LoopbackHub,
    name: &str,
    node: MeshNode,
    wallet: &PrivateKeySigner,
) -> TestPeer {
    hub.register(name, &node);
    let client = build_client_for(&node, wallet).await;
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

/// Until `node` holds `who`'s key package.
pub async fn has_key_package(node: &MeshNode, who: &TestPeer) {
    eventually("a key package", || async {
        node.has_key_package(&who.installation()).unwrap()
    })
    .await;
}

/// Until `group` shows the application message `text`.
pub async fn see(group: &MeshGroup, text: &str) {
    eventually(&format!("sees {text:?}"), || async {
        group.sync().await.ok();
        app_payloads(group).contains(&text.as_bytes().to_vec())
    })
    .await;
}

/// `from` sends `text`; `to` shows it.
pub async fn send_and_see(from: &MeshGroup, to: &MeshGroup, text: &str) {
    from.send_message(text.as_bytes(), SendMessageOpts::default())
        .await
        .unwrap();
    see(to, text).await;
}

/// `x` starts a DM with `y` (x's node is its Rule-A sequencer) and they
/// exchange "<tag>-1" and "<tag>-2". Returns (x's group, y's group).
pub async fn dm_both_ways(x: &TestPeer, y: &TestPeer, tag: &str) -> (MeshGroup, MeshGroup) {
    let before = y
        .client
        .find_groups(GroupQueryArgs::default())
        .unwrap()
        .len();
    let xd = x
        .client
        .find_or_create_dm(y.client.inbox_id(), None)
        .await
        .unwrap();
    xd.send_message(format!("{tag}-1").as_bytes(), SendMessageOpts::default())
        .await
        .unwrap();
    eventually("the welcome", || async {
        y.client.sync_welcomes().await.ok();
        y.client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .len()
            > before
    })
    .await;
    let yd = y
        .client
        .find_groups(GroupQueryArgs::default())
        .unwrap()
        .into_iter()
        .find(|g| g.group_id == xd.group_id)
        .unwrap();
    see(&yd, &format!("{tag}-1")).await;
    send_and_see(&yd, &xd, &format!("{tag}-2")).await;
    (xd, yd)
}

/// RAII guard for `set_test_mode_upload_malformed_keypackage`: the flag is
/// process-wide, so a test that panics between enabling and disabling it
/// would otherwise leak it into later tests in the same binary. Enables the
/// flag for `installations` on construction and always disables it on drop.
pub struct MalformedKeyPackages;

impl MalformedKeyPackages {
    pub fn new(installations: Vec<Vec<u8>>) -> Self {
        xmtp_mls::utils::test_mocks_helpers::set_test_mode_upload_malformed_keypackage(
            true,
            Some(installations),
        );
        Self
    }
}

impl Drop for MalformedKeyPackages {
    fn drop(&mut self) {
        xmtp_mls::utils::test_mocks_helpers::set_test_mode_upload_malformed_keypackage(false, None);
    }
}

/// RAII guard for
/// `xmtp_mls::groups::group_membership::set_test_mode_simulate_unreconciled_failed_leaf`,
/// for the same reason as [`MalformedKeyPackages`].
pub struct SimulateUnreconciledFailedLeaf;

impl SimulateUnreconciledFailedLeaf {
    pub fn new() -> Self {
        xmtp_mls::groups::group_membership::set_test_mode_simulate_unreconciled_failed_leaf(true);
        Self
    }
}

impl Drop for SimulateUnreconciledFailedLeaf {
    fn drop(&mut self) {
        xmtp_mls::groups::group_membership::set_test_mode_simulate_unreconciled_failed_leaf(false);
    }
}
