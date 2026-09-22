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
pub async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
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
    messages.into_iter().map(|m| m.decrypted_message_bytes).collect()
}
