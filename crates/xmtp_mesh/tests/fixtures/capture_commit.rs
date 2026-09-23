// tests/fixtures/capture_commit.rs — run once with:
//   cargo test -p xmtp_mesh --test capture_commit -- --ignored
#![recursion_limit = "256"]
#[path = "../common/mod.rs"]
mod common;

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn capture_creation_commit() {
    let node = xmtp_mesh::MeshNode::in_memory().unwrap();
    let client = common::build_client(&node).await;
    let group = client.create_group(None, None).unwrap();
    group
        .send_message(b"x", xmtp_mls::groups::send_message_opts::SendMessageOpts::default())
        .await
        .unwrap();
    let data = node.first_sequenced_data_for_test(&group.group_id).unwrap();
    std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/creation_commit.bin"), data).unwrap();
}
