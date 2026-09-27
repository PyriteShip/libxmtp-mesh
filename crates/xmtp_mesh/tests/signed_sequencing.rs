#![recursion_limit = "256"]
//! Signed sequencing records (DESIGN.md §B13): every stored row carries a
//! proof by the installation that ordered it, checked before it is stored.
mod common;

use common::{build_client, start_sync};
use xmtp_mesh::sync::seq;
use xmtp_mesh::{LoopbackHub, MeshNode};
use xmtp_mls::groups::send_message_opts::SendMessageOpts;

/// A client that publishes before its node ever starts syncing (offline
/// use): its rows are signed by `start_sync`, later ones as they are sequenced.
#[tokio::test(flavor = "multi_thread")]
async fn rows_sequenced_before_start_sync_are_signed_when_it_starts() {
    let hub = LoopbackHub::new();
    let node = MeshNode::in_memory().unwrap();
    hub.register("a", &node);
    let client = build_client(&node).await;
    let group = client.create_group(None, None).unwrap();
    group
        .send_message(b"one", SendMessageOpts::default())
        .await
        .unwrap();
    let gid = group.group_id.clone();
    let before = node.sequenced_rows_for_test(&gid).unwrap();
    assert!(!before.is_empty());
    assert!(
        before.iter().all(|r| r.seq_signer.is_none()),
        "no signer before start_sync"
    );

    start_sync(&node, &client, hub.transport_for("a"));
    group
        .send_message(b"two", SendMessageOpts::default())
        .await
        .unwrap();

    let key = client.installation_public_key().to_vec();
    let rows = node.sequenced_rows_for_test(&gid).unwrap();
    assert!(rows.len() > before.len());
    for row in &rows {
        assert_eq!(
            row.seq_signer.as_deref(),
            Some(key.as_slice()),
            "row {}",
            row.id
        );
        assert!(
            seq::verify_proof(
                &gid,
                row.id as u64,
                row.created_ns as u64,
                &row.data,
                &row.proof()
            ),
            "row {}",
            row.id
        );
    }
    assert_eq!(node.mesh_stats().seq_rows_signed, rows.len() as u64);
}
