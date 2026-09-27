#![recursion_limit = "256"]
mod common;

use std::path::PathBuf;

use common::{app_payloads, build_client, eventually, peer, welcome_count};
use xmtp_db::group::GroupQueryArgs;
use xmtp_mesh::{LoopbackHub, MeshNode, MeshStore, NewGroupMessage};
use xmtp_mls::groups::send_message_opts::SendMessageOpts;

/// A fresh directory, removed (with everything in it) on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("xmtp_mesh_{name}_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn db(&self) -> String {
        self.0.join("mesh.db3").to_string_lossy().into_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn store_survives_reopen_with_key() {
    let dir = TempDir::new("reopen");
    let path = dir.db();
    let key = [7u8; 32];
    {
        let mut s = MeshStore::open(Some(&path), Some(key)).unwrap();
        s.set_local_installation(b"me").unwrap();
        s.pin_sequencer(b"g", b"peer").unwrap();
        s.add_pending(
            &NewGroupMessage {
                group_id: b"g".to_vec(),
                data: b"p".to_vec(),
                sender_hmac: vec![],
                should_push: false,
                is_commit: false,
            },
            1,
        )
        .unwrap();
        s.append_identity("inbox", 1, 1, b"u1").unwrap();
        s.add_outbound_welcome(b"h", b"peer", b"w").unwrap();
    }
    let mut s = MeshStore::open(Some(&path), Some(key)).unwrap();
    assert_eq!(s.local_installation().unwrap(), Some(b"me".to_vec()));
    assert_eq!(s.sequencer(b"g").unwrap(), Some(b"peer".to_vec()));
    assert_eq!(s.pending_for(b"g").unwrap().len(), 1);
    assert_eq!(s.identity_len("inbox").unwrap(), 1);
    assert_eq!(s.outbound_welcomes_for(b"peer").unwrap().len(), 1);
}

#[test]
fn wrong_key_does_not_open() {
    let dir = TempDir::new("wrongkey");
    let path = dir.db();
    MeshStore::open(Some(&path), Some([1u8; 32])).unwrap();
    assert!(MeshStore::open(Some(&path), Some([2u8; 32])).is_err());
}

/// b's node queues a pending message and an outbound welcome while apart
/// from a, then restarts: a new node opened on the same file delivers both
/// once linked.
#[tokio::test(flavor = "multi_thread")]
async fn restarted_node_flushes_what_it_queued() {
    let dir = TempDir::new("restart");
    let key = Some([9u8; 32]);
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b_node = MeshNode::open(&dir.db(), key).unwrap();
    hub.register("b", &b_node);
    let b_client = build_client(&b_node).await;
    common::start_sync(&b_node, &b_client, hub.transport_for("b"));

    hub.link("a", "b");
    eventually("paired", || async {
        a.node
            .has_key_package(&b_client.installation_public_key().to_vec())
            .unwrap()
            && b_node.has_key_package(&a.installation()).unwrap()
    })
    .await;
    let a_dm = a
        .client
        .find_or_create_dm(b_client.inbox_id(), None)
        .await
        .unwrap();
    a_dm.send_message(b"hi", SendMessageOpts::default())
        .await
        .unwrap();
    let dm_id = a_dm.group_id.clone();
    eventually("b joins", || async {
        b_client.sync_welcomes().await.unwrap();
        !b_client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .is_empty()
    })
    .await;
    let b_dm = b_client
        .find_groups(GroupQueryArgs::default())
        .unwrap()
        .remove(0);
    eventually("b synced", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm).len() == 1
    })
    .await;
    hub.unlink("a", "b");

    // Apart: b sends in the DM (held pending, a sequences it) and creates a
    // group with a (its welcome is held outbound).
    b_dm.send_message_optimistic(b"queued", SendMessageOpts::default())
        .unwrap();
    b_dm.sync().await.ok();
    let pending = b_node.pending_count_for_test(&dm_id).unwrap();
    assert!(pending > 0);
    b_client
        .create_group_with_members(&[a.client.inbox_id()], None, None)
        .await
        .unwrap();
    assert_eq!(
        b_node
            .outbound_welcome_count_for_test(&a.installation())
            .unwrap(),
        1
    );

    // Restart. b's client stays alive only to sign Hellos; it still holds
    // the first node handle, which no longer syncs. The new node reads
    // everything from disk.
    b_node.stop_sync();
    drop(b_node);
    let b_node = MeshNode::open(&dir.db(), key).unwrap();
    assert_eq!(b_node.pending_count_for_test(&dm_id).unwrap(), pending);
    assert_eq!(
        b_node
            .outbound_welcome_count_for_test(&a.installation())
            .unwrap(),
        1
    );
    hub.register("b", &b_node);
    common::start_sync(&b_node, &b_client, hub.transport_for("b"));

    let a_high = a.node.max_group_id_for_test(&dm_id).unwrap();
    hub.link("a", "b");
    eventually("pending sequenced and welcome delivered", || async {
        b_node.pending_count_for_test(&dm_id).unwrap() == 0
            && b_node
                .outbound_welcome_count_for_test(&a.installation())
                .unwrap()
                == 0
    })
    .await;
    assert!(a.node.max_group_id_for_test(&dm_id).unwrap() >= a_high + pending as i64);
    assert_eq!(
        welcome_count(&a).await,
        1,
        "a's node holds b's group welcome"
    );
}

/// The replace records a pending client resync in its own
/// transaction; the marker survives a restart (a crash before the resync),
/// a resync of an older replace doesn't clear a newer one's marker, and the
/// current one does.
#[test]
fn a_pending_client_resync_survives_reopen() {
    let dir = TempDir::new("pending_resync");
    let path = dir.db();
    let row = |seq: i64| xmtp_mesh::store::IdentityRow {
        sequence_id: seq,
        server_timestamp_ns: seq,
        update_bytes: vec![seq as u8],
    };
    {
        let mut s = MeshStore::open(Some(&path), None).unwrap();
        assert!(s.pending_resyncs().unwrap().is_empty());
        s.replace_identity("inbox", &[row(1)], &[]).unwrap();
        assert_eq!(s.pending_resyncs().unwrap(), vec![("inbox".to_string(), 1)]);
    }
    let mut s = MeshStore::open(Some(&path), None).unwrap();
    assert_eq!(s.pending_resyncs().unwrap(), vec![("inbox".to_string(), 1)]);
    s.replace_identity("inbox", &[row(1), row(2)], &[]).unwrap();
    s.clear_pending_resync("inbox", 1).unwrap();
    assert_eq!(
        s.pending_resyncs().unwrap(),
        vec![("inbox".to_string(), 2)],
        "a stale resync keeps the newer replace's marker"
    );
    s.clear_pending_resync("inbox", 2).unwrap();
    assert!(s.pending_resyncs().unwrap().is_empty());
}
