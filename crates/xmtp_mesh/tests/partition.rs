#![recursion_limit = "256"]
mod common;

use common::{MeshGroup, TestPeer, app_payloads, eventually, peer};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use xmtp_db::group::GroupQueryArgs;
use xmtp_db::group_message::{DeliveryStatus, GroupMessageKind, MsgQueryArgs};
use xmtp_mesh::LoopbackHub;
use xmtp_mls::groups::send_message_opts::SendMessageOpts;

async fn paired_dm(hub: &LoopbackHub) -> (TestPeer, TestPeer, MeshGroup, MeshGroup) {
    let a = peer(hub, "a").await;
    let b = peer(hub, "b").await;
    hub.link("a", "b");
    eventually("paired", || async {
        a.node.has_key_package(&b.installation()).unwrap()
    })
    .await;
    let a_dm = a
        .client
        .find_or_create_dm(b.client.inbox_id(), None)
        .await
        .unwrap();
    a_dm.send_message(b"hello", SendMessageOpts::default())
        .await
        .unwrap();
    eventually("b joins", || async {
        b.client.sync_welcomes().await.unwrap();
        !b.client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .is_empty()
    })
    .await;
    let b_dm = b
        .client
        .find_groups(GroupQueryArgs::default())
        .unwrap()
        .remove(0);
    eventually("b synced", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm).len() == 1
    })
    .await;
    (a, b, a_dm, b_dm)
}

fn app_statuses(group: &MeshGroup) -> Vec<DeliveryStatus> {
    group
        .find_messages(&MsgQueryArgs::default())
        .unwrap()
        .into_iter()
        .filter(|m| m.kind == GroupMessageKind::Application)
        .map(|m| m.delivery_status)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_sends_queue_then_deliver_on_reconnect() {
    let hub = LoopbackHub::new();
    let (_a, _b, a_dm, b_dm) = paired_dm(&hub).await;
    hub.unlink("a", "b");

    // a is the sequencer: its sends resolve locally even while apart.
    for text in [b"a1".as_slice(), b"a2", b"a3"] {
        a_dm.send_message(text, SendMessageOpts::default())
            .await
            .unwrap();
    }
    // b is not: optimistic sends stay Unpublished (the UI's "queued").
    for text in [b"b1".as_slice(), b"b2", b"b3"] {
        b_dm.send_message_optimistic(text, SendMessageOpts::default())
            .unwrap();
    }
    b_dm.sync().await.ok(); // publishes intents to b's node, which holds them as pending
    assert_eq!(
        app_statuses(&b_dm)
            .iter()
            .filter(|s| **s == DeliveryStatus::Unpublished)
            .count(),
        3
    );

    hub.link("a", "b");
    eventually("both converge", || async {
        a_dm.sync().await.ok();
        b_dm.sync().await.ok();
        let (pa, pb) = (app_payloads(&a_dm), app_payloads(&b_dm));
        pa.len() == 7 && pa == pb
    })
    .await;
    assert!(
        app_statuses(&b_dm)
            .iter()
            .all(|s| *s == DeliveryStatus::Published)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_key_updates_do_not_fork() {
    let hub = LoopbackHub::new();
    let (_a, _b, a_dm, b_dm) = paired_dm(&hub).await;
    hub.unlink("a", "b");
    a_dm.key_update().await.unwrap();
    // b's commit cannot be sequenced while apart; libxmtp gives up waiting (~10 s)
    let _ = b_dm.key_update().await;
    hub.link("a", "b");
    a_dm.send_message(b"after-a", SendMessageOpts::default())
        .await
        .unwrap();
    b_dm.send_message(b"after-b", SendMessageOpts::default())
        .await
        .unwrap();
    eventually("both still talk", || async {
        a_dm.sync().await.ok();
        b_dm.sync().await.ok();
        let pa = app_payloads(&a_dm);
        pa.contains(&b"after-a".to_vec())
            && pa.contains(&b"after-b".to_vec())
            && pa == app_payloads(&b_dm)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn flapping_link_converges_to_identical_order() {
    let hub = LoopbackHub::new();
    let (_a, _b, a_dm, b_dm) = paired_dm(&hub).await;
    let mut rng = StdRng::seed_from_u64(7);
    let mut linked = true;
    for round in 0..10u8 {
        if rng.random_bool(0.5) {
            if linked {
                hub.unlink("a", "b")
            } else {
                hub.link("a", "b")
            }
            linked = !linked;
        }
        a_dm.send_message(&[b'a', round], SendMessageOpts::default())
            .await
            .unwrap();
        b_dm.send_message_optimistic(&[b'b', round], SendMessageOpts::default())
            .unwrap();
        b_dm.sync().await.ok();
    }
    if !linked {
        hub.link("a", "b");
    }
    eventually("identical history", || async {
        a_dm.sync().await.ok();
        b_dm.sync().await.ok();
        let (pa, pb) = (app_payloads(&a_dm), app_payloads(&b_dm));
        pa.len() == 21 && pa == pb
    })
    .await;
}
