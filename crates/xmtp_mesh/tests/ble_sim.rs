#![recursion_limit = "256"]
//! The two-phone scenarios again, over a hub that behaves like BLE: slow,
//! laggy, and (for `ble_flaky`) dropping the whole link now and then.
mod common;

use common::{app_payloads, eventually_for, peer};
use xmtp_db::group::GroupQueryArgs;
use xmtp_mesh::{LinkProfile, LoopbackHub};
use xmtp_mls::groups::GroupError;
use xmtp_mls::groups::send_message_opts::SendMessageOpts;

const SECS: u64 = 60;

#[tokio::test(flavor = "multi_thread")]
async fn dm_round_trip_over_ble_1m() {
    let hub = LoopbackHub::with_profile(LinkProfile::ble_1m());
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    eventually_for("paired", SECS, || async {
        a.node.has_key_package(&b.installation()).unwrap()
    })
    .await;

    let a_dm = a
        .client
        .find_or_create_dm(b.client.inbox_id(), None)
        .await
        .unwrap();
    a_dm.send_message(b"hi", SendMessageOpts::default())
        .await
        .unwrap();

    eventually_for("b receives the welcome", SECS, || async {
        b.client.sync_welcomes().await.unwrap();
        b.client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .len()
            == 1
    })
    .await;
    let b_dm = b
        .client
        .find_groups(GroupQueryArgs::default())
        .unwrap()
        .remove(0);
    eventually_for("b acks the welcome", SECS, || async {
        a.node
            .outbound_welcome_count_for_test(&b.installation())
            .unwrap()
            == 0
    })
    .await;
    eventually_for("b sees hi", SECS, || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm) == vec![b"hi".to_vec()]
    })
    .await;

    // Rule A: the joiner never self-sequences.
    assert_eq!(
        b.node.group_sequencer_for_test(&b_dm.group_id).unwrap(),
        Some(a.installation())
    );

    // b is not the sequencer, so its send must round-trip b -> a -> b. libxmtp
    // waits ~225 ms (3 sync attempts) for that, and a BLE round trip is about
    // as long, so the send may report SyncFailedToWait even though the message
    // is published. Accept only that error; delivery is asserted below.
    match b_dm.send_message(b"yo", SendMessageOpts::default()).await {
        Ok(_) | Err(GroupError::SyncFailedToWait(_)) => {}
        Err(e) => panic!("send failed: {e:?}"),
    }
    eventually_for("a sees yo", SECS, || async {
        a_dm.sync().await.ok();
        app_payloads(&a_dm) == vec![b"hi".to_vec(), b"yo".to_vec()]
    })
    .await;
    eventually_for("b sees yo", SECS, || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm) == vec![b"hi".to_vec(), b"yo".to_vec()]
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn flaky_link_converges() {
    let hub = LoopbackHub::with_profile(LinkProfile::ble_flaky());
    converge_over(&hub).await;
    assert!(hub.link_drops_for_test() >= 1, "the link never dropped");
}

/// Seed chosen (and checked) to drop the link several times, including
/// once the DM is up.
#[tokio::test(flavor = "multi_thread")]
async fn heavily_flaky_link_converges() {
    let hub = LoopbackHub::with_profile(LinkProfile {
        drop_link_per_frame: 0.1,
        seed: HEAVY_SEED,
        ..LinkProfile::ble_1m()
    });
    let drops_before_burst = converge_over(&hub).await;
    let drops = hub.link_drops_for_test();
    assert!(drops >= 3, "only {drops} link drops");
    assert!(
        drops > drops_before_burst,
        "no link drop once the DM was up ({drops} total)"
    );
}

/// Gives 8 drops, 4 of them during the 10-round burst (checked over 5 runs).
const HEAVY_SEED: u64 = 4;

/// Pair a and b over `hub`, set up their DM, then each sends 10 messages;
/// both must converge to the same 21 payloads in the same order. Returns
/// the hub's link-drop count from just before the 10-round burst.
async fn converge_over(hub: &LoopbackHub) -> u64 {
    let a = peer(hub, "a").await;
    let b = peer(hub, "b").await;
    hub.link("a", "b");
    eventually_for("paired", SECS, || async {
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
    eventually_for("b joins", SECS, || async {
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
    eventually_for("b synced", SECS, || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm).len() == 1
    })
    .await;

    let drops_before_burst = hub.link_drops_for_test();
    for round in 0..10u8 {
        a_dm.send_message(&[b'a', round], SendMessageOpts::default())
            .await
            .unwrap();
        b_dm.send_message_optimistic(&[b'b', round], SendMessageOpts::default())
            .unwrap();
        b_dm.sync().await.ok();
    }
    eventually_for("identical history", SECS, || async {
        a_dm.sync().await.ok();
        b_dm.sync().await.ok();
        let (pa, pb) = (app_payloads(&a_dm), app_payloads(&b_dm));
        pa.len() == 21 && pa == pb
    })
    .await;
    drops_before_burst
}
