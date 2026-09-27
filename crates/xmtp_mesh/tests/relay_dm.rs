#![recursion_limit = "256"]
mod common;

use std::time::Duration;

use common::{
    app_payloads, eventually, eventually_for, fast_relay_config, pair_dm,
    relay_keys_confirmed as keys_confirmed, relay_peer, relay_peer_with,
};
use xmtp_mesh::LoopbackHub;
use xmtp_mls::groups::GroupError;
use xmtp_mls::groups::send_message_opts::SendMessageOpts;

async fn send(dm: &common::MeshGroup, text: &[u8]) {
    match dm.send_message(text, SendMessageOpts::default()).await {
        Ok(_) | Err(GroupError::SyncFailedToWait(_)) => {}
        Err(e) => panic!("send failed: {e:?}"),
    }
}

/// §R2 success 1 and §R10.2 "Chain" / "Joiner round trip".
#[tokio::test(flavor = "multi_thread")]
async fn a_dm_crosses_a_three_hop_chain_both_ways() {
    let hub = LoopbackHub::new();
    let (a, a_rec) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    let (c, _) = relay_peer(&hub, "c").await;
    let (d, _) = relay_peer(&hub, "d").await;
    let (a_dm, d_dm) = pair_dm(&hub, &a, &d).await;
    let gid = a_dm.group_id.clone();
    keys_confirmed(&a, &d, &gid).await;
    hub.unlink("a", "d");
    hub.link("a", "b");
    hub.link("b", "c");
    hub.link("c", "d");

    send(&a_dm, b"over the chain").await;
    eventually_for("d sees it", 30, || async {
        d_dm.sync().await.ok();
        app_payloads(&d_dm).contains(&b"over the chain".to_vec())
    })
    .await;

    send(&d_dm, b"and back").await;
    eventually_for("a sees the reply", 30, || async {
        a_dm.sync().await.ok();
        app_payloads(&a_dm).contains(&b"and back".to_vec())
    })
    .await;
    eventually_for("d's reply settles via a Ref", 30, || async {
        d.node.pending_count_for_test(&gid).unwrap() == 0
    })
    .await;
    assert!(
        a.node.relay_stats().refs_sent >= 1,
        "no echo: the joiner's message came back as a Ref"
    );

    // §R10.3: no stable id in any relay frame a sent.
    let own_inbox = a.client.inbox_id().as_bytes().to_vec();
    let d_inbox = d.client.inbox_id().as_bytes().to_vec();
    for frame in a_rec.raw_to("b") {
        if let Ok(xmtp_mesh::frames::frame::Body::Relay(env)) = xmtp_mesh::frames::decode(&frame) {
            for needle in [
                &gid,
                &own_inbox,
                &d_inbox,
                &a.installation(),
                &d.installation(),
            ] {
                assert!(
                    !env.sealed
                        .windows(needle.len())
                        .any(|w| w == needle.as_slice())
                );
            }
        }
    }
    drop((b, c));
}

/// §R2 success 2 and §R10.2 "Carry".
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_walks_the_message_over() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    let (d, _) = relay_peer(&hub, "d").await;
    let (a_dm, d_dm) = pair_dm(&hub, &a, &d).await;
    keys_confirmed(&a, &d, &a_dm.group_id).await;
    hub.unlink("a", "d");
    hub.link("a", "b");
    send(&a_dm, b"carried").await;
    // A send may publish more than one row, each its own envelope: b must
    // hold every envelope a originated (and a stop originating) before the
    // carrier walks away.
    eventually("b carries all a originated", || async {
        let originated = a.node.relay_stats().originated;
        if originated == 0 || b.node.relay_stats().accepted < originated {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        a.node.relay_stats().originated == originated
    })
    .await;
    hub.unlink("a", "b");
    hub.link("b", "d");
    eventually_for("d sees it", 30, || async {
        d_dm.sync().await.ok();
        app_payloads(&d_dm).contains(&b"carried".to_vec())
    })
    .await;
}

/// §R6.1: a direct peer gets direct sync, not relay.
#[tokio::test(flavor = "multi_thread")]
async fn a_direct_peer_is_not_relayed_to() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (d, _) = relay_peer(&hub, "d").await;
    let (a_dm, _) = pair_dm(&hub, &a, &d).await;
    keys_confirmed(&a, &d, &a_dm.group_id).await;
    send(&a_dm, b"direct").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(a.node.relay_stats().originated, 0);
}

/// §R6.1: retries stop after the schedule runs out.
#[tokio::test(flavor = "multi_thread")]
async fn retries_stop_after_the_schedule() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (d, _) = relay_peer(&hub, "d").await;
    let (a_dm, _) = pair_dm(&hub, &a, &d).await;
    keys_confirmed(&a, &d, &a_dm.group_id).await;
    hub.unlink("a", "d");
    send(&a_dm, b"into the void").await;
    // fast config: sends at 0, +1 s, +2 s, +4 s, then stops. libxmtp may
    // publish more than one row for a send (each restarts the schedule), so
    // assert the bound and that it stops, not an exact count.
    tokio::time::sleep(Duration::from_secs(10)).await;
    let n = a.node.relay_stats().originated;
    assert!((4..=8).contains(&n), "originated {n}");
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(a.node.relay_stats().originated, n, "retries stopped");
}

/// §R4.5: until both sides hold the key, the DM relays nothing.
#[tokio::test(flavor = "multi_thread")]
async fn no_relay_without_a_confirmed_key() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let d = common::peer(&hub, "d").await; // no relay: never confirms a key
    let (a_dm, _) = pair_dm(&hub, &a, &d).await;
    hub.unlink("a", "d");
    send(&a_dm, b"waits for direct").await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(a.node.relay_stats().originated, 0);
    assert!(!matches!(
        a.node.relay_key_for_test(&a_dm.group_id),
        Some((_, true))
    ));
}

/// A joiner that cannot resolve a `Ref`
/// asks for `Full` rows and gets the message, and the two sides do not
/// ping-pong acks outside the retry schedule. `a` is forced to send every
/// row as a `Ref`, so `d` holds no pending copy for any of them.
#[tokio::test(flavor = "multi_thread")]
async fn an_unresolvable_ref_heals_with_full_rows_and_no_ack_storm() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    let (d, _) = relay_peer(&hub, "d").await;
    let (a_dm, d_dm) = pair_dm(&hub, &a, &d).await;
    keys_confirmed(&a, &d, &a_dm.group_id).await;
    hub.unlink("a", "d");
    hub.link("a", "b");
    hub.link("b", "d");
    a.node.relay_force_refs_for_test(true);

    send(&a_dm, b"as a ref").await;
    eventually_for("d sees it via Full rows", 30, || async {
        d_dm.sync().await.ok();
        app_payloads(&d_dm).contains(&b"as a ref".to_vec())
    })
    .await;
    // Settled: a few seconds of quiet, then no originations at all.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let total = || a.node.relay_stats().originated + d.node.relay_stats().originated;
    let n = total();
    assert!(n <= 16, "originated {n}: bounded by the schedule");
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(total(), n, "no ack ping-pong once settled");
    drop(b);
}

/// Even when a stall never heals (the joiner is
/// forced never to ask for `Full` rows), a repeated ack that changes
/// nothing does not restart the sequencer's schedule: originations stop.
#[tokio::test(flavor = "multi_thread")]
async fn a_persistent_stall_does_not_ping_pong() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    let (d, _) = relay_peer(&hub, "d").await;
    let (a_dm, _) = pair_dm(&hub, &a, &d).await;
    keys_confirmed(&a, &d, &a_dm.group_id).await;
    hub.unlink("a", "d");
    hub.link("a", "b");
    hub.link("b", "d");
    a.node.relay_force_refs_for_test(true);
    d.node.relay_no_full_request_for_test(true);

    send(&a_dm, b"never resolves").await;
    // fast config: 4 sends per schedule; a send may publish more than one
    // row. Without the fix this reached ~70 within 8 s and kept growing.
    tokio::time::sleep(Duration::from_secs(10)).await;
    let total = || a.node.relay_stats().originated + d.node.relay_stats().originated;
    let n = total();
    assert!(n <= 20, "originated {n}: bounded by the schedule");
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(total(), n, "no ack ping-pong");
    drop(b);
}

/// The joiner stalls below the sequencer's
/// stored ack (here raised as a direct session's note would), so its
/// `need_full_after` cannot be served. The sequencer must not re-arm on
/// it: originations stay bounded and stop.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_request_below_the_sequencer_ack_stays_bounded() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    let (d, _) = relay_peer(&hub, "d").await;
    let (a_dm, _) = pair_dm(&hub, &a, &d).await;
    let gid = a_dm.group_id.clone();
    keys_confirmed(&a, &d, &gid).await;
    hub.unlink("a", "d");
    hub.link("a", "b");
    a.node.relay_force_refs_for_test(true);

    send(&a_dm, b"first").await;
    // d never got "first", but a's stored ack says it did.
    let high = a.node.max_group_id_for_test(&gid).unwrap();
    a.node.relay_note_peer_acked_high_for_test(&gid, high);
    send(&a_dm, b"second").await;
    hub.link("b", "d");

    tokio::time::sleep(Duration::from_secs(10)).await;
    let total = || a.node.relay_stats().originated + d.node.relay_stats().originated;
    let n = total();
    assert!(n <= 24, "originated {n}: bounded by the schedule");
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(total(), n, "no ping-pong on an unservable request");
    drop(b);
}

/// The joiner's pure ack is lost. The
/// sequencer's next retry carries only rows the joiner holds; the joiner
/// must ack it, so the sequencer's stored ack catches up within the retry
/// schedule instead of staying stale.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_ack_is_repaired_by_the_next_retry() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    let (d, _) = relay_peer(&hub, "d").await;
    let (a_dm, _) = pair_dm(&hub, &a, &d).await;
    let gid = a_dm.group_id.clone();
    keys_confirmed(&a, &d, &gid).await;
    hub.unlink("a", "d");
    hub.link("a", "b");
    hub.link("b", "d");
    d.node.relay_drop_pure_acks_for_test(true);

    let before = a.node.max_group_id_for_test(&gid).unwrap();
    send(&a_dm, b"acked late").await;
    eventually("a sequenced it", || async {
        a.node.max_group_id_for_test(&gid).unwrap() > before
    })
    .await;
    // No client sync on d: its own sends would carry the ack instead.
    eventually_for("d holds all of a's rows", 30, || async {
        d.node.max_group_id_for_test(&gid).unwrap() == a.node.max_group_id_for_test(&gid).unwrap()
    })
    .await;
    d.node.relay_drop_pure_acks_for_test(false);
    eventually_for("a's stored ack catches up", 10, || async {
        a.node.relay_peer_acked_high_for_test(&gid) == a.node.max_group_id_for_test(&gid).unwrap()
    })
    .await;
    drop(b);
}

/// A joiner's message left unsent while relay
/// was off (as after an app restart) goes out once relay is enabled again,
/// without waiting for new content.
#[tokio::test(flavor = "multi_thread")]
async fn unsent_content_goes_out_when_relay_is_enabled() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    let (d, _) = relay_peer(&hub, "d").await;
    let (a_dm, d_dm) = pair_dm(&hub, &a, &d).await;
    let gid = a_dm.group_id.clone();
    keys_confirmed(&a, &d, &gid).await;
    hub.unlink("a", "d");
    hub.link("a", "b");
    hub.link("b", "d");
    // Whatever a relays on losing d settles first, so nothing from a's
    // side pulls d's message out later.
    eventually_for("a's stored ack is current", 30, || async {
        a.node.relay_peer_acked_high_for_test(&gid) == a.node.max_group_id_for_test(&gid).unwrap()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    hub.unlink("b", "d");
    d.node.disable_relay();
    send(&d_dm, b"sent while relay was off").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    d.node
        .enable_relay_with(
            std::sync::Arc::new(xmtp_mesh::ClientRelayExporter(d.client.clone())),
            fast_relay_config(),
        )
        .unwrap();
    hub.link("b", "d");
    eventually_for("a gets it", 30, || async {
        a_dm.sync().await.ok();
        app_payloads(&a_dm).contains(&b"sent while relay was off".to_vec())
    })
    .await;
    drop(b);
}

/// Rows a direct session had not delivered when
/// the link dropped go over relay (§R6.1), without new content. The
/// sequencer's pushes are suppressed so the direct session leaves one
/// behind.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_direct_link_falls_back_to_relay() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    let (d, _) = relay_peer(&hub, "d").await;
    let (a_dm, d_dm) = pair_dm(&hub, &a, &d).await;
    let gid = a_dm.group_id.clone();
    keys_confirmed(&a, &d, &gid).await;
    hub.link("a", "b");
    hub.link("b", "d");
    a.node.suppress_group_push_for_test(true);
    let before = a.node.max_group_id_for_test(&gid).unwrap();
    send(&a_dm, b"left behind").await;
    eventually("a sequenced it", || async {
        a.node.max_group_id_for_test(&gid).unwrap() > before
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(a.node.relay_stats().originated, 0, "direct: not relayed");
    hub.unlink("a", "d");
    eventually_for("d gets it over relay", 30, || async {
        d_dm.sync().await.ok();
        app_payloads(&d_dm).contains(&b"left behind".to_vec())
    })
    .await;
    drop(b);
}

/// §R9, answer timing: the joiner's ack to
/// a delivered sync leaves only after the answer delay, then settles.
#[tokio::test(flavor = "multi_thread")]
async fn a_delivery_triggered_ack_waits_the_answer_delay() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    let slow = xmtp_mesh::RelayConfig {
        answer_delay_ms: (3_000, 3_000),
        ..fast_relay_config()
    };
    let (d, _) = relay_peer_with(&hub, "d", slow).await;
    let (a_dm, _) = pair_dm(&hub, &a, &d).await;
    let gid = a_dm.group_id.clone();
    keys_confirmed(&a, &d, &gid).await;
    hub.unlink("a", "d");
    hub.link("a", "b");
    hub.link("b", "d");
    let before = a.node.max_group_id_for_test(&gid).unwrap();
    send(&a_dm, b"answer later").await;
    eventually("a sequenced it", || async {
        a.node.max_group_id_for_test(&gid).unwrap() > before
    })
    .await;
    // No client sync on d: its own sends would carry the ack instead.
    eventually_for("d holds a's rows", 30, || async {
        d.node.max_group_id_for_test(&gid).unwrap() > before
    })
    .await;
    tokio::time::sleep(Duration::from_millis(2_000)).await;
    assert_eq!(
        d.node.relay_stats().originated,
        0,
        "no ack before the delay"
    );
    eventually_for(
        "the ack goes out and a's stored ack catches up",
        15,
        || async {
            a.node.relay_peer_acked_high_for_test(&gid)
                == a.node.max_group_id_for_test(&gid).unwrap()
        },
    )
    .await;
    assert!(d.node.relay_stats().originated >= 1);
    drop(b);
}
