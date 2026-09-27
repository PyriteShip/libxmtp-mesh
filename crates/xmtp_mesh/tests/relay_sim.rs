#![recursion_limit = "256"]
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    app_payloads, eventually, eventually_for, fast_relay_config, pair_dm, relay_hashes, relay_peer,
    relay_peer_with,
};
use xmtp_mesh::{LoopbackHub, MeshNode, RelayConfig, churn_schedule, random_topology};
use xmtp_mls::groups::GroupError;
use xmtp_mls::groups::send_message_opts::SendMessageOpts;

async fn send(dm: &common::MeshGroup, text: &[u8]) {
    match dm.send_message(text, SendMessageOpts::default()).await {
        Ok(_) | Err(GroupError::SyncFailedToWait(_)) => {}
        Err(e) => panic!("send failed: {e:?}"),
    }
}

/// §R2 success 4 and §R10.2 "Spam".
#[tokio::test(flavor = "multi_thread")]
async fn a_spammer_is_capped_and_honest_traffic_still_arrives() {
    let hub = LoopbackHub::new();
    let small = RelayConfig {
        max_entries: 64,
        max_bytes: 64 * 1024,
        ..fast_relay_config()
    };
    let (a, _) = relay_peer_with(&hub, "a", small.clone()).await;
    let (b, _) = relay_peer_with(&hub, "b", small.clone()).await;
    let (d, _) = relay_peer_with(&hub, "d", small.clone()).await;
    let (x, _) = relay_peer_with(&hub, "x", small.clone()).await;
    let (a_dm, d_dm) = pair_dm(&hub, &a, &d).await;
    common::relay_keys_confirmed(&a, &d, &a_dm.group_id).await;
    hub.unlink("a", "d");
    hub.link("x", "b");
    hub.link("a", "b");
    hub.link("b", "d");
    for _ in 0..200 {
        x.node.originate_random_for_test(100, 5);
    }
    eventually("b refuses some", || async {
        let s = b.node.relay_stats();
        s.dropped_rate + s.dropped_share > 0
    })
    .await;
    assert!(b.node.relay_spool_count_from_for_test(&x.installation()) <= small.share_cap() as i64);

    send(&a_dm, b"honest").await;
    eventually_for("d still gets honest traffic", 30, || async {
        d_dm.sync().await.ok();
        app_payloads(&d_dm).contains(&b"honest".to_vec())
    })
    .await;

    // Newest wins at d too: b passes x's junk on, so b's share at d fills
    // and then churns. It never exceeds the cap.
    eventually("b's share at d churns", || async {
        x.node.originate_random_for_test(100, 5);
        d.node.relay_stats().dropped_share > 0
    })
    .await;
    assert!(d.node.relay_spool_count_from_for_test(&b.installation()) <= small.share_cap() as i64);
}

/// A recipient whose neighbour's rate budget is spent still gets its own
/// message: the limit keeps it out of the spool, not out of delivery. A
/// replay of that envelope is then a no-op (it is marked seen).
#[tokio::test(flavor = "multi_thread")]
async fn a_recipient_gets_its_message_past_a_spent_rate_budget() {
    let hub = LoopbackHub::new();
    let stingy = RelayConfig {
        max_entries: 64,
        max_bytes: 64 * 1024,
        neighbour_envelopes_per_min: 1,
        ..fast_relay_config()
    };
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, b_rec) = relay_peer(&hub, "b").await;
    let (d, _) = relay_peer_with(&hub, "d", stingy.clone()).await;
    let (a_dm, d_dm) = pair_dm(&hub, &a, &d).await;
    common::relay_keys_confirmed(&a, &d, &a_dm.group_id).await;
    hub.unlink("a", "d");
    hub.link("b", "d");
    let flood: Vec<Vec<u8>> = (0..2 * stingy.share_cap())
        .map(|_| b.node.originate_random_for_test(100, 5))
        .collect();
    eventually("d's budget for b is spent", || async {
        d.node.relay_stats().dropped_rate > 0
    })
    .await;
    let before = d.node.relay_stats();
    hub.link("a", "b");
    send(&a_dm, b"past the limit").await;
    eventually_for("d gets it anyway", 30, || async {
        d_dm.sync().await.ok();
        app_payloads(&d_dm).contains(&b"past the limit".to_vec())
    })
    .await;
    let after = d.node.relay_stats();
    assert_eq!(
        after.accepted, before.accepted,
        "nothing from b was spooled: the DM came in over the limit"
    );
    assert!(after.delivered > before.delivered);
    assert!(
        after.delivered_unspooled > before.delivered_unspooled,
        "counted as delivered past a limit"
    );

    // Replay, five times over, every DM envelope b passed on to d (all of
    // them came in over the limit, so none is in d's spool).
    hub.unlink("a", "b");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let dm_frames: Vec<(Vec<u8>, Vec<u8>)> = b_rec
        .raw_to("d")
        .into_iter()
        .filter_map(|f| {
            let h = relay_hashes(std::slice::from_ref(&f)).pop()?;
            (!flood.contains(&h)).then_some((h, f))
        })
        .collect();
    assert!(!dm_frames.is_empty(), "b passed the DM envelope on");
    for (h, _) in &dm_frames {
        assert!(!d.node.relay_spool_has_for_test(h));
    }
    let unspooled: Vec<Vec<u8>> = dm_frames.iter().map(|(_, f)| f.clone()).collect();
    let settled = d.node.relay_stats();
    for _ in 0..5 {
        for f in &unspooled {
            hub.inject("b", "d", f.clone());
        }
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let replayed = d.node.relay_stats();
    assert_eq!(
        replayed.delivered, settled.delivered,
        "a replay is not delivered again"
    );
    assert_eq!(replayed.accepted, settled.accepted);
    for (h, _) in &dm_frames {
        assert!(d.node.relay_seen_for_test(h), "marked seen after delivery");
    }
}

/// §R10.2 "Restart": the seen-set persists, so a restarted node does
/// not accept (and re-flood) what it already saw.
#[tokio::test(flavor = "multi_thread")]
async fn seen_set_survives_a_node_restart() {
    let path = std::env::temp_dir().join(format!("relay-restart-{}.db", rand::random::<u64>()));
    let path = path.to_str().unwrap().to_string();
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let node = MeshNode::open(&path, None).unwrap();
    let wallet = xmtp_cryptography::utils::generate_local_wallet();
    let b = common::peer_on(&hub, "b", node, &wallet).await;
    b.node
        .enable_relay_with(
            Arc::new(xmtp_mesh::ClientRelayExporter(b.client.clone())),
            fast_relay_config(),
        )
        .unwrap();
    hub.link("a", "b");
    let hash = a.node.originate_random_for_test(100, 5);
    eventually("b holds it", || async {
        b.node.relay_spool_has_for_test(&hash)
    })
    .await;
    b.node.stop_sync();
    drop(b);
    let reopened = MeshNode::open(&path, None).unwrap();
    assert!(reopened.relay_seen_for_test(&hash));
    let _ = std::fs::remove_file(&path);
}

/// §R10.2 "Crowd": 50 nodes, random links, churn, and a stated offered
/// load, time-compressed: every node originates one envelope (100-byte
/// body) per round, one round per second for 10 rounds (about 500
/// envelopes); after 3 rounds one DM pair sends 5 messages under the load. Slow: run with
/// `cargo test -p xmtp_mesh --test relay_sim -- --ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: 50 registered clients"]
async fn a_crowd_delivers_without_a_storm() {
    let hub = LoopbackHub::new();
    let names: Vec<String> = (0..50).map(|i| format!("n{i:02}")).collect();
    let mut peers = Vec::new();
    for n in &names {
        peers.push(relay_peer(&hub, n).await);
    }
    let (a, d) = (&peers[0].0, &peers[49].0);
    let (a_dm, d_dm) = pair_dm(&hub, a, d).await;
    common::relay_keys_confirmed(a, d, &a_dm.group_id).await;
    hub.unlink(&a.name, &d.name);
    let edges = random_topology(&names, 20, 4, 42);
    for (x, y) in &edges {
        hub.link(x, y);
    }
    let churn = churn_schedule(&names, &edges, 30, Duration::from_millis(200), 4, 42);
    let hub2 = hub.clone();
    let churning = tokio::spawn(async move { hub2.run_schedule(churn).await });

    // Offered load: 10 rounds, one 100-byte-body envelope from every node
    // per round (≈500 envelopes total), rounds 1 s apart (the test's
    // "minute"); the DM messages go out under load, after 3 rounds.
    let load_nodes: Vec<MeshNode> = peers.iter().map(|(p, _)| p.node.clone()).collect();
    let loading = tokio::spawn(async move {
        for _ in 0..10 {
            for n in &load_nodes {
                n.originate_random_for_test(100, 5);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    tokio::time::sleep(Duration::from_secs(3)).await;

    for i in 0..5 {
        send(&a_dm, format!("crowd {i}").as_bytes()).await;
    }
    eventually_for("d gets all five", 90, || async {
        d_dm.sync().await.ok();
        let got = app_payloads(&d_dm);
        (0..5).all(|i| got.contains(&format!("crowd {i}").into_bytes()))
    })
    .await;
    churning.await.unwrap();
    loading.await.unwrap();

    // No storm: each node sends a given envelope to a given neighbour at
    // most twice (once per link session; churn re-links pairs).
    for (p, rec) in &peers {
        for q in &names {
            let hashes = relay_hashes(&rec.raw_to(q));
            let mut counts = std::collections::HashMap::new();
            for h in hashes {
                *counts.entry(h).or_insert(0) += 1;
            }
            assert!(
                counts.values().all(|c| *c <= 2),
                "{} -> {q}: {counts:?}",
                p.name
            );
        }
    }
}
