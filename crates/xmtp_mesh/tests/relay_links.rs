#![recursion_limit = "256"]
mod common;

use std::time::Duration;

use common::{eventually, fast_relay_config, pair_dm, peer, relay_hashes, relay_peer};
use xmtp_mesh::LoopbackHub;
use xmtp_mesh::frames::{self, RelayEnvelope, frame::Body};

async fn verified(hub_a: &common::TestPeer, n: usize) {
    eventually("verified", || async {
        hub_a.node.verified_peers().len() == n
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_envelope_floods_down_a_chain_once_per_link_and_never_back() {
    let hub = LoopbackHub::new();
    let (a, a_rec) = relay_peer(&hub, "a").await;
    let (b, b_rec) = relay_peer(&hub, "b").await;
    let (c, _) = relay_peer(&hub, "c").await;
    hub.link("a", "b");
    hub.link("b", "c");
    verified(&b, 2).await;
    verified(&a, 1).await;
    verified(&c, 1).await;

    let hash = a.node.originate_random_for_test(100, 5);
    eventually("c holds it", || async {
        c.node.relay_spool_has_for_test(&hash)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(relay_hashes(&a_rec.raw_to("b")), vec![hash.clone()]);
    assert_eq!(relay_hashes(&b_rec.raw_to("c")), vec![hash.clone()]);
    assert!(relay_hashes(&b_rec.raw_to("a")).is_empty(), "split horizon");
    assert_eq!(a.node.relay_stats().originated, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn ttl_bounds_the_hops() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    let (c, _) = relay_peer(&hub, "c").await;
    hub.link("a", "b");
    hub.link("b", "c");
    verified(&b, 2).await;
    let hash = a.node.originate_random_for_test(100, 1);
    eventually("b holds it", || async {
        b.node.relay_spool_has_for_test(&hash)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !c.node.relay_spool_has_for_test(&hash),
        "ttl 1: a -> b only"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_neighbour_gets_the_spool_by_digest() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (d, _) = relay_peer(&hub, "d").await;
    let hash = a.node.originate_random_for_test(100, 5);
    hub.link("a", "d");
    eventually("d holds it (carry)", || async {
        d.node.relay_spool_has_for_test(&hash)
    })
    .await;
}

/// §R7: a phone without relay never receives relay frames.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_without_relay_gets_no_relay_frames() {
    let hub = LoopbackHub::new();
    let (a, a_rec) = relay_peer(&hub, "a").await;
    let old = peer(&hub, "old").await; // relay never enabled: Hello.relay = 0
    hub.link("a", "old");
    verified(&a, 1).await;
    a.node.originate_random_for_test(100, 5);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(a_rec.sent_to("old").iter().all(|b| !matches!(
        b,
        Body::Relay(_)
            | Body::SpoolDigest(_)
            | Body::SpoolWant(_)
            | Body::RelayKeyOffer(_)
            | Body::RelayKeyAck(_)
    )));
    drop(old);
}

/// §R8: relay errors never kill a session.
#[tokio::test(flavor = "multi_thread")]
async fn garbage_relay_frames_do_not_drop_the_session() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    hub.link("a", "b");
    verified(&a, 1).await;
    for sealed in [vec![0u8; 511], vec![0u8; 512], vec![]] {
        let frame = frames::encode(Body::Relay(RelayEnvelope {
            ttl: 99,
            copies: 0,
            sealed,
        }));
        hub.inject("b", "a", frame);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(hub.is_linked("a", "b"));
    assert_eq!(a.node.verified_peers().len(), 1);
    assert!(a.node.relay_stats().dropped_invalid >= 2);
    drop(b);
}

/// Switching relay off stops relaying; switching it on resumes.
#[tokio::test(flavor = "multi_thread")]
async fn disable_relay_stops_and_enable_resumes() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    hub.link("a", "b");
    verified(&a, 1).await;
    b.node.disable_relay();
    let first = a.node.originate_random_for_test(100, 5);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        !b.node.relay_spool_has_for_test(&first),
        "disabled: ignores relay frames"
    );

    b.node
        .enable_relay_with(
            std::sync::Arc::new(xmtp_mesh::ClientRelayExporter(b.client.clone())),
            fast_relay_config(),
        )
        .unwrap();
    hub.unlink("a", "b");
    hub.link("a", "b"); // new sessions advertise relay again
    eventually("b gets it after re-enable", || async {
        b.node.relay_spool_has_for_test(&first)
    })
    .await;
}

/// §R4.5: after pairing, both hold the same confirmed relay key; a
/// stranger gets no offer.
#[tokio::test(flavor = "multi_thread")]
async fn pairing_pins_one_relay_key_on_both_sides() {
    let hub = LoopbackHub::new();
    let (a, a_rec) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    let (s, _) = relay_peer(&hub, "s").await;
    hub.link("a", "s");
    let (a_dm, _b_dm) = pair_dm(&hub, &a, &b).await;
    eventually("both confirmed", || async {
        matches!(
            (a.node.relay_key_for_test(&a_dm.group_id), b.node.relay_key_for_test(&a_dm.group_id)),
            (Some((ka, true)), Some((kb, true))) if ka == kb
        )
    })
    .await;
    assert!(
        a_rec
            .sent_to("s")
            .iter()
            .all(|b| !matches!(b, Body::RelayKeyOffer(_)))
    );
    assert!(s.node.relay_key_for_test(&a_dm.group_id).is_none());
}

/// Relay disabled and enabled again with the
/// link still up (its Hellos both offered relay) relays both ways, without
/// re-linking.
#[tokio::test(flavor = "multi_thread")]
async fn re_enable_without_relinking_relays_both_ways() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    hub.link("a", "b");
    verified(&a, 1).await;
    verified(&b, 1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    b.node.disable_relay();
    b.node
        .enable_relay_with(
            std::sync::Arc::new(xmtp_mesh::ClientRelayExporter(b.client.clone())),
            fast_relay_config(),
        )
        .unwrap();
    let from_a = a.node.originate_random_for_test(100, 5);
    eventually("b holds a's envelope", || async {
        b.node.relay_spool_has_for_test(&from_a)
    })
    .await;
    let from_b = b.node.originate_random_for_test(100, 5);
    eventually("a holds b's envelope", || async {
        a.node.relay_spool_has_for_test(&from_b)
    })
    .await;
}
