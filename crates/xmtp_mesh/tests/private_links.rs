#![recursion_limit = "256"]
//! Private discovery and Noise links (DESIGN.md §B14), end to end over
//! `LoopbackHub`.
mod common;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use common::peer_on;
use common::{
    ClientGroupMembership, ClientHelloSigner, TestPeer, build_client, eventually, pair_dm, peer,
    relay_peer, send_and_see,
};
use xmtp_cryptography::utils::generate_local_wallet;
use xmtp_db::group::GroupQueryArgs;
use xmtp_mesh::frames::{self, Hello, Interest, KeyPackage, SpoolWant, frame::Body};
use xmtp_mesh::link::{WINDOW_SECS, service_data};
use xmtp_mesh::{AdvertMatch, DialIntent, LoopbackHub, MAX_FRAME_LEN, MeshError, MeshNode};
use xmtp_mesh::{LinkRole, MeshTransport, PeerId};

fn inbox(p: &TestPeer) -> String {
    p.client.inbox_id().to_string()
}

async fn verified_pair(a: &TestPeer, b: &TestPeer) {
    eventually("both verified", || async {
        a.node
            .verified_peers()
            .iter()
            .any(|p| p.installation == b.installation())
            && b.node
                .verified_peers()
                .iter()
                .any(|p| p.installation == a.installation())
    })
    .await;
}

/// The hub dials like the radio (§B14.2): the lower token dials; as a
/// contact once the pair has exchanged cards, which `link` does unless the
/// pair are strangers.
#[tokio::test(flavor = "multi_thread")]
async fn the_lower_token_dials_and_linked_pairs_are_contacts_by_default() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    // One clock reading for the tokens and both plans (no window-edge flake).
    let now = a.node.unix_now();
    let (ta, tb) = (
        a.node.own_advert_token(now).unwrap(),
        b.node.own_advert_token(now).unwrap(),
    );
    let (dialer, other_inbox) = if ta <= tb {
        ("a", inbox(&b))
    } else {
        ("b", inbox(&a))
    };
    assert_eq!(
        hub.planned_link_at_for_test("a", "b", now),
        Some((dialer.to_string(), DialIntent::Relay)),
        "strangers before any card"
    );
    hub.link("a", "b");
    assert_eq!(
        a.node.contact(&inbox(&b)).unwrap().map(|c| c.inbox_id),
        Some(inbox(&b))
    );
    assert_eq!(
        b.node.contact(&inbox(&a)).unwrap().map(|c| c.inbox_id),
        Some(inbox(&a))
    );
    assert_eq!(
        hub.planned_link_at_for_test("a", "b", now),
        Some((
            dialer.to_string(),
            DialIntent::Contact {
                inbox_id: other_inbox
            }
        ))
    );
    verified_pair(&a, &b).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn strangers_never_learn_each_others_cards() {
    let hub = LoopbackHub::new();
    let c = peer(&hub, "c").await;
    let d = peer(&hub, "d").await;
    hub.set_strangers("c", "d");
    hub.link("c", "d");
    assert!(c.node.contacts().unwrap().is_empty());
    assert!(d.node.contacts().unwrap().is_empty());
    assert!(matches!(
        hub.planned_link_for_test("c", "d"),
        Some((_, DialIntent::Relay))
    ));
}

/// Cards are exchanged once per pair: a removal survives later links and
/// simulated re-links (§B14.4).
#[tokio::test(flavor = "multi_thread")]
async fn a_removed_contact_stays_removed_across_re_links() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    assert!(
        a.node
            .contact(&inbox(&b))
            .unwrap()
            .is_some_and(|c| !c.removed)
    );
    assert!(a.node.remove_contact(&inbox(&b)).unwrap());
    hub.unlink("a", "b");
    hub.link("a", "b");
    assert!(
        a.node
            .contact(&inbox(&b))
            .unwrap()
            .is_some_and(|c| c.removed),
        "still removed"
    );
    assert!(a.node.contacts().unwrap().is_empty());
    // a no longer recognises b: if a dials, it dials as a stranger.
    if let Some((dialer, intent)) = hub.planned_link_for_test("a", "b") {
        if dialer == "a" {
            assert_eq!(intent, DialIntent::Relay);
        }
    }
}

/// Spec §10 "IK contact link": both sides authenticate inside Noise, a DM
/// round-trips, and nothing on the air names either phone (§B14 goal).
#[tokio::test(flavor = "multi_thread")]
async fn contacts_link_over_ik_and_nothing_on_the_air_names_them() {
    let hub = LoopbackHub::new();
    hub.record_wire_for_test();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let (a_dm, b_dm) = pair_dm(&hub, &a, &b).await;
    send_and_see(&b_dm, &a_dm, "back").await;
    assert_eq!(a.node.mesh_stats().links_contact, 1);
    assert_eq!(b.node.mesh_stats().links_contact, 1);
    let wire = hub.wire_for_test();
    assert!(
        wire.iter().any(|(_, _, m)| m.len() == 128),
        "a 128-byte first message"
    );
    for secret in [
        inbox(&a).into_bytes(),
        inbox(&b).into_bytes(),
        a.installation(),
        b.installation(),
    ] {
        assert!(
            !wire
                .iter()
                .any(|(_, _, m)| m.windows(secret.len()).any(|w| w == secret.as_slice())),
            "an identity crossed the air in the clear"
        );
    }
}

/// Spec §10 "NN relay link": relay frames flow between strangers; a
/// Hello, Interest or KeyPackage on the link closes it.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_link_carries_relay_frames_only() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    hub.set_strangers("a", "b");
    hub.link("a", "b");
    eventually("a relay link", || async {
        a.node.mesh_stats().links_relay == 1 && b.node.mesh_stats().links_relay == 1
    })
    .await;
    let hash = a.node.originate_random_for_test(100, 5);
    eventually("b holds a's envelope", || async {
        b.node.relay_spool_has_for_test(&hash)
    })
    .await;
    assert!(a.node.authenticated_peers().is_empty() && b.node.authenticated_peers().is_empty());
    let forbidden = [
        Body::Hello(Hello {
            installation_key: vec![1; 32],
            challenge: vec![2; 32],
            ..Default::default()
        }),
        Body::Interest(Interest {
            group_id: b"g".to_vec(),
            ..Default::default()
        }),
        Body::KeyPackage(KeyPackage {
            installation_key: a.installation(),
            key_package: vec![3; 10],
        }),
    ];
    for (n, body) in forbidden.into_iter().enumerate() {
        let n = n as u64;
        hub.inject("a", "b", frames::encode(body));
        eventually("b closes the relay link", || async {
            !hub.is_linked("a", "b")
        })
        .await;
        assert_eq!(b.node.mesh_stats().link_frame_rejected, n + 1);
        hub.link("a", "b");
        eventually("relinked", || async {
            b.node.mesh_stats().links_relay == n + 2
        })
        .await;
    }
}

/// Spec §10 "wrong static": a dialer that takes a stranger for a contact
/// fails its handshake; the stranger reads a relay link and learns
/// nothing that names the dialer.
#[tokio::test(flavor = "multi_thread")]
async fn a_dialer_that_mistakes_a_stranger_for_a_contact_leaks_nothing() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let (c, _) = relay_peer(&hub, "c").await;
    hub.make_contacts("a", "b");
    hub.record_wire_for_test();
    hub.link_as(
        "a",
        "c",
        DialIntent::Contact {
            inbox_id: inbox(&b),
        },
    );
    eventually("a gives up", || async { !hub.is_linked("a", "c") }).await;
    assert_eq!(a.node.mesh_stats().handshake_failed, 1);
    eventually("c read a relay link", || async {
        c.node.mesh_stats().links_relay == 1
    })
    .await;
    assert!(c.node.authenticated_peers().is_empty());
    let a_card = a.node.own_contact_card_for_test().unwrap();
    let to_c: Vec<Vec<u8>> = hub
        .wire_for_test()
        .into_iter()
        .filter(|(f, t, _)| f == "a" && t == "c")
        .map(|(_, _, m)| m)
        .collect();
    for secret in [
        a_card.noise_static_pub,
        a.installation(),
        inbox(&a).into_bytes(),
    ] {
        assert!(
            !to_c
                .iter()
                .any(|m| m.windows(secret.len()).any(|w| w == secret.as_slice()))
        );
    }
}

fn interest(g: &[u8]) -> Body {
    Body::Interest(Interest {
        group_id: g.to_vec(),
        high_id: 0,
        i_am_sequencer: false,
    })
}

/// Spec §10 "tampered ciphertext / reordered records".
#[tokio::test(flavor = "multi_thread")]
async fn tampered_or_reordered_records_close_the_link() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    verified_pair(&a, &b).await;
    hub.hold_for_test("a", "b");
    assert!(a.node.send_frame_for_test("b", interest(b"x1")));
    assert!(a.node.send_frame_for_test("b", interest(b"x2")));
    eventually("two held", || async {
        hub.held_count_for_test("a", "b") >= 2
    })
    .await;
    let mut held = hub.take_held_for_test("a", "b");
    held.swap(0, 1);
    for m in held {
        hub.inject_wire_for_test("a", "b", m);
    }
    eventually("b closes the reordered link", || async {
        !hub.is_linked("a", "b")
    })
    .await;
    assert_eq!(b.node.mesh_stats().link_frame_rejected, 1);

    hub.link("a", "b");
    verified_pair(&a, &b).await;
    hub.hold_for_test("a", "b");
    assert!(a.node.send_frame_for_test("b", interest(b"x3")));
    eventually("one held", || async {
        hub.held_count_for_test("a", "b") >= 1
    })
    .await;
    let mut held = hub.take_held_for_test("a", "b");
    held[0][5] ^= 1;
    for m in held {
        hub.inject_wire_for_test("a", "b", m);
    }
    eventually("b closes the tampered link", || async {
        !hub.is_linked("a", "b")
    })
    .await;
    assert_eq!(b.node.mesh_stats().link_frame_rejected, 2);
}

/// Spec §10 "1 MiB frame", end to end: a frame near the limit crosses as
/// full 65 535-byte records and the link stays in step.
#[tokio::test(flavor = "multi_thread")]
async fn a_frame_near_the_limit_crosses_as_records() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    verified_pair(&a, &b).await;
    hub.record_wire_for_test();
    let body = Body::SpoolWant(SpoolWant {
        ids: vec![vec![7u8; 8]; 100_000],
    });
    let frame_len = frames::encode(body.clone()).len();
    assert!(frame_len > 1_000_000 && frame_len <= MAX_FRAME_LEN);
    assert!(a.node.send_frame_for_test("b", body));
    assert!(a.node.send_frame_for_test("b", interest(b"after")));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(hub.is_linked("a", "b"));
    assert_eq!(b.node.mesh_stats().link_frame_rejected, 0);
    // 65 535 = a full record; 65 518 frame bytes fit in one.
    let full = hub
        .wire_for_test()
        .iter()
        .filter(|(f, t, m)| f == "a" && t == "b" && m.len() == 65_535)
        .count();
    assert_eq!(full, frame_len / 65_518);
}

/// Review focus: message 1 lost on the air (the link was replaced while
/// handshaking). The dialer times out once, counted; the next link works;
/// that stale message 1 arriving on an open link closes it cleanly.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_first_message_times_out_and_the_next_link_works() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.make_contacts("a", "b");
    a.node
        .set_handshake_timeout_for_test(Duration::from_millis(300));
    hub.hold_for_test("a", "b");
    hub.link_as(
        "a",
        "b",
        DialIntent::Contact {
            inbox_id: inbox(&b),
        },
    );
    eventually("message 1 held", || async {
        hub.held_count_for_test("a", "b") == 1
    })
    .await;
    let msg1 = hub.take_held_for_test("a", "b").remove(0);
    assert_eq!(msg1.len(), 128);
    eventually("a drops the silent link", || async {
        !hub.is_linked("a", "b")
    })
    .await;
    assert_eq!(a.node.mesh_stats().handshake_failed, 1);

    a.node
        .set_handshake_timeout_for_test(Duration::from_secs(15));
    hub.link("a", "b");
    verified_pair(&a, &b).await;
    hub.inject_wire_for_test("a", "b", msg1);
    eventually("b closes on the stale message", || async {
        !hub.is_linked("a", "b")
    })
    .await;
    assert_eq!(b.node.mesh_stats().link_frame_rejected, 1);
}

/// Review focus: the dialer's message 1 reaches the other phone before its
/// radio reported the connection; the implicit accepting session is kept.
#[tokio::test(flavor = "multi_thread")]
async fn a_first_message_before_accept_is_kept() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.make_contacts("a", "b");
    hub.link_as_dialer_first(
        "a",
        "b",
        DialIntent::Contact {
            inbox_id: inbox(&b),
        },
    )
    .await;
    verified_pair(&a, &b).await;
    assert_eq!(b.node.mesh_stats().handshake_failed, 0);
}

/// Review focus: the window changes while a link is mid-handshake; it
/// completes, and the token seen before the boundary still names the
/// contact after it.
#[tokio::test(flavor = "multi_thread")]
async fn a_link_opened_across_a_window_boundary_completes() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.make_contacts("a", "b");
    let now = a.node.unix_now();
    let to_next = (WINDOW_SECS - now % WINDOW_SECS) as i64;
    for p in [&a, &b] {
        p.node.set_clock_offset_for_test(to_next - 2);
    }
    let seen = b.node.own_advert_token(b.node.unix_now()).unwrap();
    hub.hold_for_test("b", "a");
    hub.link_as(
        "a",
        "b",
        DialIntent::Contact {
            inbox_id: inbox(&b),
        },
    );
    eventually("b answered", || async {
        hub.held_count_for_test("b", "a") >= 1
    })
    .await;
    for p in [&a, &b] {
        p.node.set_clock_offset_for_test(to_next + 1);
    }
    assert_ne!(
        b.node.own_advert_token(b.node.unix_now()).unwrap(),
        seen,
        "a new window"
    );
    assert!(matches!(
        a.node
            .classify_advert(&service_data(0, &seen), a.node.unix_now())
            .unwrap(),
        AdvertMatch::Contact { .. }
    ));
    for m in hub.take_held_for_test("b", "a") {
        hub.inject_wire_for_test("b", "a", m);
    }
    verified_pair(&a, &b).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn start_sync_needs_the_account_key() {
    let node = MeshNode::in_memory().unwrap();
    let client = build_client(&node).await;
    let err = node
        .start_sync(
            Arc::new(ClientHelloSigner(client.clone())),
            LoopbackHub::new().transport_for("x"),
            Arc::new(ClientGroupMembership(client)),
        )
        .unwrap_err();
    assert!(matches!(err, MeshError::NoAccountKey), "{err}");
}

/// §B14.3: a relay link that carries no relay frame for the idle
/// bound closes, counted, so a stranger cannot hold a radio slot forever.
#[tokio::test(flavor = "multi_thread")]
async fn a_quiet_relay_link_closes_after_the_idle_bound() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    b.node
        .set_relay_idle_timeout_for_test(Duration::from_millis(400));
    hub.set_strangers("a", "b");
    hub.link("a", "b");
    eventually("a relay link", || async {
        a.node.mesh_stats().links_relay == 1 && b.node.mesh_stats().links_relay == 1
    })
    .await;
    eventually("b closes the quiet link", || async {
        !hub.is_linked("a", "b")
    })
    .await;
    assert_eq!(b.node.mesh_stats().relay_links_idle_closed, 1);
    assert_eq!(a.node.mesh_stats().relay_links_idle_closed, 0);
    assert_eq!(b.node.mesh_stats().link_frame_rejected, 0);
}

/// §B14.3: the dialer speaks first. Until the dialer's first record
/// authenticates, the accepting side sends its handshake reply and nothing
/// else: no Hello, nothing that names it.
#[tokio::test(flavor = "multi_thread")]
async fn an_accepting_side_says_nothing_before_the_dialers_first_record() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.make_contacts("a", "b");
    hub.record_wire_for_test();
    hub.hold_for_test("a", "b");
    hub.link_as(
        "a",
        "b",
        DialIntent::Contact {
            inbox_id: inbox(&b),
        },
    );
    eventually("message 1 held", || async {
        hub.held_count_for_test("a", "b") == 1
    })
    .await;
    let msg1 = hub.take_held_for_test("a", "b").remove(0);
    hub.hold_for_test("a", "b");
    hub.inject_wire_for_test("a", "b", msg1);
    eventually("a's first record held", || async {
        hub.held_count_for_test("a", "b") >= 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let from_b: Vec<Vec<u8>> = hub
        .wire_for_test()
        .into_iter()
        .filter(|(f, _, _)| f == "b")
        .map(|(_, _, m)| m)
        .collect();
    assert_eq!(from_b.len(), 1, "only the handshake reply");
    assert_eq!(b.node.mesh_stats().links_contact, 1);
    for m in hub.take_held_for_test("a", "b") {
        hub.inject_wire_for_test("a", "b", m);
    }
    verified_pair(&a, &b).await;
}

/// §B14.2: a removed contact that still holds our static key and dials
/// IK is answered as a stranger: its handshake fails and nobody
/// authenticates.
#[tokio::test(flavor = "multi_thread")]
async fn a_removed_contact_dialing_ik_gets_the_stranger_answer() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    hub.make_contacts("a", "b");
    assert!(b.node.remove_contact(&inbox(&a)).unwrap());
    hub.link_as(
        "a",
        "b",
        DialIntent::Contact {
            inbox_id: inbox(&b),
        },
    );
    eventually("a gives up", || async { !hub.is_linked("a", "b") }).await;
    assert_eq!(a.node.mesh_stats().handshake_failed, 1);
    eventually("b answered as to a stranger", || async {
        let stats = b.node.mesh_stats();
        (stats.links_contact, stats.links_relay) == (0, 1)
    })
    .await;
    assert!(a.node.authenticated_peers().is_empty() && b.node.authenticated_peers().is_empty());
}

/// A relay link gives a stranger no leeway: bytes that authenticate but do
/// not decode as a frame close it too.
#[tokio::test(flavor = "multi_thread")]
async fn an_undecodable_frame_closes_a_relay_link() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    hub.set_strangers("a", "b");
    hub.link("a", "b");
    eventually("a relay link", || async {
        a.node.mesh_stats().links_relay == 1 && b.node.mesh_stats().links_relay == 1
    })
    .await;
    hub.inject("a", "b", vec![0xff; 5]);
    eventually("b closes the relay link", || async {
        !hub.is_linked("a", "b")
    })
    .await;
    assert_eq!(b.node.mesh_stats().link_frame_rejected, 1);
}

/// Two strangers on a relay link, with `b`'s bounds shortened.
async fn relay_strangers(
    hub: &LoopbackHub,
    idle: Duration,
    lifetime: Duration,
) -> (TestPeer, TestPeer) {
    let (a, _) = relay_peer(hub, "a").await;
    let (b, _) = relay_peer(hub, "b").await;
    b.node.set_relay_idle_timeout_for_test(idle);
    b.node.set_relay_link_lifetime_for_test(lifetime);
    hub.set_strangers("a", "b");
    hub.link("a", "b");
    eventually("a relay link", || async {
        a.node.mesh_stats().links_relay == 1 && b.node.mesh_stats().links_relay == 1
    })
    .await;
    (a, b)
}

fn digest(ids: usize) -> Vec<u8> {
    frames::encode(Body::SpoolDigest(frames::SpoolDigest {
        ids: vec![vec![9u8; 8]; ids],
    }))
}

/// §B14.3: empty digests trickled in just under the idle bound do not keep
/// a stranger link open; only useful relay traffic does.
#[tokio::test(flavor = "multi_thread")]
async fn empty_digests_do_not_keep_a_relay_link_open() {
    let hub = LoopbackHub::new();
    let (_a, b) = relay_strangers(&hub, Duration::from_millis(600), Duration::from_secs(60)).await;
    for _ in 0..6 {
        if !hub.is_linked("a", "b") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        hub.inject("a", "b", digest(0));
    }
    eventually("b closes the link", || async { !hub.is_linked("a", "b") }).await;
    let stats = b.node.mesh_stats();
    assert_eq!(
        (
            stats.relay_links_idle_closed,
            stats.relay_links_force_closed
        ),
        (1, 0)
    );
}

/// §B14.3: a busy stranger link still closes at the lifetime cap.
#[tokio::test(flavor = "multi_thread")]
async fn a_busy_relay_link_closes_at_its_lifetime_cap() {
    let hub = LoopbackHub::new();
    let (_a, b) = relay_strangers(
        &hub,
        Duration::from_millis(500),
        Duration::from_millis(1500),
    )
    .await;
    let start = std::time::Instant::now();
    while hub.is_linked("a", "b") && start.elapsed() < Duration::from_secs(10) {
        hub.inject("a", "b", digest(1));
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert!(!hub.is_linked("a", "b"));
    assert!(start.elapsed() >= Duration::from_millis(1000), "not idle");
    let stats = b.node.mesh_stats();
    assert_eq!(
        (
            stats.relay_links_idle_closed,
            stats.relay_links_force_closed
        ),
        (0, 1)
    );
}

/// §B14.3: switching relay off closes the stranger links it carried.
#[tokio::test(flavor = "multi_thread")]
async fn disable_relay_closes_open_relay_links() {
    let hub = LoopbackHub::new();
    let (_a, b) = relay_strangers(&hub, Duration::from_secs(60), Duration::from_secs(600)).await;
    b.node.disable_relay();
    eventually("b closes the link", || async { !hub.is_linked("a", "b") }).await;
    assert_eq!(b.node.mesh_stats().relay_links_force_closed, 1);
}

/// A contact link must reach the inbox its static key belongs to: `a`
/// holds a card naming inbox `c` with `b`'s static key, dials "c", reaches
/// `b`, and closes on `b`'s Hello.
#[tokio::test(flavor = "multi_thread")]
async fn a_contact_link_whose_hello_names_another_inbox_is_closed() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let c = peer(&hub, "c").await;
    let mut card = b.node.own_contact_card_for_test().unwrap();
    card.inbox_id = inbox(&c);
    a.node.add_contact_for_test(card);
    hub.link_as(
        "a",
        "b",
        DialIntent::Contact {
            inbox_id: inbox(&c),
        },
    );
    eventually("a closes the link", || async { !hub.is_linked("a", "b") }).await;
    assert_eq!(a.node.mesh_stats().link_frame_rejected, 1);
    assert!(a.node.verified_peers().is_empty());
}

/// §B14.4 IK to a restored phone that lost its contacts: the restored
/// phone (same wallet, empty node, no contacts, no groups) accepts, verifies
/// the dialer by Auth and identity log, and stores it from its card.
#[tokio::test(flavor = "multi_thread")]
async fn a_restored_phone_accepts_a_contact_and_stores_it() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer(&hub, "a").await;
    let b = peer_on(&hub, "b", MeshNode::in_memory().unwrap(), &wallet).await;
    hub.link("a", "b");
    verified_pair(&a, &b).await;
    hub.unlink("a", "b");
    b.node.stop_sync();
    // Whole-second gap: `b` stays the older origin of the inbox (D24).
    tokio::time::sleep(Duration::from_secs(1)).await;
    let b2 = peer_on(&hub, "b2", MeshNode::in_memory().unwrap(), &wallet).await;
    assert!(b2.node.contacts().unwrap().is_empty());
    assert_eq!(
        b2.node
            .own_contact_card_for_test()
            .unwrap()
            .noise_static_pub,
        b.node.own_contact_card_for_test().unwrap().noise_static_pub,
        "the recovery phrase restores the static key"
    );
    hub.link_as(
        "a",
        "b2",
        DialIntent::Contact {
            inbox_id: inbox(&b),
        },
    );
    eventually("b2 verifies a and stores it as a contact", || async {
        b2.node
            .verified_peers()
            .iter()
            .any(|p| p.installation == a.installation())
            && b2.node.contact(&inbox(&a)).unwrap().is_some()
    })
    .await;
    assert_eq!(b2.node.mesh_stats().links_contact, 1);
    assert!(
        b2.client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        b2.node
            .contact(&inbox(&a))
            .unwrap()
            .unwrap()
            .noise_static_pub
            .to_vec(),
        a.node.own_contact_card_for_test().unwrap().noise_static_pub
    );
}

/// §B14.4 discovery reset: the old token is gone; the contact does not
/// recognise the new one until the resetting phone, which still recognises
/// it, dials it and hands over the new card.
#[tokio::test(flavor = "multi_thread")]
async fn a_reset_reaches_contacts_on_the_next_contact_link() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    verified_pair(&a, &b).await;
    hub.unlink("a", "b");
    let now = a.node.unix_now();
    let old = b.node.own_advert_token(now).unwrap();
    assert_eq!(b.node.reset_discovery_key().unwrap(), 1);
    let new = b.node.own_advert_token(now).unwrap();
    assert_ne!(new, old, "the old token is no longer advertised");
    assert!(matches!(
        a.node.classify_advert(&service_data(0, &new), now).unwrap(),
        AdvertMatch::Stranger { .. }
    ));
    let a_token = a.node.own_advert_token(now).unwrap();
    assert!(matches!(
        b.node
            .classify_advert(&service_data(0, &a_token), now)
            .unwrap(),
        AdvertMatch::Contact { .. }
    ));
    hub.link_as(
        "b",
        "a",
        DialIntent::Contact {
            inbox_id: inbox(&a),
        },
    );
    eventually("a holds b's new card", || async {
        a.node
            .contact(&inbox(&b))
            .unwrap()
            .is_some_and(|c| c.generation == 1)
    })
    .await;
    assert!(matches!(
        a.node.classify_advert(&service_data(0, &new), now).unwrap(),
        AdvertMatch::Contact { .. }
    ));
    assert_eq!(b.node.mesh_stats().discovery_resets, 1);
}

/// A phone that re-derived generation 0 (restored after a reset) sends an
/// older card; the contact keeps the newer one and the link stays up.
#[tokio::test(flavor = "multi_thread")]
async fn an_older_card_never_replaces_a_newer_one() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    verified_pair(&a, &b).await;
    hub.unlink("a", "b");
    b.node.reset_discovery_key().unwrap();
    hub.link_as(
        "b",
        "a",
        DialIntent::Contact {
            inbox_id: inbox(&a),
        },
    );
    eventually("a holds generation 1", || async {
        a.node
            .contact(&inbox(&b))
            .unwrap()
            .is_some_and(|c| c.generation == 1)
    })
    .await;
    hub.unlink("a", "b");
    b.node.set_discovery_generation_for_test(0).unwrap();
    hub.link_as(
        "b",
        "a",
        DialIntent::Contact {
            inbox_id: inbox(&a),
        },
    );
    verified_pair(&a, &b).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(a.node.contact(&inbox(&b)).unwrap().unwrap().generation, 1);
    assert!(hub.is_linked("a", "b"), "a stale card is not an error");
}

/// An ex-contact still holds our static key (a reset does not change it).
/// After `remove_contact` and a reset, its IK link is refused and it learns
/// no new card.
#[tokio::test(flavor = "multi_thread")]
async fn a_removed_contact_cannot_dial_back_in() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    verified_pair(&a, &b).await;
    hub.unlink("a", "b");
    assert!(b.node.remove_contact(&inbox(&a)).unwrap());
    b.node.reset_discovery_key().unwrap();
    hub.link_as(
        "a",
        "b",
        DialIntent::Contact {
            inbox_id: inbox(&b),
        },
    );
    eventually("b refuses the link", || async { !hub.is_linked("a", "b") }).await;
    assert_eq!(b.node.mesh_stats().handshake_failed, 1);
    assert!(b.node.contact(&inbox(&a)).unwrap().unwrap().removed);
    assert_eq!(a.node.contact(&inbox(&b)).unwrap().unwrap().generation, 0);
}

/// Two parallel connections between two nodes: `a` knows them as
/// "b#1"/"b#2", `b` as "a#1"/"a#2". Disconnects are only recorded.
struct Cross {
    from_prefix: &'static str,
    to: MeshNode,
    closed: Mutex<Vec<String>>,
}

impl MeshTransport for Cross {
    fn send(&self, peer: &PeerId, frame: Vec<u8>) {
        let from = format!("{}{}", self.from_prefix, &peer[2..]);
        self.to.on_frame(&from, frame);
    }
    fn disconnect(&self, peer: &PeerId) {
        self.closed.lock().unwrap().push(peer.clone());
    }
}

/// Both contacts dial at once; each phone ends up with two verified links
/// to the other. Both keep the link dialed by the lower static key and
/// close the other one.
#[tokio::test(flavor = "multi_thread")]
async fn simultaneous_contact_dials_keep_the_same_link_on_both_phones() {
    let (na, nb) = (
        MeshNode::in_memory().unwrap(),
        MeshNode::in_memory().unwrap(),
    );
    let (ca, cb) = (build_client(&na).await, build_client(&nb).await);
    let ta = Arc::new(Cross {
        from_prefix: "a#",
        to: nb.clone(),
        closed: Mutex::new(Vec::new()),
    });
    let tb = Arc::new(Cross {
        from_prefix: "b#",
        to: na.clone(),
        closed: Mutex::new(Vec::new()),
    });
    common::start_sync(&na, &ca, ta.clone());
    common::start_sync(&nb, &cb, tb.clone());
    let (card_a, card_b) = (
        na.own_contact_card_for_test().unwrap(),
        nb.own_contact_card_for_test().unwrap(),
    );
    na.add_contact_for_test(card_b.clone());
    nb.add_contact_for_test(card_a.clone());
    // Link 1: a dials. Link 2: b dials. Each accepting side is reported first.
    nb.on_peer_connected("a#1", LinkRole::Accept);
    na.on_peer_connected(
        "b#1",
        LinkRole::Dial(DialIntent::Contact {
            inbox_id: cb.inbox_id().to_string(),
        }),
    );
    na.on_peer_connected("b#2", LinkRole::Accept);
    nb.on_peer_connected(
        "a#2",
        LinkRole::Dial(DialIntent::Contact {
            inbox_id: ca.inbox_id().to_string(),
        }),
    );
    let lose = if card_a.noise_static_pub < card_b.noise_static_pub {
        2
    } else {
        1
    };
    eventually("each phone closes one link", || async {
        !ta.closed.lock().unwrap().is_empty() && !tb.closed.lock().unwrap().is_empty()
    })
    .await;
    assert!(
        ta.closed
            .lock()
            .unwrap()
            .iter()
            .all(|p| *p == format!("b#{lose}"))
    );
    assert!(
        tb.closed
            .lock()
            .unwrap()
            .iter()
            .all(|p| *p == format!("a#{lose}"))
    );
}
