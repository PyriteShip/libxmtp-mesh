#![recursion_limit = "256"]
//! Private discovery and Noise links (DESIGN.md §B14), end to end over
//! `LoopbackHub`.
mod common;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use common::{
    ClientGroupMembership, ClientHelloSigner, TestPeer, build_client, eventually,
    fast_relay_config, pair_dm, peer, recorded_peer, relay_peer, relay_peer_with, send_and_see,
};
use common::{app_payloads, eventually_for, peer_on, relay_keys_confirmed};
use xmtp_cryptography::utils::generate_local_wallet;
use xmtp_db::group::GroupQueryArgs;
use xmtp_mesh::frames::{self, Auth, Hello, Interest, KeyPackage, SpoolWant, frame::Body};
use xmtp_mesh::link::{WINDOW_SECS, service_data};
use xmtp_mesh::{
    AdvertMatch, DialIntent, LinkKind, LoopbackHub, MAX_FRAME_LEN, MeshError, MeshNode, RelayConfig,
};
use xmtp_mesh::{HelloSigner, LinkRole, MeshTransport, PeerId};

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
    if let Some((dialer, intent)) = hub.planned_link_for_test("a", "b")
        && dialer == "a"
    {
        assert_eq!(intent, DialIntent::Relay);
    }
}

/// §B14.3 contact link (IK): both sides authenticate inside Noise, a DM
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

/// Padded records (§B14.3): after the two handshake messages, every
/// message on the air is a record of a bucket size. The dialer's first
/// record looks the same on a contact link (a Hello) and on a relay link
/// (a digest), and two phones' identity logs land in the same bucket.
#[tokio::test(flavor = "multi_thread")]
async fn records_are_padded_so_link_kinds_and_identity_logs_look_alike() {
    const RECORDS: [usize; 5] = [272, 1040, 4112, 16_400, 65_534];
    let hub = LoopbackHub::new();
    hub.record_wire_for_test();
    let (a, rec_a) = recorded_peer(&hub, "a").await;
    let (b, rec_b) = recorded_peer(&hub, "b").await;
    hub.link("a", "b");
    verified_pair(&a, &b).await;
    let (c, _) = relay_peer(&hub, "c").await;
    let (d, _) = relay_peer(&hub, "d").await;
    hub.set_strangers("c", "d");
    hub.link("c", "d");
    eventually("a relay link", || async {
        c.node.mesh_stats().links_relay == 1 && d.node.mesh_stats().links_relay == 1
    })
    .await;
    let wire = hub.wire_for_test();
    let on = |from: &str, to: &str| -> Vec<usize> {
        wire.iter()
            .filter(|(f, t, _)| f == from && t == to)
            .map(|(_, _, m)| m.len())
            .collect()
    };
    let mut first_records = Vec::new();
    for (x, y) in [("a", "b"), ("c", "d")] {
        for (from, to) in [(x, y), (y, x)] {
            let sizes = on(from, to);
            assert!(!sizes.is_empty(), "{from} -> {to} said nothing");
            assert!(
                sizes[0] == 128 || sizes[0] == 48,
                "a handshake message first"
            );
            assert!(
                sizes[1..].iter().all(|n| RECORDS.contains(n)),
                "{from} -> {to}: {sizes:?}"
            );
            if sizes[0] == 128 {
                first_records.push(sizes[1]);
            }
        }
    }
    assert_eq!(first_records.len(), 2);
    assert_eq!(
        first_records[0], first_records[1],
        "contact and relay links start alike"
    );
    let log_record = |rec: &common::Recording, to: &str| -> usize {
        let log = rec
            .raw_to(to)
            .into_iter()
            .find(|f| matches!(frames::decode(f), Ok(Body::IdentityLog(_))))
            .expect("an identity log");
        RECORDS
            .into_iter()
            .find(|&r| r >= log.len() + 3 + 16)
            .unwrap()
    };
    assert_eq!(log_record(&rec_a, "b"), log_record(&rec_b, "a"));
}

/// The radio learns each open link's kind (§B14.3), so it can keep radio
/// slots for contacts.
#[tokio::test(flavor = "multi_thread")]
async fn the_radio_learns_each_links_kind() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    assert_eq!(a.node.link_kind("b"), None);
    hub.link("a", "b");
    verified_pair(&a, &b).await;
    assert_eq!(a.node.link_kind("b"), Some(LinkKind::Contact));
    assert_eq!(b.node.link_kind("a"), Some(LinkKind::Contact));
    let (c, _) = relay_peer(&hub, "c").await;
    let (d, _) = relay_peer(&hub, "d").await;
    hub.set_strangers("c", "d");
    hub.link("c", "d");
    eventually("a relay link", || async {
        c.node.link_kind("d") == Some(LinkKind::Relay)
            && d.node.link_kind("c") == Some(LinkKind::Relay)
    })
    .await;
    let e = peer(&hub, "e").await;
    let f = peer(&hub, "f").await;
    open_pairing(&hub, &e, &f).await;
    assert_eq!(e.node.link_kind("f"), Some(LinkKind::Pairing));
    assert_eq!(f.node.link_kind("e"), Some(LinkKind::Pairing));
    hub.unlink("a", "b");
    eventually("gone with the link", || async {
        a.node.link_kind("b").is_none()
    })
    .await;
}

/// §B14.4: removing a contact closes its open link at once (no failure
/// counted), and it does not come back as a contact link.
#[tokio::test(flavor = "multi_thread")]
async fn removing_a_contact_closes_its_open_link() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let c = peer(&hub, "c").await;
    hub.link("a", "b");
    hub.link("a", "c");
    verified_pair(&a, &b).await;
    verified_pair(&a, &c).await;
    let before = a.node.mesh_stats();
    assert!(a.node.remove_contact(&inbox(&b)).unwrap());
    eventually("a closes b's link", || async { !hub.is_linked("a", "b") }).await;
    assert!(hub.is_linked("a", "c"), "other contacts stay linked");
    let after = a.node.mesh_stats();
    assert_eq!(
        (after.handshake_failed, after.link_frame_rejected),
        (before.handshake_failed, before.link_frame_rejected),
        "a close, not a failure"
    );
    hub.link_as(
        "b",
        "a",
        DialIntent::Contact {
            inbox_id: inbox(&a),
        },
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !a.node
            .verified_peers()
            .iter()
            .any(|p| p.installation == b.installation())
    );
    assert_eq!(a.node.mesh_stats().links_contact, before.links_contact);
}

/// §B14.3 relay link (NN): relay frames flow between strangers; a
/// Hello, Interest or KeyPackage on the link closes it.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_link_carries_relay_frames_only() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    // Relinked at once after each close below.
    b.node.set_relay_backoff_for_test(Duration::ZERO);
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
        // Relay keys travel only on contact links (§R4.5).
        Body::RelayKeyOffer(frames::RelayKeyOffer {
            group_id: b"g".to_vec(),
            ..Default::default()
        }),
        Body::RelayKeyAck(frames::RelayKeyAck {
            group_id: b"g".to_vec(),
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

/// §B14.3 wrong static: a dialer that takes a stranger for a contact
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

/// §B14.3 records: tampered ciphertext or reordered records close the
/// link.
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

/// §B14.3 records, end to end: a frame near the limit crosses as
/// full records of the largest bucket and the link stays in step.
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
    // 65 534 = a record of the largest bucket, which holds 65 515 frame
    // bytes. The last chunk is over 16 KiB, so it pads to that bucket too.
    assert!(frame_len % 65_515 > 16_384);
    let full = hub
        .wire_for_test()
        .iter()
        .filter(|(f, t, m)| f == "a" && t == "b" && m.len() == 65_534)
        .count();
    assert_eq!(full, frame_len.div_ceil(65_515));
}

/// Message 1 lost on the air (the link was replaced while
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

/// The dialer's message 1 reaches the other phone before its
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

/// Window boundary: the window changes while a link is mid-handshake; it
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

/// §B14.3: digests and wants trickled in just under the idle bound do not
/// keep a stranger link open, however well-formed their ids (anyone can
/// make ids up); only relayed envelopes accepted as new do.
#[tokio::test(flavor = "multi_thread")]
async fn digests_and_wants_do_not_keep_a_relay_link_open() {
    let hub = LoopbackHub::new();
    let (_a, b) = relay_strangers(&hub, Duration::from_millis(600), Duration::from_secs(60)).await;
    for n in 0..6u8 {
        if !hub.is_linked("a", "b") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let ids: Vec<Vec<u8>> = (0..4u8).map(|i| vec![n, i, 1, 2, 3, 4, 5, 6]).collect();
        hub.inject(
            "a",
            "b",
            frames::encode(if n % 2 == 0 {
                Body::SpoolDigest(frames::SpoolDigest { ids })
            } else {
                Body::SpoolWant(SpoolWant { ids })
            }),
        );
    }
    assert!(
        !hub.is_linked("a", "b"),
        "closed while the digests and wants kept coming"
    );
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
    let (a, b) = relay_strangers(
        &hub,
        Duration::from_millis(500),
        Duration::from_millis(1500),
    )
    .await;
    let start = std::time::Instant::now();
    while hub.is_linked("a", "b") && start.elapsed() < Duration::from_secs(10) {
        // A new envelope for b every 150 ms: useful traffic.
        a.node.originate_random_for_test(100, 5);
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
    // b knows a, so it answers a's IK dial as a contact link.
    b.node
        .add_contact_for_test(a.node.own_contact_card_for_test().unwrap());
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

/// A contact of `wallet`'s phone `b` (`a`), and the phone restored from
/// the same wallet on an empty node (`b2`, no contacts, no groups), with
/// its frames recorded.
async fn restored_phone(
    hub: &LoopbackHub,
    contacts: &[&str],
) -> (Vec<TestPeer>, TestPeer, TestPeer, Arc<common::Recording>) {
    let wallet = generate_local_wallet();
    let b = peer_on(hub, "b", MeshNode::in_memory().unwrap(), &wallet).await;
    let mut peers = Vec::new();
    for name in contacts {
        let p = peer(hub, name).await;
        hub.link(name, "b");
        verified_pair(&p, &b).await;
        hub.unlink(name, "b");
        peers.push(p);
    }
    b.node.stop_sync();
    // Whole-second gap: `b` stays the older origin of the inbox (D24).
    tokio::time::sleep(Duration::from_secs(1)).await;
    let node = MeshNode::in_memory().unwrap();
    let rec = Arc::new(common::Recording::default());
    node.set_frame_tap_for_test(Some(rec.clone()));
    let b2 = peer_on(hub, "b2", node, &wallet).await;
    assert!(b2.node.contacts().unwrap().is_empty());
    assert_eq!(
        b2.node
            .own_contact_card_for_test()
            .unwrap()
            .noise_static_pub,
        b.node.own_contact_card_for_test().unwrap().noise_static_pub,
        "the recovery phrase restores the static key"
    );
    (peers, b, b2, rec)
}

fn cards_to(rec: &common::Recording, peer: &str) -> usize {
    rec.sent_to(peer)
        .iter()
        .filter(|b| matches!(b, Body::ContactCard(_)))
        .count()
}

/// §B14.7: a restored phone that never opened a restore window answers a
/// contact's IK dial like a stranger's: nothing verified, nothing stored.
#[tokio::test(flavor = "multi_thread")]
async fn a_restored_phone_without_a_restore_window_refuses_unknown_dialers() {
    let hub = LoopbackHub::new();
    let (peers, b, b2, rec) = restored_phone(&hub, &["a"]).await;
    let a = &peers[0];
    hub.link_as(
        "a",
        "b2",
        DialIntent::Contact {
            inbox_id: inbox(&b),
        },
    );
    eventually("a gives up", || async { !hub.is_linked("a", "b2") }).await;
    assert_eq!(b2.node.mesh_stats().links_contact, 0);
    assert!(b2.node.authenticated_peers().is_empty());
    assert!(b2.node.contacts().unwrap().is_empty());
    assert!(rec.sent_to("a").is_empty(), "b2 said nothing");
    assert!(a.node.verified_peers().is_empty());
}

/// §B14.7 restore window: the restored phone accepts IK from all three of
/// its contacts, verifies each by Auth and identity log, and stores each
/// from its card, flagged as added by restore and counted. It sends none
/// of them its own card until the user confirms that contact; then the
/// card goes on the open link.
#[tokio::test(flavor = "multi_thread")]
async fn a_restored_phone_reconnects_to_every_contact_in_its_restore_window() {
    let hub = LoopbackHub::new();
    let (peers, b, b2, rec) = restored_phone(&hub, &["a", "c", "d"]).await;
    let until = b2.node.begin_restore_window().unwrap();
    assert_eq!(b2.node.restore_window_until(), Some(until));
    for p in &peers {
        hub.link_as(
            &p.name,
            "b2",
            DialIntent::Contact {
                inbox_id: inbox(&b),
            },
        );
    }
    for p in &peers {
        eventually("b2 verifies the contact and stores it", || async {
            b2.node
                .verified_peers()
                .iter()
                .any(|v| v.installation == p.installation())
                && b2.node.contact(&inbox(p)).unwrap().is_some()
        })
        .await;
        let stored = b2.node.contact(&inbox(p)).unwrap().unwrap();
        assert!(stored.auto_added, "flagged for the user");
        assert_eq!(
            stored.noise_static_pub.to_vec(),
            p.node.own_contact_card_for_test().unwrap().noise_static_pub
        );
    }
    assert_eq!(b2.node.mesh_stats().links_contact, 3);
    assert_eq!(b2.node.mesh_stats().restore_contacts_added, 3);
    assert!(
        b2.client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .is_empty()
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    for p in &peers {
        assert_eq!(cards_to(&rec, &p.name), 0, "no card before confirmation");
    }
    let a = &peers[0];
    assert!(b2.node.confirm_restored_contact(&inbox(a)).unwrap());
    assert!(!b2.node.contact(&inbox(a)).unwrap().unwrap().auto_added);
    eventually("the card goes to the confirmed contact", || async {
        cards_to(&rec, "a") == 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(cards_to(&rec, "c"), 0, "still unconfirmed");
    assert_eq!(cards_to(&rec, "d"), 0, "still unconfirmed");
}

/// Once the restore window ended, an unknown static gets the stranger
/// answer again.
#[tokio::test(flavor = "multi_thread")]
async fn after_the_restore_window_an_unknown_dialer_is_a_stranger() {
    let hub = LoopbackHub::new();
    let (peers, b, b2, rec) = restored_phone(&hub, &["a"]).await;
    b2.node.begin_restore_window().unwrap();
    b2.node.end_restore_window().unwrap();
    assert_eq!(b2.node.restore_window_until(), None);
    hub.link_as(
        "a",
        "b2",
        DialIntent::Contact {
            inbox_id: inbox(&b),
        },
    );
    eventually("a gives up", || async { !hub.is_linked("a", "b2") }).await;
    assert!(b2.node.contacts().unwrap().is_empty());
    assert!(rec.sent_to("a").is_empty());
    assert!(peers[0].node.verified_peers().is_empty());
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
    let (win, lose) = if card_a.noise_static_pub < card_b.noise_static_pub {
        (1, 2)
    } else {
        (2, 1)
    };
    eventually("each phone closes one link", || async {
        !ta.closed.lock().unwrap().is_empty() && !tb.closed.lock().unwrap().is_empty()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
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
    // Only the kept link is verified, and closing the other is no failure.
    let peers = |n: &MeshNode| {
        n.verified_peers()
            .into_iter()
            .map(|p| p.peer)
            .collect::<Vec<_>>()
    };
    assert_eq!(peers(&na), vec![format!("b#{win}")]);
    assert_eq!(peers(&nb), vec![format!("a#{win}")]);
    for n in [&na, &nb] {
        let stats = n.mesh_stats();
        assert_eq!((stats.handshake_failed, stats.link_frame_rejected), (0, 0));
    }
}

/// A phone in its restore window accepts an unknown IK dialer, but
/// stores and answers only one that proves its inbox: `m` dials with its
/// own static key and a Hello claiming `a`'s inbox, is dropped at the
/// verification deadline, is not stored, and never gets `b2`'s card.
#[tokio::test(flavor = "multi_thread")]
async fn a_restored_phone_drops_a_dialer_that_cannot_prove_its_inbox() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let (b2, rec) = recorded_peer(&hub, "b2").await;
    let m = peer(&hub, "m").await;
    b2.node
        .set_peer_verify_timeout_for_test(Duration::from_millis(500));
    assert!(b2.node.contacts().unwrap().is_empty());
    b2.node.begin_restore_window().unwrap();
    m.node
        .add_contact_for_test(b2.node.own_contact_card_for_test().unwrap());
    // m's link keys stay its own; only its Hello claims a's inbox.
    m.node.set_local_inbox_for_test(&inbox(&a));
    m.node.suppress_identity_log_for_test();
    hub.link_as(
        "m",
        "b2",
        DialIntent::Contact {
            inbox_id: inbox(&b2),
        },
    );
    eventually("b2 authenticates m", || async {
        b2.node.authenticated_peers().contains(&"m".to_string())
    })
    .await;
    eventually("b2 drops m", || async { !hub.is_linked("m", "b2") }).await;
    assert!(b2.node.verified_peers().is_empty());
    assert!(b2.node.contact(&inbox(&a)).unwrap().is_none());
    assert!(b2.node.contacts().unwrap().is_empty());
    assert!(
        !rec.sent_to("m")
            .iter()
            .any(|b| matches!(b, Body::ContactCard(_))),
        "no card for a dialer that did not prove its inbox"
    );
}

/// The signed hello text, pinned here: v2 binds a handshake hash.
fn hello_text_v2(challenge: &[u8], signer: &[u8], verifier: &[u8], binding: &[u8; 32]) -> String {
    format!(
        "xmtp-mesh-hello-v2:{}:{}:{}:{}",
        hex::encode(challenge),
        hex::encode(signer),
        hex::encode(verifier),
        hex::encode(binding)
    )
}

/// `a` dials `b` over IK; `b`'s real Auth is held back and `a` gets an Auth
/// signed by `b`'s installation key over `text(a's challenge, b's key,
/// a's key)` instead. It must not verify: the link closes, counted.
async fn a_forged_auth_closes_the_link(text: fn(&[u8], &[u8], &[u8]) -> String) {
    let hub = LoopbackHub::new();
    let (a, rec) = recorded_peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.make_contacts("a", "b");
    hub.hold_for_test("b", "a");
    hub.link_as(
        "a",
        "b",
        DialIntent::Contact {
            inbox_id: inbox(&b),
        },
    );
    eventually("b's handshake reply held", || async {
        hub.held_count_for_test("b", "a") == 1
    })
    .await;
    let reply = hub.take_held_for_test("b", "a").remove(0);
    hub.hold_for_test("b", "a");
    hub.inject_wire_for_test("b", "a", reply);
    // b's Hello, then its Auth (held back for good).
    eventually("b's Hello and Auth held", || async {
        hub.held_count_for_test("b", "a") >= 2
    })
    .await;
    let hello = hub.take_held_for_test("b", "a").remove(0);
    hub.hold_for_test("b", "a");
    hub.inject_wire_for_test("b", "a", hello);
    eventually("a answered b's Hello", || async {
        rec.sent_to("b").iter().any(|f| matches!(f, Body::Auth(_)))
    })
    .await;
    let challenge = rec
        .sent_to("b")
        .into_iter()
        .find_map(|f| match f {
            Body::Hello(h) => Some(h.challenge),
            _ => None,
        })
        .unwrap();
    let signature = ClientHelloSigner(b.client.clone())
        .sign(&text(&challenge, &b.installation(), &a.installation()))
        .unwrap();
    hub.inject(
        "b",
        "a",
        frames::encode(Body::Auth(Auth {
            signature,
            challenge,
        })),
    );
    eventually("a closes the link", || async { !hub.is_linked("a", "b") }).await;
    assert_eq!(a.node.mesh_stats().link_frame_rejected, 1);
    assert!(!a.node.authenticated_peers().contains(&"b".to_string()));
}

/// §B14.4: an Auth made for another link (another handshake hash) never
/// verifies on this one.
#[tokio::test(flavor = "multi_thread")]
async fn an_auth_bound_to_another_link_is_refused() {
    a_forged_auth_closes_the_link(|c, s, v| hello_text_v2(c, s, v, &[9; 32])).await;
}

/// The mesh.10 hello text (no binding) never verifies on a Noise link.
#[tokio::test(flavor = "multi_thread")]
async fn an_auth_over_the_unbound_v1_text_is_refused() {
    a_forged_auth_closes_the_link(|c, s, v| {
        format!(
            "xmtp-mesh-hello-v1:{}:{}:{}",
            hex::encode(c),
            hex::encode(s),
            hex::encode(v)
        )
    })
    .await;
}

// ---- Pairing (Noise XX) -------------------------------------------------

/// `p`'s open pairing with `peer`, if any.
fn pending_on(p: &TestPeer, peer: &str) -> Option<xmtp_mesh::PendingPairing> {
    p.node
        .pending_pairings()
        .into_iter()
        .find(|pp| pp.peer == peer)
}

/// Both phones in pairing mode; `a` dials `b` over Noise XX. Returns each
/// side's pending pairing once both show a code.
async fn open_pairing(
    hub: &LoopbackHub,
    a: &TestPeer,
    b: &TestPeer,
) -> (xmtp_mesh::PendingPairing, xmtp_mesh::PendingPairing) {
    a.node.set_pairing_mode(true);
    b.node.set_pairing_mode(true);
    hub.link_as(&a.name, &b.name, DialIntent::Pairing);
    eventually("both phones show a code", || async {
        pending_on(a, &b.name).is_some() && pending_on(b, &a.name).is_some()
    })
    .await;
    (
        pending_on(a, &b.name).unwrap(),
        pending_on(b, &a.name).unwrap(),
    )
}

/// Both people confirm; wait until each phone stored the other's card.
async fn confirm_both(a: &TestPeer, b: &TestPeer) {
    a.node.confirm_pairing(&b.name).unwrap();
    b.node.confirm_pairing(&a.name).unwrap();
    eventually("both pairings done", || async {
        pending_on(a, &b.name).is_none() && pending_on(b, &a.name).is_none()
    })
    .await;
    for (p, q) in [(a, b), (b, a)] {
        assert!(
            p.node
                .contact(&inbox(q))
                .unwrap()
                .is_some_and(|c| !c.removed)
        );
    }
}

/// A frame that names a phone, its keys or its groups.
fn identifying(body: &Body) -> bool {
    !matches!(body, Body::PairConfirm(_))
}

/// §B14.4 pairing (XX): one 6-digit code on both phones. Nothing that
/// identifies either phone crosses until both people confirmed: the
/// accepting phone, confirming first, says nothing at all until the
/// dialer's confirmation (the dialer speaks first). Then both store the
/// other's card and later reconnect as contacts.
#[tokio::test(flavor = "multi_thread")]
async fn pairing_shows_one_code_and_sends_nothing_identifying_until_both_confirm() {
    let hub = LoopbackHub::new();
    let (a, rec_a) = recorded_peer(&hub, "a").await;
    let (b, rec_b) = recorded_peer(&hub, "b").await;
    let (pa, pb) = open_pairing(&hub, &a, &b).await;
    assert_eq!(pa.code, pb.code);
    assert_eq!(pa.code.len(), 6);
    assert!(pa.code.chars().all(|c| c.is_ascii_digit()));
    assert!(!pa.confirmed && !pa.peer_confirmed);
    b.node.confirm_pairing("a").unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        rec_a.sent_to("b").is_empty(),
        "the dialer waits for its own person"
    );
    assert!(
        rec_b.sent_to("a").is_empty(),
        "the accepting side speaks only after the dialer's first record"
    );
    assert!(pending_on(&b, "a").unwrap().confirmed);
    assert!(a.node.contacts().unwrap().is_empty() && b.node.contacts().unwrap().is_empty());
    assert!(a.node.authenticated_peers().is_empty() && b.node.authenticated_peers().is_empty());
    a.node.confirm_pairing("b").unwrap();
    eventually("both cards stored", || async {
        a.node.contact(&inbox(&b)).unwrap().is_some()
            && b.node.contact(&inbox(&a)).unwrap().is_some()
    })
    .await;
    for (rec, to) in [(&rec_a, "b"), (&rec_b, "a")] {
        let sent = rec.sent_to(to);
        assert!(matches!(sent[0], Body::PairConfirm(_)), "{:?}", sent[0]);
        assert!(identifying(&sent[1]));
    }
    eventually("the pairing is done on both phones", || async {
        a.node.pending_pairings().is_empty() && b.node.pending_pairings().is_empty()
    })
    .await;
    eventually("both left pairing mode", || async {
        !a.node.pairing_mode() && !b.node.pairing_mode()
    })
    .await;
    assert_eq!(a.node.mesh_stats().links_pairing, 1);
    // The pairing ran on throwaway keys; each phone stored the other's
    // real static, from its card, and the next link is a contact link.
    for (p, q) in [(&a, &b), (&b, &a)] {
        let real = q.node.own_contact_card_for_test().unwrap().noise_static_pub;
        let stored = p.node.contact(&inbox(q)).unwrap().unwrap().noise_static_pub;
        assert_eq!(stored.as_slice(), real.as_slice());
    }
    hub.unlink("a", "b");
    for p in [&a, &b] {
        p.node.set_pairing_mode(false);
    }
    hub.link_as(
        "a",
        "b",
        DialIntent::Contact {
            inbox_id: inbox(&b),
        },
    );
    verified_pair(&a, &b).await;
    assert_eq!(a.node.mesh_stats().links_contact, 1);
}

/// Only one person confirmed: the dialer sends its confirmation and
/// nothing else, nothing is stored, and the pairing closes at its timeout
/// (counted as an unfinished pairing).
#[tokio::test(flavor = "multi_thread")]
async fn a_pairing_confirmed_on_one_phone_only_leaks_nothing_and_times_out() {
    let hub = LoopbackHub::new();
    let (a, rec_a) = recorded_peer(&hub, "a").await;
    let (b, rec_b) = recorded_peer(&hub, "b").await;
    for p in [&a, &b] {
        p.node
            .set_pairing_timeout_for_test(Duration::from_millis(800));
    }
    open_pairing(&hub, &a, &b).await;
    a.node.confirm_pairing("b").unwrap();
    eventually("b hears a's confirmation", || async {
        pending_on(&b, "a").is_some_and(|p| p.peer_confirmed && !p.confirmed)
    })
    .await;
    eventually("the pairing times out", || async {
        !hub.is_linked("a", "b")
    })
    .await;
    let from_a = rec_a.sent_to("b");
    assert_eq!(from_a.len(), 1);
    assert!(matches!(from_a[0], Body::PairConfirm(_)));
    assert!(rec_b.sent_to("a").is_empty());
    assert!(a.node.contacts().unwrap().is_empty() && b.node.contacts().unwrap().is_empty());
    eventually("nothing pending", || async {
        a.node.pending_pairings().is_empty() && b.node.pending_pairings().is_empty()
    })
    .await;
    assert!(
        a.node.pairing_mode() && b.node.pairing_mode(),
        "one failure is under the cap"
    );
}

/// A Hello (or anything but a confirmation) before both people confirmed
/// closes the pairing link.
#[tokio::test(flavor = "multi_thread")]
async fn a_hello_before_both_confirmed_closes_the_pairing() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    open_pairing(&hub, &a, &b).await;
    assert!(a.node.send_frame_for_test(
        "b",
        Body::Hello(Hello {
            installation_key: a.installation(),
            inbox_id: inbox(&a),
            challenge: vec![2; 32],
            seq: frames::SEQ_V1,
            link: frames::LINK_V1,
            ..Default::default()
        })
    ));
    eventually("b closes the link", || async { !hub.is_linked("a", "b") }).await;
    assert_eq!(b.node.mesh_stats().link_frame_rejected, 1);
    assert!(b.node.authenticated_peers().is_empty());
    assert!(b.node.contacts().unwrap().is_empty());
}

/// §B14.4: a middle phone relaying the pairing runs two handshakes, so
/// the two people see different codes (and confirming a mismatch is what
/// the people must not do).
#[tokio::test(flavor = "multi_thread")]
async fn a_relaying_middle_phone_shows_different_codes() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let m = peer(&hub, "m").await;
    let b = peer(&hub, "b").await;
    let (a_side, m_left) = open_pairing(&hub, &a, &m).await;
    let (m_right, b_side) = open_pairing(&hub, &m, &b).await;
    assert_eq!(a_side.code, m_left.code);
    assert_eq!(m_right.code, b_side.code);
    assert_ne!(a_side.code, b_side.code);
    assert_eq!(m.node.pending_pairings().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_pairing_stores_nothing_and_closes() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let (pa, _) = open_pairing(&hub, &a, &b).await;
    b.node.confirm_pairing("a").unwrap();
    a.node.reject_pairing(&pa.peer);
    assert!(a.node.pending_pairings().is_empty());
    eventually("the pairing link closes", || async {
        !hub.is_linked("a", "b")
    })
    .await;
    eventually("b forgets it too", || async {
        b.node.pending_pairings().is_empty()
    })
    .await;
    assert!(a.node.contacts().unwrap().is_empty() && b.node.contacts().unwrap().is_empty());
    assert!(matches!(
        a.node.confirm_pairing(&pa.peer),
        Err(MeshError::NotFound(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_needs_pairing_mode_on_both_phones() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    a.node.set_pairing_mode(true);
    hub.link_as("a", "b", DialIntent::Pairing);
    eventually("b refuses", || async { !hub.is_linked("a", "b") }).await;
    assert_eq!(b.node.mesh_stats().handshake_failed, 1);
    assert!(a.node.pending_pairings().is_empty());
}

/// Re-pairing in person replaces a card a contact link could
/// not (an older generation).
#[tokio::test(flavor = "multi_thread")]
async fn pairing_replaces_a_stale_card() {
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
    open_pairing(&hub, &a, &b).await;
    confirm_both(&a, &b).await;
    eventually("a holds generation 0 again", || async {
        a.node
            .contact(&inbox(&b))
            .unwrap()
            .is_some_and(|c| c.generation == 0)
    })
    .await;
}

/// Re-pairing in person brings back a removed contact, and the new contact
/// may dial in over IK at once (the allowed-dialer set is refreshed).
#[tokio::test(flavor = "multi_thread")]
async fn pairing_re_adds_a_removed_contact_who_may_then_dial_in() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.make_contacts("a", "b");
    assert!(a.node.remove_contact(&inbox(&b)).unwrap());
    open_pairing(&hub, &a, &b).await;
    confirm_both(&a, &b).await;
    assert!(
        a.node
            .contact(&inbox(&b))
            .unwrap()
            .is_some_and(|c| !c.removed)
    );
    hub.unlink("a", "b");
    for p in [&a, &b] {
        p.node.set_pairing_mode(false);
    }
    hub.link_as(
        "b",
        "a",
        DialIntent::Contact {
            inbox_id: inbox(&a),
        },
    );
    verified_pair(&a, &b).await;
    assert_eq!(a.node.mesh_stats().links_contact, 1);
}

/// An online guesser gets few tries: after the cap of unfinished pairing
/// handshakes the phone leaves pairing mode (counted) and refuses the next.
#[tokio::test(flavor = "multi_thread")]
async fn unfinished_pairings_end_pairing_mode_at_the_cap() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    b.node.set_pairing_mode(true);
    for n in 1..=xmtp_mesh::MAX_UNFINISHED_PAIRINGS {
        a.node.set_pairing_mode(true); // a fresh entry each time on the guesser
        hub.link_as("a", "b", DialIntent::Pairing);
        eventually("b shows a code", || async { pending_on(&b, "a").is_some() }).await;
        b.node.reject_pairing("a");
        eventually("closed", || async { !hub.is_linked("a", "b") }).await;
        if n < xmtp_mesh::MAX_UNFINISHED_PAIRINGS {
            assert!(b.node.pairing_mode(), "still pairing after {n}");
        }
    }
    eventually("b left pairing mode", || async { !b.node.pairing_mode() }).await;
    assert_eq!(b.node.mesh_stats().pairing_attempts_exhausted, 1);
    let failed = b.node.mesh_stats().handshake_failed;
    a.node.set_pairing_mode(true);
    hub.link_as("a", "b", DialIntent::Pairing);
    eventually("b refuses", || async { !hub.is_linked("a", "b") }).await;
    assert_eq!(b.node.mesh_stats().handshake_failed, failed + 1);
    // Entering pairing mode again starts a new count.
    b.node.set_pairing_mode(true);
    let (_, pb) = open_pairing(&hub, &a, &b).await;
    assert_eq!(pb.peer, "a");
}

/// Once a pairing stored the peer's card, later cards on that link are
/// ignored: one forced store per pairing.
#[tokio::test(flavor = "multi_thread")]
async fn a_paired_link_stores_no_second_card() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    open_pairing(&hub, &a, &b).await;
    confirm_both(&a, &b).await;
    assert!(b.node.remove_contact(&inbox(&a)).unwrap());
    assert!(a.node.send_frame_for_test(
        "b",
        Body::ContactCard(a.node.own_contact_card_for_test().unwrap())
    ));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(hub.is_linked("a", "b"));
    assert!(
        b.node
            .contact(&inbox(&a))
            .unwrap()
            .is_some_and(|c| c.removed),
        "the removal stands"
    );
}

/// The app turning pairing mode off closes a pairing the people have not
/// both confirmed.
#[tokio::test(flavor = "multi_thread")]
async fn leaving_pairing_mode_closes_an_unconfirmed_pairing() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    open_pairing(&hub, &a, &b).await;
    a.node.confirm_pairing("b").unwrap();
    b.node.set_pairing_mode(false);
    assert!(b.node.pending_pairings().is_empty());
    eventually("the pairing link closes", || async {
        !hub.is_linked("a", "b")
    })
    .await;
    assert!(a.node.contacts().unwrap().is_empty() && b.node.contacts().unwrap().is_empty());
}

/// When the cap ends pairing mode, an open unconfirmed pairing closes and
/// a pairing handshake still running is refused when it completes.
#[tokio::test(flavor = "multi_thread")]
async fn the_cap_closes_open_and_in_flight_pairings() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let c = peer(&hub, "c").await;
    let d = peer(&hub, "d").await;
    open_pairing(&hub, &d, &b).await;
    // c's handshake with b waits for its message 3.
    c.node.set_pairing_mode(true);
    hub.hold_for_test("c", "b");
    hub.link_as("c", "b", DialIntent::Pairing);
    eventually("c's message 1 held", || async {
        hub.held_count_for_test("c", "b") == 1
    })
    .await;
    let msg1 = hub.take_held_for_test("c", "b").remove(0);
    hub.hold_for_test("c", "b");
    hub.inject_wire_for_test("c", "b", msg1);
    eventually("c's message 3 held", || async {
        hub.held_count_for_test("c", "b") == 1
    })
    .await;
    for _ in 0..xmtp_mesh::MAX_UNFINISHED_PAIRINGS {
        a.node.set_pairing_mode(true);
        hub.link_as("a", "b", DialIntent::Pairing);
        eventually("b shows a code", || async { pending_on(&b, "a").is_some() }).await;
        b.node.reject_pairing("a");
        eventually("closed", || async { !hub.is_linked("a", "b") }).await;
    }
    eventually("b left pairing mode", || async { !b.node.pairing_mode() }).await;
    assert_eq!(b.node.mesh_stats().pairing_attempts_exhausted, 1);
    eventually("d's unconfirmed pairing closes", || async {
        !hub.is_linked("d", "b")
    })
    .await;
    for m in hub.take_held_for_test("c", "b") {
        hub.inject_wire_for_test("c", "b", m);
    }
    eventually("c's pairing is refused", || async {
        !hub.is_linked("c", "b")
    })
    .await;
    assert!(b.node.pending_pairings().is_empty());
    assert!(b.node.contacts().unwrap().is_empty());
}

/// §R5.4: one stranger link keeps to its own budget; several stranger
/// links together keep to the per-window cap.
#[tokio::test(flavor = "multi_thread")]
async fn stranger_relay_limits_hold_per_link_and_per_window() {
    let hub = LoopbackHub::new();
    let cfg = RelayConfig {
        max_entries: 16,
        neighbour_envelopes_per_min: 1,
        stranger_window_factor: 4,
        ..fast_relay_config()
    };
    let (r, _) = relay_peer_with(&hub, "r", cfg).await;
    // Pin r a few seconds into a window, so the test never straddles one.
    let now = r.node.unix_now();
    r.node
        .set_clock_offset_for_test((WINDOW_SECS - now % WINDOW_SECS) as i64 + 5);
    let mut strangers = Vec::new();
    for i in 0..5 {
        let name = format!("s{i}");
        let (s, _) = relay_peer(&hub, &name).await;
        hub.set_strangers(&name, "r");
        strangers.push(s);
    }
    // One stranger link: burst = share cap = 4, refill 1/min.
    hub.link("s0", "r");
    eventually("s0 linked", || async {
        r.node.mesh_stats().links_relay == 1
    })
    .await;
    for _ in 0..6 {
        strangers[0].node.originate_random_for_test(100, 5);
    }
    eventually("r took 4 of 6", || async {
        let s = r.node.relay_stats();
        s.accepted == 4 && s.dropped_rate == 2
    })
    .await;
    // Four more stranger links, 4 envelopes each: 16 per window in all.
    for (i, stranger) in strangers.iter().enumerate().skip(1) {
        hub.link(&format!("s{i}"), "r");
        eventually("linked", || async {
            r.node.mesh_stats().links_relay == i as u64 + 1
        })
        .await;
        for _ in 0..4 {
            stranger.node.originate_random_for_test(100, 5);
        }
        eventually("r saw them", || async {
            let s = r.node.relay_stats();
            s.accepted + s.dropped_rate == 6 + 4 * i as u64
        })
        .await;
    }
    let s = r.node.relay_stats();
    assert_eq!(s.accepted, 16, "{s:?}");
    assert_eq!(s.dropped_rate, 6, "{s:?}");
}

/// §B14.3: after closing a stranger link (idle here), a phone refuses the
/// same radio peer as a stranger for a short back-off, whether it would
/// accept or dial, counted; once the back-off is over, a relay link opens.
#[tokio::test(flavor = "multi_thread")]
async fn a_closed_relay_link_backs_off_the_same_peer() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    b.node
        .set_relay_idle_timeout_for_test(Duration::from_millis(400));
    b.node.set_relay_backoff_for_test(Duration::from_secs(3));
    hub.set_strangers("a", "b");
    hub.link("a", "b");
    eventually("a relay link", || async {
        b.node.mesh_stats().links_relay == 1
    })
    .await;
    eventually("b closes the quiet link", || async {
        !hub.is_linked("a", "b")
    })
    .await;
    assert_eq!(b.node.mesh_stats().relay_links_idle_closed, 1);
    // a dials, b accepts: refused once the handshake names a relay link.
    hub.link_as("a", "b", DialIntent::Relay);
    eventually("b refuses a", || async {
        b.node.mesh_stats().relay_links_backoff_refused == 1
    })
    .await;
    eventually("closed", || async { !hub.is_linked("a", "b") }).await;
    // b dials: it skips a.
    hub.link_as("b", "a", DialIntent::Relay);
    eventually("b skips a", || async {
        b.node.mesh_stats().relay_links_backoff_refused == 2
    })
    .await;
    eventually("closed", || async { !hub.is_linked("a", "b") }).await;
    let stats = b.node.mesh_stats();
    assert_eq!(
        (stats.links_relay, stats.handshake_failed),
        (1, 0),
        "{stats:?}"
    );
    // The back-off is over: a new relay link opens.
    tokio::time::sleep(Duration::from_secs(3)).await;
    hub.link_as("a", "b", DialIntent::Relay);
    eventually("relinked", || async {
        b.node.mesh_stats().links_relay == 2 && a.node.mesh_stats().links_relay >= 2
    })
    .await;
    assert_eq!(b.node.mesh_stats().relay_links_backoff_refused, 2);
}

/// §B14.3: a digest or want whose ids are all malformed is not useful
/// traffic: it does not keep a stranger link open.
#[tokio::test(flavor = "multi_thread")]
async fn malformed_digest_ids_do_not_keep_a_relay_link_open() {
    let hub = LoopbackHub::new();
    let (_a, b) = relay_strangers(&hub, Duration::from_millis(600), Duration::from_secs(60)).await;
    let bad = |want: bool| {
        let ids = vec![vec![9u8; 3], vec![]];
        frames::encode(if want {
            Body::SpoolWant(SpoolWant { ids })
        } else {
            Body::SpoolDigest(frames::SpoolDigest { ids })
        })
    };
    for n in 0..6 {
        if !hub.is_linked("a", "b") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        hub.inject("a", "b", bad(n % 2 == 1));
    }
    assert!(
        !hub.is_linked("a", "b"),
        "closed while the malformed digests kept coming"
    );
    let stats = b.node.mesh_stats();
    assert_eq!(
        (
            stats.relay_links_idle_closed,
            stats.relay_links_force_closed
        ),
        (1, 0)
    );
}

/// §B14.3: a stranger whose frame closed its relay link is backed off
/// too, counted.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_frame_on_a_relay_link_backs_off_the_peer() {
    let hub = LoopbackHub::new();
    let (_a, b) = relay_strangers(&hub, Duration::from_secs(60), Duration::from_secs(600)).await;
    hub.inject("a", "b", frames::encode(interest(b"g")));
    eventually("b closes the link", || async { !hub.is_linked("a", "b") }).await;
    assert_eq!(b.node.mesh_stats().link_frame_rejected, 1);
    hub.link_as("a", "b", DialIntent::Relay);
    eventually("b refuses a", || async {
        b.node.mesh_stats().relay_links_backoff_refused == 1
    })
    .await;
    eventually("closed", || async { !hub.is_linked("a", "b") }).await;
    assert_eq!(b.node.mesh_stats().links_relay, 1);
}

async fn send_dm(dm: &common::MeshGroup, text: &[u8]) {
    use xmtp_mls::groups::GroupError;
    use xmtp_mls::groups::send_message_opts::SendMessageOpts;
    match dm.send_message(text, SendMessageOpts::default()).await {
        Ok(_) | Err(GroupError::SyncFailedToWait(_)) => {}
        Err(e) => panic!("send failed: {e:?}"),
    }
}

/// §R5.4: a stranger link that meets the spent window still hands this
/// phone its own message; it is only kept out of the spool.
#[tokio::test(flavor = "multi_thread")]
async fn a_recipient_gets_its_message_past_the_stranger_window() {
    let hub = LoopbackHub::new();
    let cfg = RelayConfig {
        max_entries: 64,
        neighbour_envelopes_per_min: 1,
        stranger_window_factor: 1,
        ..fast_relay_config()
    };
    let (a, _) = relay_peer(&hub, "a").await;
    let (_b, _) = relay_peer(&hub, "b").await;
    let (c, _) = relay_peer(&hub, "c").await;
    let (d, _) = relay_peer_with(&hub, "d", cfg.clone()).await;
    let (a_dm, d_dm) = pair_dm(&hub, &a, &d).await;
    relay_keys_confirmed(&a, &d, &a_dm.group_id).await;
    hub.unlink("a", "d");
    // Pin d a few seconds into a window, so the test never straddles one.
    let now = d.node.unix_now();
    d.node
        .set_clock_offset_for_test((WINDOW_SECS - now % WINDOW_SECS) as i64 + 5);
    hub.set_strangers("b", "d");
    hub.set_strangers("c", "d");
    // c spends the whole window (its own link's burst is the same size).
    hub.link("c", "d");
    eventually("c linked", || async {
        d.node.mesh_stats().links_relay == 1
    })
    .await;
    for _ in 0..cfg.share_cap() {
        c.node.originate_random_for_test(100, 5);
    }
    eventually("the window is spent", || async {
        d.node.relay_stats().accepted == cfg.share_cap() as u64
    })
    .await;
    hub.link("b", "d");
    eventually("b linked", || async {
        d.node.mesh_stats().links_relay == 2
    })
    .await;
    let before = d.node.relay_stats();
    hub.link("a", "b");
    send_dm(&a_dm, b"past the window").await;
    eventually_for("d gets it anyway", 30, || async {
        d_dm.sync().await.ok();
        app_payloads(&d_dm).contains(&b"past the window".to_vec())
    })
    .await;
    let after = d.node.relay_stats();
    assert_eq!(after.accepted, before.accepted, "nothing more was spooled");
    assert!(after.dropped_rate > before.dropped_rate, "{after:?}");
    assert!(
        after.delivered_unspooled > before.delivered_unspooled,
        "{after:?}"
    );
}
