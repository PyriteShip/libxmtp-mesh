#![recursion_limit = "256"]
//! Rule A scoping: group traffic flows only between members of the group (as
//! the local libxmtp client sees it). A verified stranger (any inbox can be
//! made offline) must not be able to pin itself as a group's sequencer, get
//! its messages sequenced, or pull history, even after delivering a welcome.
mod common;

use std::time::Duration;

use common::{app_payloads, eventually, peer, query_group, recorded_peer, welcome_count};
use xmtp_db::group::GroupQueryArgs;
use xmtp_mesh::LoopbackHub;
use xmtp_mesh::frames::{self, Interest, Pending, Sequenced, Welcome, frame::Body};
use xmtp_mls::groups::send_message_opts::SendMessageOpts;
use xmtp_proto::mls_v1::{WelcomeMessageInput, welcome_message_input};

#[tokio::test(flavor = "multi_thread")]
async fn verified_stranger_cannot_hijack_or_read_a_dm() {
    let hub = LoopbackHub::new();
    let (a, a_sent) = recorded_peer(&hub, "a").await;
    let (b, b_sent) = recorded_peer(&hub, "b").await;
    let c = peer(&hub, "c").await; // the stranger: no welcome with a or b

    // a creates a DM with b; b's node gets the welcome, then the link drops
    // before b could learn (pin) the sequencer.
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
    a_dm.send_message(b"hi", SendMessageOpts::default())
        .await
        .unwrap();
    let gid = a_dm.group_id.clone();
    eventually("b's node holds the welcome", || async {
        welcome_count(&b).await == 1
    })
    .await;
    eventually("b acked it", || async {
        a.node
            .outbound_welcome_count_for_test(&b.installation())
            .unwrap()
            == 0
    })
    .await;
    hub.unlink("a", "b");

    // b joins while apart and publishes: its node holds the messages pending.
    b.client.sync_welcomes().await.unwrap();
    let b_dm = b
        .client
        .find_groups(GroupQueryArgs::default())
        .unwrap()
        .remove(0);
    b_dm.send_message_optimistic(b"yo", SendMessageOpts::default())
        .unwrap();
    b_dm.sync().await.ok();
    query_group(&b.node, &gid).await;
    let b_pending = b.node.pending_inputs_for_test(&gid).unwrap();
    assert!(!b_pending.is_empty());
    assert_eq!(b.node.group_sequencer_for_test(&gid).unwrap(), None);

    // (a) c, verified by b, delivers a junk welcome addressed to b (b stores
    // and acks it), then claims to sequence b's DM before a is back.
    hub.link("b", "c");
    eventually("b verified c", || async {
        b.node.has_key_package(&c.installation()).unwrap()
    })
    .await;
    let junk = WelcomeMessageInput {
        version: Some(welcome_message_input::Version::V1(
            welcome_message_input::V1 {
                installation_key: b.installation(),
                data: vec![7; 64],
                hpke_public_key: vec![],
                wrapper_algorithm: 0,
                welcome_metadata: vec![],
            },
        )),
    };
    let welcome = Welcome {
        envelope_hash: xmtp_mesh::store::sha256(&prost::Message::encode_to_vec(&junk)),
        input: Some(junk),
    };
    hub.inject("c", "b", frames::encode(Body::Welcome(welcome)));
    eventually("b stored the junk welcome", || async {
        welcome_count(&b).await == 2
    })
    .await;
    let claim = Interest {
        group_id: gid.clone(),
        high_id: 5,
        i_am_sequencer: true,
    };
    hub.inject("c", "b", frames::encode(Body::Interest(claim)));
    let claim = Sequenced {
        group_id: gid.clone(),
        messages: vec![],
        sender_is_sequencer: true,
        proofs: vec![],
    };
    hub.inject("c", "b", frames::encode(Body::Sequenced(claim)));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        b.node.group_sequencer_for_test(&gid).unwrap(),
        None,
        "stranger pinned itself"
    );
    for body in b_sent.sent_to("c") {
        match body {
            Body::Pending(p) => assert!(p.group_id != gid, "b sent its pending to a stranger"),
            Body::Interest(i) => assert!(i.group_id != gid, "b announced the DM to a stranger"),
            _ => {}
        }
    }

    // (b) c relays b's pending messages to the sequencer a: ignored.
    hub.link("a", "c");
    eventually("a verified c", || async {
        a.node.has_key_package(&c.installation()).unwrap()
    })
    .await;
    let high = a.node.max_group_id_for_test(&gid).unwrap();
    let pending = Pending {
        group_id: gid.clone(),
        messages: b_pending,
    };
    hub.inject("c", "a", frames::encode(Body::Pending(pending)));
    // (c) c asks a for the DM's whole history: no answer.
    let ask = Interest {
        group_id: gid.clone(),
        high_id: 0,
        i_am_sequencer: false,
    };
    hub.inject("c", "a", frames::encode(Body::Interest(ask)));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        a.node.max_group_id_for_test(&gid).unwrap(),
        high,
        "stranger's pending was sequenced"
    );
    for body in a_sent.sent_to("c") {
        match body {
            Body::Sequenced(s) => {
                assert!(s.group_id != gid, "a served the DM's history to a stranger")
            }
            Body::Interest(i) => assert!(i.group_id != gid, "a announced the DM to a stranger"),
            _ => {}
        }
    }

    // The real sequencer is still learned, and b's messages flow, once a is back.
    hub.link("a", "b");
    eventually("a sees yo", || async {
        b_dm.sync().await.ok(); // publishes "yo" once b's own commit is sequenced
        a_dm.sync().await.ok();
        app_payloads(&a_dm) == vec![b"hi".to_vec(), b"yo".to_vec()]
    })
    .await;
    assert_eq!(
        b.node.group_sequencer_for_test(&gid).unwrap(),
        Some(a.installation())
    );
}
