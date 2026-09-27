#![recursion_limit = "256"]
mod common;

use common::{app_payloads, eventually, peer, query_group, welcome_count};
use xmtp_db::group::GroupQueryArgs;
use xmtp_mesh::LoopbackHub;
use xmtp_mesh::frames::{self, Interest, frame::Body};
use xmtp_mls::groups::send_message_opts::SendMessageOpts;

#[tokio::test(flavor = "multi_thread")]
async fn dm_round_trip_between_two_nodes() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
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

    eventually("b receives the welcome", || async {
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
    eventually("b acks the welcome", || async {
        a.node
            .outbound_welcome_count_for_test(&b.installation())
            .unwrap()
            == 0
    })
    .await;
    eventually("b sees hi", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm) == vec![b"hi".to_vec()]
    })
    .await;

    // Rule A: the joiner never self-sequences.
    assert_eq!(
        b.node.group_sequencer_for_test(&b_dm.group_id).unwrap(),
        Some(a.installation())
    );

    // b is not the sequencer: its send goes via a and must still resolve.
    b_dm.send_message(b"yo", SendMessageOpts::default())
        .await
        .unwrap();
    eventually("a sees yo", || async {
        a_dm.sync().await.ok();
        app_payloads(&a_dm) == vec![b"hi".to_vec(), b"yo".to_vec()]
    })
    .await;
    assert_eq!(app_payloads(&b_dm), vec![b"hi".to_vec(), b"yo".to_vec()]);
}

/// The app-level "sync everything" path alone must deliver a new DM's
/// messages. `sync_all_welcomes_and_groups` only syncs groups whose newest
/// message (per `GetNewestGroupMessage`) is past the local cursor, so that
/// query must make the node learn the group and pull it from peers; before
/// the fix it answered "nothing" forever for a group the node never queried.
#[tokio::test(flavor = "multi_thread")]
async fn joiner_receives_dm_via_sync_all_only() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
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

    eventually("b receives hi via sync_all only", || async {
        b.client.sync_all_welcomes_and_groups(None).await.ok();
        b.client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .first()
            .is_some_and(|g| app_payloads(g) == vec![b"hi".to_vec()])
    })
    .await;
}

/// Rule A, exercised: b joins while cut off from a, so its first
/// publish (epoch > 0) happens before it has learned the sequencer. The
/// message must wait in pending, unsequenced, until a is reachable again.
#[tokio::test(flavor = "multi_thread")]
async fn joiner_publish_before_learning_sequencer_stays_pending() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
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

    // Cut the link as soon as b's node holds the welcome, before b's client
    // has seen the group (and so before b could learn who sequences it).
    eventually("b's node holds the welcome", || async {
        welcome_count(&b).await == 1
    })
    .await;
    hub.unlink("a", "b");

    b.client.sync_welcomes().await.unwrap();
    let b_dm = b
        .client
        .find_groups(GroupQueryArgs::default())
        .unwrap()
        .remove(0);
    // Unreachable sequencer: libxmtp gives up waiting for its message to come
    // back sequenced, so the send may report an error; the message is published
    // to b's node either way.
    // (libxmtp also publishes the joiner's own commit first; it waits too.)
    let _ = b_dm.send_message(b"yo", SendMessageOpts::default()).await;
    assert!(b.node.pending_count_for_test(&b_dm.group_id).unwrap() > 0);
    assert_eq!(
        b.node.group_sequencer_for_test(&b_dm.group_id).unwrap(),
        None
    );
    assert_eq!(b.node.max_group_id_for_test(&b_dm.group_id).unwrap(), 0);

    hub.link("a", "b");
    eventually("a sees yo", || async {
        a_dm.sync().await.ok();
        app_payloads(&a_dm) == vec![b"hi".to_vec(), b"yo".to_vec()]
    })
    .await;
    eventually("b sees both", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm) == vec![b"hi".to_vec(), b"yo".to_vec()]
    })
    .await;
    assert_eq!(
        b.node.group_sequencer_for_test(&b_dm.group_id).unwrap(),
        Some(a.installation())
    );
    assert_eq!(b.node.pending_count_for_test(&b_dm.group_id).unwrap(), 0);
}

/// A member whose event stream lagged past a push is behind; the sequencer's
/// Interest (what `on_lagged` re-announces) alone must make it catch up.
#[tokio::test(flavor = "multi_thread")]
async fn member_catches_up_from_sequencer_interest_alone() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
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
    eventually("b joins", || async {
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
    let gid = b_dm.group_id.clone();
    eventually("b has a's rows", || async {
        b_dm.sync().await.ok();
        b.node.max_group_id_for_test(&gid).unwrap() == a.node.max_group_id_for_test(&gid).unwrap()
    })
    .await;

    // a sequences a message but its push to b is lost.
    a.node.suppress_group_push_for_test(true);
    a_dm.send_message(b"missed", SendMessageOpts::default())
        .await
        .unwrap();
    let high = a.node.max_group_id_for_test(&gid).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(b.node.max_group_id_for_test(&gid).unwrap() < high);
    a.node.suppress_group_push_for_test(false);

    // Only a's re-announced Interest arrives.
    let interest = Interest {
        group_id: gid.clone(),
        high_id: high as u64,
        i_am_sequencer: true,
    };
    hub.inject("a", "b", frames::encode(Body::Interest(interest)));
    eventually("b catches up", || async {
        b.node.max_group_id_for_test(&gid).unwrap() == high
    })
    .await;
    eventually("b sees missed", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm) == vec![b"hi".to_vec(), b"missed".to_vec()]
    })
    .await;
}

/// A message too large for any mesh frame is refused at publish: the sender's
/// libxmtp sees an error, and the DM keeps working afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn oversized_message_is_refused_and_the_dm_keeps_working() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
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
    eventually("b joins", || async {
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

    let huge = vec![7u8; xmtp_mesh::MAX_FRAME_LEN];
    let sent = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        a_dm.send_message(&huge, SendMessageOpts::default()),
    )
    .await
    .expect("send must not hang");
    assert!(sent.is_err(), "oversized message was accepted");

    a_dm.send_message(b"after", SendMessageOpts::default())
        .await
        .unwrap();
    eventually("b sees after", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm) == vec![b"hi".to_vec(), b"after".to_vec()]
    })
    .await;
}

/// Liveness of membership gating: the sequencer's claim reaches b while b's
/// node knows the group but b's client has not processed the welcome yet
/// (membership unknown), so b cannot pin it then. Once b's client joins, b
/// must pin a and sync without a reconnect or any further frame from a.
#[tokio::test(flavor = "multi_thread")]
async fn claim_before_the_client_knows_the_group_is_pinned_later() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
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

    // b's node learns the group id; b's client has not joined yet.
    query_group(&b.node, &gid).await;
    let claim = Interest {
        group_id: gid.clone(),
        high_id: a.node.max_group_id_for_test(&gid).unwrap() as u64,
        i_am_sequencer: true,
    };
    hub.inject("a", "b", frames::encode(Body::Interest(claim)));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(b.node.group_sequencer_for_test(&gid).unwrap(), None);

    b.client.sync_welcomes().await.unwrap();
    eventually("b pins a", || async {
        b.node.group_sequencer_for_test(&gid).unwrap() == Some(a.installation())
    })
    .await;
    let b_dm = b.client.group(&gid).unwrap();
    eventually("b sees hi", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm) == vec![b"hi".to_vec()]
    })
    .await;
}
