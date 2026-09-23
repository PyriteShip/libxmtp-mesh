#![recursion_limit = "256"]
mod common;

use bytes::Bytes;
use common::{app_payloads, eventually, peer};
use http::{request, uri::PathAndQuery};
use prost::Message;
use xmtp_db::group::GroupQueryArgs;
use xmtp_mesh::LoopbackHub;
use xmtp_mesh::frames::{self, Interest, frame::Body};
use xmtp_mls::groups::send_message_opts::SendMessageOpts;
use xmtp_proto::api::Client;
use xmtp_proto::mls_v1::{QueryWelcomeMessagesRequest, QueryWelcomeMessagesResponse};

#[tokio::test(flavor = "multi_thread")]
async fn dm_round_trip_between_two_nodes() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    eventually("paired", || async { a.node.has_key_package(&b.installation()).unwrap() }).await;

    let a_dm = a.client.find_or_create_dm(b.client.inbox_id(), None).await.unwrap();
    a_dm.send_message(b"hi", SendMessageOpts::default()).await.unwrap();

    eventually("b receives the welcome", || async {
        b.client.sync_welcomes().await.unwrap();
        b.client.find_groups(GroupQueryArgs::default()).unwrap().len() == 1
    })
    .await;
    let b_dm = b.client.find_groups(GroupQueryArgs::default()).unwrap().remove(0);
    eventually("b acks the welcome", || async {
        a.node.outbound_welcome_count_for_test(&b.installation()).unwrap() == 0
    })
    .await;
    eventually("b sees hi", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm) == vec![b"hi".to_vec()]
    })
    .await;

    // Review focus 5: the joiner never self-sequences.
    assert_eq!(
        b.node.group_sequencer_for_test(&b_dm.group_id).unwrap(),
        Some(a.installation())
    );

    // b is not the sequencer: its send goes via a and must still resolve.
    b_dm.send_message(b"yo", SendMessageOpts::default()).await.unwrap();
    eventually("a sees yo", || async {
        a_dm.sync().await.ok();
        app_payloads(&a_dm) == vec![b"hi".to_vec(), b"yo".to_vec()]
    })
    .await;
    assert_eq!(app_payloads(&b_dm), vec![b"hi".to_vec(), b"yo".to_vec()]);
}

/// Review focus 5, exercised: b joins while cut off from a, so its first
/// publish (epoch > 0) happens before it has learned the sequencer. The
/// message must wait in pending, unsequenced, until a is reachable again.
#[tokio::test(flavor = "multi_thread")]
async fn joiner_publish_before_learning_sequencer_stays_pending() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    eventually("paired", || async { a.node.has_key_package(&b.installation()).unwrap() }).await;

    let a_dm = a.client.find_or_create_dm(b.client.inbox_id(), None).await.unwrap();
    a_dm.send_message(b"hi", SendMessageOpts::default()).await.unwrap();

    // Cut the link as soon as b's node holds the welcome, before b's client
    // has seen the group (and so before b could learn who sequences it).
    eventually("b's node holds the welcome", || async { welcome_count(&b).await == 1 }).await;
    hub.unlink("a", "b");

    b.client.sync_welcomes().await.unwrap();
    let b_dm = b.client.find_groups(GroupQueryArgs::default()).unwrap().remove(0);
    // Unreachable sequencer: libxmtp gives up waiting for its message to come
    // back sequenced, so the send may report an error; the message is published
    // to b's node either way.
    // (libxmtp also publishes the joiner's own commit first; it waits too.)
    let _ = b_dm.send_message(b"yo", SendMessageOpts::default()).await;
    assert!(b.node.pending_count_for_test(&b_dm.group_id).unwrap() > 0);
    assert_eq!(b.node.group_sequencer_for_test(&b_dm.group_id).unwrap(), None);
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
    assert_eq!(b.node.group_sequencer_for_test(&b_dm.group_id).unwrap(), Some(a.installation()));
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
    eventually("paired", || async { a.node.has_key_package(&b.installation()).unwrap() }).await;
    let a_dm = a.client.find_or_create_dm(b.client.inbox_id(), None).await.unwrap();
    a_dm.send_message(b"hi", SendMessageOpts::default()).await.unwrap();
    eventually("b joins", || async {
        b.client.sync_welcomes().await.unwrap();
        b.client.find_groups(GroupQueryArgs::default()).unwrap().len() == 1
    })
    .await;
    let b_dm = b.client.find_groups(GroupQueryArgs::default()).unwrap().remove(0);
    let gid = b_dm.group_id.clone();
    eventually("b has a's rows", || async {
        b_dm.sync().await.ok();
        b.node.max_group_id_for_test(&gid).unwrap() == a.node.max_group_id_for_test(&gid).unwrap()
    })
    .await;

    // a sequences a message but its push to b is lost.
    a.node.suppress_group_push_for_test(true);
    a_dm.send_message(b"missed", SendMessageOpts::default()).await.unwrap();
    let high = a.node.max_group_id_for_test(&gid).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(b.node.max_group_id_for_test(&gid).unwrap() < high);
    a.node.suppress_group_push_for_test(false);

    // Only a's re-announced Interest arrives.
    let interest = Interest { group_id: gid.clone(), high_id: high as u64, i_am_sequencer: true };
    hub.inject("a", "b", frames::encode(Body::Interest(interest)));
    eventually("b catches up", || async { b.node.max_group_id_for_test(&gid).unwrap() == high }).await;
    eventually("b sees missed", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm) == vec![b"hi".to_vec(), b"missed".to_vec()]
    })
    .await;
}

/// Welcomes b's node holds for b, read through the node's own API.
async fn welcome_count(p: &common::TestPeer) -> usize {
    let req = QueryWelcomeMessagesRequest { installation_key: p.installation(), paging_info: None };
    let path = PathAndQuery::try_from(xmtp_proto::path_and_query::<QueryWelcomeMessagesRequest>().as_ref()).unwrap();
    let res = p
        .node
        .request(request::Builder::new(), path, Bytes::from(req.encode_to_vec()))
        .await
        .unwrap();
    QueryWelcomeMessagesResponse::decode(res.into_body()).unwrap().messages.len()
}
