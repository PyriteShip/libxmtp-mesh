#![recursion_limit = "256"]
mod common;

use std::time::Duration;

use bytes::Bytes;
use common::{app_payloads, build_client};
use http::{request, uri::PathAndQuery};
use prost::Message;
use xmtp_db::group_message::{DeliveryStatus, MsgQueryArgs};
use xmtp_mesh::{MeshNode, NodeEvent};
use xmtp_mls::groups::send_message_opts::SendMessageOpts;
use xmtp_proto::api::Client;
use xmtp_proto::mls_v1::{
    GroupMessageInput, PagingInfo, QueryGroupMessagesRequest, QueryGroupMessagesResponse,
    SendGroupMessagesRequest, SortDirection, group_message_input,
};

#[tokio::test(flavor = "multi_thread")]
async fn creator_self_sequences_and_messages_publish() {
    let node = MeshNode::in_memory().unwrap();
    let client = build_client(&node).await;
    let group = client.create_group(None, None).unwrap();
    group
        .send_message(b"hello", SendMessageOpts::default())
        .await
        .unwrap();
    group
        .send_message(b"again", SendMessageOpts::default())
        .await
        .unwrap();

    assert_eq!(
        app_payloads(&group),
        vec![b"hello".to_vec(), b"again".to_vec()]
    );
    let all = group.find_messages(&MsgQueryArgs::default()).unwrap();
    assert!(
        all.iter()
            .all(|m| m.delivery_status == DeliveryStatus::Published)
    );
    assert_eq!(
        node.group_sequencer_for_test(&group.group_id).unwrap(),
        Some(client.installation_public_key().to_vec())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn query_group_messages_pages_like_v3() {
    let node = MeshNode::in_memory().unwrap();
    let client = build_client(&node).await;
    let group = client.create_group(None, None).unwrap();
    for i in 0..3u8 {
        group
            .send_message(&[i], SendMessageOpts::default())
            .await
            .unwrap();
    }
    let query = |cursor: u64, limit: u32, direction: SortDirection| {
        let node = node.clone();
        let gid = group.group_id.clone();
        async move {
            let body = QueryGroupMessagesRequest {
                group_id: gid,
                paging_info: Some(PagingInfo {
                    direction: direction as i32,
                    limit,
                    id_cursor: cursor,
                }),
            }
            .encode_to_vec();
            let resp = node
                .request(
                    request::Builder::new(),
                    PathAndQuery::from_static("/xmtp.mls.api.v1.MlsApi/QueryGroupMessages"),
                    Bytes::from(body),
                )
                .await
                .unwrap();
            QueryGroupMessagesResponse::decode(resp.into_body()).unwrap()
        }
    };
    // 3 app messages plus however many commits libxmtp published for a solo group
    let total = node.max_group_id_for_test(&group.group_id).unwrap() as usize;
    assert!(total >= 3);
    let all = query(0, 100, SortDirection::Ascending).await;
    assert_eq!(all.messages.len(), total);
    assert_eq!(
        all.paging_info.unwrap().id_cursor,
        0,
        "short page ends paging"
    );
    let page = query(0, 2, SortDirection::Ascending).await;
    assert_eq!(page.messages.len(), 2);
    assert_eq!(page.paging_info.unwrap().id_cursor, 2);
    let newest = query(0, 1, SortDirection::Descending).await;
    let Some(xmtp_proto::mls_v1::group_message::Version::V1(v1)) =
        newest.messages[0].version.clone()
    else {
        panic!("expected V1");
    };
    assert_eq!(v1.id as usize, total);
}

/// Store mutations for earlier items in a `SendGroupMessages` batch must not
/// be observed by their store effects alone: the `NodeEvent`s that mirror
/// them have to be emitted too, even when a later item in the same batch
/// fails and the whole call returns an error. Sync (tasks 6-8) relies on
/// `NodeEvent` mirroring store state exactly.
#[tokio::test(flavor = "multi_thread")]
async fn send_group_messages_emits_events_for_earlier_items_when_a_later_item_errors() {
    let node = MeshNode::in_memory().unwrap();
    let _client = build_client(&node).await;

    // A second, unrelated node/client/group, used only to mint real,
    // parseable MLS bytes (the epoch-0 creation commit) for a group id that
    // `node` has never seen. Feeding that into `node` below is guaranteed to
    // be a fresh insert, not a hash-deduped no-op, and it is valid enough
    // for `parse_group_message` to succeed (this layer does not check
    // membership).
    let other_node = MeshNode::in_memory().unwrap();
    let other_client = build_client(&other_node).await;
    let other_group = other_client.create_group(None, None).unwrap();
    other_group
        .send_message(b"seed", SendMessageOpts::default())
        .await
        .unwrap();

    let query_body = QueryGroupMessagesRequest {
        group_id: other_group.group_id.clone(),
        paging_info: Some(PagingInfo {
            direction: SortDirection::Ascending as i32,
            limit: 100,
            id_cursor: 0,
        }),
    }
    .encode_to_vec();
    let resp = other_node
        .request(
            request::Builder::new(),
            PathAndQuery::from_static("/xmtp.mls.api.v1.MlsApi/QueryGroupMessages"),
            Bytes::from(query_body),
        )
        .await
        .unwrap();
    let messages = QueryGroupMessagesResponse::decode(resp.into_body())
        .unwrap()
        .messages;
    let Some(xmtp_proto::mls_v1::group_message::Version::V1(valid)) = messages[0].version.clone()
    else {
        panic!("expected V1");
    };

    let mut events = node.subscribe_events();

    let batch = SendGroupMessagesRequest {
        messages: vec![
            GroupMessageInput {
                version: Some(group_message_input::Version::V1(group_message_input::V1 {
                    data: valid.data.clone(),
                    sender_hmac: vec![],
                    should_push: false,
                })),
            },
            GroupMessageInput {
                version: Some(group_message_input::Version::V1(group_message_input::V1 {
                    data: b"not a valid mls message".to_vec(),
                    sender_hmac: vec![],
                    should_push: false,
                })),
            },
        ],
    }
    .encode_to_vec();

    let result = node
        .request(
            request::Builder::new(),
            PathAndQuery::from_static("/xmtp.mls.api.v1.MlsApi/SendGroupMessages"),
            Bytes::from(batch),
        )
        .await;
    assert!(
        result.is_err(),
        "a batch with a garbage second message must error"
    );

    // The first item (valid, epoch 0) must still have been self-sequenced
    // and its event emitted, even though the whole call errored.
    let mut saw_processed_event = false;
    for _ in 0..2 {
        let Ok(Ok(event)) = tokio::time::timeout(Duration::from_secs(5), events.recv()).await
        else {
            break;
        };
        match event {
            NodeEvent::GroupSequenced(row) if row.group_id == other_group.group_id => {
                saw_processed_event = true;
                break;
            }
            NodeEvent::PendingAdded(gid) if gid == other_group.group_id => {
                saw_processed_event = true;
                break;
            }
            _ => {}
        }
    }
    assert!(
        saw_processed_event,
        "expected a GroupSequenced or PendingAdded event for the first (valid) batch item"
    );
}
