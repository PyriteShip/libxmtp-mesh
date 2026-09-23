#![recursion_limit = "256"]
mod common;

use std::time::Duration;

use bytes::Bytes;
use common::{app_payloads, build_client, eventually, peer};
use futures::StreamExt;
use http::{request, uri::PathAndQuery};
use prost::Message;
use xmtp_mesh::MeshNode;
use xmtp_mls::groups::send_message_opts::SendMessageOpts;
use xmtp_proto::api::Client;
use xmtp_proto::mls_v1::{
    GroupMessage, SubscribeGroupMessagesRequest, group_message,
    subscribe_group_messages_request::Filter,
};

#[tokio::test(flavor = "multi_thread")]
async fn group_stream_yields_backlog_then_live_without_duplicates() {
    let node = MeshNode::in_memory().unwrap();
    let client = build_client(&node).await;
    let group = client.create_group(None, None).unwrap();
    group
        .send_message(b"before", SendMessageOpts::default())
        .await
        .unwrap();

    let body = SubscribeGroupMessagesRequest {
        filters: vec![Filter {
            group_id: group.group_id.clone(),
            id_cursor: 0,
        }],
    }
    .encode_to_vec();
    let mut stream = node
        .stream(
            request::Builder::new(),
            PathAndQuery::from_static("/xmtp.mls.api.v1.MlsApi/SubscribeGroupMessages"),
            Bytes::from(body),
        )
        .await
        .unwrap()
        .into_body();

    group
        .send_message(b"after", SendMessageOpts::default())
        .await
        .unwrap();
    let total = node.max_group_id_for_test(&group.group_id).unwrap() as u64;

    let mut ids = vec![];
    while (ids.len() as u64) < total {
        let item = tokio::time::timeout(Duration::from_secs(10), stream.next())
            .await
            .expect("stream stalled")
            .unwrap()
            .unwrap();
        let Some(group_message::Version::V1(v1)) = GroupMessage::decode(item).unwrap().version
        else {
            panic!("expected V1");
        };
        ids.push(v1.id);
    }
    // every sequenced message exactly once, in order: backlog then live
    assert_eq!(ids, (1..=total).collect::<Vec<_>>());
    // and nothing further arrives
    assert!(
        tokio::time::timeout(Duration::from_millis(300), stream.next())
            .await
            .is_err()
    );
}

/// libxmtp's own stream on b yields, live, a message a sends over the mesh.
#[tokio::test(flavor = "multi_thread")]
async fn stream_all_messages_receives_a_peer_message_live() {
    use xmtp_db::group::GroupQueryArgs;
    use xmtp_db::group_message::GroupMessageKind;
    use xmtp_mesh::LoopbackHub;

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
    eventually("b synced", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm).len() == 1
    })
    .await;

    let stream = b.client.stream_all_messages(None, None).await.unwrap();
    futures::pin_mut!(stream);
    a_dm.send_message(b"live", SendMessageOpts::default())
        .await
        .unwrap();
    let received = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(message) = stream.next().await {
            let message = message.unwrap();
            if message.kind == GroupMessageKind::Application
                && message.decrypted_message_bytes == b"live"
            {
                return message;
            }
        }
        panic!("stream ended");
    })
    .await
    .expect("b's stream never yielded a's message");
    assert_eq!(received.group_id, b_dm.group_id);
}
