#![recursion_limit = "256"]
//! Frames stay bounded: a sequencer serves a long backlog in pages.
mod common;

use common::{app_payloads, eventually, peer, recorded_peer};
use xmtp_db::group::GroupQueryArgs;
use xmtp_mesh::frames::{self, frame::Body};
use xmtp_mesh::{LoopbackHub, MAX_FRAME_LEN};
use xmtp_mls::groups::send_message_opts::SendMessageOpts;
use xmtp_proto::mls_v1::group_message;

#[tokio::test(flavor = "multi_thread")]
async fn sequencer_serves_a_long_backlog_in_bounded_pages() {
    let hub = LoopbackHub::new();
    let (a, a_sent) = recorded_peer(&hub, "a").await;
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

    hub.unlink("a", "b");
    for i in 0..200u32 {
        a_dm.send_message(&i.to_be_bytes(), SendMessageOpts::default())
            .await
            .unwrap();
    }
    let high = a.node.max_group_id_for_test(&gid).unwrap();
    let sent_before = a_sent.raw_to("b").len();

    hub.link("a", "b");
    eventually("b catches up", || async {
        b.node.max_group_id_for_test(&gid).unwrap() == high
    })
    .await;

    let mut pages = 0;
    for raw in &a_sent.raw_to("b")[sent_before..] {
        assert!(raw.len() <= MAX_FRAME_LEN);
        let Body::Sequenced(s) = frames::decode(raw).unwrap() else {
            continue;
        };
        assert!(
            s.messages.len() <= 64,
            "page of {} messages",
            s.messages.len()
        );
        let ids: Vec<u64> = s
            .messages
            .iter()
            .map(|m| match &m.version {
                Some(group_message::Version::V1(v1)) => v1.id,
                _ => panic!("expected V1"),
            })
            .collect();
        let data: usize = s
            .messages
            .iter()
            .map(|m| match &m.version {
                Some(group_message::Version::V1(v1)) => v1.data.len(),
                _ => 0,
            })
            .sum();
        assert!(data <= 128 * 1024, "page of {data} bytes");
        assert!(
            ids.windows(2).all(|w| w[1] == w[0] + 1),
            "page out of order: {ids:?}"
        );
        if ids.len() > 1 {
            pages += 1;
        }
    }
    assert!(
        pages >= 4,
        "backlog of 200 served in {pages} multi-message pages"
    );
    eventually("b sees all", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm).len() == 201
    })
    .await;
}
