#![recursion_limit = "256"]
//! The surface the mobile bindings use: callbacks from any thread, presence,
//! stopping and restarting sync.
mod common;

use common::{eventually, peer};
use xmtp_mesh::LoopbackHub;
use xmtp_mesh::frames::{self, Interest, frame::Body};

/// The radio calls back on its own (non-tokio) threads.
#[tokio::test(flavor = "multi_thread")]
async fn node_callbacks_work_from_a_plain_thread() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let radio = hub.clone();
    std::thread::spawn(move || {
        radio.link("a", "b"); // on_peer_connected on both nodes
        let interest = Interest {
            group_id: b"g".to_vec(),
            high_id: 0,
            i_am_sequencer: false,
        };
        radio.inject("b", "a", frames::encode(Body::Interest(interest))); // on_frame
    })
    .join()
    .expect("callbacks from a plain thread must not panic");
    eventually("mutual auth", || async {
        a.node.authenticated_peers() == vec!["b".to_string()]
            && b.node.authenticated_peers() == vec!["a".to_string()]
    })
    .await;
}

struct NoSigner;

impl xmtp_mesh::HelloSigner for NoSigner {
    fn installation_key(&self) -> Vec<u8> {
        vec![1; 32]
    }
    fn sign(&self, _: &str) -> Result<Vec<u8>, xmtp_mesh::MeshError> {
        unreachable!()
    }
}

struct NoGroups;

#[async_trait::async_trait]
impl xmtp_mesh::GroupMembership for NoGroups {
    async fn member_inboxes(&self, _: &[u8]) -> Result<Option<Vec<String>>, xmtp_mesh::MeshError> {
        Ok(None)
    }
}

#[test]
fn start_sync_outside_a_runtime_is_an_error() {
    let node = xmtp_mesh::MeshNode::in_memory().unwrap();
    let err = node
        .start_sync(
            std::sync::Arc::new(NoSigner),
            LoopbackHub::new().transport_for("a"),
            std::sync::Arc::new(NoGroups),
        )
        .unwrap_err();
    assert!(matches!(err, xmtp_mesh::MeshError::NoRuntime), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn presence_events_and_verified_peers() {
    use xmtp_mesh::{NodeEvent, VerifiedPeer};
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let mut events = a.node.subscribe_events();
    hub.link("a", "b");
    let expected = VerifiedPeer {
        peer: "b".to_string(),
        inbox_id: b.client.inbox_id().to_string(),
        installation: b.installation(),
    };
    eventually("b verified", || async {
        a.node.verified_peers() == vec![expected.clone()]
    })
    .await;
    hub.unlink("a", "b");
    eventually("b gone", || async { a.node.verified_peers().is_empty() }).await;

    let mut seen = vec![];
    while let Ok(event) = events.try_recv() {
        match event {
            NodeEvent::PeerVerified {
                peer,
                inbox_id,
                installation,
            } => seen.push(format!(
                "verified {peer} {} {}",
                inbox_id == expected.inbox_id,
                installation == expected.installation
            )),
            NodeEvent::PeerLost { peer } => seen.push(format!("lost {peer}")),
            _ => {}
        }
    }
    assert_eq!(
        seen,
        vec!["verified b true true".to_string(), "lost b".to_string()]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_sync_then_restart_with_a_new_transport() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    eventually("mutual auth", || async {
        a.node.authenticated_peers().len() == 1 && b.node.authenticated_peers().len() == 1
    })
    .await;

    a.node.stop_sync();
    assert!(a.node.authenticated_peers().is_empty());
    assert!(a.node.verified_peers().is_empty());
    // Frames for a stopped node go nowhere (no session is created).
    hub.unlink("a", "b");
    hub.link("a", "b");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(a.node.authenticated_peers().is_empty());
    b.node.stop_sync();

    let radio = LoopbackHub::new();
    radio.register("a", &a.node);
    radio.register("b", &b.node);
    common::restart_sync(&a, radio.transport_for("a"));
    common::restart_sync(&b, radio.transport_for("b"));
    radio.link("a", "b");
    eventually("mutual auth over the new transport", || async {
        a.node.authenticated_peers() == vec!["b".to_string()]
            && b.node.authenticated_peers() == vec!["a".to_string()]
    })
    .await;
}

/// Per the transport contract every new connection gets a fresh `PeerId`
/// (e.g. "b#2"), even to the same device. A relink under fresh ids
/// re-authenticates and re-verifies both sides, drops the old ids from
/// presence, and group sync resumes over the new pipe.
#[tokio::test(flavor = "multi_thread")]
async fn relink_under_fresh_peer_ids_reauthenticates() {
    use common::app_payloads;
    use xmtp_db::group::GroupQueryArgs;
    use xmtp_mls::groups::send_message_opts::SendMessageOpts;
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
    eventually("b sees hi", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm) == vec![b"hi".to_vec()]
    })
    .await;

    // The connection drops; the radio reconnects the same two devices under
    // fresh connection-scoped ids.
    hub.unlink("a", "b");
    eventually("old ids gone", || async {
        a.node.verified_peers().is_empty() && b.node.verified_peers().is_empty()
    })
    .await;
    for (p, id) in [(&a, "a#2"), (&b, "b#2")] {
        p.node.stop_sync();
        hub.register(id, &p.node);
        common::restart_sync(p, hub.transport_for(id));
    }
    hub.link("a#2", "b#2");
    eventually("re-verified under the new ids", || async {
        let a_sees = a.node.verified_peers();
        let b_sees = b.node.verified_peers();
        a_sees.len() == 1
            && a_sees[0].peer == "b#2"
            && a_sees[0].inbox_id == b.client.inbox_id()
            && b_sees.len() == 1
            && b_sees[0].peer == "a#2"
            && b_sees[0].installation == a.installation()
    })
    .await;
    assert_eq!(a.node.authenticated_peers(), vec!["b#2".to_string()]);

    a_dm.send_message(b"again", SendMessageOpts::default())
        .await
        .unwrap();
    eventually("b sees again", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm) == vec![b"hi".to_vec(), b"again".to_vec()]
    })
    .await;
}
