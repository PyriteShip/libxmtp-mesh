#![recursion_limit = "256"]
mod common;

use std::time::Duration;

use bytes::Bytes;
use common::{TestPeer, eventually, peer};
use http::{request, uri::PathAndQuery};
use prost::Message;
use xmtp_mesh::LoopbackHub;
use xmtp_mesh::frames::{self, KeyPackage, frame::Body};
use xmtp_proto::api::Client;
use xmtp_proto::mls_v1::{FetchKeyPackagesRequest, FetchKeyPackagesResponse};

fn authenticated(p: &TestPeer, other: &str) -> bool {
    p.node.authenticated_peers().contains(&other.to_string())
}

/// `p`'s own key package, as its node serves it.
async fn served_key_package(p: &TestPeer) -> Vec<u8> {
    let req = FetchKeyPackagesRequest {
        installation_keys: vec![p.installation()],
    };
    let path =
        PathAndQuery::try_from(xmtp_proto::path_and_query::<FetchKeyPackagesRequest>().as_ref())
            .unwrap();
    let res = p
        .node
        .request(
            request::Builder::new(),
            path,
            Bytes::from(req.encode_to_vec()),
        )
        .await
        .unwrap();
    let mut res = FetchKeyPackagesResponse::decode(res.into_body()).unwrap();
    res.key_packages.remove(0).key_package_tls_serialized
}

#[tokio::test(flavor = "multi_thread")]
async fn linked_nodes_learn_each_others_identity_and_key_package() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    eventually("key packages exchanged", || async {
        a.node.has_key_package(&b.installation()).unwrap()
            && b.node.has_key_package(&a.installation()).unwrap()
    })
    .await;
    assert!(authenticated(&a, "b") && authenticated(&b, "a"));
    // a's client can now resolve b's inbox state offline, through a's node
    let state = a
        .client
        .identity_updates()
        .get_latest_association_state(&a.client.context.db(), b.client.inbox_id())
        .await
        .unwrap();
    assert!(state.installation_ids().contains(&b.installation()));
}

#[tokio::test(flavor = "multi_thread")]
async fn impostor_installation_is_disconnected() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let mallory = peer(&hub, "mallory").await;
    // mallory claims to be b's inbox but signs with its own installation key
    mallory.node.set_local_inbox_for_test(b.client.inbox_id());
    hub.link("a", "b"); // a learns b's real log
    eventually("a knows b", || async {
        a.node.has_key_package(&b.installation()).unwrap()
    })
    .await;
    hub.link("a", "mallory");
    // Only a disconnect removes the link.
    eventually("mallory disconnected", || async {
        !hub.is_linked("a", "mallory")
    })
    .await;
    assert!(!authenticated(&a, "mallory"));
    assert!(authenticated(&a, "b"));
}

#[tokio::test(flavor = "multi_thread")]
async fn silent_impostor_is_disconnected_at_the_deadline() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let mallory = peer(&hub, "mallory").await;
    a.node
        .set_peer_verify_timeout_for_test(Duration::from_millis(500));
    // mallory claims b's inbox and never sends an identity log to disprove it.
    mallory.node.set_local_inbox_for_test(b.client.inbox_id());
    mallory.node.suppress_identity_log_for_test();
    hub.link("a", "b");
    eventually("a knows b", || async {
        a.node.has_key_package(&b.installation()).unwrap()
    })
    .await;
    hub.link("a", "mallory");
    eventually("mallory authenticated", || async {
        authenticated(&a, "mallory")
    })
    .await;
    eventually("mallory disconnected", || async {
        !hub.is_linked("a", "mallory")
    })
    .await;
    assert!(!authenticated(&a, "mallory"));
    // b proved membership, so the deadline (long past) left it alone.
    assert!(hub.is_linked("a", "b") && authenticated(&a, "b"));
}

#[tokio::test(flavor = "multi_thread")]
async fn key_package_for_another_installation_is_ignored() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let x = peer(&hub, "x").await;
    let b_key_package = served_key_package(&b).await;
    hub.link("a", "x");
    eventually("a knows x", || async {
        a.node.has_key_package(&x.installation()).unwrap()
    })
    .await;
    // x relays b's genuine key package to a.
    hub.inject(
        "x",
        "a",
        frames::encode(Body::KeyPackage(KeyPackage {
            installation_key: b.installation(),
            key_package: b_key_package,
        })),
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!a.node.has_key_package(&b.installation()).unwrap());
    assert!(hub.is_linked("a", "x"), "ignored, not fatal");
}

/// Sessions exchange each other's identity logs only (spec §5): a log for a
/// third inbox, relayed by a verified peer, is ignored.
#[tokio::test(flavor = "multi_thread")]
async fn identity_log_of_a_third_inbox_is_ignored() {
    use xmtp_mesh::frames::IdentityLog;
    use xmtp_proto::xmtp::identity::api::v1::{
        GetIdentityUpdatesRequest, GetIdentityUpdatesResponse, get_identity_updates_request,
    };
    async fn log_of(
        node: &xmtp_mesh::MeshNode,
        inbox_id: &str,
    ) -> Vec<xmtp_proto::xmtp::identity::api::v1::get_identity_updates_response::IdentityUpdateLog>
    {
        let req = GetIdentityUpdatesRequest {
            requests: vec![get_identity_updates_request::Request {
                inbox_id: inbox_id.to_string(),
                sequence_id: 0,
            }],
        };
        let path = PathAndQuery::try_from(
            xmtp_proto::path_and_query::<GetIdentityUpdatesRequest>().as_ref(),
        )
        .unwrap();
        let res = node
            .request(
                request::Builder::new(),
                path,
                Bytes::from(req.encode_to_vec()),
            )
            .await
            .unwrap();
        GetIdentityUpdatesResponse::decode(res.into_body())
            .unwrap()
            .responses
            .remove(0)
            .updates
    }

    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let x = peer(&hub, "x").await;
    hub.link("a", "x");
    eventually("a knows x", || async {
        a.node.has_key_package(&x.installation()).unwrap()
    })
    .await;
    let b_log = log_of(&b.node, b.client.inbox_id()).await;
    assert!(!b_log.is_empty());
    let frame = IdentityLog {
        inbox_id: b.client.inbox_id().to_string(),
        updates: b_log,
    };
    hub.inject("x", "a", frames::encode(Body::IdentityLog(frame)));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        log_of(&a.node, b.client.inbox_id()).await.is_empty(),
        "a stored a third inbox's log"
    );
    assert!(hub.is_linked("a", "x"), "ignored, not fatal");
}
