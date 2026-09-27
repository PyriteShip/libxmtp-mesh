#![recursion_limit = "256"]
mod common;

use std::sync::{Arc, Mutex};

use common::{ClientHelloSigner, build_client, eventually, peer, query_group};
use xmtp_id::associations::verify_signed_with_public_context;
use xmtp_mesh::frames::{self, Auth, Hello, Interest, frame::Body};
use xmtp_mesh::{HelloSigner, LoopbackHub, MeshNode, MeshTransport, PeerId};

#[tokio::test(flavor = "multi_thread")]
async fn linked_peers_authenticate_each_other() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    eventually("mutual auth", || async {
        a.node.authenticated_peers() == vec!["b".to_string()]
            && b.node.authenticated_peers() == vec!["a".to_string()]
    })
    .await;
    hub.unlink("a", "b");
    eventually("sessions dropped", || async {
        a.node.authenticated_peers().is_empty() && b.node.authenticated_peers().is_empty()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn frames_before_auth_are_ignored() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    // a knows the group (as after a client query), so only the missing
    // authentication can stop the pin below.
    query_group(&a.node, b"g").await;
    // A frame from an unknown, unauthenticated "mallory" must not create state.
    hub.inject(
        "mallory",
        "a",
        frames::encode(Body::Interest(Interest {
            group_id: b"g".to_vec(),
            high_id: 0,
            i_am_sequencer: true,
        })),
    );
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(a.node.authenticated_peers().is_empty());
    assert_eq!(a.node.group_sequencer_for_test(b"g").unwrap(), None);
}

/// A frame from b's previous connection reaches a after the link dropped. The
/// session it creates must not wedge the next connection's handshake.
#[tokio::test(flavor = "multi_thread")]
async fn late_frame_after_unlink_does_not_wedge_the_next_link() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    eventually("mutual auth", || async {
        a.node.authenticated_peers() == vec!["b".to_string()]
            && b.node.authenticated_peers() == vec!["a".to_string()]
    })
    .await;
    hub.unlink("a", "b");
    eventually("sessions dropped", || async {
        a.node.authenticated_peers().is_empty() && b.node.authenticated_peers().is_empty()
    })
    .await;

    hub.inject(
        "b",
        "a",
        frames::encode(Body::Interest(Interest {
            group_id: b"g".to_vec(),
            high_id: 0,
            i_am_sequencer: false,
        })),
    );
    // Let the session it spawned send its Hello into the dead link.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    hub.link("a", "b");
    eventually("mutual auth after the late frame", || async {
        a.node.authenticated_peers() == vec!["b".to_string()]
            && b.node.authenticated_peers() == vec!["a".to_string()]
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rapid_relink_reauthenticates_every_time() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    for cycle in 0..5 {
        hub.link("a", "b");
        eventually(&format!("mutual auth, cycle {cycle}"), || async {
            a.node.authenticated_peers() == vec!["b".to_string()]
                && b.node.authenticated_peers() == vec!["a".to_string()]
        })
        .await;
        hub.unlink("a", "b");
        // Relink immediately: stale sessions must not disturb the new handshake.
    }
    // Drop links mid-handshake: stale sessions still hold unsent Hellos and
    // buffered frames that must never reach the next session.
    for _ in 0..20 {
        hub.link("a", "b");
        hub.unlink("a", "b");
    }
    hub.link("a", "b");
    eventually("mutual auth after final relink", || async {
        a.node.authenticated_peers() == vec!["b".to_string()]
            && b.node.authenticated_peers() == vec!["a".to_string()]
    })
    .await;
}

/// Records everything a node sends instead of delivering it.
#[derive(Default)]
struct Recorder {
    sent: Mutex<Vec<(PeerId, Vec<u8>)>>,
    disconnected: Mutex<Vec<PeerId>>,
}

impl MeshTransport for Recorder {
    fn send(&self, peer: &PeerId, frame: Vec<u8>) {
        self.sent.lock().unwrap().push((peer.clone(), frame));
    }
    fn disconnect(&self, peer: &PeerId) {
        self.disconnected.lock().unwrap().push(peer.clone());
    }
}

impl Recorder {
    fn sent_to(&self, peer: &str) -> Vec<Body> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p == peer)
            .map(|(_, f)| frames::decode(f).unwrap())
            .collect()
    }
    fn disconnected(&self, peer: &str) -> bool {
        self.disconnected.lock().unwrap().iter().any(|p| p == peer)
    }
    /// The challenge in the Hello this node sent to `peer`.
    async fn challenge_to(&self, peer: &str) -> Vec<u8> {
        eventually("hello sent", || async {
            self.sent_to(peer)
                .iter()
                .any(|b| matches!(b, Body::Hello(_)))
        })
        .await;
        self.sent_to(peer)
            .into_iter()
            .find_map(|b| match b {
                Body::Hello(h) => Some(h.challenge),
                _ => None,
            })
            .unwrap()
    }
}

/// The wire format of the signed hello text, pinned independently of the
/// crate. Test cleartext links bind 32 zero bytes (no handshake hash).
fn hello_text(challenge: &[u8], signer: &[u8], verifier: &[u8]) -> String {
    format!(
        "xmtp-mesh-hello-v2:{}:{}:{}:{}",
        hex::encode(challenge),
        hex::encode(signer),
        hex::encode(verifier),
        hex::encode([0u8; 32])
    )
}

/// A syncing node attached to `hub` as "a" whose outbound frames are recorded.
async fn recorded_node(hub: &LoopbackHub) -> (MeshNode, Vec<u8>, Arc<Recorder>) {
    let node = MeshNode::in_memory().unwrap();
    hub.register("a", &node);
    let client = build_client(&node).await;
    let key = client.installation_public_key().to_vec();
    let recorder = Arc::new(Recorder::default());
    common::start_sync(&node, &client, recorder.clone());
    (node, key, recorder)
}

fn hello(installation_key: Vec<u8>, challenge: [u8; 32]) -> Vec<u8> {
    frames::encode(Body::Hello(Hello {
        installation_key,
        inbox_id: String::new(),
        challenge: challenge.to_vec(),
        relay: 0,
        seq: frames::SEQ_V1,
        link: frames::LINK_V1,
    }))
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_signed_by_another_key_is_rejected() {
    let hub = LoopbackHub::new();
    let (a, a_key, recorder) = recorded_node(&hub).await;
    let honest = ClientHelloSigner(build_client(&MeshNode::in_memory().unwrap()).await);
    let impostor = ClientHelloSigner(build_client(&MeshNode::in_memory().unwrap()).await);
    let honest_key = honest.installation_key();

    // Control: the honest key holder completes the handshake.
    hub.inject("honest", "a", hello(honest_key.clone(), [7; 32]));
    let challenge = recorder.challenge_to("honest").await;
    let signature = honest
        .sign(&hello_text(&challenge, &honest_key, &a_key))
        .unwrap();
    hub.inject(
        "honest",
        "a",
        frames::encode(Body::Auth(Auth {
            signature,
            challenge: challenge.clone(),
        })),
    );
    eventually("honest authenticated", || async {
        a.authenticated_peers() == vec!["honest".to_string()]
    })
    .await;
    // a's own Auth binds our challenge, a's key (signer) and the honest key (verifier).
    let a_auth = recorder
        .sent_to("honest")
        .into_iter()
        .find_map(|b| match b {
            Body::Auth(auth) => Some(auth.signature),
            _ => None,
        })
        .unwrap();
    verify_signed_with_public_context(
        hello_text(&[7; 32], &a_key, &honest_key),
        a_auth.as_slice().try_into().unwrap(),
        a_key.as_slice().try_into().unwrap(),
    )
    .unwrap();

    // Mallory claims the honest key but can only sign with the impostor's.
    hub.inject("mallory", "a", hello(honest_key.clone(), [9; 32]));
    let challenge = recorder.challenge_to("mallory").await;
    let signature = impostor
        .sign(&hello_text(&challenge, &honest_key, &a_key))
        .unwrap();
    hub.inject(
        "mallory",
        "a",
        frames::encode(Body::Auth(Auth {
            signature,
            challenge: challenge.clone(),
        })),
    );
    eventually("mallory dropped", || async {
        recorder.disconnected("mallory")
    })
    .await;
    assert_eq!(a.authenticated_peers(), vec!["honest".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn reflected_hello_is_rejected() {
    let hub = LoopbackHub::new();
    let (a, a_key, recorder) = recorded_node(&hub).await;
    // Mallory replays a Hello carrying a's own installation key.
    hub.inject("mallory", "a", hello(a_key, [5; 32]));
    eventually("mallory dropped", || async {
        recorder.disconnected("mallory")
    })
    .await;
    assert!(
        !recorder
            .sent_to("mallory")
            .iter()
            .any(|b| matches!(b, Body::Auth(_)))
    );
    assert!(a.authenticated_peers().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn stray_handshake_frames_from_a_previous_connection_are_tolerated() {
    let hub = LoopbackHub::new();
    let (a, a_key, recorder) = recorded_node(&hub).await;
    let peer_signer = ClientHelloSigner(build_client(&MeshNode::in_memory().unwrap()).await);
    let peer_key = peer_signer.installation_key();

    // A stale Hello, then the new connection's Hello: a answers both.
    hub.inject("p", "a", hello(peer_key.clone(), [1; 32]));
    hub.inject("p", "a", hello(peer_key.clone(), [2; 32]));
    let challenge = recorder.challenge_to("p").await;
    eventually("both hellos answered", || async {
        let echoed: Vec<_> = recorder
            .sent_to("p")
            .into_iter()
            .filter_map(|b| match b {
                Body::Auth(auth) => Some(auth.challenge),
                _ => None,
            })
            .collect();
        echoed == vec![vec![1; 32], vec![2; 32]]
    })
    .await;

    // A stale Auth answering some other challenge is ignored, not fatal.
    let stale = peer_signer
        .sign(&hello_text(&[0; 32], &peer_key, &a_key))
        .unwrap();
    hub.inject(
        "p",
        "a",
        frames::encode(Body::Auth(Auth {
            signature: stale,
            challenge: vec![0; 32],
        })),
    );
    let signature = peer_signer
        .sign(&hello_text(&challenge, &peer_key, &a_key))
        .unwrap();
    hub.inject(
        "p",
        "a",
        frames::encode(Body::Auth(Auth {
            signature,
            challenge,
        })),
    );
    eventually("p authenticated", || async {
        a.authenticated_peers() == vec!["p".to_string()]
    })
    .await;
    assert!(!recorder.disconnected("p"));

    // A Hello under the same PeerId but another installation key is fatal.
    let other = ClientHelloSigner(build_client(&MeshNode::in_memory().unwrap()).await);
    hub.inject("p", "a", hello(other.installation_key(), [3; 32]));
    eventually("p dropped", || async { recorder.disconnected("p") }).await;
}

/// A peer that never says Hello, and one that never answers our challenge,
/// are both dropped once the handshake deadline passes.
#[tokio::test(flavor = "multi_thread")]
async fn peer_that_never_completes_the_handshake_is_dropped_at_the_deadline() {
    let hub = LoopbackHub::new();
    let (a, _, recorder) = recorded_node(&hub).await;
    a.set_handshake_timeout_for_test(std::time::Duration::from_millis(300));
    a.connect_plain_for_test("silent");
    hub.inject("mute", "a", hello(vec![3; 32], [4; 32]));
    eventually("both dropped", || async {
        recorder.disconnected("silent") && recorder.disconnected("mute")
    })
    .await;
    assert!(a.authenticated_peers().is_empty());
}

/// Each Hello received while handshaking is answered with our Hello again (the
/// peer may have missed it), at most three times per session.
#[tokio::test(flavor = "multi_thread")]
async fn hello_is_resent_while_handshaking_and_bounded() {
    let hub = LoopbackHub::new();
    let (a, _, recorder) = recorded_node(&hub).await;
    let hellos = || {
        recorder
            .sent_to("p")
            .iter()
            .filter(|b| matches!(b, Body::Hello(_)))
            .count()
    };
    a.connect_plain_for_test("p");
    recorder.challenge_to("p").await;
    for i in 0..5u8 {
        hub.inject("p", "a", hello(vec![3; 32], [i; 32]));
    }
    eventually("all five answered", || async {
        recorder
            .sent_to("p")
            .iter()
            .filter(|b| matches!(b, Body::Auth(_)))
            .count()
            == 5
    })
    .await;
    assert_eq!(hellos(), 1 + 3);
}

/// §B13 hard cut: a Hello without signed sequencing (a mesh.9 phone) ends
/// the session before any Auth, and is counted.
#[tokio::test(flavor = "multi_thread")]
async fn a_hello_without_signed_sequencing_is_refused() {
    let hub = LoopbackHub::new();
    let (a, _a_key, recorder) = recorded_node(&hub).await;
    let old = ClientHelloSigner(build_client(&MeshNode::in_memory().unwrap()).await);
    hub.inject(
        "old",
        "a",
        frames::encode(Body::Hello(Hello {
            installation_key: old.installation_key(),
            inbox_id: String::new(),
            challenge: vec![7; 32],
            relay: 0,
            seq: 0,
            link: frames::LINK_V1,
        })),
    );
    eventually("a disconnects the mesh.9 peer", || async {
        recorder.disconnected("old")
    })
    .await;
    assert_eq!(a.mesh_stats().peers_rejected_version, 1);
    assert!(
        !recorder
            .sent_to("old")
            .iter()
            .any(|b| matches!(b, Body::Auth(_))),
        "no Auth answers a mesh.9 Hello"
    );
}

/// §B14 hard cut: a Hello below link version 1 (a mesh.10 phone) ends the
/// session before any Auth, and is counted.
#[tokio::test(flavor = "multi_thread")]
async fn a_hello_below_the_link_version_is_refused() {
    let hub = LoopbackHub::new();
    let (a, _a_key, recorder) = recorded_node(&hub).await;
    let old = ClientHelloSigner(build_client(&MeshNode::in_memory().unwrap()).await);
    hub.inject(
        "old",
        "a",
        frames::encode(Body::Hello(Hello {
            installation_key: old.installation_key(),
            inbox_id: String::new(),
            challenge: vec![7; 32],
            relay: 0,
            seq: frames::SEQ_V1,
            link: 0,
        })),
    );
    eventually("a disconnects the mesh.10 peer", || async {
        recorder.disconnected("old")
    })
    .await;
    assert_eq!(a.mesh_stats().peers_rejected_version, 1);
    assert!(
        !recorder
            .sent_to("old")
            .iter()
            .any(|b| matches!(b, Body::Auth(_)))
    );
}
