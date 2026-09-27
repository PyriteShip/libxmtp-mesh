#![recursion_limit = "256"]
//! Signed sequencing records (DESIGN.md §B13): every stored row carries a
//! proof by the installation that ordered it, checked before it is stored.
mod common;

use common::{
    TestPeer, build_client, eventually, pair_dm, peer, recorded_peer, send_and_see, start_sync,
};
use xmtp_cryptography::{CredentialSign, XmtpInstallationCredential};
use xmtp_mesh::frames::{self, Sequenced, frame::Body};
use xmtp_mesh::sync::seq::{self, SeqProof};
use xmtp_mesh::{
    ClientHelloSigner, HelloSigner, LoopbackHub, MeshError, MeshNode, MeshStats, StoredGroupMessage,
};
use xmtp_mls::groups::send_message_opts::SendMessageOpts;

/// A client that publishes before its node ever starts syncing (offline
/// use): its rows are signed by `start_sync`, later ones as they are sequenced.
#[tokio::test(flavor = "multi_thread")]
async fn rows_sequenced_before_start_sync_are_signed_when_it_starts() {
    let hub = LoopbackHub::new();
    let node = MeshNode::in_memory().unwrap();
    hub.register("a", &node);
    let client = build_client(&node).await;
    let group = client.create_group(None, None).unwrap();
    group
        .send_message(b"one", SendMessageOpts::default())
        .await
        .unwrap();
    let gid = group.group_id.clone();
    let before = node.sequenced_rows_for_test(&gid).unwrap();
    assert!(!before.is_empty());
    assert!(
        before.iter().all(|r| r.seq_signer.is_none()),
        "no signer before start_sync"
    );

    start_sync(&node, &client, hub.transport_for("a"));
    group
        .send_message(b"two", SendMessageOpts::default())
        .await
        .unwrap();

    let key = client.installation_public_key().to_vec();
    let rows = node.sequenced_rows_for_test(&gid).unwrap();
    assert!(rows.len() > before.len());
    for row in &rows {
        assert_eq!(
            row.seq_signer.as_deref(),
            Some(key.as_slice()),
            "row {}",
            row.id
        );
        assert!(
            seq::verify_proof(
                &gid,
                row.id as u64,
                row.created_ns as u64,
                &row.data,
                &row.proof()
            ),
            "row {}",
            row.id
        );
    }
    assert_eq!(node.mesh_stats().seq_rows_signed, rows.len() as u64);
}

/// An installation key no member's log lists.
struct Stranger(XmtpInstallationCredential);

impl HelloSigner for Stranger {
    fn installation_key(&self) -> Vec<u8> {
        self.0.public_slice().to_vec()
    }

    fn sign(&self, text: &str) -> Result<Vec<u8>, MeshError> {
        self.0
            .credential_sign::<xmtp_id::associations::signature::PublicContext>(text)
            .map_err(|e| MeshError::AuthFailed(e.to_string()))
    }
}

fn sequenced(gid: &[u8], rows: &[StoredGroupMessage], proofs: Vec<SeqProof>) -> Vec<u8> {
    frames::encode(Body::Sequenced(Sequenced {
        group_id: gid.to_vec(),
        messages: rows.iter().map(StoredGroupMessage::to_proto).collect(),
        sender_is_sequencer: true,
        proofs,
    }))
}

fn proofs(rows: &[StoredGroupMessage]) -> Vec<SeqProof> {
    rows.iter().map(StoredGroupMessage::proof).collect()
}

fn rejections(s: &MeshStats) -> u64 {
    s.seq_rejected_missing_proof
        + s.seq_rejected_bad_signature
        + s.seq_rejected_wrong_signer
        + s.seq_equivocations
}

/// `a` sequences a DM with `b`; then `a` sequences two rows it does not
/// push, so a frame carrying them can be tampered with and injected.
struct Unsent {
    hub: LoopbackHub,
    a: TestPeer,
    b: TestPeer,
    gid: Vec<u8>,
    b_high: i64,
    rows: Vec<StoredGroupMessage>,
}

async fn two_unsent_rows() -> Unsent {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let (a_dm, _b_dm) = pair_dm(&hub, &a, &b).await;
    let gid = a_dm.group_id.clone();
    eventually("b holds all of a's rows", || async {
        b.node.max_group_id_for_test(&gid).unwrap() == a.node.max_group_id_for_test(&gid).unwrap()
    })
    .await;
    a.node.suppress_group_push_for_test(true);
    let b_high = b.node.max_group_id_for_test(&gid).unwrap();
    for text in [b"one".as_slice(), b"two"] {
        a_dm.send_message(text, SendMessageOpts::default())
            .await
            .unwrap();
    }
    let rows: Vec<StoredGroupMessage> = a
        .node
        .sequenced_rows_for_test(&gid)
        .unwrap()
        .into_iter()
        .filter(|r| r.id > b_high)
        .take(2)
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        b.node.max_group_id_for_test(&gid).unwrap(),
        b_high,
        "pushes are suppressed"
    );
    Unsent {
        hub,
        a,
        b,
        gid,
        b_high,
        rows,
    }
}

/// A tampered frame is refused, counted once under `reason`, the session
/// ends and b (so its client) holds none of the rows.
async fn assert_refused(u: &Unsent, frame: Vec<u8>, reason: fn(&MeshStats) -> u64) {
    assert!(u.hub.is_linked("a", "b"));
    u.hub.inject("a", "b", frame);
    eventually("b ends the session", || async {
        !u.hub.is_linked("a", "b")
    })
    .await;
    assert_eq!(u.b.node.max_group_id_for_test(&u.gid).unwrap(), u.b_high);
    let stats = u.b.node.mesh_stats();
    assert_eq!(reason(&stats), 1, "{stats:?}");
    assert_eq!(rejections(&stats), 1, "{stats:?}");
}

/// Round trip (§B13): served history and the live push both carry one
/// proof per message, and b stores each row with it.
#[tokio::test(flavor = "multi_thread")]
async fn every_sequenced_frame_carries_one_proof_per_message() {
    let hub = LoopbackHub::new();
    let (a, a_sent) = recorded_peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let (a_dm, b_dm) = pair_dm(&hub, &a, &b).await;
    send_and_see(&a_dm, &b_dm, "live").await;
    let gid = a_dm.group_id.clone();
    eventually("b holds all of a's rows", || async {
        b.node.max_group_id_for_test(&gid).unwrap() == a.node.max_group_id_for_test(&gid).unwrap()
    })
    .await;
    let key = a.installation();
    let rows = b.node.sequenced_rows_for_test(&gid).unwrap();
    for row in &rows {
        assert_eq!(
            row.seq_signer.as_deref(),
            Some(key.as_slice()),
            "row {}",
            row.id
        );
        assert!(seq::verify_proof(
            &gid,
            row.id as u64,
            row.created_ns as u64,
            &row.data,
            &row.proof()
        ));
    }
    let frames: Vec<Sequenced> = a_sent
        .sent_to("b")
        .into_iter()
        .filter_map(|body| match body {
            Body::Sequenced(s) if !s.messages.is_empty() => Some(s),
            _ => None,
        })
        .collect();
    assert!(!frames.is_empty());
    for s in &frames {
        assert_eq!(s.proofs.len(), s.messages.len());
        assert!(s.proofs.iter().all(|p| p.signer == key));
    }
    assert!(a.node.mesh_stats().seq_rows_signed >= rows.len() as u64);
    assert_eq!(b.node.mesh_stats().seq_rows_verified, rows.len() as u64);
    assert_eq!(
        rejections(&a.node.mesh_stats()) + rejections(&b.node.mesh_stats()),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_untampered_frame_is_stored() {
    let u = two_unsent_rows().await;
    let verified = u.b.node.mesh_stats().seq_rows_verified;
    u.hub
        .inject("a", "b", sequenced(&u.gid, &u.rows, proofs(&u.rows)));
    eventually("b stores both rows", || async {
        u.b.node.max_group_id_for_test(&u.gid).unwrap() == u.b_high + 2
    })
    .await;
    assert_eq!(u.b.node.mesh_stats().seq_rows_verified, verified + 2);
    assert!(u.hub.is_linked("a", "b"));
    let _ = &u.a;
}

#[tokio::test(flavor = "multi_thread")]
async fn swapping_two_rows_ids_is_a_bad_signature() {
    let u = two_unsent_rows().await;
    let mut swapped = u.rows.clone();
    (swapped[0].id, swapped[1].id) = (u.rows[1].id, u.rows[0].id);
    swapped.swap(0, 1);
    let p = proofs(&swapped);
    assert_refused(&u, sequenced(&u.gid, &swapped, p), |s| {
        s.seq_rejected_bad_signature
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn changed_data_is_a_bad_signature() {
    let u = two_unsent_rows().await;
    let mut rows = u.rows.clone();
    let last = rows[0].data.len() - 1;
    rows[0].data[last] ^= 1;
    assert_refused(&u, sequenced(&u.gid, &rows, proofs(&u.rows)), |s| {
        s.seq_rejected_bad_signature
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_changed_created_ns_is_a_bad_signature() {
    let u = two_unsent_rows().await;
    let mut rows = u.rows.clone();
    rows[1].created_ns += 1;
    assert_refused(&u, sequenced(&u.gid, &rows, proofs(&u.rows)), |s| {
        s.seq_rejected_bad_signature
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_proofs_are_missing_proof() {
    let u = two_unsent_rows().await;
    assert_refused(&u, sequenced(&u.gid, &u.rows, vec![]), |s| {
        s.seq_rejected_missing_proof
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_valid_proof_from_another_group_is_a_bad_signature() {
    let u = two_unsent_rows().await;
    let signer = ClientHelloSigner(u.a.client.clone());
    let p = u
        .rows
        .iter()
        .map(|r| {
            seq::sign_row(
                &signer,
                b"another group",
                r.id as u64,
                r.created_ns as u64,
                &r.data,
            )
            .unwrap()
        })
        .collect();
    assert_refused(&u, sequenced(&u.gid, &u.rows, p), |s| {
        s.seq_rejected_bad_signature
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_valid_proof_replayed_on_another_row_is_a_bad_signature() {
    let u = two_unsent_rows().await;
    let first = u.rows[0].proof();
    assert_refused(
        &u,
        sequenced(&u.gid, &u.rows, vec![first.clone(), first]),
        |s| s.seq_rejected_bad_signature,
    )
    .await;
}

/// §B13 rule 2: a signer no member inbox's log lists.
#[tokio::test(flavor = "multi_thread")]
async fn a_signer_no_member_log_lists_is_a_wrong_signer() {
    let u = two_unsent_rows().await;
    let stranger = Stranger(XmtpInstallationCredential::new());
    let p = u
        .rows
        .iter()
        .map(|r| {
            seq::sign_row(&stranger, &u.gid, r.id as u64, r.created_ns as u64, &r.data).unwrap()
        })
        .collect();
    assert_refused(&u, sequenced(&u.gid, &u.rows, p), |s| {
        s.seq_rejected_wrong_signer
    })
    .await;
}
