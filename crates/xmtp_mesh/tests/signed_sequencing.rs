#![recursion_limit = "256"]
//! Signed sequencing records (DESIGN.md §B13): every stored row carries a
//! proof by the installation that ordered it, checked before it is stored.
mod common;

use common::{
    TestPeer, a1_created_dm, build_client, carried_node, eventually, eventually_for, pair_dm, peer,
    peer_on, recorded_peer, relay_keys_confirmed, relay_peer, restart_sync,
    revoke_all_other_installations, send_and_see, start_sync,
};
use xmtp_cryptography::utils::generate_local_wallet;
use xmtp_cryptography::{CredentialSign, XmtpInstallationCredential};
use xmtp_db::group::GroupQueryArgs;
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

/// §B13 rule 3 with the §C4.7 handover: A1 sequenced the DM, then was
/// revoked and b took over. Re-pinning to itself, b attests every row it
/// holds that A1 ordered, so A2, the owner's new installation, fetches the
/// whole history under b's key alone: b's attestations for A1's rows, then
/// b's own rows. A row A1 signs at a new id is refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_installation_gets_the_successors_attested_history_after_a_handover() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let (a, b, b_dm) = a1_created_dm(&hub, &wallet).await;
    let gid = b_dm.group_id.clone();
    let inbox = a.client.inbox_id().to_string();
    let a1_high = b.node.max_group_id_for_test(&gid).unwrap();
    assert!(a1_high > 0);
    hub.unlink("a", "b");
    a.node.stop_sync();
    let a2 = peer_on(&hub, "a2", carried_node(&a.node, &inbox).await, &wallet).await;
    revoke_all_other_installations(&a2, &wallet).await;
    hub.link("a2", "b");
    eventually("b takes over sequencing", || async {
        b.node.group_sequencer_for_test(&gid).unwrap() == Some(b.installation())
    })
    .await;
    eventually("b has a2's key package", || async {
        b.node.has_key_package(&a2.installation()).unwrap()
    })
    .await;
    b_dm.update_installations().await.unwrap();
    b_dm.send_message(b"after the handover", SendMessageOpts::default())
        .await
        .unwrap();
    eventually("a2 joins", || async {
        a2.client.sync_welcomes().await.ok();
        a2.client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .iter()
            .any(|g| g.group_id == gid)
    })
    .await;
    eventually("a2 holds all of b's rows", || async {
        a2.client.group(&gid).unwrap().sync().await.ok();
        a2.node.max_group_id_for_test(&gid).unwrap() == b.node.max_group_id_for_test(&gid).unwrap()
    })
    .await;

    let rows = a2.node.sequenced_rows_for_test(&gid).unwrap();
    assert_eq!(rows[0].id, 1, "a2 fetched the history from the start");
    assert!(rows.last().unwrap().id > a1_high, "b sequenced rows too");
    let b_key = b.installation();
    for row in &rows {
        assert_eq!(row.seq_signer.as_ref(), Some(&b_key), "row {}", row.id);
        assert_eq!(
            row.seq_attested,
            row.id <= a1_high,
            "row {}: attested iff A1 ordered it",
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
    assert_eq!(rejections(&a2.node.mesh_stats()), 0);
    assert_eq!(a2.node.group_sequencer_for_test(&gid).unwrap(), Some(b_key));

    let have = a2.node.max_group_id_for_test(&gid).unwrap();
    let late = StoredGroupMessage {
        id: have + 1,
        created_ns: rows.last().unwrap().created_ns + 1,
        data: b"the revoked phone orders again".to_vec(),
        ..rows.last().unwrap().clone()
    };
    let proof = seq::sign_row(
        &ClientHelloSigner(a.client.clone()),
        &gid,
        late.id as u64,
        late.created_ns as u64,
        &late.data,
    )
    .unwrap();
    hub.inject("b", "a2", sequenced(&gid, &[late], vec![proof]));
    eventually("a2 ends the session", || async {
        !hub.is_linked("a2", "b")
    })
    .await;
    assert_eq!(a2.node.max_group_id_for_test(&gid).unwrap(), have);
    let stats = a2.node.mesh_stats();
    assert_eq!(stats.seq_rejected_wrong_signer, 1, "{stats:?}");
    assert_eq!(rejections(&stats), 1, "{stats:?}");
}

/// §B13 rule 4: the sequencer's key signs a second payload for an id b
/// holds; b keeps both records and signatures and ends the session.
#[tokio::test(flavor = "multi_thread")]
async fn one_signer_two_payloads_at_one_id_is_kept_as_equivocation() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let (a_dm, _) = pair_dm(&hub, &a, &b).await;
    let gid = a_dm.group_id.clone();
    eventually("b holds all of a's rows", || async {
        b.node.max_group_id_for_test(&gid).unwrap() == a.node.max_group_id_for_test(&gid).unwrap()
    })
    .await;
    let held = b.node.sequenced_rows_for_test(&gid).unwrap().pop().unwrap();
    let forged = StoredGroupMessage {
        data: b"a second payload for the same id".to_vec(),
        ..held.clone()
    };
    let proof = seq::sign_row(
        &ClientHelloSigner(a.client.clone()),
        &gid,
        forged.id as u64,
        forged.created_ns as u64,
        &forged.data,
    )
    .unwrap();
    hub.inject("a", "b", sequenced(&gid, &[forged], vec![proof.clone()]));
    eventually("b ends the session", || async { !hub.is_linked("a", "b") }).await;
    let kept = b.node.equivocations_for_test(&gid).unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!((kept[0].id, &kept[0].signer), (held.id, &a.installation()));
    assert_eq!(kept[0].signature_a, held.seq_signature.clone().unwrap());
    assert_eq!(kept[0].signature_b, proof.signature);
    assert_eq!(
        (kept[0].attested_a, kept[0].attested_b),
        (false, false),
        "neither record is an upgrade attestation"
    );
    assert_eq!(
        b.node
            .sequenced_rows_for_test(&gid)
            .unwrap()
            .last()
            .unwrap()
            .data,
        held.data,
        "the stored row stays"
    );
    assert_eq!(b.node.mesh_stats().seq_equivocations, 1);
}

/// §B13 rule 4 over relay: the sequencer's retries re-send rows the joiner
/// already holds (its acks are lost). They are duplicates, not rejections.
#[tokio::test(flavor = "multi_thread")]
async fn relay_retries_of_held_rows_are_not_rejections() {
    let hub = LoopbackHub::new();
    let (a, _) = relay_peer(&hub, "a").await;
    let (b, _) = relay_peer(&hub, "b").await;
    let (d, _) = relay_peer(&hub, "d").await;
    let (a_dm, _) = pair_dm(&hub, &a, &d).await;
    let gid = a_dm.group_id.clone();
    relay_keys_confirmed(&a, &d, &gid).await;
    hub.unlink("a", "d");
    hub.link("a", "b");
    hub.link("b", "d");
    d.node.relay_drop_pure_acks_for_test(true);
    a_dm.send_message(b"acked late", SendMessageOpts::default())
        .await
        .ok();
    eventually_for("d holds all of a's rows", 30, || async {
        d.node.max_group_id_for_test(&gid).unwrap() == a.node.max_group_id_for_test(&gid).unwrap()
    })
    .await;
    let delivered = d.node.relay_stats().delivered;
    eventually_for("a re-sends rows d already holds", 30, || async {
        d.node.relay_stats().delivered >= delivered + 2
    })
    .await;
    let stats = d.node.mesh_stats();
    assert_eq!(rejections(&stats), 0, "{stats:?}");
    assert!(d.node.equivocations_for_test(&gid).unwrap().is_empty());
    drop(b);
}

/// §B13 upgrade, pinned end to end over a session: both sides hold rows the
/// migration would leave without a proof and mark legacy, the joiner
/// behind the sequencer. `start_sync` on each attests its own held history
/// before either can serve or accept anything; the joiner then fetches
/// what it is missing under the sequencer's attested proofs, and nothing
/// is rejected.
#[tokio::test(flavor = "multi_thread")]
async fn an_upgrade_over_a_session_fetches_attested_history_with_nothing_rejected() {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let b = peer(&hub, "b").await;
    let (a_dm, _b_dm) = pair_dm(&hub, &a, &b).await;
    let gid = a_dm.group_id.clone();
    eventually("b holds all of a's rows", || async {
        b.node.max_group_id_for_test(&gid).unwrap() == a.node.max_group_id_for_test(&gid).unwrap()
    })
    .await;

    // a orders two more rows b never sees before the upgrade.
    hub.unlink("a", "b");
    for text in [b"two".as_slice(), b"three"] {
        a_dm.send_message(text, SendMessageOpts::default())
            .await
            .unwrap();
    }
    let a_high = a.node.max_group_id_for_test(&gid).unwrap();
    let b_high = b.node.max_group_id_for_test(&gid).unwrap();
    assert!(a_high > b_high);

    // Both sides now look as the signed-sequencing migration would leave
    // data older than it: every stored row loses its proof and is marked
    // legacy (§B13; `store::tests` covers the migration's own `UPDATE`).
    a.node.stop_sync();
    b.node.stop_sync();
    a.node.mark_rows_legacy_for_test(&gid).unwrap();
    b.node.mark_rows_legacy_for_test(&gid).unwrap();
    for row in a.node.sequenced_rows_for_test(&gid).unwrap() {
        assert_eq!((row.seq_signer, row.seq_signature), (None, None));
    }

    // start_sync's backfill attests each side's own held rows as its own
    // history before the reconnect below can serve or accept any of them.
    restart_sync(&a, hub.transport_for("a"));
    restart_sync(&b, hub.transport_for("b"));
    hub.link("a", "b");

    eventually("b fetches what it was missing", || async {
        b.node.max_group_id_for_test(&gid).unwrap() == a_high
    })
    .await;

    let a_key = a.installation();
    let b_key = b.installation();
    let rows = b.node.sequenced_rows_for_test(&gid).unwrap();
    for row in &rows {
        assert!(
            row.seq_attested,
            "row {}: legacy history is attested, not freshly sequenced",
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
        let expected = if row.id > b_high { &a_key } else { &b_key };
        assert_eq!(
            row.seq_signer.as_deref(),
            Some(expected.as_slice()),
            "row {}: {}",
            row.id,
            if row.id > b_high {
                "fetched under the sequencer's attestation"
            } else {
                "b's own pre-existing row keeps its own attestation"
            }
        );
    }
    assert_eq!(
        rejections(&a.node.mesh_stats()),
        0,
        "{:?}",
        a.node.mesh_stats()
    );
    assert_eq!(
        rejections(&b.node.mesh_stats()),
        0,
        "{:?}",
        b.node.mesh_stats()
    );
    assert_eq!(b.node.group_sequencer_for_test(&gid).unwrap(), Some(a_key));
}
