use super::*;

fn msg(gid: &[u8], data: &[u8]) -> NewGroupMessage {
    NewGroupMessage {
        group_id: gid.to_vec(),
        data: data.to_vec(),
        sender_hmac: vec![9],
        should_push: true,
        is_commit: false,
    }
}

#[test]
fn append_sequenced_assigns_contiguous_ids_and_dedupes() {
    let mut s = MeshStore::open_in_memory().unwrap();
    let (a, new_a) = s.append_sequenced(&msg(b"g", b"one"), 10).unwrap();
    let (b, new_b) = s.append_sequenced(&msg(b"g", b"two"), 11).unwrap();
    let (a2, new_a2) = s.append_sequenced(&msg(b"g", b"one"), 12).unwrap();
    assert_eq!((a.id, b.id), (1, 2));
    assert!(new_a && new_b && !new_a2);
    assert_eq!(a2, a);
    assert_eq!(s.max_group_id(b"g").unwrap(), 2);
    assert_eq!(s.max_group_id(b"other").unwrap(), 0);
}

#[test]
fn query_group_pages_ascending_and_descending() {
    let mut s = MeshStore::open_in_memory().unwrap();
    for i in 0..5u8 {
        s.append_sequenced(&msg(b"g", &[i]), i as i64).unwrap();
    }
    let ids = |v: Vec<StoredGroupMessage>| v.into_iter().map(|m| m.id).collect::<Vec<_>>();
    assert_eq!(
        ids(s.query_group(b"g", 0, 100, false).unwrap()),
        vec![1, 2, 3, 4, 5]
    );
    assert_eq!(ids(s.query_group(b"g", 2, 2, false).unwrap()), vec![3, 4]);
    assert_eq!(ids(s.query_group(b"g", 0, 1, true).unwrap()), vec![5]);
    assert_eq!(
        ids(s.query_group(b"g", 4, 10, true).unwrap()),
        vec![3, 2, 1]
    );
}

#[test]
fn insert_sequenced_detects_gap() {
    let mut s = MeshStore::open_in_memory().unwrap();
    let (one, _) = s.append_sequenced(&msg(b"g", b"one"), 1).unwrap();
    let mut three = one.clone();
    three.id = 3;
    three.data = b"three".to_vec();
    assert_eq!(
        s.insert_sequenced(&three).unwrap(),
        InsertOutcome::Gap { have: 1 }
    );
    assert_eq!(s.insert_sequenced(&one).unwrap(), InsertOutcome::Duplicate);
    let mut two = three.clone();
    two.id = 2;
    assert_eq!(s.insert_sequenced(&two).unwrap(), InsertOutcome::Inserted);
    assert_eq!(s.max_group_id(b"g").unwrap(), 2);
}

#[test]
fn pending_round_trip() {
    let mut s = MeshStore::open_in_memory().unwrap();
    s.add_pending(&msg(b"g", b"p1"), 1).unwrap();
    s.add_pending(&msg(b"g", b"p1"), 2).unwrap(); // duplicate ignored
    s.add_pending(&msg(b"g", b"p2"), 3).unwrap();
    let pending = s.pending_for(b"g").unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].data, b"p1");
    s.remove_pending(b"g", &sha256(b"p1")).unwrap();
    assert_eq!(s.pending_for(b"g").unwrap().len(), 1);
}

#[test]
fn sequencer_is_pinned_once() {
    let mut s = MeshStore::open_in_memory().unwrap();
    assert!(s.ensure_group(b"g").unwrap());
    assert!(!s.ensure_group(b"g").unwrap());
    assert_eq!(s.sequencer(b"g").unwrap(), None);
    assert_eq!(s.pin_sequencer(b"g", b"A").unwrap(), b"A".to_vec());
    assert_eq!(s.pin_sequencer(b"g", b"B").unwrap(), b"A".to_vec());
    assert_eq!(s.known_groups().unwrap(), vec![b"g".to_vec()]);
}

#[test]
fn identity_log_is_contiguous() {
    let mut s = MeshStore::open_in_memory().unwrap();
    s.append_identity("inbox", 1, 100, b"u1").unwrap();
    let err = s.append_identity("inbox", 3, 100, b"u3").unwrap_err();
    assert!(matches!(
        err,
        MeshError::IdentityConflict {
            expected: 2,
            got: 3,
            ..
        }
    ));
    s.append_identity("inbox", 2, 101, b"u2").unwrap();
    let rows = s.identity_rows("inbox", 1).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].update_bytes, b"u2");
    s.set_identifier("0xabc", 1, "inbox").unwrap();
    assert_eq!(
        s.inbox_for_identifier("0xabc", 1).unwrap().as_deref(),
        Some("inbox")
    );
    assert_eq!(s.inbox_for_identifier("0xabc", 2).unwrap(), None);
}

#[test]
fn welcomes_dedupe_and_page() {
    let mut s = MeshStore::open_in_memory().unwrap();
    assert!(s.append_welcome(b"I", b"h1", b"w1", 1).unwrap().is_some());
    assert!(s.append_welcome(b"I", b"h1", b"w1", 2).unwrap().is_none());
    s.append_welcome(b"I", b"h2", b"w2", 3).unwrap();
    let page = s.query_welcomes(b"I", 1, 10).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].input, b"w2");
    s.add_outbound_welcome(b"h3", b"J", b"w3").unwrap();
    assert_eq!(
        s.outbound_welcomes_for(b"J").unwrap(),
        vec![(b"h3".to_vec(), b"w3".to_vec())]
    );
    assert!(
        !s.remove_outbound_welcome_for(b"K", b"h3").unwrap(),
        "not K's"
    );
    assert_eq!(s.outbound_welcomes_for(b"J").unwrap().len(), 1);
    assert!(s.remove_outbound_welcome_for(b"J", b"h3").unwrap());
    assert!(s.outbound_welcomes_for(b"J").unwrap().is_empty());
}

#[test]
fn meta_and_key_packages() {
    let mut s = MeshStore::open_in_memory().unwrap();
    assert_eq!(s.local_installation().unwrap(), None);
    s.set_local_installation(b"me").unwrap();
    s.set_local_inbox("inbox-me").unwrap();
    assert_eq!(s.local_installation().unwrap(), Some(b"me".to_vec()));
    assert_eq!(s.local_inbox().unwrap().as_deref(), Some("inbox-me"));
    s.put_key_package(b"me", b"kp1").unwrap();
    s.put_key_package(b"me", b"kp2").unwrap();
    assert_eq!(s.key_package(b"me").unwrap(), Some(b"kp2".to_vec()));
}

/// The welcome-era `contacts` table (installation_key, kind) was dropped;
/// the name now holds the private-discovery contacts (§B14.4).
#[test]
fn fresh_database_has_only_the_discovery_contacts_table() {
    let mut s = MeshStore::open_in_memory().unwrap();
    let count = |s: &mut MeshStore, column: &str| -> i64 {
        let rows: Vec<I64Row> =
            sql_query("SELECT COUNT(*) AS v FROM pragma_table_info('contacts') WHERE name = ?")
                .bind::<Text, _>(column)
                .load(&mut s.conn)
                .unwrap();
        rows[0].v
    };
    assert_eq!(
        count(&mut s, "installation_key"),
        0,
        "the old table is gone"
    );
    for column in [
        "inbox_id",
        "noise_static_pub",
        "discovery_key",
        "generation",
        "updated_ns",
        "removed_ns",
    ] {
        assert_eq!(count(&mut s, column), 1, "{column}");
    }
}

#[test]
fn transaction_rolls_back_every_statement_on_error() {
    let mut s = MeshStore::open_in_memory().unwrap();
    let result: Result<(), MeshError> = s.transaction(|s| {
        s.add_pending(&msg(b"g", b"p"), 1)?;
        s.pin_sequencer(b"g", b"seq")?; // nested transaction
        Err(MeshError::NotFound("abort".into()))
    });
    assert!(result.is_err());
    assert!(s.pending_for(b"g").unwrap().is_empty());
    assert_eq!(s.sequencer(b"g").unwrap(), None);

    s.transaction(|s| {
        s.add_pending(&msg(b"g", b"p"), 1)?;
        s.pin_sequencer(b"g", b"seq").map(|_| ())
    })
    .unwrap();
    assert_eq!(s.pending_for(b"g").unwrap().len(), 1);
    assert_eq!(s.sequencer(b"g").unwrap(), Some(b"seq".to_vec()));
}

#[test]
fn transaction_rolls_back_when_the_closure_panics() {
    let mut s = MeshStore::open_in_memory().unwrap();
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), MeshError> = s.transaction(|s| {
            s.add_pending(&msg(b"g", b"p"), 1)?;
            panic!("boom");
        });
    }));
    assert!(panicked.is_err());
    assert!(
        s.pending_for(b"g").unwrap().is_empty(),
        "write survived a panic"
    );

    // No transaction was left open: a later one commits for real.
    s.transaction(|s| s.add_pending(&msg(b"g", b"q"), 1))
        .unwrap();
    type Tm = <SqliteConnection as Connection>::TransactionManager;
    assert_eq!(
        Tm::transaction_manager_status_mut(&mut s.conn)
            .transaction_depth()
            .unwrap(),
        None
    );
    assert_eq!(s.pending_for(b"g").unwrap().len(), 1);
}

use std::sync::Arc;

use crate::sync::HelloSigner;
use crate::sync::seq::{self, Equivocation, KeySigner, SeqProof};

#[test]
fn a_row_is_signed_when_it_is_sequenced() {
    let mut s = MeshStore::open_in_memory().unwrap();
    let signer = Arc::new(KeySigner::new());
    s.set_seq_signer(signer.clone());
    let (row, _) = s
        .append_sequenced_marked(&msg(b"g", b"one"), 7, true)
        .unwrap();
    assert_eq!(
        row.seq_signer.as_deref(),
        Some(signer.installation_key().as_slice())
    );
    assert!(seq::verify_proof(b"g", 1, 7, b"one", &row.proof()));
    assert_eq!(
        s.query_group(b"g", 0, 1, false).unwrap()[0],
        row,
        "stored as returned"
    );
    assert_eq!(s.seq_counters().snapshot().seq_rows_signed, 1);
}

#[test]
fn rows_are_looked_up_by_id_with_their_signers() {
    let mut s = MeshStore::open_in_memory().unwrap();
    s.append_sequenced(&msg(b"g", b"unsigned"), 1).unwrap();
    let signer = Arc::new(KeySigner::new());
    s.set_seq_signer(signer.clone());
    s.append_sequenced(&msg(b"g", b"signed"), 2).unwrap();
    assert_eq!(s.sequenced_at(b"g", 2).unwrap().unwrap().data, b"signed");
    assert!(s.sequenced_at(b"g", 3).unwrap().is_none());
    assert_eq!(
        s.sequenced_at(b"g", 2).unwrap().unwrap().seq_signer,
        Some(signer.installation_key())
    );
}

/// §B13: a row's attestation flag is stored with its proof and travels in it.
#[test]
fn a_stored_proof_keeps_its_attestation_flag() {
    let mut s = MeshStore::open_in_memory().unwrap();
    let signer = KeySigner::new();
    let attested = seq::attested_row(&signer, b"g", 1, b"a");
    let signed = seq::signed_row(&signer, b"g", 2, b"b");
    for row in [&attested, &signed] {
        assert_eq!(s.insert_sequenced(row).unwrap(), InsertOutcome::Inserted);
    }
    assert_eq!(s.sequenced_at(b"g", 1).unwrap().unwrap(), attested);
    let rows = s.query_group(b"g", 0, 10, false).unwrap();
    assert_eq!(rows, vec![attested.clone(), signed.clone()]);
    assert!(rows[0].proof().attested && !rows[1].proof().attested);
    assert!(seq::verify_proof(b"g", 1, 10, b"a", &rows[0].proof()));
}

/// No stored rows: what a fresh node that fetches a group's history sees.
struct NoRows;

impl seq::RowLookup for NoRows {
    fn max_id(&mut self) -> Result<i64, MeshError> {
        Ok(0)
    }
    fn stored_at(&mut self, _id: i64) -> Result<Option<StoredGroupMessage>, MeshError> {
        Ok(None)
    }
}

/// §C4.7 + §B13: B holds rows the revoked A1 ordered. Re-pinning the group
/// to itself, B re-signs them as its own attestations in the same
/// transaction, so a fresh node pinned to B accepts B's whole history.
#[test]
fn a_repin_to_self_attests_the_held_history() {
    let mut s = MeshStore::open_in_memory().unwrap();
    let (a1, b) = (KeySigner::new(), Arc::new(KeySigner::new()));
    let (a1_key, b_key) = (a1.installation_key(), b.installation_key());
    s.pin_sequencer(b"g", &a1_key).unwrap();
    for id in 1..=3 {
        let row = seq::signed_row(&a1, b"g", id, &[id as u8]);
        assert_eq!(s.insert_sequenced(&row).unwrap(), InsertOutcome::Inserted);
    }
    s.set_seq_signer(b.clone());
    s.add_pending(&msg(b"g", b"pending"), 1).unwrap();
    let drained = s
        .repin_sequencer_and_drain_pending(b"g", &b_key, 99)
        .unwrap();
    assert_eq!(drained.len(), 1);

    let rows = s.query_group(b"g", 0, 10, false).unwrap();
    assert_eq!(rows.len(), 4);
    for row in &rows[..3] {
        assert_eq!(row.seq_signer.as_deref(), Some(b_key.as_slice()));
        assert!(row.seq_attested, "row {}", row.id);
        assert!(seq::verify_proof(
            b"g",
            row.id as u64,
            row.created_ns as u64,
            &row.data,
            &row.proof()
        ));
    }
    assert!(!rows[3].seq_attested, "the drained row is B's own");
    assert!(seq::verify_proof(b"g", 4, 99, b"pending", &rows[3].proof()));

    let ctx = seq::SignerContext {
        sequencer: Some(b_key.clone()),
        known: [a1_key.clone(), b_key.clone()].into(),
        revoked: [a1_key].into(),
    };
    let v = seq::check_rows(&ctx, b"g", rows, &mut NoRows).unwrap();
    assert!(
        matches!(v, seq::Verdict::Accept { ref new_rows, gap: None, .. } if new_rows.len() == 4),
        "{v:?}"
    );
}

/// Without a signer (sync stopped) the re-pin leaves the proofs; the next
/// start's `attest_foreign_rows` attests them. A group pinned elsewhere,
/// or a row this node signed, is left as it is.
#[test]
fn held_rows_of_a_group_pinned_to_self_are_attested_once_a_signer_is_set() {
    let mut s = MeshStore::open_in_memory().unwrap();
    let (a1, b) = (KeySigner::new(), Arc::new(KeySigner::new()));
    let b_key = b.installation_key();
    let foreign = seq::signed_row(&a1, b"g", 1, b"a");
    let own = seq::signed_row(b.as_ref(), b"g", 2, b"b");
    let elsewhere = seq::signed_row(&a1, b"h", 1, b"c");
    for row in [&foreign, &own, &elsewhere] {
        s.insert_sequenced(row).unwrap();
    }
    s.pin_sequencer(b"h", &a1.installation_key()).unwrap();
    s.repin_sequencer_and_drain_pending(b"g", &b_key, 5)
        .unwrap();
    assert_eq!(
        s.sequenced_at(b"g", 1).unwrap().unwrap(),
        foreign,
        "no signer yet"
    );

    s.set_seq_signer(b.clone());
    assert_eq!(s.attest_foreign_rows(None).unwrap(), 1);
    assert_eq!(s.attest_foreign_rows(None).unwrap(), 0, "idempotent");
    let row = s.sequenced_at(b"g", 1).unwrap().unwrap();
    assert!(row.seq_attested && row.seq_signer.as_deref() == Some(b_key.as_slice()));
    assert!(seq::verify_proof(b"g", 1, 10, b"a", &row.proof()));
    assert_eq!(s.sequenced_at(b"g", 2).unwrap().unwrap(), own);
    assert_eq!(s.sequenced_at(b"h", 1).unwrap().unwrap(), elsewhere);
}

#[test]
fn unsigned_rows_are_signed_once() {
    let mut s = MeshStore::open_in_memory().unwrap();
    s.append_sequenced(&msg(b"g", b"a"), 1).unwrap();
    s.append_sequenced(&msg(b"h", b"b"), 2).unwrap();
    assert_eq!(
        s.sign_unsigned_rows().unwrap(),
        0,
        "no signer: nothing to do"
    );
    let signer = Arc::new(KeySigner::new());
    s.set_seq_signer(signer.clone());
    assert_eq!(s.sign_unsigned_rows().unwrap(), 2);
    assert_eq!(s.sign_unsigned_rows().unwrap(), 0, "idempotent");
    for (gid, data, ns) in [(b"g", b"a", 1), (b"h", b"b", 2)] {
        let row = s.query_group(gid, 0, 1, false).unwrap().remove(0);
        assert!(seq::verify_proof(gid, 1, ns, data, &row.proof()));
    }
}

/// §B13 upgrade: the migration keeps rows stored before it, without proofs,
/// and marks them legacy. The start-up backfill attests those, and signs a
/// row sequenced after the migration (while no signer was set) as its
/// sequencer.
#[test]
fn the_backfill_attests_legacy_rows_and_signs_later_ones() {
    // Reverts this migration by its own version, not whichever one happens
    // to be last: a `revert_last_migration` call here would revert the
    // wrong one once a later migration is added.
    use diesel::migration::{Migration, MigrationSource};
    use diesel::sqlite::Sqlite;
    const SIGNED_SEQUENCING_MIGRATION_VERSION: &str = "20261002000000";

    let mut s = MeshStore::open_in_memory().unwrap();
    let migrations: Vec<Box<dyn Migration<Sqlite>>> = MIGRATIONS.migrations().unwrap();
    let signed_sequencing = migrations
        .iter()
        .find(|m| m.name().version().to_string() == SIGNED_SEQUENCING_MIGRATION_VERSION)
        .expect("the signed_sequencing migration is embedded");
    s.conn.revert_migration(&**signed_sequencing).unwrap();
    s.conn
        .batch_execute(
            // data_hash is sha256(b"old"): sign_unsigned_rows signs from the
            // stored hash, not by re-hashing data, so this must be genuine.
            "INSERT INTO group_messages (group_id, id, created_ns, data, sender_hmac, should_push, is_commit, data_hash, from_peer) \
             VALUES (x'67', 1, 5, x'6f6c64', x'', 1, 0, x'cba06b5736faf67e54b07b561eae94395e774c517a7d910a54369e1263ccfbd4', 0);",
        )
        .unwrap();
    s.conn.run_pending_migrations(MIGRATIONS).unwrap();
    let row = s.query_group(b"g", 0, 10, false).unwrap().remove(0);
    assert_eq!(
        (row.seq_signer, row.seq_signature, row.seq_attested),
        (None, None, false)
    );
    s.append_sequenced(&msg(b"g", b"new"), 6).unwrap();

    let signer = Arc::new(KeySigner::new());
    s.set_seq_signer(signer.clone());
    assert_eq!(s.sign_unsigned_rows().unwrap(), 2);
    let rows = s.query_group(b"g", 0, 10, false).unwrap();
    assert!(rows[0].seq_attested, "the legacy row is attested");
    assert!(seq::verify_proof(b"g", 1, 5, b"old", &rows[0].proof()));
    let as_sequenced = SeqProof {
        attested: false,
        ..rows[0].proof()
    };
    assert!(!seq::verify_proof(b"g", 1, 5, b"old", &as_sequenced));
    assert!(
        !rows[1].seq_attested,
        "the later row is signed as sequenced"
    );
    assert!(seq::verify_proof(b"g", 2, 6, b"new", &rows[1].proof()));
}

/// §C4.7 at start: the drain after a repin signs what it sequences.
#[test]
fn the_handover_drain_signs_the_rows_it_sequences() {
    let mut s = MeshStore::open_in_memory().unwrap();
    let signer = Arc::new(KeySigner::new());
    s.set_seq_signer(signer.clone());
    s.add_pending(&msg(b"g", b"held for the dead sequencer"), 1)
        .unwrap();
    let rows = s
        .repin_sequencer_and_drain_pending(b"g", &signer.installation_key(), 9)
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(seq::verify_proof(
        b"g",
        1,
        9,
        b"held for the dead sequencer",
        &rows[0].proof()
    ));
}

#[test]
fn equivocations_keep_the_newest_1024() {
    let mut s = MeshStore::open_in_memory().unwrap();
    for id in 1..=1030i64 {
        let e = Equivocation {
            group_id: b"g".to_vec(),
            id,
            signer: vec![1],
            record_a: vec![2],
            signature_a: vec![3],
            attested_a: true,
            record_b: vec![4],
            signature_b: vec![5],
            attested_b: false,
        };
        s.record_equivocation(&e, id).unwrap();
    }
    let kept = s.equivocations(b"g").unwrap();
    assert_eq!(kept.len(), 1024);
    assert_eq!(kept[0].id, 7, "the six oldest were dropped");
    assert_eq!(kept[0].record_b, vec![4]);
    assert_eq!(
        (kept[0].attested_a, kept[0].attested_b),
        (true, false),
        "each record's attested flag is kept"
    );
}

fn card(inbox: &str, key: u8, generation: u32) -> crate::sync::frames::ContactCard {
    crate::sync::frames::ContactCard {
        inbox_id: inbox.into(),
        noise_static_pub: vec![key; 32],
        discovery_key: vec![key.wrapping_add(100); 32],
        generation,
    }
}

#[test]
fn contacts_insert_update_and_ignore_older_generations() {
    let mut s = MeshStore::open_in_memory().unwrap();
    assert_eq!(
        s.upsert_contact(&card("i", 1, 0), 10, false).unwrap(),
        ContactUpdate::Inserted
    );
    assert_eq!(
        s.upsert_contact(&card("i", 1, 0), 11, false).unwrap(),
        ContactUpdate::Unchanged
    );
    let mut newer = card("i", 1, 1);
    newer.discovery_key = vec![7; 32];
    assert_eq!(
        s.upsert_contact(&newer, 12, false).unwrap(),
        ContactUpdate::Updated
    );
    assert_eq!(
        s.upsert_contact(&card("i", 1, 0), 13, false).unwrap(),
        ContactUpdate::Stale
    );
    assert_eq!(
        s.upsert_contact(&card("i", 2, 5), 14, false).unwrap(),
        ContactUpdate::Stale,
        "another static key for the inbox needs a pairing"
    );
    let c = s.contact("i").unwrap().unwrap();
    assert_eq!(
        (c.generation, c.discovery_key, c.updated_ns, c.removed),
        (1, [7; 32], 12, false)
    );
    assert_eq!(
        s.upsert_contact(&card("i", 2, 0), 15, true).unwrap(),
        ContactUpdate::Updated,
        "a confirmed pairing replaces the card"
    );
    let c = s.contact("i").unwrap().unwrap();
    assert_eq!((c.noise_static_pub, c.generation), ([2; 32], 0));
    assert_eq!(s.contacts().unwrap().len(), 1);
}

#[test]
fn a_removed_contact_stays_removed_until_it_is_paired_again() {
    let mut s = MeshStore::open_in_memory().unwrap();
    s.upsert_contact(&card("i", 1, 0), 10, false).unwrap();
    assert!(s.remove_contact("i", 11).unwrap());
    assert!(!s.remove_contact("i", 12).unwrap(), "already removed");
    assert!(!s.remove_contact("unknown", 12).unwrap());
    assert!(s.contacts().unwrap().is_empty());
    assert_eq!(
        s.contact_statics().unwrap(),
        ContactStatics {
            live: vec![],
            removed: vec![[1; 32]]
        },
        "no live static; the removed one is on file"
    );
    let tomb = s.contact_by_static(&[1; 32]).unwrap().unwrap();
    assert!(
        tomb.removed,
        "the static key of a removed contact is still known"
    );
    assert_eq!(
        s.upsert_contact(&card("i", 1, 3), 13, false).unwrap(),
        ContactUpdate::Removed
    );
    assert_eq!(
        s.upsert_contact(&card("i", 1, 0), 14, true).unwrap(),
        ContactUpdate::Updated
    );
    assert!(!s.contact("i").unwrap().unwrap().removed);
    assert_eq!(
        s.contact_statics().unwrap(),
        ContactStatics {
            live: vec![[1; 32]],
            removed: vec![]
        }
    );
    assert_eq!(
        MeshStore::open_in_memory()
            .unwrap()
            .contact_statics()
            .unwrap(),
        ContactStatics::default()
    );
}

/// §B14.7: a contact a restore window added is flagged until the user
/// confirms it; a pairing (forced store) clears the flag, other updates
/// keep it.
#[test]
fn a_contact_added_by_restore_is_flagged_until_confirmed() {
    let mut s = MeshStore::open_in_memory().unwrap();
    assert_eq!(
        s.upsert_contact_with(&card("i", 1, 0), 10, false, true)
            .unwrap(),
        ContactUpdate::Inserted
    );
    assert!(s.contact("i").unwrap().unwrap().auto_added);
    s.upsert_contact_with(&card("i", 1, 1), 11, false, false)
        .unwrap();
    assert!(
        s.contact("i").unwrap().unwrap().auto_added,
        "a newer card keeps the flag"
    );
    assert!(s.confirm_contact("i").unwrap());
    assert!(!s.confirm_contact("i").unwrap(), "already confirmed");
    assert!(!s.contact("i").unwrap().unwrap().auto_added);
    s.upsert_contact_with(&card("j", 2, 0), 12, false, true)
        .unwrap();
    s.upsert_contact(&card("j", 2, 0), 13, true).unwrap();
    assert!(
        !s.contact("j").unwrap().unwrap().auto_added,
        "pairing confirms"
    );
    s.upsert_contact_with(&card("k", 3, 0), 14, false, false)
        .unwrap();
    assert!(!s.contact("k").unwrap().unwrap().auto_added);
    assert!(!s.confirm_contact("k").unwrap());
}

#[test]
fn the_restore_window_persists_until_cleared() {
    let mut s = MeshStore::open_in_memory().unwrap();
    assert_eq!(s.restore_window().unwrap(), None);
    let w = RestoreWindow {
        until: 1_000,
        seen: 10,
    };
    s.set_restore_window(w).unwrap();
    assert_eq!(s.restore_window().unwrap(), Some(w));
    s.clear_restore_window().unwrap();
    assert_eq!(s.restore_window().unwrap(), None);
}

/// A static key names one contact: a card claiming a key on file under
/// another inbox, live or removed, is refused, even forced.
#[test]
fn a_card_claiming_another_contacts_static_is_refused() {
    let mut s = MeshStore::open_in_memory().unwrap();
    s.upsert_contact(&card("c", 1, 0), 10, false).unwrap();
    for force in [false, true] {
        assert_eq!(
            s.upsert_contact(&card("p", 1, 0), 11, force).unwrap(),
            ContactUpdate::StaticTaken
        );
    }
    assert!(s.contact("p").unwrap().is_none());
    assert!(s.remove_contact("c", 12).unwrap());
    assert_eq!(
        s.upsert_contact(&card("p", 1, 0), 13, true).unwrap(),
        ContactUpdate::StaticTaken,
        "a removed contact's key too"
    );
    assert_eq!(
        s.contact_by_static(&[1; 32]).unwrap().unwrap().inbox_id,
        "c"
    );
    // The same inbox may re-key through a pairing.
    assert_eq!(
        s.upsert_contact(&card("c", 2, 0), 14, true).unwrap(),
        ContactUpdate::Updated
    );
}

#[test]
fn malformed_contact_cards_are_refused() {
    let mut s = MeshStore::open_in_memory().unwrap();
    let mut short = card("i", 1, 0);
    short.noise_static_pub.pop();
    assert!(matches!(
        s.upsert_contact(&short, 1, false),
        Err(MeshError::InvalidRequest(_))
    ));
    assert!(matches!(
        s.upsert_contact(&card("", 1, 0), 1, false),
        Err(MeshError::InvalidRequest(_))
    ));
}

#[test]
fn the_discovery_generation_starts_at_zero_and_persists() {
    let mut s = MeshStore::open_in_memory().unwrap();
    assert_eq!(s.discovery_generation().unwrap(), 0);
    assert_eq!(s.discovery_reset_salt().unwrap(), None);
    s.set_discovery_generation(3, Some(&[9; 32])).unwrap();
    assert_eq!(s.discovery_generation().unwrap(), 3);
    assert_eq!(s.discovery_reset_salt().unwrap(), Some([9; 32]));
    s.set_discovery_generation(0, None).unwrap();
    assert_eq!(s.discovery_reset_salt().unwrap(), None);
}
