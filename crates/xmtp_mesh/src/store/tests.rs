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

#[test]
fn fresh_database_has_no_contacts_table() {
    let mut s = MeshStore::open_in_memory().unwrap();
    let rows: Vec<I64Row> = sql_query(
        "SELECT COUNT(*) AS v FROM sqlite_master WHERE type = 'table' AND name = 'contacts'",
    )
    .load(&mut s.conn)
    .unwrap();
    assert_eq!(rows[0].v, 0);
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
use crate::sync::seq::{self, Equivocation, KeySigner};

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
        s.seq_signers(b"g").unwrap(),
        vec![None, Some(signer.installation_key())]
    );
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

/// §B13 upgrade: the migration keeps rows stored before it, without proofs.
#[test]
fn the_migration_keeps_existing_rows_unsigned_until_they_are_signed() {
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
    assert_eq!((row.seq_signer, row.seq_signature), (None, None));
    let signer = Arc::new(KeySigner::new());
    s.set_seq_signer(signer.clone());
    assert_eq!(s.sign_unsigned_rows().unwrap(), 1);
    let row = s.query_group(b"g", 0, 10, false).unwrap().remove(0);
    assert!(seq::verify_proof(b"g", 1, 5, b"old", &row.proof()));
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
            record_b: vec![4],
            signature_b: vec![5],
        };
        s.record_equivocation(&e, id).unwrap();
    }
    let kept = s.equivocations(b"g").unwrap();
    assert_eq!(kept.len(), 1024);
    assert_eq!(kept[0].id, 7, "the six oldest were dropped");
    assert_eq!(kept[0].record_b, vec![4]);
}
