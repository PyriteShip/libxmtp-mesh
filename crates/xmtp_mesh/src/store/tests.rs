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
    assert_eq!(ids(s.query_group(b"g", 0, 100, false).unwrap()), vec![1, 2, 3, 4, 5]);
    assert_eq!(ids(s.query_group(b"g", 2, 2, false).unwrap()), vec![3, 4]);
    assert_eq!(ids(s.query_group(b"g", 0, 1, true).unwrap()), vec![5]);
    assert_eq!(ids(s.query_group(b"g", 4, 10, true).unwrap()), vec![3, 2, 1]);
}

#[test]
fn insert_sequenced_detects_gap() {
    let mut s = MeshStore::open_in_memory().unwrap();
    let (one, _) = s.append_sequenced(&msg(b"g", b"one"), 1).unwrap();
    let mut three = one.clone();
    three.id = 3;
    three.data = b"three".to_vec();
    assert_eq!(s.insert_sequenced(&three).unwrap(), InsertOutcome::Gap { have: 1 });
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
    assert!(matches!(err, MeshError::IdentityConflict { expected: 2, got: 3, .. }));
    s.append_identity("inbox", 2, 101, b"u2").unwrap();
    let rows = s.identity_rows("inbox", 1).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].update_bytes, b"u2");
    s.set_identifier("0xabc", 1, "inbox").unwrap();
    assert_eq!(s.inbox_for_identifier("0xabc", 1).unwrap().as_deref(), Some("inbox"));
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
    assert_eq!(s.outbound_welcomes_for(b"J").unwrap(), vec![(b"h3".to_vec(), b"w3".to_vec())]);
    s.remove_outbound_welcome(b"h3").unwrap();
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
