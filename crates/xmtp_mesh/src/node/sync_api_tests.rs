use prost::Message;
use xmtp_proto::mls_v1::{
    GroupMessageInput, WelcomeMessageInput, group_message, group_message_input,
    welcome_message_input,
};

use super::MeshNode;
use crate::sync::frames::Welcome;

const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/creation_commit.bin");
const SEQUENCER: &[u8] = b"sequencer-installation-key-32byt";

/// A node that is the pinned sequencer of the fixture's group (a real MLS
/// message captured by `tests/fixtures/capture_commit.rs`).
fn seeded_node() -> (MeshNode, Vec<u8>) {
    let node = MeshNode::in_memory().unwrap();
    let parsed = crate::mls_parse::parse_group_message(FIXTURE).unwrap();
    assert!(
        parsed.is_commit && parsed.epoch == 0,
        "fixture is the creation commit"
    );
    let mut store = node.inner.store.lock();
    store.set_local_installation(SEQUENCER).unwrap();
    store.ensure_group(&parsed.group_id).unwrap();
    store.pin_sequencer(&parsed.group_id, SEQUENCER).unwrap();
    drop(store);
    (node, parsed.group_id)
}

#[test]
fn duplicate_pending_is_sequenced_once() {
    let (node, gid) = seeded_node();
    let input = GroupMessageInput {
        version: Some(group_message_input::Version::V1(group_message_input::V1 {
            data: FIXTURE.to_vec(),
            sender_hmac: vec![],
            should_push: false,
        })),
    };
    node.sequence_from_peer(&gid, vec![input.clone()]).unwrap();
    node.sequence_from_peer(&gid, vec![input]).unwrap();
    assert_eq!(node.inner.store.lock().max_group_id(&gid).unwrap(), 1);
}

#[test]
fn sequenced_gap_requests_resend() {
    let (node, gid) = seeded_node();
    let far = xmtp_proto::mls_v1::GroupMessage {
        version: Some(group_message::Version::V1(group_message::V1 {
            id: 5,
            created_ns: 1,
            group_id: gid.clone(),
            data: FIXTURE.to_vec(),
            sender_hmac: vec![],
            should_push: false,
            is_commit: true,
        })),
    };
    assert_eq!(node.ingest_sequenced(&gid, vec![far]).unwrap(), Some(0));
    assert_eq!(node.inner.store.lock().max_group_id(&gid).unwrap(), 0);
}

#[test]
fn welcome_for_other_installation_is_ignored() {
    let (node, _) = seeded_node();
    let input = WelcomeMessageInput {
        version: Some(welcome_message_input::Version::V1(
            welcome_message_input::V1 {
                installation_key: b"someone-else".to_vec(),
                data: vec![1, 2, 3],
                hpke_public_key: vec![],
                wrapper_algorithm: 0,
                welcome_metadata: vec![],
            },
        )),
    };
    let welcome = Welcome {
        envelope_hash: crate::store::sha256(&input.encode_to_vec()),
        input: Some(input),
    };
    assert_eq!(node.ingest_welcome(welcome).unwrap(), None);
    assert!(
        node.inner
            .store
            .lock()
            .query_welcomes(b"someone-else", 0, 10)
            .unwrap()
            .is_empty()
    );
    assert!(
        node.inner
            .store
            .lock()
            .query_welcomes(SEQUENCER, 0, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn welcome_ack_only_from_its_recipient() {
    let (node, _) = seeded_node();
    node.inner
        .store
        .lock()
        .add_outbound_welcome(b"hash", b"recipient", b"input")
        .unwrap();
    assert!(!node.ack_outbound_welcome(b"another-peer", b"hash").unwrap());
    assert_eq!(
        node.inner
            .store
            .lock()
            .outbound_welcomes_for(b"recipient")
            .unwrap()
            .len(),
        1
    );
    assert!(node.ack_outbound_welcome(b"recipient", b"hash").unwrap());
    assert!(
        node.inner
            .store
            .lock()
            .outbound_welcomes_for(b"recipient")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn pending_is_not_sequenced_by_a_non_sequencer() {
    let node = MeshNode::in_memory().unwrap();
    let gid = crate::mls_parse::parse_group_message(FIXTURE)
        .unwrap()
        .group_id;
    {
        let mut store = node.inner.store.lock();
        store.set_local_installation(b"local-installation").unwrap();
        store.pin_sequencer(&gid, SEQUENCER).unwrap();
    }
    let input = GroupMessageInput {
        version: Some(group_message_input::Version::V1(group_message_input::V1 {
            data: FIXTURE.to_vec(),
            sender_hmac: vec![],
            should_push: false,
        })),
    };
    assert!(node.sequence_from_peer(&gid, vec![input]).is_err());
    assert_eq!(node.inner.store.lock().max_group_id(&gid).unwrap(), 0);
}

fn fixture_row(gid: &[u8]) -> crate::store::StoredGroupMessage {
    let parsed = crate::mls_parse::parse_group_message(FIXTURE).unwrap();
    crate::store::StoredGroupMessage {
        group_id: gid.to_vec(),
        id: 1,
        created_ns: 1,
        data: FIXTURE.to_vec(),
        sender_hmac: vec![],
        should_push: false,
        is_commit: parsed.is_commit,
        seq_signer: None,
        seq_signature: None,
        seq_attested: false,
    }
}

/// A member node (not the sequencer) of the fixture's group.
fn member_node() -> (MeshNode, Vec<u8>) {
    let node = MeshNode::in_memory().unwrap();
    let gid = crate::mls_parse::parse_group_message(FIXTURE)
        .unwrap()
        .group_id;
    let mut store = node.inner.store.lock();
    store
        .set_local_installation(b"member-installation")
        .unwrap();
    store.pin_sequencer(&gid, SEQUENCER).unwrap();
    drop(store);
    (node, gid)
}

#[test]
fn duplicate_sequenced_copy_clears_stale_pending() {
    let (node, gid) = member_node();
    let row = fixture_row(&gid);
    let pending = crate::store::NewGroupMessage {
        group_id: gid.clone(),
        data: FIXTURE.to_vec(),
        sender_hmac: vec![],
        should_push: false,
        is_commit: row.is_commit,
    };
    {
        let mut store = node.inner.store.lock();
        store.insert_sequenced(&row).unwrap();
        store.add_pending(&pending, 1).unwrap();
    }
    assert_eq!(
        node.ingest_sequenced(&gid, vec![row.to_proto()]).unwrap(),
        None
    );
    assert!(
        node.inner
            .store
            .lock()
            .pending_for(&gid)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn publish_of_already_sequenced_message_is_not_pending() {
    let (node, gid) = member_node();
    node.inner
        .store
        .lock()
        .insert_sequenced(&fixture_row(&gid))
        .unwrap();
    let mut events = node.subscribe_events();
    node.send_group_messages(xmtp_proto::mls_v1::SendGroupMessagesRequest {
        messages: vec![GroupMessageInput {
            version: Some(group_message_input::Version::V1(group_message_input::V1 {
                data: FIXTURE.to_vec(),
                sender_hmac: vec![],
                should_push: false,
            })),
        }],
    })
    .unwrap();
    assert!(
        node.inner
            .store
            .lock()
            .pending_for(&gid)
            .unwrap()
            .is_empty()
    );
    assert!(
        events.try_recv().is_err(),
        "no event for an already sequenced message"
    );
}

#[test]
fn undecodable_outbound_welcome_does_not_block_others() {
    let (node, _) = seeded_node();
    let good = WelcomeMessageInput {
        version: Some(welcome_message_input::Version::V1(
            welcome_message_input::V1 {
                installation_key: b"recipient".to_vec(),
                data: vec![1, 2, 3],
                hpke_public_key: vec![],
                wrapper_algorithm: 0,
                welcome_metadata: vec![],
            },
        )),
    };
    {
        let mut store = node.inner.store.lock();
        store
            .add_outbound_welcome(b"bad", b"recipient", b"\xff\xff")
            .unwrap();
        store
            .add_outbound_welcome(b"good", b"recipient", &good.encode_to_vec())
            .unwrap();
    }
    let welcomes = node.outbound_welcomes_for(b"recipient").unwrap();
    assert_eq!(welcomes.len(), 1);
    assert_eq!(welcomes[0].envelope_hash, b"good".to_vec());
}

/// A message whose Sequenced/Pending frame could never be sent is refused at
/// publish (libxmtp sees the error) instead of wedging the group.
#[test]
fn publish_of_a_message_too_large_for_a_frame_is_rejected() {
    let (node, gid) = seeded_node();
    let huge = GroupMessageInput {
        version: Some(group_message_input::Version::V1(group_message_input::V1 {
            data: vec![0; crate::MAX_FRAME_LEN],
            sender_hmac: vec![],
            should_push: false,
        })),
    };
    let err = node
        .send_group_messages(xmtp_proto::mls_v1::SendGroupMessagesRequest {
            messages: vec![huge],
        })
        .unwrap_err();
    assert!(
        matches!(&err, crate::MeshError::InvalidRequest(m) if m.contains("frame")),
        "{err:?}"
    );
    assert_eq!(node.inner.store.lock().max_group_id(&gid).unwrap(), 0);
}
