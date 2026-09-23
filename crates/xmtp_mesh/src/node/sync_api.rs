use std::sync::atomic::Ordering;
use std::time::Duration;

use prost::Message;
use xmtp_proto::mls_v1::{GroupMessage, GroupMessageInput, WelcomeMessageInput, group_message, group_message_input};
use xmtp_proto::xmtp::identity::api::v1::get_identity_updates_response::IdentityUpdateLog;
use xmtp_proto::xmtp::identity::associations::IdentityUpdate as IdentityUpdateProto;

use super::welcomes::welcome_recipient;
use super::{MeshNode, NodeEvent};
use crate::MeshError;
use crate::mls_parse::{parse_group_message, verify_key_package};
use crate::store::{InsertOutcome, NewGroupMessage, StoredGroupMessage, sha256};
use crate::sync::frames::{IdentityLog, Interest, KeyPackage, Welcome};

impl MeshNode {
    pub(crate) fn own_identity_log(&self) -> Result<Option<IdentityLog>, MeshError> {
        if self.inner.suppress_identity_log.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let mut store = self.inner.store.lock();
        let Some(inbox_id) = store.local_inbox()? else { return Ok(None) };
        let updates = store
            .identity_rows(&inbox_id, 0)?
            .into_iter()
            .map(|r| {
                Ok(IdentityUpdateLog {
                    sequence_id: r.sequence_id as u64,
                    server_timestamp_ns: r.server_timestamp_ns as u64,
                    update: Some(IdentityUpdateProto::decode(r.update_bytes.as_slice())?),
                })
            })
            .collect::<Result<Vec<_>, MeshError>>()?;
        Ok(Some(IdentityLog { inbox_id, updates }))
    }

    pub(crate) fn own_key_package(&self) -> Result<Option<KeyPackage>, MeshError> {
        let mut store = self.inner.store.lock();
        let Some(installation) = store.local_installation()? else { return Ok(None) };
        Ok(store.key_package(&installation)?.map(|key_package| KeyPackage {
            installation_key: installation,
            key_package,
        }))
    }

    /// Append a peer-supplied log contiguously (Rule B): updates we already
    /// hold (sequence id <= our length) are skipped without comparing them to
    /// ours, and ingestion stops at the first gap.
    pub(crate) async fn ingest_identity_log(
        &self,
        inbox_id: &str,
        mut updates: Vec<IdentityUpdateLog>,
    ) -> Result<(), MeshError> {
        updates.sort_by_key(|u| u.sequence_id);
        for u in updates {
            let have = self.inner.store.lock().identity_len(inbox_id)?;
            let seq = u.sequence_id as i64;
            if seq <= have {
                continue;
            }
            if seq != have + 1 {
                break;
            }
            let proto = u
                .update
                .ok_or_else(|| MeshError::InvalidRequest("empty identity update".into()))?;
            if proto.inbox_id != inbox_id {
                return Err(MeshError::IdentityRejected("update inbox id mismatch".into()));
            }
            self.accept_identity_update(proto, Some(seq), Some(u.server_timestamp_ns as i64), false)
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn installations_of(&self, inbox_id: &str) -> Result<Vec<Vec<u8>>, MeshError> {
        Ok(self
            .verified_state(inbox_id)
            .await?
            .map(|s| s.installation_ids())
            .unwrap_or_default())
    }

    pub(crate) fn ingest_peer_key_package(&self, kp: &KeyPackage) -> Result<(), MeshError> {
        let installation = verify_key_package(&kp.key_package)?;
        if installation != kp.installation_key {
            return Err(MeshError::InvalidKeyPackage("installation key mismatch".into()));
        }
        let mut store = self.inner.store.lock();
        if store.local_installation()?.as_deref() == Some(installation.as_slice()) {
            return Ok(()); // never overwrite our own from the network
        }
        store.put_key_package(&installation, &kp.key_package)
    }

    pub(crate) fn peer_verify_timeout(&self) -> Duration {
        *self.inner.peer_verify_timeout.lock()
    }

    #[doc(hidden)]
    pub fn set_peer_verify_timeout_for_test(&self, timeout: Duration) {
        *self.inner.peer_verify_timeout.lock() = timeout;
    }

    #[doc(hidden)]
    pub fn suppress_identity_log_for_test(&self) {
        self.inner.suppress_identity_log.store(true, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn suppress_group_push_for_test(&self, suppress: bool) {
        self.inner.suppress_group_push.store(suppress, Ordering::Relaxed);
    }

    pub(crate) fn group_push_suppressed(&self) -> bool {
        self.inner.suppress_group_push.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn outbound_welcome_count_for_test(&self, installation: &[u8]) -> Result<usize, MeshError> {
        Ok(self.inner.store.lock().outbound_welcomes_for(installation)?.len())
    }

    #[doc(hidden)]
    pub fn set_local_inbox_for_test(&self, inbox_id: &str) {
        self.inner.store.lock().set_local_inbox(inbox_id).unwrap();
    }
}

/// Welcome delivery and group-message sequencing between peers. Sessions call
/// these only for verified peers.
impl MeshNode {
    /// Welcomes queued for `installation`. Best effort per row: an undecodable
    /// row is logged and skipped so it cannot block the others.
    pub(crate) fn outbound_welcomes_for(&self, installation: &[u8]) -> Result<Vec<Welcome>, MeshError> {
        let rows = self.inner.store.lock().outbound_welcomes_for(installation)?;
        Ok(rows
            .into_iter()
            .filter_map(|(envelope_hash, bytes)| match WelcomeMessageInput::decode(bytes.as_slice()) {
                Ok(input) => Some(Welcome { envelope_hash, input: Some(input) }),
                Err(e) => {
                    tracing::warn!(error = %e, "skipping undecodable outbound welcome");
                    None
                }
            })
            .collect())
    }

    /// Store a welcome if it is addressed to this node's installation.
    /// Returns the hash to acknowledge, or None when it is not for us.
    pub(crate) fn ingest_welcome(&self, welcome: Welcome) -> Result<Option<Vec<u8>>, MeshError> {
        let input = welcome
            .input
            .ok_or_else(|| MeshError::InvalidRequest("welcome without input".into()))?;
        let bytes = input.encode_to_vec();
        let hash = sha256(&bytes);
        let mut events = Vec::new();
        let result = (|| -> Result<Option<Vec<u8>>, MeshError> {
            let mut store = self.inner.store.lock();
            let local = store.local_installation()?.ok_or(MeshError::NotRegistered)?;
            if welcome_recipient(&input)? != local {
                return Ok(None);
            }
            if let Some(stored) = store.append_welcome(&local, &hash, &bytes, Self::now_ns())? {
                events.push(NodeEvent::WelcomeStored(stored));
            }
            Ok(Some(hash))
        })();
        self.emit(events);
        result
    }

    /// Drop an outbound welcome once its recipient `installation` acknowledged
    /// it. A hash queued for another installation is left alone, so one peer
    /// cannot cancel delivery to another.
    pub(crate) fn ack_outbound_welcome(&self, installation: &[u8], envelope_hash: &[u8]) -> Result<(), MeshError> {
        let mut store = self.inner.store.lock();
        let queued = store.outbound_welcomes_for(installation)?;
        if queued.iter().any(|(hash, _)| hash.as_slice() == envelope_hash) {
            store.remove_outbound_welcome(envelope_hash)?;
        }
        Ok(())
    }

    pub(crate) fn group_summary(&self, group_id: &[u8]) -> Result<Interest, MeshError> {
        let mut store = self.inner.store.lock();
        let local = store.local_installation()?;
        Ok(Interest {
            group_id: group_id.to_vec(),
            high_id: store.max_group_id(group_id)? as u64,
            i_am_sequencer: local.is_some() && store.sequencer(group_id)? == local,
        })
    }

    pub(crate) fn group_summaries(&self) -> Result<Vec<Interest>, MeshError> {
        let groups = self.inner.store.lock().known_groups()?;
        groups.iter().map(|g| self.group_summary(g)).collect()
    }

    pub(crate) fn sequencer_of(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>, MeshError> {
        self.inner.store.lock().sequencer(group_id)
    }

    pub(crate) fn is_known_group(&self, group_id: &[u8]) -> Result<bool, MeshError> {
        self.inner.store.lock().is_known_group(group_id)
    }

    /// Trust-on-first-use: returns the group's sequencer, which is
    /// `installation` only if none was pinned before.
    pub(crate) fn pin_sequencer(&self, group_id: &[u8], installation: &[u8]) -> Result<Vec<u8>, MeshError> {
        self.inner.store.lock().pin_sequencer(group_id, installation)
    }

    pub(crate) fn sequenced_after(&self, group_id: &[u8], high: i64) -> Result<Vec<GroupMessage>, MeshError> {
        Ok(self
            .inner
            .store
            .lock()
            .query_group(group_id, high, i64::MAX, false)?
            .iter()
            .map(StoredGroupMessage::to_proto)
            .collect())
    }

    /// Store messages the sequencer sent us, in order. Returns Some(have) on a gap.
    pub(crate) fn ingest_sequenced(
        &self,
        group_id: &[u8],
        messages: Vec<GroupMessage>,
    ) -> Result<Option<i64>, MeshError> {
        let mut events = Vec::new();
        let result = (|| -> Result<Option<i64>, MeshError> {
            let mut store = self.inner.store.lock();
            for message in messages {
                let Some(group_message::Version::V1(v1)) = message.version else { continue };
                if v1.group_id != group_id {
                    return Err(MeshError::InvalidRequest("sequenced message for another group".into()));
                }
                let row = StoredGroupMessage {
                    group_id: v1.group_id,
                    id: v1.id as i64,
                    created_ns: v1.created_ns as i64,
                    data: v1.data,
                    sender_hmac: v1.sender_hmac,
                    should_push: v1.should_push,
                    is_commit: v1.is_commit,
                };
                match store.insert_sequenced(&row)? {
                    InsertOutcome::Inserted => {
                        store.remove_pending(group_id, &sha256(&row.data))?;
                        events.push(NodeEvent::GroupSequenced(row));
                    }
                    // We may hold our own copy in pending (e.g. published
                    // again after it was sequenced); it is settled now.
                    InsertOutcome::Duplicate => store.remove_pending(group_id, &sha256(&row.data))?,
                    InsertOutcome::Gap { have } => return Ok(Some(have)),
                }
            }
            Ok(None)
        })();
        self.emit(events);
        result
    }

    pub(crate) fn pending_inputs(&self, group_id: &[u8]) -> Result<Vec<GroupMessageInput>, MeshError> {
        Ok(self
            .inner
            .store
            .lock()
            .pending_for(group_id)?
            .into_iter()
            .map(|m| GroupMessageInput {
                version: Some(group_message_input::Version::V1(group_message_input::V1 {
                    data: m.data,
                    sender_hmac: m.sender_hmac,
                    should_push: m.should_push,
                })),
            })
            .collect())
    }

    /// Sequencer side: assign ids to a peer's pending messages (deduplicated by
    /// `sha256(data)`). Refused unless this node is the group's pinned sequencer.
    pub(crate) fn sequence_from_peer(&self, group_id: &[u8], inputs: Vec<GroupMessageInput>) -> Result<(), MeshError> {
        let mut events = Vec::new();
        let result = (|| -> Result<(), MeshError> {
            let mut store = self.inner.store.lock();
            let local = store.local_installation()?.ok_or(MeshError::NotRegistered)?;
            if store.sequencer(group_id)?.as_deref() != Some(local.as_slice()) {
                return Err(MeshError::InvalidRequest("not this group's sequencer".into()));
            }
            for input in inputs {
                let Some(group_message_input::Version::V1(v1)) = input.version else { continue };
                let parsed = parse_group_message(&v1.data)?;
                if parsed.group_id != group_id {
                    return Err(MeshError::InvalidRequest("pending message for another group".into()));
                }
                let msg = NewGroupMessage {
                    group_id: parsed.group_id,
                    data: v1.data,
                    sender_hmac: v1.sender_hmac,
                    should_push: v1.should_push,
                    is_commit: parsed.is_commit,
                };
                let (row, inserted) = store.append_sequenced(&msg, Self::now_ns())?;
                if inserted {
                    events.push(NodeEvent::GroupSequenced(row));
                }
            }
            Ok(())
        })();
        self.emit(events);
        result
    }
}

#[cfg(test)]
mod tests {
    use xmtp_cryptography::utils::generate_local_wallet;
    use xmtp_id::associations::builder::SignatureRequestBuilder;
    use xmtp_id::associations::test_utils::{WalletTestExt, add_wallet_signature};

    use super::*;

    /// A real three-update log for one inbox: create it, then add two wallets.
    async fn three_update_log() -> (String, Vec<IdentityUpdateLog>) {
        let owner = generate_local_wallet();
        let inbox_id = owner.get_inbox_id(0);

        let mut create = SignatureRequestBuilder::new(&inbox_id)
            .create_inbox(owner.identifier(), 0)
            .build();
        add_wallet_signature(&mut create, &owner).await;
        let mut updates = vec![create.build_identity_update().unwrap()];

        for _ in 0..2 {
            let added = generate_local_wallet();
            let mut add = SignatureRequestBuilder::new(&inbox_id)
                .add_association(added.member_identifier(), owner.member_identifier())
                .build();
            add_wallet_signature(&mut add, &owner).await;
            add_wallet_signature(&mut add, &added).await;
            updates.push(add.build_identity_update().unwrap());
        }

        let log = updates
            .into_iter()
            .zip(1u64..)
            .map(|(u, seq)| IdentityUpdateLog {
                sequence_id: seq,
                server_timestamp_ns: 1_000 + seq,
                update: Some(IdentityUpdateProto::from(u)),
            })
            .collect();
        (inbox_id, log)
    }

    fn timestamps(node: &MeshNode, inbox_id: &str) -> Vec<i64> {
        let rows = node.inner.store.lock().identity_rows(inbox_id, 0).unwrap();
        rows.iter().map(|r| r.server_timestamp_ns).collect()
    }

    #[tokio::test]
    async fn peer_log_stops_at_gap_and_skips_held_updates() {
        let node = MeshNode::in_memory().unwrap();
        let (inbox_id, log) = three_update_log().await;
        let (u1, u2, u3) = (log[0].clone(), log[1].clone(), log[2].clone());

        // 1 and 3 (out of order): 1 is appended, ingestion stops at the gap before 3.
        node.ingest_identity_log(&inbox_id, vec![u3.clone(), u1.clone()])
            .await
            .unwrap();
        assert_eq!(timestamps(&node, &inbox_id), vec![1_001]);

        // The duplicate 1 is skipped; 2 and 3 now append contiguously.
        node.ingest_identity_log(&inbox_id, vec![u1.clone(), u2.clone(), u3])
            .await
            .unwrap();
        assert_eq!(timestamps(&node, &inbox_id), vec![1_001, 1_002, 1_003]);

        // Older updates sent again are skipped without error.
        let mut stale = u2;
        stale.server_timestamp_ns = 9_999;
        node.ingest_identity_log(&inbox_id, vec![stale, u1]).await.unwrap();
        assert_eq!(timestamps(&node, &inbox_id), vec![1_001, 1_002, 1_003]);
    }

    #[tokio::test]
    async fn misnumbered_update_is_a_conflict() {
        let node = MeshNode::in_memory().unwrap();
        let (inbox_id, log) = three_update_log().await;
        node.ingest_identity_log(&inbox_id, log[..2].to_vec()).await.unwrap();

        // `expected` is the sequence id the store needs next; `got` is the one
        // the caller claimed for the update.
        let err = node
            .accept_identity_update(log[2].update.clone().unwrap(), Some(5), None, false)
            .await
            .unwrap_err();
        match err {
            MeshError::IdentityConflict { inbox_id: id, expected, got } => {
                assert_eq!((id, expected, got), (inbox_id.clone(), 3, 5));
            }
            other => panic!("expected IdentityConflict, got {other:?}"),
        }
        assert_eq!(timestamps(&node, &inbox_id).len(), 2);
    }

    #[tokio::test]
    async fn update_for_another_inbox_is_rejected() {
        let node = MeshNode::in_memory().unwrap();
        let (_, log) = three_update_log().await;
        let err = node
            .ingest_identity_log("some-other-inbox", log[..1].to_vec())
            .await
            .unwrap_err();
        assert!(matches!(err, MeshError::IdentityRejected(_)), "{err:?}");
        assert!(timestamps(&node, "some-other-inbox").is_empty());
    }
}
