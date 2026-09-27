use std::sync::atomic::Ordering;
use std::time::Duration;

use prost::Message;
use xmtp_proto::mls_v1::{
    GroupMessage, GroupMessageInput, WelcomeMessageInput, group_message_input,
};
use xmtp_proto::xmtp::identity::api::v1::get_identity_updates_response::IdentityUpdateLog;
use xmtp_proto::xmtp::identity::associations::IdentityUpdate as IdentityUpdateProto;

use super::welcomes::welcome_recipient;
use super::{MeshNode, NodeEvent};
use crate::MeshError;
use crate::mls_parse::{parse_group_message, verify_key_package};
use crate::store::{NewGroupMessage, sha256};
use crate::sync::frames::{IdentityLog, Interest, KeyPackage, Welcome};
use crate::sync::seq::SeqProof;

/// Longest identity log accepted from a peer. Under D7 (one installation per
/// inbox) an honest log stays far shorter; the cap bounds what a peer can
/// make us verify and store.
pub(crate) const MAX_PEER_IDENTITY_LOG: i64 = 256;

impl MeshNode {
    pub(crate) fn own_identity_log(&self) -> Result<Option<IdentityLog>, MeshError> {
        if self.inner.suppress_identity_log.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let Some(inbox_id) = self.inner.store.lock().local_inbox()? else {
            return Ok(None);
        };
        let updates = self.identity_log(&inbox_id)?;
        Ok(Some(IdentityLog { inbox_id, updates }))
    }

    /// This node's whole stored identity log for `inbox_id`, oldest first
    /// (empty when the inbox is unknown).
    pub fn identity_log(&self, inbox_id: &str) -> Result<Vec<IdentityUpdateLog>, MeshError> {
        self.inner
            .store
            .lock()
            .identity_rows(inbox_id, 0)?
            .into_iter()
            .map(|r| {
                Ok(IdentityUpdateLog {
                    sequence_id: r.sequence_id as u64,
                    server_timestamp_ns: r.server_timestamp_ns as u64,
                    update: Some(IdentityUpdateProto::decode(r.update_bytes.as_slice())?),
                })
            })
            .collect::<Result<Vec<_>, MeshError>>()
    }

    /// Copy another node's log of `inbox_id` into this one: the carry on a
    /// node rotation, so that a reset's new installation extends the log
    /// its peers already hold instead of re-creating the inbox
    /// (DESIGN.md §B10.2). Each update is verified and appended as a peer's
    /// would be, so the identifier mappings follow and libxmtp's
    /// `get_inbox_ids` finds the inbox. Only an unbound node may import:
    /// this never sets the local installation or inbox (the next
    /// installation's own key package and publish do). Not capped: the log
    /// comes from this device's own previous node.
    ///
    /// Returns how many updates this node now holds for `inbox_id`. An
    /// error if ingestion reports the source log forked at a sequence id we
    /// already held, or if, after ingestion, this node holds fewer
    /// updates than the source's highest sequence id — a silent stop at a
    /// gap would leave a truncated log that forks again at N+1.
    pub async fn import_identity_log(
        &self,
        inbox_id: &str,
        updates: Vec<IdentityUpdateLog>,
    ) -> Result<i64, MeshError> {
        if self.local_installation()?.is_some() || self.local_inbox()?.is_some() {
            return Err(MeshError::InvalidRequest(
                "identity log import into a node already bound to an installation".into(),
            ));
        }
        let highest = updates
            .iter()
            .map(|u| u.sequence_id as i64)
            .max()
            .unwrap_or(0);
        if let Some(fork_seq) = self
            .ingest_identity_log_capped(inbox_id, updates, i64::MAX)
            .await?
        {
            return Err(MeshError::InvalidRequest(format!(
                "identity log import for {inbox_id} forked at sequence {fork_seq}"
            )));
        }
        let held = self.inner.store.lock().identity_len(inbox_id)?;
        if held < highest {
            return Err(MeshError::InvalidRequest(format!(
                "identity log import for {inbox_id} stopped at a gap: holding {held}, source had {highest}"
            )));
        }
        Ok(held)
    }

    pub(crate) fn own_key_package(&self) -> Result<Option<KeyPackage>, MeshError> {
        let mut store = self.inner.store.lock();
        let Some(installation) = store.local_installation()? else {
            return Ok(None);
        };
        Ok(store
            .key_package(&installation)?
            .map(|key_package| KeyPackage {
                installation_key: installation,
                key_package,
            }))
    }

    /// Append a peer-supplied log contiguously (Rule B): ingestion stops at
    /// the first gap, and nothing past [`MAX_PEER_IDENTITY_LOG`] updates is
    /// accepted. Updates we already hold (sequence id <= our length) are
    /// skipped. If one differs from ours at the same sequence id, the peer
    /// holds a forked log (for example a second `CreateInbox` for this inbox,
    /// minted on an empty node): it is logged, the rest of that log is not
    /// ingested, and that sequence id is returned. `Ok(None)`: no fork seen.
    pub(crate) async fn ingest_identity_log(
        &self,
        inbox_id: &str,
        updates: Vec<IdentityUpdateLog>,
    ) -> Result<Option<i64>, MeshError> {
        self.ingest_identity_log_capped(inbox_id, updates, MAX_PEER_IDENTITY_LOG)
            .await
    }

    async fn ingest_identity_log_capped(
        &self,
        inbox_id: &str,
        mut updates: Vec<IdentityUpdateLog>,
        cap: i64,
    ) -> Result<Option<i64>, MeshError> {
        updates.retain(|u| (u.sequence_id as i64) <= cap);
        updates.sort_by_key(|u| u.sequence_id);
        for u in updates {
            let have = self.inner.store.lock().identity_len(inbox_id)?;
            let seq = u.sequence_id as i64;
            if seq <= have {
                if self.differs_from_held(inbox_id, seq, &u)? {
                    tracing::warn!(
                        inbox_id,
                        seq,
                        "peer identity log differs from ours at a held sequence id \
                         (forked log); not ingesting the rest of it"
                    );
                    return Ok(Some(seq));
                }
                continue;
            }
            if seq != have + 1 {
                break;
            }
            let proto = u
                .update
                .ok_or_else(|| MeshError::InvalidRequest("empty identity update".into()))?;
            if proto.inbox_id != inbox_id {
                return Err(MeshError::IdentityRejected(
                    "update inbox id mismatch".into(),
                ));
            }
            self.accept_identity_update(
                proto,
                Some(seq),
                Some(u.server_timestamp_ns as i64),
                false,
            )
            .await?;
        }
        Ok(None)
    }

    /// True when we hold `seq` for `inbox_id` and `u` carries a different
    /// update there. Timestamps are not compared: only the update itself.
    fn differs_from_held(
        &self,
        inbox_id: &str,
        seq: i64,
        u: &IdentityUpdateLog,
    ) -> Result<bool, MeshError> {
        let Some(update) = &u.update else {
            return Ok(false);
        };
        let held = self.inner.store.lock().identity_rows(inbox_id, seq - 1)?;
        Ok(held.first().is_some_and(|row| {
            row.sequence_id == seq && row.update_bytes != update.encode_to_vec()
        }))
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
            return Err(MeshError::InvalidKeyPackage(
                "installation key mismatch".into(),
            ));
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

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn set_peer_verify_timeout_for_test(&self, timeout: Duration) {
        *self.inner.peer_verify_timeout.lock() = timeout;
    }

    pub(crate) fn handshake_timeout(&self) -> Duration {
        *self.inner.handshake_timeout.lock()
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn set_handshake_timeout_for_test(&self, timeout: Duration) {
        *self.inner.handshake_timeout.lock() = timeout;
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn suppress_identity_log_for_test(&self) {
        self.inner
            .suppress_identity_log
            .store(true, Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn suppress_group_push_for_test(&self, suppress: bool) {
        self.inner
            .suppress_group_push
            .store(suppress, Ordering::Relaxed);
    }

    pub(crate) fn group_push_suppressed(&self) -> bool {
        self.inner.suppress_group_push.load(Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn outbound_welcome_count_for_test(&self, installation: &[u8]) -> Result<usize, MeshError> {
        Ok(self
            .inner
            .store
            .lock()
            .outbound_welcomes_for(installation)?
            .len())
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn set_local_inbox_for_test(&self, inbox_id: &str) {
        self.inner.store.lock().set_local_inbox(inbox_id).unwrap();
    }

    /// Test only: fold a peer-supplied log into this
    /// node's store directly, as a session's `on_identity_log` would, but
    /// without a live peer session -- so a test can simulate "the update
    /// landed while this node's sync was stopped" (`ingest_identity_log` is
    /// otherwise `pub(crate)`, and a bound node has no other way to receive
    /// a foreign inbox's update outside a running session).
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub async fn ingest_identity_log_for_test(
        &self,
        inbox_id: &str,
        updates: Vec<IdentityUpdateLog>,
    ) -> Result<Option<i64>, MeshError> {
        self.ingest_identity_log(inbox_id, updates).await
    }
}

/// Welcome delivery and group-message sequencing between peers. Sessions call
/// these only for verified peers.
impl MeshNode {
    /// Welcomes queued for `installation`. Best effort per row: an undecodable
    /// row is logged and skipped so it cannot block the others.
    pub(crate) fn outbound_welcomes_for(
        &self,
        installation: &[u8],
    ) -> Result<Vec<Welcome>, MeshError> {
        let rows = self
            .inner
            .store
            .lock()
            .outbound_welcomes_for(installation)?;
        Ok(rows
            .into_iter()
            .filter_map(|(envelope_hash, bytes)| {
                match WelcomeMessageInput::decode(bytes.as_slice()) {
                    Ok(input) => Some(Welcome {
                        envelope_hash,
                        input: Some(input),
                    }),
                    Err(e) => {
                        tracing::warn!(error = %e, "skipping undecodable outbound welcome");
                        None
                    }
                }
            })
            .collect())
    }

    /// Store a welcome if it is addressed to this node's installation (one
    /// transaction: see [`MeshStore::append_welcome`]). Returns the hash to
    /// acknowledge, or None when it is not for us. Delivering a welcome
    /// grants the sender nothing: group traffic is scoped by membership.
    ///
    /// [`MeshStore::append_welcome`]: crate::store::MeshStore::append_welcome
    pub(crate) fn ingest_welcome(&self, welcome: Welcome) -> Result<Option<Vec<u8>>, MeshError> {
        let input = welcome
            .input
            .ok_or_else(|| MeshError::InvalidRequest("welcome without input".into()))?;
        let bytes = input.encode_to_vec();
        let hash = sha256(&bytes);
        let mut events = Vec::new();
        let result = (|| -> Result<Option<Vec<u8>>, MeshError> {
            let mut store = self.inner.store.lock();
            let local = store
                .local_installation()?
                .ok_or(MeshError::NotRegistered)?;
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

    /// Drop an outbound welcome once its recipient `installation`
    /// acknowledged it (one atomic statement). A hash queued for another
    /// installation is left alone, so one peer cannot cancel delivery to
    /// another. Returns whether a queued welcome was acknowledged.
    pub(crate) fn ack_outbound_welcome(
        &self,
        installation: &[u8],
        envelope_hash: &[u8],
    ) -> Result<bool, MeshError> {
        self.inner
            .store
            .lock()
            .remove_outbound_welcome_for(installation, envelope_hash)
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
    pub(crate) fn pin_sequencer(
        &self,
        group_id: &[u8],
        installation: &[u8],
    ) -> Result<Vec<u8>, MeshError> {
        self.inner
            .store
            .lock()
            .pin_sequencer(group_id, installation)
    }

    /// Up to `limit` sequenced messages with `id > high`, oldest first, each
    /// with its sequencing proof (§B13).
    pub(crate) fn sequenced_after(
        &self,
        group_id: &[u8],
        high: i64,
        limit: usize,
    ) -> Result<Vec<(GroupMessage, SeqProof)>, MeshError> {
        Ok(self
            .inner
            .store
            .lock()
            .query_group(group_id, high, limit as i64, false)?
            .iter()
            .map(|row| (row.to_proto(), row.proof()))
            .collect())
    }

    pub(crate) fn pending_inputs(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<GroupMessageInput>, MeshError> {
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
    pub(crate) fn sequence_from_peer(
        &self,
        group_id: &[u8],
        inputs: Vec<GroupMessageInput>,
    ) -> Result<(), MeshError> {
        let mut events = Vec::new();
        let result = (|| -> Result<(), MeshError> {
            let mut store = self.inner.store.lock();
            let local = store
                .local_installation()?
                .ok_or(MeshError::NotRegistered)?;
            if store.sequencer(group_id)?.as_deref() != Some(local.as_slice()) {
                return Err(MeshError::InvalidRequest(
                    "not this group's sequencer".into(),
                ));
            }
            for input in inputs {
                let Some(group_message_input::Version::V1(v1)) = input.version else {
                    continue;
                };
                let parsed = parse_group_message(&v1.data)?;
                if parsed.group_id != group_id {
                    return Err(MeshError::InvalidRequest(
                        "pending message for another group".into(),
                    ));
                }
                let msg = NewGroupMessage {
                    group_id: parsed.group_id,
                    data: v1.data,
                    sender_hmac: v1.sender_hmac,
                    should_push: v1.should_push,
                    is_commit: parsed.is_commit,
                };
                let (row, inserted) = store.append_sequenced_marked(&msg, Self::now_ns(), true)?;
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
    use xmtp_id::associations::test_utils::WalletTestExt;

    use super::*;
    use crate::node::test_logs::{
        added_wallet, owned_three_update_log, three_update_log, timestamps,
    };

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
        node.ingest_identity_log(&inbox_id, vec![stale, u1])
            .await
            .unwrap();
        assert_eq!(timestamps(&node, &inbox_id), vec![1_001, 1_002, 1_003]);
    }

    #[tokio::test]
    async fn peer_log_is_capped() {
        let node = MeshNode::in_memory().unwrap();
        let (inbox_id, log) = three_update_log().await;
        node.ingest_identity_log_capped(&inbox_id, log, 2)
            .await
            .unwrap();
        assert_eq!(timestamps(&node, &inbox_id), vec![1_001, 1_002]);
    }

    #[tokio::test]
    async fn misnumbered_update_is_a_conflict() {
        let node = MeshNode::in_memory().unwrap();
        let (inbox_id, log) = three_update_log().await;
        node.ingest_identity_log(&inbox_id, log[..2].to_vec())
            .await
            .unwrap();

        // `expected` is the sequence id the store needs next; `got` is the one
        // the caller claimed for the update.
        let err = node
            .accept_identity_update(log[2].update.clone().unwrap(), Some(5), None, false)
            .await
            .unwrap_err();
        match err {
            MeshError::IdentityConflict {
                inbox_id: id,
                expected,
                got,
            } => {
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

    /// A peer whose log differs from ours at a held sequence
    /// id (a second CreateInbox minted on an empty node, §B10.2)
    /// is reported, and nothing after the fork is appended on
    /// top of our history.
    #[tokio::test]
    async fn a_forked_log_is_reported_and_the_rest_of_it_is_not_ingested() {
        let node = MeshNode::in_memory().unwrap();
        let (owner, inbox_id, log) = owned_three_update_log().await;
        assert_eq!(
            node.ingest_identity_log(&inbox_id, log[..2].to_vec())
                .await
                .unwrap(),
            None
        );

        // Same seq 1, another update at seq 2, and a seq 3 that would apply
        // on top of our state if ingestion went on.
        let fork = vec![
            log[0].clone(),
            added_wallet(&owner, &inbox_id, 2, 2_002).await,
            added_wallet(&owner, &inbox_id, 3, 2_003).await,
        ];
        assert_eq!(
            node.ingest_identity_log(&inbox_id, fork).await.unwrap(),
            Some(2)
        );
        assert_eq!(
            timestamps(&node, &inbox_id),
            vec![1_001, 1_002],
            "nothing of the fork is appended"
        );

        // Our own updates sent again, even with other timestamps, are not a fork.
        let mut resent = log[1].clone();
        resent.server_timestamp_ns = 9_999;
        assert_eq!(
            node.ingest_identity_log(&inbox_id, vec![log[0].clone(), resent])
                .await
                .unwrap(),
            None
        );
    }

    /// The reset carry (§B10.2): a fresh node gets
    /// the inbox's log and identifier mappings, so libxmtp's get_inbox_ids
    /// finds the inbox, but it stays unbound.
    #[tokio::test]
    async fn import_copies_the_log_and_identifiers_and_leaves_the_node_unbound() {
        use xmtp_proto::types::ApiIdentifier;
        let (owner, inbox_id, log) = owned_three_update_log().await;
        let old = MeshNode::in_memory().unwrap();
        old.ingest_identity_log(&inbox_id, log).await.unwrap();

        let fresh = MeshNode::in_memory().unwrap();
        let held = fresh
            .import_identity_log(&inbox_id, old.identity_log(&inbox_id).unwrap())
            .await
            .unwrap();

        assert_eq!(held, 3);
        assert_eq!(timestamps(&fresh, &inbox_id), vec![1_001, 1_002, 1_003]);
        let api: ApiIdentifier = (&owner.identifier()).into();
        assert_eq!(
            fresh
                .inner
                .store
                .lock()
                .inbox_for_identifier(&api.identifier, api.identifier_kind as i32)
                .unwrap(),
            Some(inbox_id.clone())
        );
        assert_eq!(fresh.local_installation().unwrap(), None);
        assert_eq!(fresh.local_inbox().unwrap(), None);
    }

    /// A node already serving an installation never takes
    /// an imported log ("a mesh node serves exactly one local installation").
    #[tokio::test]
    async fn import_into_a_bound_node_is_refused() {
        let (inbox_id, log) = three_update_log().await;
        let bound = MeshNode::in_memory().unwrap();
        bound
            .inner
            .store
            .lock()
            .set_local_installation(b"installation-key-of-a-live-clien")
            .unwrap();
        let err = bound.import_identity_log(&inbox_id, log).await.unwrap_err();
        assert!(matches!(err, MeshError::InvalidRequest(_)), "{err:?}");
        assert!(timestamps(&bound, &inbox_id).is_empty());
    }

    #[test]
    fn the_log_of_an_unknown_inbox_is_empty() {
        let node = MeshNode::in_memory().unwrap();
        assert!(node.identity_log("unknown").unwrap().is_empty());
    }

    /// A source log that forked at a sequence id the target already
    /// held (from an earlier, partial import) is an error, not a silent
    /// partial import.
    #[tokio::test]
    async fn import_of_a_forked_log_is_an_error() {
        let (owner, inbox_id, log) = owned_three_update_log().await;
        let target = MeshNode::in_memory().unwrap();
        target
            .import_identity_log(&inbox_id, log[..2].to_vec())
            .await
            .unwrap();
        let fork = vec![
            log[0].clone(),
            added_wallet(&owner, &inbox_id, 2, 2_002).await,
        ];
        let err = target
            .import_identity_log(&inbox_id, fork)
            .await
            .unwrap_err();
        assert!(matches!(err, MeshError::InvalidRequest(_)), "{err:?}");
    }

    /// A source log with a gap (here, sequence 2 missing) must not
    /// silently stop short of the source's highest sequence id — that would
    /// leave a truncated log that forks again at the next append.
    #[tokio::test]
    async fn import_that_stops_at_a_gap_is_an_error() {
        let (inbox_id, log) = three_update_log().await;
        let target = MeshNode::in_memory().unwrap();
        let gapped = vec![log[0].clone(), log[2].clone()];
        let err = target
            .import_identity_log(&inbox_id, gapped)
            .await
            .unwrap_err();
        assert!(matches!(err, MeshError::InvalidRequest(_)), "{err:?}");
    }
}
