//! Signed sequencing records on the node (DESIGN.md §B13): the counters,
//! and storing a received row only once its proof checks out.
use std::collections::HashSet;

use xmtp_proto::mls_v1::GroupMessage;

use super::{MeshNode, NodeEvent};
use crate::MeshError;
use crate::store::{InsertOutcome, MeshStore, StoredGroupMessage, sha256};
use crate::sync::GroupMembership;
use crate::sync::seq::{
    self, MeshStats, RowLookup, SeqCounters, SeqProof, SeqReject, SignerContext, Verdict,
};

/// A `Sequenced` frame's rows with their proofs. Fewer (or more) proofs
/// than messages is `MissingProof`; a proof without a signer or signature
/// leaves the row unproven, which the accept rule refuses.
pub(crate) fn rows_from_sequenced(
    messages: Vec<GroupMessage>,
    proofs: Vec<SeqProof>,
) -> Result<Vec<StoredGroupMessage>, SeqReject> {
    if messages.len() != proofs.len() {
        return Err(SeqReject::MissingProof);
    }
    Ok(messages
        .into_iter()
        .zip(proofs)
        .filter_map(|(m, p)| StoredGroupMessage::from_proto(m, Some(&p), None))
        .collect())
}

/// One group's stored rows, as the accept rule reads them.
struct StoreLookup<'a> {
    store: &'a mut MeshStore,
    group_id: &'a [u8],
}

impl RowLookup for StoreLookup<'_> {
    fn max_id(&mut self) -> Result<i64, MeshError> {
        self.store.max_group_id(self.group_id)
    }

    fn stored_at(&mut self, id: i64) -> Result<Option<StoredGroupMessage>, MeshError> {
        self.store.sequenced_at(self.group_id, id)
    }
}

impl MeshNode {
    /// Count a refused frame and make its (fatal) error.
    pub(crate) fn reject_sequencing(&self, reason: SeqReject) -> MeshError {
        self.inner.seq.count_rejected(reason);
        MeshError::SequencingRejected(reason)
    }

    /// §B13 rule 2: every installation the held logs of the group's member
    /// inboxes (per the local client) ever added, and which of those were
    /// revoked. `sequencer` is left for the caller to read under its lock.
    /// Unknown members are a non-fatal `Membership` error.
    pub(crate) async fn signer_context(
        &self,
        group_id: &[u8],
        membership: &dyn GroupMembership,
    ) -> Result<SignerContext, MeshError> {
        let members = membership.member_inboxes(group_id).await?.ok_or_else(|| {
            MeshError::Membership("group members unknown; sequenced rows not checked".into())
        })?;
        let (mut known, mut live) = (HashSet::new(), HashSet::new());
        for inbox_id in &members {
            match self.replay_inbox_log(inbox_id).await {
                Ok(Some((seen, now_live))) => {
                    known.extend(seen);
                    live.extend(now_live);
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    inbox_id,
                    error = %e,
                    "identity log replay failed; its installations cannot sign rows for now"
                ),
            }
        }
        let revoked = known.difference(&live).cloned().collect();
        Ok(SignerContext {
            sequencer: None,
            known,
            revoked,
        })
    }

    /// Store rows another node sequenced, only if the whole frame passes the
    /// §B13 accept rule; the check and the insert share one store lock.
    /// `Ok(Some(have))` on a gap. A refused frame stores nothing, keeps an
    /// equivocation as proof, is counted once and returns the fatal
    /// `SequencingRejected`.
    pub(crate) async fn ingest_proven(
        &self,
        group_id: &[u8],
        rows: Vec<StoredGroupMessage>,
        membership: &dyn GroupMembership,
    ) -> Result<Option<i64>, MeshError> {
        if rows.is_empty() {
            return Ok(None);
        }
        if rows.iter().any(|r| r.group_id != group_id) {
            return Err(MeshError::InvalidRequest(
                "sequenced message for another group".into(),
            ));
        }
        let mut ctx = self.signer_context(group_id, membership).await?;
        let mut events = Vec::new();
        let result = {
            let mut store = self.inner.store.lock();
            self.check_and_store(&mut store, &mut ctx, group_id, rows, &mut events)
        };
        self.emit(events);
        result
    }

    fn check_and_store(
        &self,
        store: &mut MeshStore,
        ctx: &mut SignerContext,
        group_id: &[u8],
        rows: Vec<StoredGroupMessage>,
        events: &mut Vec<NodeEvent>,
    ) -> Result<Option<i64>, MeshError> {
        ctx.sequencer = store.sequencer(group_id)?;
        let verdict = seq::check_rows(ctx, group_id, rows, &mut StoreLookup { store, group_id })?;
        match verdict {
            Verdict::Reject {
                reason,
                equivocation,
            } => {
                if let Some(e) = &equivocation {
                    store.record_equivocation(e, Self::now_ns())?;
                }
                Err(self.reject_sequencing(reason))
            }
            Verdict::Accept {
                held,
                new_rows,
                gap,
            } => Self::store_accepted_locked(
                store,
                group_id,
                held,
                new_rows,
                gap,
                &self.inner.seq,
                events,
            ),
        }
    }

    /// Insert `new_rows` (each settling our pending copy of it) in one
    /// transaction; a `GroupSequenced` event per inserted row. `held` rows
    /// are duplicates: one settles our pending copy of its payload only
    /// when the row stored at its id carries that same payload (a §C4.7 id
    /// reuse leaves our copy pending).
    fn store_accepted_locked(
        store: &mut MeshStore,
        group_id: &[u8],
        held: Vec<StoredGroupMessage>,
        new_rows: Vec<StoredGroupMessage>,
        gap: Option<i64>,
        counters: &SeqCounters,
        events: &mut Vec<NodeEvent>,
    ) -> Result<Option<i64>, MeshError> {
        let (inserted, gap) = store.transaction(|s| {
            let mut inserted = Vec::new();
            let mut gap = gap;
            for row in new_rows {
                match s.insert_sequenced_settling_pending(&row)? {
                    InsertOutcome::Inserted => inserted.push(row),
                    InsertOutcome::Duplicate => {}
                    InsertOutcome::Gap { have } => {
                        gap = Some(have);
                        break;
                    }
                }
            }
            for row in &held {
                let same = s
                    .sequenced_at(group_id, row.id)?
                    .is_some_and(|kept| kept.data == row.data);
                if same {
                    s.remove_pending(group_id, &sha256(&row.data))?;
                }
            }
            Ok((inserted, gap))
        })?;
        counters.count_verified(inserted.len() as u64);
        events.extend(inserted.into_iter().map(NodeEvent::GroupSequenced));
        Ok(gap)
    }

    /// [`Self::store_accepted_locked`] under its own lock (tests).
    #[cfg(test)]
    pub(crate) fn store_accepted(
        &self,
        group_id: &[u8],
        held: Vec<StoredGroupMessage>,
        new_rows: Vec<StoredGroupMessage>,
        gap: Option<i64>,
    ) -> Result<Option<i64>, MeshError> {
        let mut events = Vec::new();
        let result = {
            let mut store = self.inner.store.lock();
            Self::store_accepted_locked(
                &mut store,
                group_id,
                held,
                new_rows,
                gap,
                &self.inner.seq,
                &mut events,
            )
        };
        self.emit(events);
        result
    }

    /// Signed-sequencing counters since this node was opened (§B13).
    pub fn mesh_stats(&self) -> MeshStats {
        self.inner.seq.snapshot()
    }

    pub(crate) fn seq_counters(&self) -> &SeqCounters {
        &self.inner.seq
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn sequenced_rows_for_test(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<StoredGroupMessage>, MeshError> {
        self.inner
            .store
            .lock()
            .query_group(group_id, 0, i64::MAX, false)
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn equivocations_for_test(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<seq::Equivocation>, MeshError> {
        self.inner.store.lock().equivocations(group_id)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::node::test_logs::{
        Members, NoTransport, drain, node_with_a_revoked_and_a_live_installation,
    };
    use crate::store::NewGroupMessage;
    use crate::sync::HelloSigner;
    use crate::sync::seq::{KeySigner, attested_row, signed_row};

    const GID: &[u8] = b"dm";

    #[tokio::test]
    async fn verified_rows_are_stored_with_their_proofs_and_counted() {
        let (node, inbox, _k1, k2) = node_with_a_revoked_and_a_live_installation().await;
        let seq = KeySigner(k2);
        node.inner
            .store
            .lock()
            .pin_sequencer(GID, &seq.installation_key())
            .unwrap();
        let mut events = node.subscribe_events();
        let rows = vec![
            attested_row(&seq, GID, 1, b"a"),
            signed_row(&seq, GID, 2, b"b"),
        ];
        let gap = node
            .ingest_proven(GID, rows.clone(), &Members(Some(vec![inbox])))
            .await
            .unwrap();
        assert_eq!(gap, None);
        assert_eq!(node.sequenced_rows_for_test(GID).unwrap(), rows);
        assert!(node.sequenced_rows_for_test(GID).unwrap()[0].seq_attested);
        assert_eq!(node.mesh_stats().seq_rows_verified, 2);
        let sequenced = drain(&mut events)
            .into_iter()
            .filter(|e| matches!(e, NodeEvent::GroupSequenced(_)))
            .count();
        assert_eq!(sequenced, 2);
    }

    #[tokio::test]
    async fn an_equivocation_is_kept_as_proof_and_the_frame_refused() {
        let (node, inbox, _k1, k2) = node_with_a_revoked_and_a_live_installation().await;
        let seq = KeySigner(k2);
        node.inner
            .store
            .lock()
            .pin_sequencer(GID, &seq.installation_key())
            .unwrap();
        let members = Members(Some(vec![inbox]));
        let first = signed_row(&seq, GID, 1, b"first");
        node.ingest_proven(GID, vec![first.clone()], &members)
            .await
            .unwrap();
        let other = signed_row(&seq, GID, 1, b"other");
        let err = node
            .ingest_proven(GID, vec![other.clone()], &members)
            .await
            .unwrap_err();
        assert!(
            matches!(err, MeshError::SequencingRejected(SeqReject::Equivocation)),
            "{err}"
        );
        let kept = node.equivocations_for_test(GID).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!((kept[0].id, &kept[0].signer), (1, &seq.installation_key()));
        assert_eq!(kept[0].signature_a, first.seq_signature.unwrap());
        assert_eq!(kept[0].signature_b, other.seq_signature.unwrap());
        assert_eq!(node.sequenced_rows_for_test(GID).unwrap()[0].data, b"first");
        assert_eq!(node.mesh_stats().seq_equivocations, 1);
    }

    /// A refused frame counts once, under its first failure, and stores
    /// nothing, not even the rows before the failing one.
    #[tokio::test]
    async fn a_refused_frame_stores_nothing_and_counts_once() {
        let (node, inbox, k1, k2) = node_with_a_revoked_and_a_live_installation().await;
        let (revoked, seq) = (KeySigner(k1), KeySigner(k2));
        node.inner
            .store
            .lock()
            .pin_sequencer(GID, &seq.installation_key())
            .unwrap();
        let rows = vec![
            signed_row(&seq, GID, 1, b"a"),
            signed_row(&revoked, GID, 2, b"forged"),
            signed_row(&revoked, GID, 3, b"forged too"),
        ];
        let err = node
            .ingest_proven(GID, rows, &Members(Some(vec![inbox])))
            .await
            .unwrap_err();
        assert!(
            matches!(err, MeshError::SequencingRejected(SeqReject::WrongSigner)),
            "{err}"
        );
        assert!(err.is_fatal());
        assert_eq!(node.max_group_id_for_test(GID).unwrap(), 0);
        assert_eq!(
            node.mesh_stats(),
            MeshStats {
                seq_rejected_wrong_signer: 1,
                ..MeshStats::default()
            }
        );
    }

    /// Rule 2 needs the client's member list; without it nothing is
    /// checked, stored or counted, and the session is not ended.
    #[tokio::test]
    async fn unknown_group_members_are_not_a_rejection() {
        let (node, _inbox, _k1, k2) = node_with_a_revoked_and_a_live_installation().await;
        let seq = KeySigner(k2);
        let err = node
            .ingest_proven(GID, vec![signed_row(&seq, GID, 1, b"a")], &Members(None))
            .await
            .unwrap_err();
        assert!(matches!(err, MeshError::Membership(_)), "{err}");
        assert!(!err.is_fatal());
        assert_eq!(node.mesh_stats(), MeshStats::default());
        assert_eq!(node.max_group_id_for_test(GID).unwrap(), 0);
    }

    /// A held id carrying another record (§C4.7 id reuse) is only a
    /// duplicate: it does not settle our pending copy of its payload, which
    /// is not sequenced here.
    #[tokio::test]
    async fn an_id_reuse_row_does_not_settle_our_pending_copy() {
        let (node, inbox, k1, k2) = node_with_a_revoked_and_a_live_installation().await;
        let (other, seq) = (KeySigner(k1), KeySigner(k2));
        let members = Members(Some(vec![inbox]));
        {
            let mut store = node.inner.store.lock();
            store.pin_sequencer(GID, &seq.installation_key()).unwrap();
            store
                .add_pending(
                    &NewGroupMessage {
                        group_id: GID.to_vec(),
                        data: b"ours".to_vec(),
                        sender_hmac: vec![],
                        should_push: false,
                        is_commit: false,
                    },
                    1,
                )
                .unwrap();
        }
        node.ingest_proven(GID, vec![signed_row(&seq, GID, 1, b"a")], &members)
            .await
            .unwrap();
        let reused = signed_row(&other, GID, 1, b"ours");
        assert_eq!(
            node.ingest_proven(GID, vec![reused], &members)
                .await
                .unwrap(),
            None
        );
        assert_eq!(node.inner.store.lock().pending_for(GID).unwrap().len(), 1);
        assert_eq!(node.sequenced_rows_for_test(GID).unwrap()[0].data, b"a");
        assert_eq!(node.mesh_stats().seq_rows_verified, 1);
    }

    #[test]
    fn fewer_proofs_than_messages_is_missing_proof() {
        let s = KeySigner::new();
        let row = signed_row(&s, GID, 1, b"a");
        assert_eq!(
            rows_from_sequenced(vec![row.to_proto()], vec![]),
            Err(SeqReject::MissingProof)
        );
        assert_eq!(
            rows_from_sequenced(vec![row.to_proto()], vec![row.proof()]),
            Ok(vec![row])
        );
        let attested = attested_row(&s, GID, 2, b"b");
        assert_eq!(
            rows_from_sequenced(vec![attested.to_proto()], vec![attested.proof()]),
            Ok(vec![attested])
        );
    }

    /// `is_commit` is not signed: a row whose data parses as MLS takes it
    /// from the data, whatever the wire says.
    #[test]
    fn is_commit_is_rederived_from_the_data() {
        const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/creation_commit.bin");
        let s = KeySigner::new();
        let mut row = signed_row(&s, GID, 1, FIXTURE);
        row.is_commit = false;
        let got = rows_from_sequenced(vec![row.to_proto()], vec![row.proof()]).unwrap();
        assert!(got[0].is_commit, "the fixture is a commit");
        let mut row = signed_row(&s, GID, 1, b"not mls");
        row.is_commit = true;
        let got = rows_from_sequenced(vec![row.to_proto()], vec![row.proof()]).unwrap();
        assert!(got[0].is_commit, "unparsable data keeps the wire value");
    }

    fn msg(data: &[u8]) -> NewGroupMessage {
        NewGroupMessage {
            group_id: b"g".to_vec(),
            data: data.to_vec(),
            sender_hmac: vec![],
            should_push: false,
            is_commit: false,
        }
    }

    /// §B13: a row sequenced while sync is stopped (here: before the first
    /// start) is signed by `start_sync`, before any session exists.
    /// `stop_sync` clears the store's signer (a Client-backed signer would
    /// otherwise hold the node alive forever, an Arc cycle): a row
    /// sequenced after that stays unsigned until the *next* `start_sync`'s
    /// backfill signs it, again before any session exists.
    #[tokio::test]
    async fn start_sync_signs_rows_sequenced_while_sync_was_stopped() {
        let signer = Arc::new(KeySigner::new());
        let node = MeshNode::in_memory().unwrap();
        {
            let mut store = node.inner.store.lock();
            store
                .set_local_installation(&signer.installation_key())
                .unwrap();
            store.append_sequenced(&msg(b"before"), 1).unwrap();
        }
        assert_eq!(
            node.sequenced_rows_for_test(b"g").unwrap()[0].seq_signer,
            None
        );

        node.start_sync(
            signer.clone(),
            Arc::new(NoTransport),
            Arc::new(Members(Some(vec![]))),
        )
        .unwrap();
        let rows = node.sequenced_rows_for_test(b"g").unwrap();
        assert_eq!(
            rows[0].seq_signer.as_deref(),
            Some(signer.installation_key().as_slice())
        );
        assert!(seq::verify_proof(b"g", 1, 1, b"before", &rows[0].proof()));
        assert_eq!(node.mesh_stats().seq_rows_signed, 1);

        node.stop_sync();
        node.inner
            .store
            .lock()
            .append_sequenced(&msg(b"after stop"), 2)
            .unwrap();
        let rows = node.sequenced_rows_for_test(b"g").unwrap();
        assert!(
            rows[1].seq_signer.is_none(),
            "cleared by stop_sync: nothing unsigned is ever served, since \
             serving only happens while sync runs"
        );
        assert_eq!(
            node.mesh_stats().seq_rows_signed,
            1,
            "not signed until the next start_sync backfill"
        );

        node.start_sync(
            signer.clone(),
            Arc::new(NoTransport),
            Arc::new(Members(Some(vec![]))),
        )
        .unwrap();
        let rows = node.sequenced_rows_for_test(b"g").unwrap();
        assert_eq!(
            rows[1].seq_signer.as_deref(),
            Some(signer.installation_key().as_slice()),
            "signed by the next start_sync's backfill"
        );
        assert!(seq::verify_proof(
            b"g",
            2,
            2,
            b"after stop",
            &rows[1].proof()
        ));
        assert_eq!(node.mesh_stats().seq_rows_signed, 2);
    }

    /// §C4.7 + §B13: a re-pin to this node while sync was stopped leaves
    /// the former sequencer's proofs; `start_sync` attests them as ours.
    #[tokio::test]
    async fn start_sync_attests_held_rows_of_groups_pinned_to_us() {
        let (former, signer) = (KeySigner::new(), Arc::new(KeySigner::new()));
        let node = MeshNode::in_memory().unwrap();
        {
            let mut store = node.inner.store.lock();
            store
                .set_local_installation(&signer.installation_key())
                .unwrap();
            store
                .insert_sequenced(&seq::signed_row(&former, b"g", 1, b"a"))
                .unwrap();
            store
                .repin_sequencer_and_drain_pending(b"g", &signer.installation_key(), 1)
                .unwrap();
        }
        assert_eq!(
            node.sequenced_rows_for_test(b"g").unwrap()[0].seq_signer,
            Some(former.installation_key())
        );

        node.start_sync(
            signer.clone(),
            Arc::new(NoTransport),
            Arc::new(Members(Some(vec![]))),
        )
        .unwrap();
        let row = node.sequenced_rows_for_test(b"g").unwrap().remove(0);
        assert_eq!(row.seq_signer, Some(signer.installation_key()));
        assert!(row.seq_attested);
        assert!(seq::verify_proof(b"g", 1, 10, b"a", &row.proof()));
    }

    /// The review's Arc-cycle finding: a signer that itself holds a strong
    /// reference back to the node (as `ClientHelloSigner` does in
    /// production, through the client's own API bundle) must not be kept by
    /// the store past `stop_sync`, or the node could never be dropped after
    /// logout. This reproduces the cycle with an in-crate stand-in for
    /// `ClientHelloSigner` rather than a real libxmtp client (out of this
    /// crate's reach), and checks it is actually broken.
    #[test]
    fn stop_sync_drops_a_signer_that_holds_the_node_alive() {
        struct NodeHoldingSigner(KeySigner, #[allow(dead_code)] MeshNode);
        impl HelloSigner for NodeHoldingSigner {
            fn installation_key(&self) -> Vec<u8> {
                self.0.installation_key()
            }
            fn sign(&self, text: &str) -> Result<Vec<u8>, crate::MeshError> {
                self.0.sign(text)
            }
        }

        let node = MeshNode::in_memory().unwrap();
        let weak = Arc::downgrade(&node.inner);
        let signer: Arc<dyn HelloSigner> =
            Arc::new(NodeHoldingSigner(KeySigner::new(), node.clone()));
        node.inner.store.lock().set_seq_signer(signer.clone());
        drop(signer);
        drop(node);
        assert!(
            weak.upgrade().is_some(),
            "the signer's own clone of the node keeps it alive (the cycle)"
        );

        MeshNode {
            inner: weak.upgrade().unwrap(),
        }
        .stop_sync();
        assert!(
            weak.upgrade().is_none(),
            "stop_sync must clear the store's signer, or the node (and its \
             database) can never be dropped"
        );
    }
}
