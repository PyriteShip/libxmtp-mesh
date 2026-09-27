//! Sequencer handover (DESIGN.md §C4.7; §B5.2 Rule A,
//! amended). A DM's sequencer is its pinned installation while that
//! installation is not revoked in its inbox's identity log. Once the log
//! revokes it, the sequencer is the lowest non-revoked installation id
//! among the group's leaves that belong to the OTHER inbox -- never the
//! revoked sequencer's own inbox. A revocation is a signed update in the
//! log, so every node holding it computes the same successor with no
//! coordination. In a DM the successor is the contact: the returning
//! installation always belongs to the revoked sequencer's own inbox, so it
//! is never eligible, whatever order its add and the revoke arrive in
//! (D29). It learns the sequencer from the
//! welcome's sender, as Rule A already says for joiners.
//!
//! D29: a group qualifies
//! for the handover when it has exactly two member inboxes, however many
//! installations each has. A larger group's revoked-but-pinned sequencer is
//! left exactly as it was.
//!
//! A message the dead sequencer sequenced but the
//! successor never received (an id above the successor's own max) is lost;
//! sequence ids continue from the last one the successor holds and it
//! reuses those ids. This matches §C4.7's "continue from the last id
//! the successor holds".

use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;

use prost::Message;
use xmtp_id::associations;
use xmtp_proto::xmtp::identity::associations::IdentityUpdate as IdentityUpdateProto;

use super::identity::verify;
use super::{MeshNode, NodeEvent};
use crate::MeshError;
use crate::sync::GroupMembership;

/// The group's next sequencer once its pinned one is revoked: the lowest
/// installation id among `leaves` that is neither `revoked` nor a member of
/// the revoked sequencer's own inbox (`same_inbox`) -- D29: the
/// successor always comes from the OTHER inbox, so a newly-added
/// installation of the revoked sequencer's own inbox can never affect the
/// choice, whatever order the add and the revoke arrive in.
pub(crate) fn successor(
    leaves: &[Vec<u8>],
    revoked: &HashSet<Vec<u8>>,
    same_inbox: &HashSet<Vec<u8>>,
) -> Option<Vec<u8>> {
    leaves
        .iter()
        .filter(|leaf| !revoked.contains(*leaf) && !same_inbox.contains(*leaf))
        .min()
        .cloned()
}

/// One inbox's held log, replayed: every installation id it has ever added
/// ("seen"), and the ones still live (its current association state).
type InboxHistory = HashMap<String, (HashSet<Vec<u8>>, HashSet<Vec<u8>>)>;

/// The inbox (and everything it has ever added) that added `installation`,
/// or `None` if no held log did. Used to exclude the revoked sequencer's
/// own inbox from the successor choice (D29).
fn owning_inbox<'a>(
    history: &'a InboxHistory,
    installation: &[u8],
) -> Option<&'a HashSet<Vec<u8>>> {
    history
        .values()
        .find(|(seen, _)| seen.contains(installation))
        .map(|(seen, _)| seen)
}

impl MeshNode {
    /// Every inbox this node holds a log for, replayed once: the
    /// installation ids it has ever added, and the ones still live.
    /// Shared by [`Self::revoked_installations`] and
    /// [`Self::hand_over_sequencers`]'s owning-inbox lookup, which both
    /// otherwise replayed the same logs separately.
    ///
    /// A bad row in one inbox's log is logged and that
    /// inbox is skipped, rather than failing every inbox's computation (and
    /// so every group's handover) with `?`.
    async fn inbox_installation_history(&self) -> Result<InboxHistory, MeshError> {
        let inboxes = self.inner.store.lock().identity_inboxes()?;
        let mut history = HashMap::new();
        for inbox_id in inboxes {
            match self.replay_inbox_log(&inbox_id).await {
                Ok(Some(entry)) => {
                    history.insert(inbox_id, entry);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        inbox_id,
                        error = %e,
                        "identity log replay failed; the §C4.7 handover skips this inbox for now"
                    );
                }
            }
        }
        Ok(history)
    }

    /// Replays one inbox's held log: every installation id it has ever
    /// added, and the ones still live. `Ok(None)` for an empty log.
    async fn replay_inbox_log(
        &self,
        inbox_id: &str,
    ) -> Result<Option<(HashSet<Vec<u8>>, HashSet<Vec<u8>>)>, MeshError> {
        let rows = self.inner.store.lock().identity_rows(inbox_id, 0)?;
        let mut state = None;
        let mut seen = HashSet::new();
        for row in rows {
            let update = verify(&IdentityUpdateProto::decode(row.update_bytes.as_slice())?).await?;
            let next = match state.take() {
                None => associations::get_state([update]),
                Some(previous) => associations::apply_update(previous, update),
            }
            .map_err(|e| MeshError::IdentityRejected(e.to_string()))?;
            seen.extend(next.installation_ids());
            state = Some(next);
        }
        Ok(state.map(|state| {
            let live: HashSet<Vec<u8>> = state.installation_ids().into_iter().collect();
            (seen, live)
        }))
    }

    /// Installations that some identity log on this node added and a later
    /// update of the same log removed.
    pub(crate) async fn revoked_installations(&self) -> Result<HashSet<Vec<u8>>, MeshError> {
        let mut revoked = HashSet::new();
        for (seen, live) in self.inbox_installation_history().await?.into_values() {
            revoked.extend(seen.into_iter().filter(|id| !live.contains(id)));
        }
        Ok(revoked)
    }

    /// §C4.7: re-pin every known group whose pinned sequencer is revoked, to
    /// the lowest live leaf of the OTHER inbox per the local client (D29).
    /// When that is us, our own pending messages are sequenced here at
    /// once. When it is a peer, the sessions are told (PendingAdded), so
    /// they flush our pending messages to it. Returns the groups handed
    /// over.
    ///
    /// D29: a group qualifies only when it has
    /// exactly two member inboxes (`GroupMembership::member_inboxes`), a
    /// DM -- not by leaf count, which a merged add-installation commit
    /// could push past 2 even for a genuine DM.
    ///
    /// A group whose members or leaves this node
    /// doesn't yet know, or whose store update fails, is logged and
    /// skipped -- it does not abort the handover for every other group.
    ///
    /// The common case (nothing revoked, the
    /// vast majority of identity-log changes) does only the one replay
    /// [`Self::revoked_installations`] needs, then returns; the second,
    /// owning-inbox replay only runs once there is at least one group to
    /// actually hand over. `identity.rs::verified_state_and_len` still
    /// replays independently; a shared "replay to states" cache would be a
    /// larger change.
    pub async fn hand_over_sequencers(
        &self,
        membership: &dyn GroupMembership,
    ) -> Result<Vec<Vec<u8>>, MeshError> {
        let revoked = self.revoked_installations().await?;
        if revoked.is_empty() {
            return Ok(vec![]);
        }
        let local = self.local_installation()?;
        let stale: Vec<(Vec<u8>, Vec<u8>)> = {
            let mut store = self.inner.store.lock();
            let mut stale = Vec::new();
            for group_id in store.known_groups()? {
                if let Some(pinned) = store.sequencer(&group_id)?
                    && revoked.contains(&pinned)
                {
                    stale.push((group_id, pinned));
                }
            }
            stale
        };
        if stale.is_empty() {
            return Ok(vec![]);
        }
        let history = self.inbox_installation_history().await?;
        let mut handed = Vec::new();
        for (group_id, old) in stale {
            match membership.member_inboxes(&group_id).await {
                Ok(Some(members)) if members.len() == 2 => {}
                Ok(_) => continue,
                Err(e) => {
                    tracing::warn!(group = %hex::encode(&group_id), error = %e, "group members unavailable; sequencer not handed over yet");
                    continue;
                }
            }
            let leaves = match membership.leaf_installations(&group_id).await {
                Ok(Some(leaves)) => leaves,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(group = %hex::encode(&group_id), error = %e, "group leaves unavailable; sequencer not handed over yet");
                    continue;
                }
            };
            let Some(same_inbox) = owning_inbox(&history, &old) else {
                tracing::warn!(group = %hex::encode(&group_id), "revoked sequencer's own inbox not held; sequencer not handed over yet");
                continue;
            };
            let Some(next) = successor(&leaves, &revoked, same_inbox) else {
                tracing::warn!(group = %hex::encode(&group_id), "sequencer revoked and no live leaf of the other inbox to take over");
                continue;
            };
            let outcome = if local.as_deref() == Some(next.as_slice()) {
                self.inner
                    .store
                    .lock()
                    .repin_sequencer_and_drain_pending(&group_id, &next, Self::now_ns())
                    .map(|rows| {
                        self.emit(rows.into_iter().map(NodeEvent::GroupSequenced).collect())
                    })
            } else {
                self.inner
                    .store
                    .lock()
                    .repin_sequencer(&group_id, &next)
                    .map(|()| self.emit(vec![NodeEvent::PendingAdded(group_id.clone())]))
            };
            if let Err(e) = outcome {
                tracing::warn!(group = %hex::encode(&group_id), error = %e, "sequencer handover failed for this group; will retry on the next identity-log change");
                continue;
            }
            tracing::info!(
                group = %hex::encode(&group_id),
                old = %hex::encode(&old),
                new = %hex::encode(&next),
                "sequencer handed over: the pinned one was revoked (§C4.7)"
            );
            handed.push(group_id);
        }
        Ok(handed)
    }

    /// Runs [`Self::hand_over_sequencers`] and logs (rather than propagates)
    /// a failure, so a caller in the identity task's event loop or
    /// `start_sync` never has to handle it specially.
    ///
    /// Test only: suppressed by
    /// `suppress_handover_for_test`, so a test can hold the pinned
    /// sequencer still while it proves a different gate refuses a revoked
    /// installation's frames. [`Self::hand_over_sequencers`] itself is never
    /// suppressed.
    pub(crate) async fn hand_over(&self, membership: &dyn GroupMembership) {
        if self.inner.suppress_handover.load(Ordering::Relaxed) {
            return;
        }
        if let Err(e) = self.hand_over_sequencers(membership).await {
            tracing::warn!(error = %e, "sequencer handover failed");
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn suppress_handover_for_test(&self, suppress: bool) {
        self.inner
            .suppress_handover
            .store(suppress, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use async_trait::async_trait;
    use xmtp_cryptography::XmtpInstallationCredential;
    use xmtp_cryptography::utils::generate_local_wallet;
    use xmtp_id::associations::test_utils::WalletTestExt;

    use super::*;
    use crate::node::test_logs::{added_installation, drain, origin, revoked_installation};
    use crate::store::NewGroupMessage;

    /// A configurable [`GroupMembership`] double: `members` models
    /// `member_inboxes` (D29's DM-qualification gate) and `leaves`
    /// models `leaf_installations`.
    struct FakeMembership {
        members: Vec<String>,
        leaves: Vec<Vec<u8>>,
    }

    impl FakeMembership {
        /// A DM: exactly two member inboxes (placeholder ids -- only the
        /// count matters to `hand_over_sequencers`).
        fn dm(leaves: Vec<Vec<u8>>) -> Self {
            FakeMembership {
                members: vec!["inbox-a".into(), "inbox-b".into()],
                leaves,
            }
        }
    }

    #[async_trait]
    impl GroupMembership for FakeMembership {
        async fn member_inboxes(&self, _: &[u8]) -> Result<Option<Vec<String>>, MeshError> {
            Ok(Some(self.members.clone()))
        }
        async fn leaf_installations(&self, _: &[u8]) -> Result<Option<Vec<Vec<u8>>>, MeshError> {
            Ok(Some(self.leaves.clone()))
        }
    }

    fn ids(keys: &[&[u8]]) -> Vec<Vec<u8>> {
        keys.iter().map(|k| k.to_vec()).collect()
    }

    #[test]
    fn the_successor_is_the_lowest_leaf_that_is_neither_revoked_nor_the_same_inbox() {
        let revoked: HashSet<Vec<u8>> = ids(&[b"a"]).into_iter().collect();
        let same_inbox = HashSet::new();
        assert_eq!(
            successor(&ids(&[b"d", b"a", b"c"]), &revoked, &same_inbox),
            Some(b"c".to_vec())
        );
        assert_eq!(
            successor(&ids(&[b"a"]), &revoked, &same_inbox),
            None,
            "every leaf revoked"
        );
    }

    /// D29: the owner's new installation ("a2")
    /// always belongs to the revoked sequencer's own inbox, so it
    /// is excluded from the choice whether or not it sorts lower than the
    /// contact's installation -- the pre-fix code (revoked-only filtering)
    /// would have picked it here, since `b"a2" < b"b"`.
    #[test]
    fn the_successor_never_picks_the_revoked_sequencers_own_inbox_even_if_it_sorts_lower() {
        let revoked: HashSet<Vec<u8>> = ids(&[b"a1"]).into_iter().collect();
        let same_inbox: HashSet<Vec<u8>> = ids(&[b"a1", b"a2"]).into_iter().collect();
        assert_eq!(
            successor(&ids(&[b"a1", b"a2", b"b"]), &revoked, &same_inbox),
            Some(b"b".to_vec()),
            "a2 belongs to the revoked sequencer's own inbox and must never be chosen"
        );
        // Same result whether or not a2's add has been merged into the
        // group's leaves yet -- both arrival orders agree.
        assert_eq!(
            successor(&ids(&[b"a1", b"b"]), &revoked, &same_inbox),
            Some(b"b".to_vec())
        );
    }

    /// A node holding inbox I's log [create, add k1, add k2, revoke k1].
    async fn node_with_a_revocation() -> (MeshNode, Vec<u8>, Vec<u8>) {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let (k1, k2) = (
            XmtpInstallationCredential::new(),
            XmtpInstallationCredential::new(),
        );
        let log = vec![
            origin(&owner).await,
            added_installation(&owner, &inbox, 2, &k1).await,
            added_installation(&owner, &inbox, 3, &k2).await,
            revoked_installation(&owner, &inbox, 4, &k1).await,
        ];
        let node = MeshNode::in_memory().unwrap();
        node.ingest_identity_log(&inbox, log).await.unwrap();
        (node, k1.public_slice().to_vec(), k2.public_slice().to_vec())
    }

    #[tokio::test]
    async fn an_installation_added_then_removed_is_revoked_and_a_live_one_is_not() {
        let (node, k1, k2) = node_with_a_revocation().await;
        let revoked = node.revoked_installations().await.unwrap();
        assert!(revoked.contains(&k1));
        assert!(!revoked.contains(&k2));
    }

    /// §C4.7: our node takes over a group whose pinned sequencer was revoked
    /// (we are the lowest live leaf of the other inbox); our own pending
    /// messages are sequenced here, ids continuing from the last one we
    /// hold. `k2` (the owner's own new installation, same inbox as the
    /// revoked `k1`) is also a leaf here, to prove it is never chosen.
    #[tokio::test]
    async fn a_revoked_sequencer_is_handed_to_the_lowest_live_leaf_and_our_pending_is_sequenced() {
        let (node, k1, k2) = node_with_a_revocation().await;
        let local = vec![0u8; 32]; // lower than any real key, and never revoked
        {
            let mut store = node.inner.store.lock();
            store.set_local_installation(&local).unwrap();
            store.pin_sequencer(b"dm", &k1).unwrap();
            store
                .insert_sequenced(&crate::store::StoredGroupMessage {
                    group_id: b"dm".to_vec(),
                    id: 1,
                    created_ns: 1,
                    data: b"before".to_vec(),
                    sender_hmac: vec![],
                    should_push: false,
                    is_commit: false,
                    seq_signer: None,
                    seq_signature: None,
                })
                .unwrap();
            store
                .add_pending(
                    &NewGroupMessage {
                        group_id: b"dm".to_vec(),
                        data: b"held for the dead sequencer".to_vec(),
                        sender_hmac: vec![],
                        should_push: false,
                        is_commit: false,
                    },
                    2,
                )
                .unwrap();
        }

        let handed = node
            .hand_over_sequencers(&FakeMembership::dm(vec![
                k1.clone(),
                k2.clone(),
                local.clone(),
            ]))
            .await
            .unwrap();

        assert_eq!(handed, vec![b"dm".to_vec()]);
        let mut store = node.inner.store.lock();
        assert_eq!(store.sequencer(b"dm").unwrap(), Some(local));
        assert!(store.pending_for(b"dm").unwrap().is_empty());
        assert_eq!(store.max_group_id(b"dm").unwrap(), 2, "ids continue from 1");
    }

    #[tokio::test]
    async fn a_live_sequencer_is_kept() {
        let (node, _k1, k2) = node_with_a_revocation().await;
        node.inner.store.lock().pin_sequencer(b"dm", &k2).unwrap();
        let handed = node
            .hand_over_sequencers(&FakeMembership::dm(vec![k2.clone(), vec![0u8; 32]]))
            .await
            .unwrap();
        assert!(handed.is_empty());
        assert_eq!(node.inner.store.lock().sequencer(b"dm").unwrap(), Some(k2));
    }

    /// D29: a group qualifies for the handover
    /// only when it has exactly two MEMBER INBOXES, not by leaf count. This
    /// models a real (3-person) group chat: 3 member inboxes, so its
    /// revoked-but-pinned sequencer is left exactly as it was, out of v1's
    /// DM-only scope.
    #[tokio::test]
    async fn a_group_with_three_member_inboxes_keeps_its_pinned_sequencer() {
        let (node, k1, k2) = node_with_a_revocation().await;
        let local = vec![0u8; 32];
        node.inner
            .store
            .lock()
            .pin_sequencer(b"group", &k1)
            .unwrap();

        let membership = FakeMembership {
            members: vec!["inbox-a".into(), "inbox-b".into(), "inbox-c".into()],
            leaves: vec![k1.clone(), k2.clone(), local.clone()],
        };
        let handed = node.hand_over_sequencers(&membership).await.unwrap();

        assert!(
            handed.is_empty(),
            "a 3-member group is out of §C4.7's DM-only scope"
        );
        assert_eq!(
            node.inner.store.lock().sequencer(b"group").unwrap(),
            Some(k1)
        );
    }

    /// Arrival order (a): the owner's re-based installation (k2, standing in for
    /// A2) is added to the group *before* the revoke of k1 (A1) is ingested,
    /// so the group already has 3 leaves by the time the handover runs.
    /// Under a leaf-count guard this would have been
    /// skipped entirely, stalling the DM forever. D29's member-inbox
    /// qualification still hands it over, to the contact (`local`).
    #[tokio::test]
    async fn an_add_that_lands_before_the_revoke_still_hands_the_dm_over() {
        let (node, k1, k2) = node_with_a_revocation().await;
        // This test's job is just "it isn't skipped despite 3 leaves"; the
        // adversarial sort order (does the fix's same-inbox exclusion
        // actually matter, not just the group-qualification gate) is the
        // next test's job.
        let local = vec![0u8; 32];
        node.inner.store.lock().pin_sequencer(b"dm", &k1).unwrap();

        let handed = node
            .hand_over_sequencers(&FakeMembership::dm(vec![
                k1.clone(),
                k2.clone(),
                local.clone(),
            ]))
            .await
            .unwrap();

        assert_eq!(
            handed,
            vec![b"dm".to_vec()],
            "3 leaves must not skip a genuine DM (D29)"
        );
        assert_eq!(
            node.inner.store.lock().sequencer(b"dm").unwrap(),
            Some(local)
        );
    }

    /// Arrival order (b): the owner's add-installation commit (adding k2, i.e.
    /// A2) is sequenced and merged *before* this node's session demotes the
    /// revoked sequencer -- so by the time the handover runs, k2 is already
    /// a leaf. `local` (the contact, B) is chosen here specifically because
    /// `k2` was crafted to sort lower than `local`: the pre-fix code (which
    /// only excluded `revoked`, not "the revoked sequencer's own inbox")
    /// would have picked k2 here, and k2's own node never pins itself
    /// (§C4.7: only a peer can be handed the sequencer, never one's own
    /// still-unaccepted installation) -- the DM would stall. The fix always
    /// picks the OTHER inbox's leaf, so B, never A2, is chosen.
    #[tokio::test]
    async fn a_merged_commit_does_not_let_the_new_installation_out_sort_the_contact() {
        // k2 (standing in for A2) is a genuine, randomly-generated
        // installation key -- with near certainty it sorts below an
        // 0xff-filled id, so `local` (B) is deliberately the *higher*
        // candidate here. Only the same-inbox exclusion (not "lowest of the
        // non-revoked leaves" alone) can make B win.
        let (node, k1, k2) = node_with_a_revocation().await;
        let local = vec![0xffu8; 32];
        node.inner.store.lock().pin_sequencer(b"dm", &k1).unwrap();

        let handed = node
            .hand_over_sequencers(&FakeMembership::dm(vec![
                k1.clone(),
                k2.clone(),
                local.clone(),
            ]))
            .await
            .unwrap();

        assert_eq!(handed, vec![b"dm".to_vec()]);
        assert_eq!(
            node.inner.store.lock().sequencer(b"dm").unwrap(),
            Some(local),
            "B, not A2 -- A2 belongs to the revoked sequencer's own inbox, so it is excluded \
             even though it sorts lower than B here"
        );
    }

    /// The peer-successor branch (we are not the new
    /// sequencer) has its own coverage -- our pending stays held for the
    /// peer to flush, and a `PendingAdded` event fires so sessions know to
    /// flush it.
    #[tokio::test]
    async fn a_peer_successor_gets_pending_added_and_our_pending_stays_held() {
        let (node, k1, _k2) = node_with_a_revocation().await;
        let local = vec![0xffu8; 32]; // sorts above the peer leaf below
        let peer_installation = vec![0x01u8; 32]; // the lowest leaf: the peer becomes sequencer
        {
            let mut store = node.inner.store.lock();
            store.set_local_installation(&local).unwrap();
            store.pin_sequencer(b"dm", &k1).unwrap();
            store
                .add_pending(
                    &NewGroupMessage {
                        group_id: b"dm".to_vec(),
                        data: b"held for the dead sequencer".to_vec(),
                        sender_hmac: vec![],
                        should_push: false,
                        is_commit: false,
                    },
                    1,
                )
                .unwrap();
        }
        let mut events = node.subscribe_events();

        let handed = node
            .hand_over_sequencers(&FakeMembership::dm(vec![
                k1.clone(),
                peer_installation.clone(),
                local.clone(),
            ]))
            .await
            .unwrap();

        assert_eq!(handed, vec![b"dm".to_vec()]);
        assert_eq!(
            node.inner.store.lock().sequencer(b"dm").unwrap(),
            Some(peer_installation)
        );
        assert_eq!(
            node.inner.store.lock().pending_for(b"dm").unwrap().len(),
            1,
            "our pending stays held for the peer sequencer to flush"
        );
        assert!(
            drain(&mut events)
                .iter()
                .any(|e| matches!(e, NodeEvent::PendingAdded(g) if g == b"dm")),
            "sessions must be told to flush our pending to the new (peer) sequencer"
        );
    }
}
