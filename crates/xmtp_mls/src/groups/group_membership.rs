use crate::groups::intents::Installation;
use openmls::key_packages::KeyPackage;
use prost::{DecodeError, Message};
use std::collections::{HashMap, HashSet};
use xmtp_proto::xmtp::mls::message_contents::GroupMembership as GroupMembershipProto;

#[derive(Debug, Clone, PartialEq)]
pub struct GroupMembership {
    pub(crate) members: HashMap<String, u64>,
    pub(crate) failed_installations: Vec<Vec<u8>>,
}

impl GroupMembership {
    pub fn new() -> Self {
        GroupMembership {
            members: HashMap::new(),
            failed_installations: Vec::new(),
        }
    }

    pub fn add(&mut self, inbox_id: String, last_sequence_id: u64) {
        self.members.insert(inbox_id, last_sequence_id);
    }

    pub fn remove<InboxId: AsRef<str>>(&mut self, inbox_id: InboxId) {
        self.members.remove(inbox_id.as_ref());
    }

    pub fn get<InboxId: AsRef<str>>(&self, inbox_id: InboxId) -> Option<&u64> {
        self.members.get(inbox_id.as_ref())
    }

    pub fn inbox_ids(&self) -> Vec<&str> {
        self.members.keys().map(AsRef::as_ref).collect()
    }

    // Convert the mapping to a vector of `inbox_id`/`sequence_id` tuples
    pub fn to_filters(&self) -> Vec<(&str, i64)> {
        self.members
            .iter()
            .map(|(inbox_id, sequence_id)| (inbox_id.as_str(), *sequence_id as i64))
            .collect()
    }

    pub fn diff<'inbox_id>(
        &'inbox_id self,
        new_group_membership: &'inbox_id Self,
    ) -> MembershipDiff<'inbox_id> {
        let mut removed_inboxes: Vec<&String> = vec![];
        let mut updated_inboxes: Vec<&String> = vec![];

        for (inbox_id, last_sequence_id) in self.members.iter() {
            match new_group_membership.get(inbox_id) {
                Some(new_last_sequence_id) => {
                    if new_last_sequence_id.ne(last_sequence_id) {
                        updated_inboxes.push(inbox_id);
                    }
                }
                None => {
                    removed_inboxes.push(inbox_id);
                }
            }
        }

        let added_inboxes = new_group_membership
            .members
            .iter()
            .filter_map(|(inbox_id, _)| {
                if self.members.contains_key(inbox_id) {
                    None
                } else {
                    Some(inbox_id)
                }
            })
            .collect::<Vec<&String>>();

        MembershipDiff {
            added_inboxes,
            removed_inboxes,
            updated_inboxes,
        }
    }
}

impl Default for GroupMembership {
    fn default() -> Self {
        GroupMembership::new()
    }
}

impl TryFrom<Vec<u8>> for GroupMembership {
    type Error = DecodeError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let membership_proto = GroupMembershipProto::decode(value.as_slice())?;

        Ok(GroupMembership {
            members: membership_proto.members,
            failed_installations: membership_proto.failed_installations,
        })
    }
}

impl From<&GroupMembership> for Vec<u8> {
    fn from(value: &GroupMembership) -> Self {
        let membership_proto = GroupMembershipProto {
            members: value.members.clone(),
            failed_installations: value.failed_installations.clone(),
        };

        membership_proto.encode_to_vec()
    }
}

#[derive(Debug, Clone)]
pub struct MembershipDiff<'inbox_id> {
    pub added_inboxes: Vec<&'inbox_id String>,
    pub removed_inboxes: Vec<&'inbox_id String>,
    pub updated_inboxes: Vec<&'inbox_id String>,
}

#[derive(Debug)]
pub struct MembershipDiffWithKeyPackages {
    pub new_installations: Vec<Installation>,
    pub new_key_packages: Vec<KeyPackage>,
    pub removed_installations: HashSet<Vec<u8>>,
    pub failed_installations: Vec<Vec<u8>>,
}

impl MembershipDiffWithKeyPackages {
    pub fn new(
        new_installations: Vec<Installation>,
        new_key_packages: Vec<KeyPackage>,
        removed_installations: HashSet<Vec<u8>>,
        failed_installations: Vec<Vec<u8>>,
    ) -> MembershipDiffWithKeyPackages {
        MembershipDiffWithKeyPackages {
            new_installations,
            new_key_packages,
            removed_installations,
            failed_installations,
        }
    }

    /// xmtp-mesh restore convergence §4.6, committer half: reconcile the
    /// association-state diff with the ratchet tree (`leaves`: the current
    /// leaves' signature keys). After an identity log was replaced, the diff
    /// can list, as added, an installation that is already a leaf (re-adding
    /// it is an openmls DuplicateSignatureKey error), and, as removed, one
    /// that never was a leaf. Drops both. The add-side drop is load-bearing:
    /// without it the commit itself would fail. The removal-side drop is
    /// redundant with `get_removed_leaf_nodes` (which already intersects
    /// removals with the tree's current members) — the refusal for removing
    /// a non-leaf is cured by the *validator* half
    /// (`expected_diff_matches_commit`), not by this filter; it is kept here
    /// for parity and as a safety net. The commit still carries the new
    /// inbox → sequence_id extension. `new_installations` and
    /// `new_key_packages` are parallel lists (built in one loop in
    /// `get_keypackages_for_installation_ids`).
    pub fn reconcile_with_leaves(&mut self, leaves: &HashSet<Vec<u8>>) {
        debug_assert_eq!(
            self.new_installations.len(),
            self.new_key_packages.len(),
            "new_installations and new_key_packages must stay parallel lists"
        );
        let (installations, key_packages): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.new_installations)
                .into_iter()
                .zip(std::mem::take(&mut self.new_key_packages))
                .filter(|(installation, _)| !leaves.contains(&installation.installation_key))
                .unzip();
        self.new_installations = installations;
        self.new_key_packages = key_packages;
        self.removed_installations.retain(|id| leaves.contains(id));
    }
}

/// Test-only: when enabled, `apply_update_group_membership_intent` skips
/// stripping current leaves from a newly published commit's
/// `failed_installations`, simulating a pre-fix or hostile committer's
/// extension. Lets a test construct "this inbox's already-published state
/// wrongly excuses a leaf's removal" without needing an actual unpatched or
/// malicious peer to have produced it.
#[cfg(any(test, feature = "test-utils"))]
static SIMULATE_UNRECONCILED_FAILED_LEAF: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(any(test, feature = "test-utils"))]
pub fn set_test_mode_simulate_unreconciled_failed_leaf(enable: bool) {
    SIMULATE_UNRECONCILED_FAILED_LEAF.store(enable, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn is_test_mode_simulate_unreconciled_failed_leaf() -> bool {
    SIMULATE_UNRECONCILED_FAILED_LEAF.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(test)]
pub(crate) mod tests {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    use super::{GroupMembership, MembershipDiffWithKeyPackages};
    use std::collections::HashSet;

    /// `reconcile_with_leaves`'s removal-side filter, in isolation (the
    /// add-side filter needs a real openmls `KeyPackage` to construct,
    /// which is exercised end to end instead by the
    /// `after_a_replace_the_contact_can_commit_first` loopback test).
    #[xmtp_common::test]
    fn reconcile_with_leaves_prunes_removals_to_current_leaves() {
        let mut diff = MembershipDiffWithKeyPackages::new(
            Vec::new(),
            Vec::new(),
            HashSet::from([b"leaf".to_vec(), b"ghost".to_vec()]),
            Vec::new(),
        );
        diff.reconcile_with_leaves(&HashSet::from([b"leaf".to_vec()]));
        assert_eq!(
            diff.removed_installations,
            HashSet::from([b"leaf".to_vec()])
        );
    }

    #[xmtp_common::test]
    fn test_equality_works() {
        let inbox_id_1 = "inbox_1".to_string();
        let sequence_id_1: u64 = 1;
        let mut member_map_1 = GroupMembership::new();
        let mut member_map_2 = GroupMembership::new();

        member_map_1.add(inbox_id_1.clone(), sequence_id_1);

        assert!(member_map_1.ne(&member_map_2));

        member_map_2.add(inbox_id_1.clone(), sequence_id_1);
        assert!(member_map_1.eq(&member_map_2));

        // Now change the sequence ID and make sure it is not equal again
        member_map_2.add(inbox_id_1.clone(), 2);
        assert!(member_map_1.ne(&member_map_2));
    }

    #[xmtp_common::test]
    fn test_diff() {
        let mut initial_members = GroupMembership::new();
        initial_members.add("inbox_1".into(), 1);
        initial_members.add("inbox_2".into(), 1);

        let mut updated_list = initial_members.clone();
        updated_list.remove("inbox_1");
        updated_list.add("inbox_2".into(), 2);
        updated_list.add("inbox_3".into(), 1);

        let diff = initial_members.diff(&updated_list);
        assert_eq!(diff.added_inboxes, vec!["inbox_3"]);
        assert_eq!(diff.updated_inboxes, vec!["inbox_2"]);
        assert_eq!(diff.removed_inboxes, vec!["inbox_1"]);
    }
}
