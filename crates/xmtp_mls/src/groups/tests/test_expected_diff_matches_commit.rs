//! xmtp-mesh restore convergence DESIGN.md §C4.6, validator half: after an identity
//! log was replaced, the expected diff can list, as removed, an installation
//! that was never a leaf. Removing a non-leaf is a no-op, so no commit can
//! do it; it must not be required. Everything else is validated as before.
use std::collections::HashSet;

use crate::groups::validated_commit::{CommitValidationError, expected_diff_matches_commit};
use crate::identity_updates::InstallationDiff;

fn set(ids: &[&[u8]]) -> HashSet<Vec<u8>> {
    ids.iter().map(|id| id.to_vec()).collect()
}

fn expected(added: &[&[u8]], removed: &[&[u8]]) -> InstallationDiff {
    InstallationDiff {
        added_installations: set(added),
        removed_installations: set(removed),
    }
}

#[test]
fn an_expected_removal_of_an_installation_that_is_not_a_leaf_is_not_required() {
    // The replaced log revokes `a`, which never joined this DM (leaves a2, c).
    let result = expected_diff_matches_commit(
        &expected(&[], &[b"a"]),
        set(&[]),
        set(&[]),
        set(&[b"a2", b"c"]),
        set(&[]),
    );
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn an_expected_removal_of_a_leaf_is_still_required() {
    let err = expected_diff_matches_commit(
        &expected(&[], &[b"a"]),
        set(&[]),
        set(&[]),
        set(&[b"a", b"c"]),
        set(&[]),
    )
    .unwrap_err();
    // The diagnostic names the missing removal instead of printing an
    // empty `unexpected` vec.
    match err {
        CommitValidationError::UnexpectedInstallationsRemoved {
            unexpected,
            missing,
        } => {
            assert!(unexpected.is_empty(), "{unexpected:?}");
            assert_eq!(missing, vec![b"a".to_vec()]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn removing_a_leaf_nobody_expected_is_still_refused() {
    let err = expected_diff_matches_commit(
        &expected(&[], &[]),
        set(&[]),
        set(&[b"c"]),
        set(&[b"a2", b"c"]),
        set(&[]),
    )
    .unwrap_err();
    match err {
        CommitValidationError::UnexpectedInstallationsRemoved {
            unexpected,
            missing,
        } => {
            assert_eq!(unexpected, vec![b"c".to_vec()]);
            assert!(missing.is_empty(), "{missing:?}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_failed_installations_entry_cannot_excuse_a_leafs_removal() {
    // `a` is both a current leaf and (wrongly, from stale state or a
    // planted entry) listed as failed. Its removal is still required: a
    // commit's own claimed failed list must never excuse removing an
    // installation that is genuinely still a leaf.
    let err = expected_diff_matches_commit(
        &expected(&[], &[b"a"]),
        set(&[]),
        set(&[]),
        set(&[b"a", b"c"]),
        set(&[b"a"]),
    )
    .unwrap_err();
    match err {
        CommitValidationError::UnexpectedInstallationsRemoved {
            unexpected,
            missing,
        } => {
            assert!(unexpected.is_empty(), "{unexpected:?}");
            assert_eq!(missing, vec![b"a".to_vec()]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_unexpected_new_installation_is_still_refused() {
    let err = expected_diff_matches_commit(
        &expected(&[], &[]),
        set(&[b"x"]),
        set(&[]),
        set(&[b"a2", b"c"]),
        set(&[]),
    )
    .unwrap_err();
    assert!(
        matches!(err, CommitValidationError::UnexpectedInstallationAdded(_)),
        "{err:?}"
    );
}
