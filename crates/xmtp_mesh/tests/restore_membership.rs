#![recursion_limit = "256"]
//! Group membership across an identity-log replace plus the owner's
//! re-base (restore spec 2026-09-24 §4.5–§4.6; spike note
//! 2026-09-24-restore-spike-membership.md). The replace and resync are
//! driven by hand with sync stopped (Task 4 automates them); what is under
//! test is libxmtp's update-installations commit on both sides.
mod common;

use std::time::Duration;

use alloy::signers::local::PrivateKeySigner;
use common::{
    MalformedKeyPackages, MeshGroup, SimulateUnreconciledFailedLeaf, TestPeer, dm_both_ways,
    eventually, has_key_package, peer, peer_on, rebase, restart_sync,
    revoke_all_other_installations, revoke_installation, send_and_see,
};
use xmtp_cryptography::utils::generate_local_wallet;
use xmtp_mesh::{LoopbackHub, MeshNode};

struct Restored {
    _hub: LoopbackHub,
    wallet: PrivateKeySigner,
    inbox: String,
    a2: TestPeer,
    c: TestPeer,
    a2c: MeshGroup,
    ca2: MeshGroup,
}

/// `a` registers inbox I (the older origin). `a2`, the same wallet on an
/// empty node, forks I and starts a DM with `c`, so the DM's leaves are
/// {a2, c} at I:1 of the fork. Then `a2`'s and `c`'s nodes replace I's log
/// with `a`'s, both clients resync, and `a2` re-bases (I = {a, a2} at
/// seq 2). Sync restarts, and `c` learns seq 2 from `a2`.
async fn restored_dm() -> Restored {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    a.node.stop_sync();
    // Whole-second winner rule (S1, Task 1's C1 fix): `a`'s and `a2`'s
    // `CreateInbox` signatures must land in different whole seconds for `a`
    // to reliably be the earlier origin. A sub-second gap is not enough
    // (see task-2-report.md's identical deviation and node/test_logs.rs's
    // `origin()` helper, which uses the same 1 s spacing for the same reason).
    tokio::time::sleep(Duration::from_secs(1)).await;
    let a2 = peer_on(&hub, "a2", MeshNode::in_memory().unwrap(), &wallet).await;
    let c = peer(&hub, "c").await;
    hub.link("a2", "c");
    has_key_package(&a2.node, &c).await;
    has_key_package(&c.node, &a2).await;
    let (a2c, ca2) = dm_both_ways(&a2, &c, "pre").await;
    hub.unlink("a2", "c");
    a2.node.stop_sync();
    c.node.stop_sync();

    let winner = a.node.identity_log(&inbox).unwrap();
    for p in [&a2, &c] {
        p.node
            .replace_identity_log(&inbox, winner.clone())
            .await
            .unwrap();
        p.client
            .identity_updates()
            .resync_identity_log(&inbox)
            .await
            .unwrap();
    }
    assert!(rebase(&a2, &wallet).await);

    restart_sync(&a2, hub.transport_for("a2"));
    restart_sync(&c, hub.transport_for("c"));
    hub.link("a2", "c");
    eventually("c verifies the re-based a2", || async {
        c.node
            .verified_peers()
            .iter()
            .any(|p| p.installation == a2.installation())
    })
    .await;
    Restored {
        _hub: hub,
        wallet,
        inbox,
        a2,
        c,
        a2c,
        ca2,
    }
}

/// Spike case 1: the contact commits first. Its update would re-add a2,
/// already a leaf (openmls DuplicateSignatureKey), and every send of c's
/// failed until a2 committed. Leaf-aware: c's commit only moves the group
/// to I:2.
#[tokio::test(flavor = "multi_thread")]
async fn after_a_replace_the_contact_can_commit_first() {
    let r = restored_dm().await;
    r.ca2
        .update_installations()
        .await
        .expect("c's update must not re-add a2, which is already a leaf");
    send_and_see(&r.ca2, &r.a2c, "post-1").await;
    send_and_see(&r.a2c, &r.ca2, "post-2").await;
}

/// The spike's control case, which worked before the fix and must keep working.
#[tokio::test(flavor = "multi_thread")]
async fn after_a_replace_the_owner_can_commit_first() {
    let r = restored_dm().await;
    r.a2c.update_installations().await.unwrap();
    send_and_see(&r.a2c, &r.ca2, "post-1").await;
    send_and_see(&r.ca2, &r.a2c, "post-2").await;
}

/// Spike case 2: R2 revokes `a`, which the winning log lists from seq 1 but
/// which never was a leaf of this DM. The expected diff says "remove a",
/// the commit removes nothing, and every receiver refused it
/// (UnexpectedInstallationsRemoved): the DM was dead both ways.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_the_original_that_never_joined_keeps_the_dm_alive() {
    let r = restored_dm().await;
    r.a2c.update_installations().await.unwrap();
    revoke_all_other_installations(&r.a2, &r.wallet).await;
    eventually("c's node holds the revocation (seq 3)", || async {
        r.c.node.identity_log(&r.inbox).unwrap().len() == 3
    })
    .await;

    r.a2c.update_installations().await.unwrap();
    send_and_see(&r.a2c, &r.ca2, "after-revoke-1").await;
    r.ca2.update_installations().await.unwrap();
    send_and_see(&r.ca2, &r.a2c, "after-revoke-2").await;
}

/// c's association-state diff for I is computed against the pre-replace
/// sequence, so it can see a2 as newly "added" even though a2 is already a
/// leaf (the same confusion `after_a_replace_the_contact_can_commit_first`
/// exercises). If a2's own key-package fetch happens to fail at that
/// moment, a leaf must never be recorded as failed in the group's
/// persisted `failed_installations` — otherwise a later, genuine revoke of
/// that leaf could be silently skipped, defeating §4.7's revoke guarantee.
#[tokio::test(flavor = "multi_thread")]
async fn a_leaf_with_a_failed_key_package_fetch_can_still_be_revoked() {
    let r = restored_dm().await;

    // c commits first; a2 looks "added" to c's stale diff, and its own
    // key-package fetch is forced to fail.
    let result = {
        let _guard = MalformedKeyPackages::new(vec![r.a2.installation()]);
        r.ca2.update_installations().await
    };
    result.expect(
        "a spurious failed key-package fetch for an already-leaf installation must not error the commit",
    );

    // The DM must still work: a2 was never actually removed or unreachable.
    send_and_see(&r.a2c, &r.ca2, "post-1").await;
    send_and_see(&r.ca2, &r.a2c, "post-2").await;

    // Now a2's installation is genuinely revoked (the wallet holder can
    // revoke any of their own installations, live or not; R2).
    revoke_installation(&r.a2, &r.wallet, r.a2.installation()).await;
    eventually("c holds a2's revocation (seq 3)", || async {
        r.c.node.identity_log(&r.inbox).unwrap().len() == 3
    })
    .await;

    // The removal must be required and must happen: c's next commit drops
    // a2 from the group's *ratchet-tree leaves* (not just its identity-level
    // association state, which already stops listing a revoked installation
    // regardless of whether the MLS-level removal actually ran).
    r.ca2.update_installations().await.unwrap();
    let leaves = r.ca2.leaf_installation_ids().unwrap();
    assert!(
        !leaves.contains(&r.a2.installation()),
        "a2's revoked installation must be removed from the group's MLS leaves, not silently kept \
         because an earlier, unrelated failed key-package fetch wrongly marked it as failed"
    );
}

/// A `failed_installations` entry can outlive the state that produced it: an
/// inbox's already-published extension can list a leaf as failed (from
/// before a fix existed, or planted by another member — nothing validates
/// what a commit adds to that list). c's copy of I's group is put into
/// exactly that state (`SimulateUnreconciledFailedLeaf`, on top of the same
/// forced key-package failure as the test above), so a2 is both a genuine
/// leaf and (wrongly) listed as failed. A later, genuine revoke of a2 must
/// still remove it: neither the committer's failed∩removed pruning nor the
/// validator's failed-installation exclusion may treat it as already
/// accounted for, because that entry is not, and never was, a legitimate
/// excuse for the removal of an installation that is still a leaf.
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_failed_installations_entry_does_not_excuse_a_leafs_revoke() {
    let r = restored_dm().await;

    // Plant a2 (a genuine leaf) into c's published `failed_installations`,
    // simulating a pre-fix or hostile committer.
    {
        let _malformed = MalformedKeyPackages::new(vec![r.a2.installation()]);
        let _simulate = SimulateUnreconciledFailedLeaf::new();
        r.ca2
            .update_installations()
            .await
            .expect("planting the stale entry must not itself error the commit");
    }

    // Now a2's installation is genuinely revoked.
    revoke_installation(&r.a2, &r.wallet, r.a2.installation()).await;
    eventually("c holds a2's revocation (seq 3)", || async {
        r.c.node.identity_log(&r.inbox).unwrap().len() == 3
    })
    .await;

    // With both test-mode flags off (normal, patched behaviour), the
    // removal must be required and must happen.
    r.ca2.update_installations().await.unwrap();
    let leaves = r.ca2.leaf_installation_ids().unwrap();
    assert!(
        !leaves.contains(&r.a2.installation()),
        "a stale failed_installations entry must not excuse a2's revoked installation from \
         removal, even though that entry predates the revoke and was never cleared"
    );
}
