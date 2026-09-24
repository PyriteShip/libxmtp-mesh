#![recursion_limit = "256"]
//! Reset local data under the mesh (root-cause note 2026-09-24). A reset
//! gives the inbox a new installation on a new node generation. A peer that
//! already holds the inbox's log admits it only if the new node carried
//! that log forward, so libxmtp appends AddAssociation at seq N+1 instead
//! of re-creating the inbox at seq 1.
mod common;

use alloy::signers::local::PrivateKeySigner;
use common::{
    TestPeer, app_payloads, association_state, eventually, peer, peer_on,
    revoke_all_other_installations,
};
use std::time::Duration;
use xmtp_cryptography::utils::generate_local_wallet;
use xmtp_db::group::GroupQueryArgs;
use xmtp_mesh::{LoopbackHub, MeshNode};
use xmtp_mls::groups::GroupError;
use xmtp_mls::groups::send_message_opts::SendMessageOpts;

fn verified_installations(node: &MeshNode, inbox_id: &str) -> Vec<Vec<u8>> {
    node.verified_peers()
        .into_iter()
        .filter(|p| p.inbox_id == inbox_id)
        .map(|p| p.installation)
        .collect()
}

/// `a` registers `wallet`'s inbox and `b` verifies it (so `b` holds the
/// log); then `a`'s phone resets: `a` leaves the mesh for good.
async fn known_to_b(hub: &LoopbackHub, wallet: &PrivateKeySigner) -> (TestPeer, TestPeer) {
    let a = peer_on(hub, "a", MeshNode::in_memory().unwrap(), wallet).await;
    let b = peer(hub, "b").await;
    hub.link("a", "b");
    eventually("b verifies a", || async {
        verified_installations(&b.node, a.client.inbox_id()) == vec![a.installation()]
    })
    .await;
    hub.unlink("a", "b");
    a.node.stop_sync();
    (a, b)
}

/// The reset path rotates twice (stopAndRotate, then forClient because the
/// libxmtp DB is gone); each rotation carries the log.
async fn carried_node(old: &MeshNode, inbox_id: &str) -> MeshNode {
    let mid = MeshNode::in_memory().unwrap();
    mid.import_identity_log(inbox_id, old.identity_log(inbox_id).unwrap())
        .await
        .unwrap();
    let fresh = MeshNode::in_memory().unwrap();
    fresh
        .import_identity_log(inbox_id, mid.identity_log(inbox_id).unwrap())
        .await
        .unwrap();
    fresh
}

/// The bug, pinned: without a carry the new installation's node re-creates
/// the inbox at seq 1, and a peer that knew the old installation refuses it.
#[tokio::test(flavor = "multi_thread")]
async fn a_reset_without_a_carry_forks_the_log_and_is_refused() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let (a, b) = known_to_b(&hub, &wallet).await;
    let inbox = a.client.inbox_id().to_string();

    let a2 = peer_on(&hub, "a2", MeshNode::in_memory().unwrap(), &wallet).await;
    assert_eq!(a2.client.inbox_id(), inbox);
    assert_eq!(
        a2.node.identity_log(&inbox).unwrap().len(),
        1,
        "libxmtp re-created the inbox at seq 1"
    );

    hub.link("a2", "b");
    eventually("b drops a2", || async { !hub.is_linked("a2", "b") }).await;
    assert!(!verified_installations(&b.node, &inbox).contains(&a2.installation()));
    assert_eq!(b.node.identity_log(&inbox).unwrap().len(), 1);
}

/// The fix: A registered, B holds A's log, A resets with the log carried
/// forward through both rotations, and B admits A2.
#[tokio::test(flavor = "multi_thread")]
async fn a_reset_that_carries_the_log_is_admitted_by_a_peer_that_knew_the_old_installation() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let (a, b) = known_to_b(&hub, &wallet).await;
    let inbox = a.client.inbox_id().to_string();

    let fresh = carried_node(&a.node, &inbox).await;
    assert_eq!(fresh.local_installation().unwrap(), None);
    assert_eq!(fresh.local_inbox().unwrap(), None);

    let a2 = peer_on(&hub, "a2", fresh, &wallet).await;
    assert_eq!(a2.client.inbox_id(), inbox);
    assert_ne!(a2.installation(), a.installation());
    assert_eq!(
        a2.node.identity_log(&inbox).unwrap().len(),
        2,
        "AddAssociation appended at seq 2, not a second CreateInbox"
    );
    assert_eq!(a2.node.local_inbox().unwrap(), Some(inbox.clone()));

    hub.link("a2", "b");
    eventually("b verifies a2", || async {
        verified_installations(&b.node, &inbox).contains(&a2.installation())
    })
    .await;
    assert!(hub.is_linked("a2", "b"), "b must not drop a2");
    assert_eq!(b.node.identity_log(&inbox).unwrap().len(), 2);
}

/// The device check in miniature: after a carried reset, a DM works both
/// ways, with the reset installation (`a2`, i.e. A2) initiating — the
/// brief's original direction.
///
/// Was ignored, pending Task 2b: blocked on the dead old installation
/// (`a`, i.e. A1) still listed as a member of `a`'s inbox. `find_or_create_dm`
/// on `a2` resolves DM membership to every currently-valid installation of
/// both inboxes, including the carried log's still-listed A1, and the mesh
/// only ever hands a peer its own node's key package, at handshake
/// (`own_key_package`, `src/node/key_packages.rs`; `send_own_identity`,
/// `src/sync/session.rs`), never a peer's previously-learned third-party key
/// package, so `a2` could never obtain A1's key package once A1 was offline.
/// Full trace: `dm-after-reset-analysis.md`, "(a) The old installation's key
/// package".
///
/// Fixed here by having `a2` revoke A1 right after the carried registration
/// — the same `identity_updates().revoke_installations` + wallet-signature
/// call the app's instance `client.revokeAllOtherInstallations(signer)`
/// uses underneath (`progress.md` Ruling R2; `dm-after-reset-analysis.md`
/// Option 1; see `revoke_all_other_installations` in `tests/common/mod.rs`).
/// `b`'s view of `a`'s inbox is asserted to drop A1 and list A2 before the
/// DM is created, pinning the protocol-level half of Ruling R2 (the
/// app-level hook is Task 6a/7).
#[tokio::test(flavor = "multi_thread")]
async fn after_a_carried_reset_a_dm_works_both_ways() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let (a, b) = known_to_b(&hub, &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    let a2 = peer_on(&hub, "a2", carried_node(&a.node, &inbox).await, &wallet).await;

    revoke_all_other_installations(&a2, &wallet).await;

    hub.link("a2", "b");
    eventually("b's view of a's inbox drops a1 and lists a2", || async {
        let ids = association_state(&b.node, &inbox).await.installation_ids();
        !ids.contains(&a.installation()) && ids.contains(&a2.installation())
    })
    .await;
    eventually("a2 has b's key package", || async {
        a2.node.has_key_package(&b.installation()).unwrap()
    })
    .await;

    let a2_dm = a2
        .client
        .find_or_create_dm(b.client.inbox_id(), None)
        .await
        .unwrap();
    a2_dm
        .send_message(b"back", SendMessageOpts::default())
        .await
        .unwrap();

    eventually("b receives the welcome", || async {
        b.client.sync_welcomes().await.unwrap();
        b.client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .len()
            == 1
    })
    .await;
    let b_dm = b
        .client
        .find_groups(GroupQueryArgs::default())
        .unwrap()
        .remove(0);
    eventually("b sees back", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm) == vec![b"back".to_vec()]
    })
    .await;

    b_dm.send_message(b"welcome back", SendMessageOpts::default())
        .await
        .unwrap();
    eventually("a2 sees the reply", || async {
        a2_dm.sync().await.ok();
        app_payloads(&a2_dm) == vec![b"back".to_vec(), b"welcome back".to_vec()]
    })
    .await;
}

/// Like [`after_a_carried_reset_a_dm_works_both_ways`], but the peer (`b`)
/// initiates the DM instead of the reset installation. `b` already cached
/// A1's key package from the earlier `a`<->`b` handshake in `known_to_b`,
/// and libxmtp's update-installations-on-send then only needs to *add* A2
/// (whose key package `b` has from its own handshake with `a2`), so blocker
/// (a) above does not apply on this path (`dm-after-reset-analysis.md`,
/// "The B-initiated path works without the fix").
///
/// Was ignored, pending Task 2a: blocked on an upstream `xmtp_db` bug, not
/// on the old installation. `MlsGroup::members()`
/// (`crates/xmtp_mls/src/groups/members.rs:35-86`) asks
/// `batch_read_from_cache` for the group's `(inbox_id, sequence_id)` pairs;
/// that function
/// (`crates/xmtp_db/src/encrypted_store/association_state.rs:115-139`)
/// filtered `inbox IN (..) AND seq IN (..)` — a cross product of the two
/// lists, not a match on the requested pairs. Once any mesh inbox's log
/// reaches two updates (which the carry is what first produces), a
/// two-member DM's cache query returned more rows than requested and
/// `members()` failed with `InvalidGroupMembership`, on both linking orders
/// and regardless of A1's revocation state. Full trace:
/// `dm-after-reset-analysis.md`, "(b) Root cause: the association-state
/// cache query returns a cross product"; fixed by Task 2a, filtering
/// `batch_read_from_cache` to the exact requested pairs (`progress.md`
/// Ruling R1).
#[tokio::test(flavor = "multi_thread")]
async fn after_a_carried_reset_a_dm_started_by_the_peer_works_both_ways() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let (a, b) = known_to_b(&hub, &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    let a2 = peer_on(&hub, "a2", carried_node(&a.node, &inbox).await, &wallet).await;

    hub.link("a2", "b");
    eventually("b has a2's key package", || async {
        b.node.has_key_package(&a2.installation()).unwrap()
    })
    .await;

    let b_dm = b
        .client
        .find_or_create_dm(a2.client.inbox_id(), None)
        .await
        .unwrap();
    b_dm.send_message(b"hi again", SendMessageOpts::default())
        .await
        .unwrap();

    eventually("a2 receives the welcome", || async {
        a2.client.sync_welcomes().await.unwrap();
        a2.client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .len()
            == 1
    })
    .await;
    let a2_dm = a2
        .client
        .find_groups(GroupQueryArgs::default())
        .unwrap()
        .remove(0);
    eventually("a2 sees hi again", || async {
        a2_dm.sync().await.ok();
        app_payloads(&a2_dm) == vec![b"hi again".to_vec()]
    })
    .await;

    a2_dm
        .send_message(b"back", SendMessageOpts::default())
        .await
        .unwrap();
    eventually("b sees back", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm) == vec![b"hi again".to_vec(), b"back".to_vec()]
    })
    .await;
}

/// Task 2b, step 4: the app calls the revoke on every mesh client-ready
/// (Ruling R2), so a second call after the first already applied must not
/// fail. `revoke_all_other_installations` mirrors the FFI's own guard
/// (`revoke_all_other_installations_signature_request`,
/// `bindings/mobile/src/mls.rs:952-976`): the second call finds no other
/// installation in `a2`'s inbox state and returns without submitting
/// anything, rather than resubmitting the first call's now-stale wallet
/// signature (which the association state's replay protection would
/// reject).
#[tokio::test(flavor = "multi_thread")]
async fn revoking_the_old_installation_twice_is_idempotent() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    a.node.stop_sync();

    let a2 = peer_on(&hub, "a2", carried_node(&a.node, &inbox).await, &wallet).await;

    revoke_all_other_installations(&a2, &wallet).await;
    let after_first = association_state(&a2.node, &inbox).await.installation_ids();
    assert_eq!(after_first, vec![a2.installation()], "a1 is revoked");

    revoke_all_other_installations(&a2, &wallet).await;
    let after_second = association_state(&a2.node, &inbox).await.installation_ids();
    assert_eq!(after_second, after_first, "second revoke is a no-op");
}

/// Final-review finding I1: a DM the *contact* created, before the reset,
/// keeps working after a carried reset plus the R2 revoke — in both
/// directions, with the contact able to send first. Rule A pins the
/// group's sequencer to whichever node's client created it
/// (`group_messages.rs:86-90`); here that is `b`, and `b`'s node survives
/// the reset untouched, so the sequencer never goes away. Contrast with
/// [`a_dm_a1_created_before_the_reset_stays_held_until_a2_sends_known_limitation`],
/// where `a`'s (dead) installation is the sequencer.
#[tokio::test(flavor = "multi_thread")]
async fn a_dm_the_peer_created_before_the_reset_keeps_working_after_a_carried_reset() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    eventually("b has a's key package", || async {
        b.node.has_key_package(&a.installation()).unwrap()
    })
    .await;

    // b creates the DM before a's reset, and they exchange messages.
    let b_dm = b
        .client
        .find_or_create_dm(a.client.inbox_id(), None)
        .await
        .unwrap();
    b_dm.send_message(b"hi before reset", SendMessageOpts::default())
        .await
        .unwrap();

    eventually("a receives the welcome", || async {
        a.client.sync_welcomes().await.unwrap();
        a.client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .len()
            == 1
    })
    .await;
    let a_dm = a
        .client
        .find_groups(GroupQueryArgs::default())
        .unwrap()
        .remove(0);
    eventually("a sees hi before reset", || async {
        a_dm.sync().await.ok();
        app_payloads(&a_dm) == vec![b"hi before reset".to_vec()]
    })
    .await;

    a_dm.send_message(b"hi back before reset", SendMessageOpts::default())
        .await
        .unwrap();
    eventually("b sees hi back before reset", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm)
            == vec![
                b"hi before reset".to_vec(),
                b"hi back before reset".to_vec(),
            ]
    })
    .await;

    // a resets: carried log, revoke A1.
    let inbox = a.client.inbox_id().to_string();
    hub.unlink("a", "b");
    a.node.stop_sync();
    let a2 = peer_on(&hub, "a2", carried_node(&a.node, &inbox).await, &wallet).await;
    revoke_all_other_installations(&a2, &wallet).await;

    hub.link("a2", "b");
    eventually("b's view of a's inbox drops a1 and lists a2", || async {
        let ids = association_state(&b.node, &inbox).await.installation_ids();
        !ids.contains(&a.installation()) && ids.contains(&a2.installation())
    })
    .await;

    // Force the membership check send_message would otherwise throttle to
    // SEND_MESSAGE_UPDATE_INSTALLATIONS_INTERVAL_NS (5s); the test doesn't
    // wait that long between the reset and the contact's next send.
    b_dm.update_installations().await.unwrap();

    // The contact sends first, into the DM it originally created.
    b_dm.send_message(b"after reset, from b first", SendMessageOpts::default())
        .await
        .unwrap();

    eventually(
        "a2 receives the welcome from b's membership-update commit",
        || async {
            a2.client.sync_welcomes().await.unwrap();
            a2.client
                .find_groups(GroupQueryArgs::default())
                .unwrap()
                .len()
                == 1
        },
    )
    .await;
    let a2_dm = a2
        .client
        .find_groups(GroupQueryArgs::default())
        .unwrap()
        .remove(0);
    eventually("a2 sees b's after-reset message", || async {
        a2_dm.sync().await.ok();
        app_payloads(&a2_dm).contains(&b"after reset, from b first".to_vec())
    })
    .await;

    a2_dm
        .send_message(b"a2 replies", SendMessageOpts::default())
        .await
        .unwrap();
    eventually("b sees a2's reply", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm).contains(&b"a2 replies".to_vec())
    })
    .await;
}

/// Final-review finding I1, pinned as a known limitation: a DM that **A1**
/// (the old installation) created before the reset. Rule A pinned the
/// group's sequencer to A1's installation
/// (`group_messages.rs:86-90`), and A1 never comes back. After the carried
/// reset plus the R2 revoke, if the contact (`b`) sends first into that
/// same DM, its membership-update commit (dropping A1, adding A2) has
/// nowhere to be sequenced: it sits in `add_pending` on `b`'s node forever,
/// and `a2` never receives it (`b`'s own installation is not the
/// sequencer, `a2` does not exist as a member of that MLS group at all).
///
/// Matches `dm-after-reset-analysis.md` and restore-spike surprise 2.
///
/// The rescue the app relies on — the reset phone opens the contact and
/// sends — turns out to be worse than final-review.md I1 describes.
/// `find_or_create_dm` on `a2`'s (empty, post-reset) database has no local
/// record of the old group, so it creates a *new* MLS group, dm_id-stitched
/// to the old one (`xmtp_db`'s `find_active_dm_group`/`fetch_stitched`,
/// which pick the group with the newest `last_message_ns`). `b` *does*
/// receive the welcome for that new group and its own group listing
/// (`find_groups`, which dedupes by dm_id) switches over to it. But
/// `MlsGroup::sync()` unconditionally also syncs every other group sharing
/// the same `dm_id` first (`mls_sync.rs:306-320`, "Also sync the 'stitched
/// DMs'") and propagates that sync's error with `?`. The old, abandoned
/// group is one of those "other dms", and it can never sync (A1 is still
/// its sequencer, and A1 is gone forever), so **every** `.sync()` call
/// b ever makes on this dm_id — old group, new group, doesn't matter which
/// object — keeps failing with `SyncFailedToWait`, permanently. b's client
/// can see that a2's new DM exists, but can never actually pull down a2's
/// message content through the public `sync()` API. This is asserted below
/// instead of the "conversation resumes" outcome the mechanism paragraph
/// above (and the docs) describe, because that is not what this test
/// observes.
///
/// This test asserts what actually happens; if a future libxmtp/mesh
/// change makes any part of this pass differently (the limitation is
/// fixed, in full or in part), update the assertions below to match and
/// drop "known_limitation" from the name once nothing here is pinning
/// broken behaviour anymore.
#[tokio::test(flavor = "multi_thread")]
async fn a_dm_a1_created_before_the_reset_stays_held_until_a2_sends_known_limitation() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    eventually("b has a's key package", || async {
        b.node.has_key_package(&a.installation()).unwrap()
    })
    .await;

    // A1 creates the DM before the reset, and they exchange messages.
    let a_dm = a
        .client
        .find_or_create_dm(b.client.inbox_id(), None)
        .await
        .unwrap();
    a_dm.send_message(b"hi from a1", SendMessageOpts::default())
        .await
        .unwrap();

    eventually("b receives the welcome", || async {
        b.client.sync_welcomes().await.unwrap();
        b.client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .len()
            == 1
    })
    .await;
    let b_dm = b
        .client
        .find_groups(GroupQueryArgs::default())
        .unwrap()
        .remove(0);
    eventually("b sees hi from a1", || async {
        b_dm.sync().await.ok();
        app_payloads(&b_dm) == vec![b"hi from a1".to_vec()]
    })
    .await;

    b_dm.send_message(b"reply from b before reset", SendMessageOpts::default())
        .await
        .unwrap();
    eventually("a1 sees the reply before reset", || async {
        a_dm.sync().await.ok();
        app_payloads(&a_dm)
            == vec![
                b"hi from a1".to_vec(),
                b"reply from b before reset".to_vec(),
            ]
    })
    .await;

    // a resets: carried log, revoke A1. a1's node (and its pin as this
    // group's sequencer) is now gone for good.
    let inbox = a.client.inbox_id().to_string();
    hub.unlink("a", "b");
    a.node.stop_sync();
    let a2 = peer_on(&hub, "a2", carried_node(&a.node, &inbox).await, &wallet).await;
    revoke_all_other_installations(&a2, &wallet).await;

    hub.link("a2", "b");
    eventually("b's view of a's inbox drops a1 and lists a2", || async {
        let ids = association_state(&b.node, &inbox).await.installation_ids();
        !ids.contains(&a.installation()) && ids.contains(&a2.installation())
    })
    .await;

    // Force the same membership check send_message would otherwise throttle
    // to SEND_MESSAGE_UPDATE_INSTALLATIONS_INTERVAL_NS (5s); this test
    // doesn't wait that long between the reset and b's next send. b is not
    // this group's sequencer (a1 is, and a1 is gone), so this
    // membership-update commit itself has nowhere to be sequenced: pinned,
    // it fails synchronously rather than silently succeeding and being
    // held server-side.
    let update_result = b_dm.update_installations().await;
    assert!(
        matches!(update_result, Err(GroupError::SyncFailedToWait(_))),
        "expected update_installations to fail waiting for a1 (the dead sequencer) to \
         acknowledge the membership-update commit; got {update_result:?} instead — the known \
         limitation no longer reproduces this way, update the docs and this test"
    );

    // b sends first, into the DM A1 created. Pinned: this also fails
    // synchronously, for the same reason (b's send_message runs the same
    // update-installations check first, at mod.rs:604-605).
    let send_result = b_dm
        .send_message(
            b"after reset, from b first (should be held)",
            SendMessageOpts::default(),
        )
        .await;
    assert!(
        matches!(send_result, Err(GroupError::SyncFailedToWait(_))),
        "expected b's send to fail the same way as update_installations; got {send_result:?} \
         instead — the known limitation no longer reproduces this way, update the docs and \
         this test"
    );

    // a2 never even learns this group exists: the membership-update commit
    // that would add it never got sequenced, so no welcome for it was ever
    // built. Give it a moment to prove that, rather than a bare snapshot.
    tokio::time::sleep(Duration::from_millis(500)).await;
    a2.client.sync_welcomes().await.ok();
    let a2_groups_before_rescue = a2.client.find_groups(GroupQueryArgs::default()).unwrap();
    assert!(
        a2_groups_before_rescue.is_empty(),
        "a2 unexpectedly has a group before sending its own rescue message: {:?}; the known \
         limitation no longer reproduces the way I1 describes it — update the docs and this test",
        a2_groups_before_rescue
            .iter()
            .map(|g| g.group_id.clone())
            .collect::<Vec<_>>()
    );

    // The only known rescue: a2 opens the contact and sends, which (per the
    // app's find_or_create_dm on a2's empty post-reset database) creates a
    // *new* MLS group rather than resuming the held one.
    eventually("a2 has b's key package", || async {
        a2.node.has_key_package(&b.installation()).unwrap()
    })
    .await;
    let a2_dm = a2
        .client
        .find_or_create_dm(b.client.inbox_id(), None)
        .await
        .unwrap();
    assert_ne!(
        a2_dm.group_id, b_dm.group_id,
        "the rescue creates a new MLS group rather than resuming A1's old one"
    );
    a2_dm
        .send_message(
            b"a2 sends to rescue the conversation",
            SendMessageOpts::default(),
        )
        .await
        .unwrap();

    // b *does* receive the welcome, and its own (deduped) group listing
    // switches over to a2's new group.
    eventually(
        "b's group listing switches to a2's new (stitched) group",
        || async {
            b.client.sync_welcomes().await.unwrap();
            b.client
                .find_groups(GroupQueryArgs::default())
                .unwrap()
                .iter()
                .any(|g| g.group_id == a2_dm.group_id)
        },
    )
    .await;

    // But the rescue does not actually resume delivery of new messages:
    // MlsGroup::sync() also syncs every other group sharing this dm_id
    // before syncing itself (mls_sync.rs "Also sync the 'stitched DMs'"),
    // and propagates that sync's error. The old, abandoned group is one of
    // those "other dms", can never sync (a1 is still its pinned sequencer),
    // so *every* sync() call on this dm_id keeps failing — b can see that
    // a2's DM exists, but can never pull down a2's rescuing message through
    // the public sync() API.
    let b_stitched = b.client.stitched_group(&b_dm.group_id).unwrap();
    assert_eq!(
        b_stitched.group_id, a2_dm.group_id,
        "the stitched lookup should already prefer a2's new group over a1's old one"
    );
    let stitched_sync_result = b_stitched.sync().await;
    assert!(
        matches!(stitched_sync_result, Err(GroupError::SyncFailedToWait(_))),
        "expected syncing the rescued (stitched) group to still fail, cascading from the old \
         group's permanently-stuck sync; got {stitched_sync_result:?} instead — either the \
         known limitation is fully resolved, or it takes a different shape now. Update the \
         docs and this test to match, rather than leaving this assertion in place"
    );
    assert!(
        !app_payloads(&b_stitched).contains(&b"a2 sends to rescue the conversation".to_vec()),
        "b unexpectedly received a2's rescuing message despite the stitched sync failing; the \
         known limitation no longer reproduces this way — update the docs and this test"
    );
}
