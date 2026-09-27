#![recursion_limit = "256"]
//! Reset local data under the mesh (DESIGN.md §B10.2). A reset
//! gives the inbox a new installation on a new node generation. A peer that
//! already holds the inbox's log admits it only if the new node carried
//! that log forward, so libxmtp appends AddAssociation at seq N+1 instead
//! of re-creating the inbox at seq 1.
mod common;

use alloy::signers::local::PrivateKeySigner;
use common::{
    ClientGroupMembership, MeshGroup, TestPeer, app_payloads, association_state, eventually, peer,
    peer_on, restart_sync, revoke_all_other_installations,
};
use std::time::Duration;
use xmtp_cryptography::utils::generate_local_wallet;
use xmtp_db::group::GroupQueryArgs;
use xmtp_mesh::frames::{self, Sequenced, frame::Body};
use xmtp_mesh::{LoopbackHub, MeshNode};
use xmtp_mls::groups::send_message_opts::SendMessageOpts;
use xmtp_proto::mls_v1::{GroupMessage, group_message};

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
/// ways, with the reset installation (`a2`, i.e. A2) initiating.
///
/// Without the revoke this is blocked on the dead old installation
/// (`a`, i.e. A1) still listed as a member of `a`'s inbox. `find_or_create_dm`
/// on `a2` resolves DM membership to every currently-valid installation of
/// both inboxes, including the carried log's still-listed A1, and the mesh
/// only ever hands a peer its own node's key package, at handshake
/// (`own_key_package`, `src/node/key_packages.rs`; `send_own_identity`,
/// `src/sync/session.rs`), never a peer's previously-learned third-party key
/// package, so `a2` could never obtain A1's key package once A1 was offline.
///
/// Fixed here by having `a2` revoke A1 right after the carried registration
/// — the same `identity_updates().revoke_installations` + wallet-signature
/// call the app's instance `client.revokeAllOtherInstallations(signer)`
/// uses underneath (see `revoke_all_other_installations` in `tests/common/mod.rs`).
/// `b`'s view of `a`'s inbox is asserted to drop A1 and list A2 before the
/// DM is created, pinning the protocol-level half of D28 (the
/// app-level half is the host's revoke after a reset).
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
/// (a) above does not apply on this path.
///
/// This path used to be blocked on an upstream `xmtp_db` bug, not
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
/// and regardless of A1's revocation state. Fixed by filtering
/// `batch_read_from_cache` to the exact requested pairs (see PATCHES.md;
/// upstream fixed the same bug later).
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

/// The app calls the revoke on every mesh client-ready
/// (D28), so a second call after the first already applied must not
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

/// A DM the *contact* created, before the reset,
/// keeps working after a carried reset plus the D28 revoke — in both
/// directions, with the contact able to send first. Rule A pins the
/// group's sequencer to whichever node's client created it
/// (`group_messages.rs:86-90`); here that is `b`, and `b`'s node survives
/// the reset untouched, so the sequencer never goes away. Contrast with
/// [`a_dm_a1_created_before_the_reset_resumes_with_the_contact_as_sequencer`],
/// where `a`'s (dead) installation was the sequencer, and the §C4.7 handover
/// gives it to `b`.
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

/// `a` (A1) creates a DM with `b` before the reset and they exchange a
/// message each way. Returns (a, b, b's copy of the DM).
async fn a1_created_dm(
    hub: &LoopbackHub,
    wallet: &PrivateKeySigner,
) -> (TestPeer, TestPeer, MeshGroup) {
    let a = peer_on(hub, "a", MeshNode::in_memory().unwrap(), wallet).await;
    let b = peer(hub, "b").await;
    hub.link("a", "b");
    eventually("b has a's key package", || async {
        b.node.has_key_package(&a.installation()).unwrap()
    })
    .await;
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
    (a, b, b_dm)
}

/// Fixed by the §C4.7 sequencer handover (before it, this was
/// a known limitation). Rule A pinned the DM to
/// A1, the installation that created it. After the carried reset, A2's D28
/// revoke of A1 reaches b, and b's node, the lowest live leaf, takes over
/// sequencing. So b can send first into the DM A1 created: its
/// update-installations commit (remove A1, add A2) is sequenced by b, A2
/// joins through the welcome, and the conversation resumes both ways.
#[tokio::test(flavor = "multi_thread")]
async fn a_dm_a1_created_before_the_reset_resumes_with_the_contact_as_sequencer() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let (a, b, b_dm) = a1_created_dm(&hub, &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    hub.unlink("a", "b");
    a.node.stop_sync();
    let a2 = peer_on(&hub, "a2", carried_node(&a.node, &inbox).await, &wallet).await;
    revoke_all_other_installations(&a2, &wallet).await;

    hub.link("a2", "b");
    eventually(
        "b's node takes over sequencing the DM A1 created",
        || async {
            b.node.group_sequencer_for_test(&b_dm.group_id).unwrap() == Some(b.installation())
        },
    )
    .await;
    eventually("b has a2's key package", || async {
        b.node.has_key_package(&a2.installation()).unwrap()
    })
    .await;

    b_dm.update_installations().await.unwrap();
    b_dm.send_message(b"after reset, from b first", SendMessageOpts::default())
        .await
        .unwrap();
    eventually("a2 joins the DM A1 created", || async {
        a2.client.sync_welcomes().await.ok();
        a2.client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .iter()
            .any(|g| g.group_id == b_dm.group_id)
    })
    .await;
    let a2_dm = a2.client.group(&b_dm.group_id).unwrap();
    eventually("a2 sees b's message", || async {
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

/// §C4.7: before the handover, a new DM a2 started with b was stitched to the same
/// dm_id as A1's dead one, and every `sync()` on that dm_id failed
/// (SyncFailedToWait), because libxmtp also syncs the stitched DMs. With
/// the handover, the old DM syncs, so the new one does too.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_dm_stitched_to_a_dm_whose_creator_was_revoked_syncs() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let (a, b, b_dm) = a1_created_dm(&hub, &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    hub.unlink("a", "b");
    a.node.stop_sync();
    let a2 = peer_on(&hub, "a2", carried_node(&a.node, &inbox).await, &wallet).await;
    revoke_all_other_installations(&a2, &wallet).await;
    hub.link("a2", "b");
    eventually("b's node takes over the old DM", || async {
        b.node.group_sequencer_for_test(&b_dm.group_id).unwrap() == Some(b.installation())
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
    assert_ne!(
        a2_dm.group_id, b_dm.group_id,
        "a new MLS group, stitched by dm_id"
    );
    a2_dm
        .send_message(b"a2 starts again", SendMessageOpts::default())
        .await
        .unwrap();
    eventually("b's listing switches to the stitched DM", || async {
        b.client.sync_welcomes().await.ok();
        b.client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .iter()
            .any(|g| g.group_id == a2_dm.group_id)
    })
    .await;
    let b_stitched = b.client.stitched_group(&b_dm.group_id).unwrap();
    eventually("the stitched DM syncs and shows a2's message", || async {
        b_stitched.sync().await.is_ok()
            && app_payloads(&b_stitched).contains(&b"a2 starts again".to_vec())
    })
    .await;
    b_stitched
        .send_message(b"b answers", SendMessageOpts::default())
        .await
        .unwrap();
    eventually("a2 sees b's answer", || async {
        a2_dm.sync().await.ok();
        app_payloads(&a2_dm).contains(&b"b answers".to_vec())
    })
    .await;
}

/// §C4.7 "no split brain": A1 is still alive and verified by
/// b when b learns of its revocation. b demotes it (the §C4.2 re-check),
/// and a Sequenced frame from A1 changes nothing. A1's node also learns of
/// its own revocation from b's log.
///
/// The demotion (the session
/// task's `recheck_membership`) and the handover (the identity task) fire
/// off the *same* log-change event and race each other, so injecting the
/// forged frame right after demotion doesn't by itself prove which check
/// refused it -- the handover might already have repinned the sequencer to
/// b, and a stale-pointer check alone (`sequencer == peer` in
/// `on_sequenced`) would also refuse the frame. b's automatic handover
/// trigger is suppressed for the whole demotion-plus-injection window
/// (`suppress_handover_for_test`; `hand_over_sequencers` itself, called
/// directly at the end, is never suppressed), so the pinned sequencer
/// provably cannot move on its own; the pin is asserted unchanged both
/// right before and right after the injection, so only the membership gate
/// (`on_authenticated_frame` dispatches group traffic to a verified session
/// only) can be what refused it. Only after that is the handover run, to
/// also confirm the DM resumes as §C4.7 intends.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_installation_that_is_still_alive_cannot_sequence() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let (a, b, b_dm) = a1_created_dm(&hub, &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    assert_eq!(
        b.node.group_sequencer_for_test(&b_dm.group_id).unwrap(),
        Some(a.installation())
    );
    b.node.suppress_handover_for_test(true);

    // A2 is carried from A1's live node; A1 stays linked to b.
    let a2 = peer_on(&hub, "a2", carried_node(&a.node, &inbox).await, &wallet).await;
    revoke_all_other_installations(&a2, &wallet).await;

    hub.link("a2", "b");
    eventually("b no longer counts a1 as verified", || async {
        !b.node
            .verified_peers()
            .iter()
            .any(|p| p.installation == a.installation())
    })
    .await;
    assert_eq!(
        b.node.group_sequencer_for_test(&b_dm.group_id).unwrap(),
        Some(a.installation()),
        "b's handover trigger is suppressed: the pin cannot have moved on its own"
    );

    let have = b.node.max_group_id_for_test(&b_dm.group_id).unwrap();
    let forged = GroupMessage {
        version: Some(group_message::Version::V1(group_message::V1 {
            id: have as u64 + 1,
            created_ns: 1,
            group_id: b_dm.group_id.clone(),
            data: b"a1 still thinks it orders this DM".to_vec(),
            sender_hmac: vec![],
            should_push: false,
            is_commit: false,
        })),
    };
    hub.inject(
        "a",
        "b",
        frames::encode(Body::Sequenced(Sequenced {
            group_id: b_dm.group_id.clone(),
            messages: vec![forged],
            sender_is_sequencer: true,
            proofs: vec![],
        })),
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(b.node.max_group_id_for_test(&b_dm.group_id).unwrap(), have);
    assert_eq!(
        b.node.group_sequencer_for_test(&b_dm.group_id).unwrap(),
        Some(a.installation()),
        "the pin still hasn't moved -- only the membership gate could have refused a1's frame"
    );

    // Now let the handover actually run (the trigger stays suppressed, so
    // this is the only thing that can move the pin), to also confirm the
    // DM resumes with b as sequencer.
    b.node
        .hand_over_sequencers(&ClientGroupMembership(b.client.clone()))
        .await
        .unwrap();
    assert_eq!(
        b.node.group_sequencer_for_test(&b_dm.group_id).unwrap(),
        Some(b.installation())
    );
    eventually("a1's node learns its own revocation", || async {
        a.node.identity_log(&inbox).unwrap().len() >= 3
    })
    .await;
    assert_eq!(
        b.node.max_group_id_for_test(&b_dm.group_id).unwrap(),
        have,
        "a1's forged frame still changed nothing, even after the handover"
    );
}

/// A revocation that lands while this node's sync is
/// stopped gets no identity-log event for a running identity task to react
/// to (there is none), so the next `start_sync`'s one-shot handover
/// (node/mod.rs::start_sync) is what must catch it up.
#[tokio::test(flavor = "multi_thread")]
async fn a_revocation_ingested_while_sync_is_stopped_is_handed_over_at_the_next_start_sync() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let (a, b, b_dm) = a1_created_dm(&hub, &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    hub.unlink("a", "b");
    a.node.stop_sync();
    let a2 = peer_on(&hub, "a2", carried_node(&a.node, &inbox).await, &wallet).await;
    revoke_all_other_installations(&a2, &wallet).await;
    let revoked_log = a2.node.identity_log(&inbox).unwrap();

    // b's sync stops before the revocation is folded in, so no identity
    // task is running to hand the DM over when it lands.
    b.node.stop_sync();
    b.node
        .ingest_identity_log_for_test(&inbox, revoked_log)
        .await
        .unwrap();
    assert_eq!(
        b.node.group_sequencer_for_test(&b_dm.group_id).unwrap(),
        Some(a.installation()),
        "no identity task was running to hand over while sync was stopped"
    );

    restart_sync(&b, hub.transport_for("b"));
    eventually(
        "b hands the DM over to itself at the next start_sync",
        || async {
            b.node.group_sequencer_for_test(&b_dm.group_id).unwrap() == Some(b.installation())
        },
    )
    .await;
}
