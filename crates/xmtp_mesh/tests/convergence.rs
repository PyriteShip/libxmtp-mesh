#![recursion_limit = "256"]
//! Restore convergence through the sync session (spec 2026-09-24 §4.1–§4.4,
//! §6 "Rust integration test (4 nodes)"). A restore with no old node forks
//! the inbox's identity log at sequence 1. Peers keep the log with the
//! earlier origin, relay it, and hand it to the restored owner in an
//! IdentityConflict. The owner's node replaces its log, its client reloads
//! and re-bases, and R2 revokes the original. Everything here runs through
//! real sessions; only the app's reaction (re-base, then revoke) is driven
//! by the test, as the app does it.
mod common;

use std::time::Duration;

use alloy::signers::local::PrivateKeySigner;
use std::sync::Arc;

use common::{
    Recording, TestPeer, association_state, client_log, dm_both_ways, eventually, eventually_for,
    has_key_package, next_resync, node_log, peer, peer_on, rebase, recorded_peer,
    revoke_all_other_installations, see, send_and_see,
};
use xmtp_cryptography::utils::generate_local_wallet;
use xmtp_db::group::GroupQueryArgs;
use xmtp_mesh::frames::{self, IdentityLog, frame::Body};
use xmtp_mesh::{LoopbackHub, MeshNode, ResyncOutcome};
use xmtp_proto::xmtp::identity::api::v1::get_identity_updates_response::IdentityUpdateLog;

fn verifies(node: &MeshNode, who: &TestPeer) -> bool {
    node.verified_peers()
        .iter()
        .any(|p| p.installation == who.installation())
}

/// The app's reaction to RebaseNeeded (Task 10): re-base, then R2.
async fn rebase_and_revoke(owner: &TestPeer, wallet: &PrivateKeySigner) {
    assert!(
        rebase(owner, wallet).await,
        "the owner was not in the winning log"
    );
    revoke_all_other_installations(owner, wallet).await;
}

/// §6: A is the original and B holds A's log (B started an A–B DM). A′
/// restores alone and meets C. Then C meets B (no relay: C shares no group
/// with I that B knows), A′ meets B, and A′ meets C again.
/// Afterwards A′, B and C hold one log, A′ is a member, A is revoked (R2),
/// and DMs A′↔C (the contact committing first) and A′↔B carry new messages.
#[tokio::test(flavor = "multi_thread")]
async fn a_restored_owner_and_its_contacts_converge_on_the_older_log() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();

    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    let b = peer(&hub, "b").await;
    // Ruling F10 (progress.md): b gets the same 60 s verification deadline
    // as c, its sibling below.
    b.node
        .set_peer_verify_timeout_for_test(Duration::from_secs(60));
    hub.link("a", "b");
    has_key_package(&a.node, &b).await;
    has_key_package(&b.node, &a).await;
    let (b_ab, _a_ab) = dm_both_ways(&b, &a, "ab").await;
    hub.unlink("a", "b");
    a.node.stop_sync();
    let a_log = node_log(&a.node, &inbox);

    // Whole-second winner rule (S1, Task 1's C1 fix): a's and a2's
    // CreateInbox signatures must land in different whole seconds for a's
    // origin to reliably rank earlier (deviation from the brief's 2 ms).
    tokio::time::sleep(Duration::from_secs(1)).await;
    let a2 = peer_on(&hub, "a2", MeshNode::in_memory().unwrap(), &wallet).await;
    let fork = node_log(&a2.node, &inbox);
    assert_ne!(fork[0], a_log[0], "a2 forked I at seq 1");
    let c = peer(&hub, "c").await;
    c.node
        .set_peer_verify_timeout_for_test(Duration::from_secs(60));
    hub.link("a2", "c");
    has_key_package(&a2.node, &c).await;
    has_key_package(&c.node, &a2).await;
    let (a2c, ca2) = dm_both_ways(&a2, &c, "pre").await;
    hub.unlink("a2", "c");

    // C meets B. C and I share no group that B knows (B knows only its DM
    // with A), so B relays nothing to C, a stranger to I: C keeps the fork.
    hub.link("b", "c");
    eventually("b verifies c", || async { verifies(&b.node, &c) }).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        node_log(&c.node, &inbox),
        fork,
        "no relay to a peer outside every shared group"
    );
    hub.unlink("b", "c");

    // A′ meets B: B's log wins, so A′ gets an IdentityConflict, replaces its
    // own log, and must re-base; then R2 revokes A.
    let mut a2_events = a2.node.subscribe_events();
    hub.link("a2", "b");
    assert_eq!(
        next_resync(&mut a2_events, &inbox).await,
        ResyncOutcome::RebaseNeeded
    );
    assert_eq!(client_log(&a2, &inbox), a_log, "no hybrid on the owner");
    rebase_and_revoke(&a2, &wallet).await;
    eventually("b verifies the re-based a2", || async {
        verifies(&b.node, &a2)
    })
    .await;
    eventually("b holds the re-base and the revoke", || async {
        node_log(&b.node, &inbox).len() == 3
    })
    .await;
    has_key_package(&b.node, &a2).await;
    b_ab.update_installations().await.unwrap();
    send_and_see_new(&b_ab, &a2, "b-after").await;
    hub.unlink("a2", "b");

    // A′ meets C again (spec §4.2: contacts met while alone converge when
    // they meet the owner again). A′'s log now starts with A's older origin,
    // so C replaces its fork, reloads its client, and verifies A′.
    hub.link("a2", "c");
    eventually("c replaces the fork with the owner's log", || async {
        node_log(&c.node, &inbox) == node_log(&a2.node, &inbox)
    })
    .await;
    eventually("c's client reloads (no hybrid on a contact)", || async {
        client_log(&c, &inbox) == node_log(&a2.node, &inbox)
    })
    .await;
    eventually("c verifies the re-based a2", || async {
        verifies(&c.node, &a2)
    })
    .await;

    // A′↔C, the contact committing first (spec §4.6).
    ca2.update_installations().await.unwrap();
    send_and_see(&ca2, &a2c, "post-1").await;
    send_and_see(&a2c, &ca2, "post-2").await;

    // One log everywhere, A′ in it, A revoked, and each node replaced at most once.
    let converged = node_log(&a2.node, &inbox);
    assert_eq!(node_log(&b.node, &inbox), converged);
    assert_eq!(node_log(&c.node, &inbox), converged);
    assert_eq!(
        association_state(&b.node, &inbox).await.installation_ids(),
        vec![a2.installation()]
    );
    assert_eq!(a2.node.replacements_for_test(), 1);
    assert_eq!(b.node.replacements_for_test(), 0);
    assert_eq!(c.node.replacements_for_test(), 1);
}

/// `from` (a DM the other side joins through a welcome) sends `text`;
/// `to` joins that DM and shows it, then replies.
async fn send_and_see_new(from: &common::MeshGroup, to: &TestPeer, text: &str) {
    from.send_message(text.as_bytes(), Default::default())
        .await
        .unwrap();
    eventually("the welcome to the existing DM", || async {
        to.client.sync_welcomes().await.ok();
        to.client
            .find_groups(GroupQueryArgs::default())
            .unwrap()
            .iter()
            .any(|g| g.group_id == from.group_id)
    })
    .await;
    let joined = to
        .client
        .find_groups(GroupQueryArgs::default())
        .unwrap()
        .into_iter()
        .find(|g| g.group_id == from.group_id)
        .unwrap();
    see(&joined, text).await;
    send_and_see(&joined, from, &format!("{text}-reply")).await;
}

/// §6: an early clock on the restored phone. A′'s origin is older, so its
/// fork wins; the original A replaces its own log and re-bases instead (and
/// R2 then revokes A′), with the same convergence.
#[tokio::test(flavor = "multi_thread")]
async fn an_early_clock_on_the_restored_phone_makes_the_original_re_base() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    // A′ signs its CreateInbox first: the earlier client timestamp. Whole-
    // second winner rule (S1): the gap must cross a whole second reliably,
    // so 1 s (deviation from the brief's 2 ms, which was observed flaky).
    let a2 = peer_on(&hub, "a2", MeshNode::in_memory().unwrap(), &wallet).await;
    let inbox = a2.client.inbox_id().to_string();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let b = peer(&hub, "b").await;
    b.node
        .set_peer_verify_timeout_for_test(Duration::from_secs(60));
    hub.link("a", "b");
    has_key_package(&a.node, &b).await;
    has_key_package(&b.node, &a).await;
    let (b_ab, a_ab) = dm_both_ways(&b, &a, "ab").await;
    hub.unlink("a", "b");

    // A′ meets B: A′'s origin is older, so B replaces A's log with it and
    // verifies A′.
    let a2_log = node_log(&a2.node, &inbox);
    hub.link("a2", "b");
    eventually("b replaces A's log with the older fork", || async {
        node_log(&b.node, &inbox) == a2_log
    })
    .await;
    eventually("b verifies a2", || async { verifies(&b.node, &a2) }).await;
    hub.unlink("a2", "b");

    let mut a_events = a.node.subscribe_events();
    hub.link("a", "b");
    assert_eq!(
        next_resync(&mut a_events, &inbox).await,
        ResyncOutcome::RebaseNeeded
    );
    rebase_and_revoke(&a, &wallet).await;
    eventually("b verifies the re-based a", || async {
        verifies(&b.node, &a)
    })
    .await;
    eventually("b holds A's re-base and the revoke of A′", || async {
        node_log(&b.node, &inbox).len() == 3
    })
    .await;

    b_ab.update_installations().await.unwrap();
    send_and_see(&b_ab, &a_ab, "after-1").await;
    send_and_see(&a_ab, &b_ab, "after-2").await;

    assert_eq!(node_log(&a.node, &inbox), node_log(&b.node, &inbox));
    assert_eq!(
        node_log(&a.node, &inbox)[0],
        a2_log[0],
        "the older origin is kept"
    );
    assert_eq!(
        association_state(&b.node, &inbox).await.installation_ids(),
        vec![a.installation()]
    );
    assert_eq!(a.node.replacements_for_test(), 1);
    assert_eq!(b.node.replacements_for_test(), 1);
}

/// §4.2 backward compatibility: a node that predates convergence (it
/// ignores IdentityConflict and relayed logs) keeps today's behaviour: it
/// drops the fork as PeerNotMember, its log is unchanged, nothing crashes.
#[tokio::test(flavor = "multi_thread")]
async fn an_old_node_keeps_todays_behaviour() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    let b = peer(&hub, "b").await;
    b.node.set_legacy_identity_for_test();
    hub.link("a", "b");
    eventually("b verifies a", || async { verifies(&b.node, &a) }).await;
    hub.unlink("a", "b");
    a.node.stop_sync();

    tokio::time::sleep(Duration::from_secs(1)).await;
    let a2 = peer_on(&hub, "a2", MeshNode::in_memory().unwrap(), &wallet).await;
    let fork = node_log(&a2.node, &inbox);
    hub.link("a2", "b");
    eventually("b drops a2", || async { !hub.is_linked("a2", "b") }).await;
    assert_eq!(node_log(&b.node, &inbox), node_log(&a.node, &inbox));
    assert_eq!(
        node_log(&a2.node, &inbox),
        fork,
        "an old node sends no conflict"
    );
    assert_eq!(b.node.replacements_for_test(), 0);
}

/// §4.2 while connected: C meets A′ (the restored fork) first and verifies
/// it naively, on the fork. Then A -- the original, still alive and
/// reachable, never stopped -- connects to C directly. A's claimed log
/// (the earlier origin) wins at C on the claimed path (no relay, no
/// group, no gate on that path), replacing C's held fork. C's session
/// with A′ then notices, via the ordinary demotion check, that A′ is no
/// longer a member of I and demotes it, handing it the winning log. A′
/// re-bases (revoking A), and C verifies it again -- demoted, not
/// dropped.
///
/// Restructured (review re-review 1, N2) to drop the relay/group path
/// entirely: the original version needed C's libxmtp client to validate
/// an MLS welcome for a group containing A, which requires C to already
/// have A's identity log -- exactly circular with what that version was
/// trying to test (see the git history for the original diagnosis). This
/// version needs neither a group nor a welcome: A's claimed-inbox log
/// reaches C the same direct way A2's did.
#[tokio::test(flavor = "multi_thread")]
async fn a_contact_connected_to_the_restored_owner_hands_it_the_winning_log() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    // A stays alive, syncing, and unlinked from everyone for now -- unlike
    // every other test here, it is never stopped.

    // Whole-second winner rule (S1): a2's claimed log must reliably start
    // out later than a's (so c's first meeting with it is a genuine fork),
    // but earlier than what a's log will look like once a2 re-bases onto
    // it below.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let a2 = peer_on(&hub, "a2", MeshNode::in_memory().unwrap(), &wallet).await;
    let c = peer(&hub, "c").await;
    c.node
        .set_peer_verify_timeout_for_test(Duration::from_secs(60));
    hub.link("a2", "c");
    eventually("c verifies a2 on the fork", || async {
        verifies(&c.node, &a2)
    })
    .await;
    assert_eq!(
        node_log(&c.node, &inbox),
        node_log(&a2.node, &inbox),
        "c holds the fork"
    );

    let mut a2_events = a2.node.subscribe_events();
    hub.link("a", "c");
    assert_eq!(
        next_resync(&mut a2_events, &inbox).await,
        ResyncOutcome::RebaseNeeded
    );
    rebase_and_revoke(&a2, &wallet).await;
    eventually("c verifies a2 again, on the winning log", || async {
        verifies(&c.node, &a2) && node_log(&c.node, &inbox).len() == 3
    })
    .await;
    assert!(hub.is_linked("a2", "c"), "demoted, not dropped");
}

/// The inbox ids of the IdentityLog frames `rec` sent to `peer` after the
/// first `skip` frames, other than `own` (each side's own log).
fn relayed_inboxes(rec: &Recording, peer: &str, skip: usize, own: &[&str]) -> Vec<String> {
    rec.sent_to(peer)
        .into_iter()
        .skip(skip)
        .filter_map(|body| match body {
            Body::IdentityLog(log) if !own.contains(&log.inbox_id.as_str()) => Some(log.inbox_id),
            _ => None,
        })
        .collect()
}

/// B (recorded) created a group with A and C; D is a verified stranger.
async fn relay_scope() -> (LoopbackHub, TestPeer, TestPeer, Arc<Recording>, TestPeer) {
    let hub = LoopbackHub::new();
    let a = peer(&hub, "a").await;
    let (b, rec) = recorded_peer(&hub, "b").await;
    let c = peer(&hub, "c").await;
    hub.link("a", "b");
    hub.link("b", "c");
    has_key_package(&b.node, &a).await;
    has_key_package(&b.node, &c).await;
    eventually("b verifies a and c", || async {
        verifies(&b.node, &a) && verifies(&b.node, &c)
    })
    .await;
    b.client
        .create_group_with_members(&[a.client.inbox_id(), c.client.inbox_id()], None, None)
        .await
        .unwrap();
    hub.unlink("a", "b");
    hub.unlink("b", "c");
    (hub, a, b, rec, c)
}

/// §4.2 relay scope (owner decision 2026-09-24): a peer that shares a group
/// with inbox X gets X's log when it is verified.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_sharing_a_group_gets_the_relayed_log() {
    let (hub, a, b, rec, c) = relay_scope().await;
    let before = rec.sent_to("c").len();
    hub.link("b", "c");
    eventually("b relays A's log to c", || async {
        relayed_inboxes(
            &rec,
            "c",
            before,
            &[b.client.inbox_id(), c.client.inbox_id()],
        )
        .contains(&a.client.inbox_id().to_string())
    })
    .await;
}

/// §4.2 relay scope, Review Focus 1: a verified peer that shares no group
/// with any inbox we hold (any nearby PyriteChat user) gets no relayed log.
#[tokio::test(flavor = "multi_thread")]
async fn a_verified_stranger_gets_no_relayed_logs() {
    let (hub, _a, b, rec, _c) = relay_scope().await;
    let d = peer(&hub, "d").await;
    hub.link("b", "d");
    eventually("b verifies d", || async { verifies(&b.node, &d) }).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        relayed_inboxes(&rec, "d", 0, &[b.client.inbox_id(), d.client.inbox_id()]).is_empty(),
        "a stranger must not learn which inboxes b has met"
    );
}

/// Review Focus 1: a verified peer's IdentityConflict carrying a losing log,
/// or a log whose older-looking origin is forged (bad signature), changes
/// nothing on the receiver.
#[tokio::test(flavor = "multi_thread")]
async fn a_conflict_frame_with_a_losing_or_forged_log_changes_nothing() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    let b = peer(&hub, "b").await;
    hub.link("a", "b");
    eventually("b verifies a", || async { verifies(&b.node, &a) }).await;
    hub.unlink("a", "b");
    a.node.stop_sync();
    let held = node_log(&b.node, &inbox);

    // Whole-second winner rule (S1): a2's genuinely later origin must
    // reliably lose against b's held log (deviation from the brief's 2 ms).
    tokio::time::sleep(Duration::from_secs(1)).await;
    let a2 = peer_on(&hub, "a2", MeshNode::in_memory().unwrap(), &wallet).await;
    let losing = a2.node.identity_log(&inbox).unwrap();
    let mut forged = losing.clone();
    forged[0].update.as_mut().unwrap().client_timestamp_ns = 1; // "older", unsigned

    let c = peer(&hub, "c").await;
    hub.link("b", "c");
    eventually("b verifies c", || async { verifies(&b.node, &c) }).await;
    for updates in [losing, forged] {
        hub.inject(
            "c",
            "b",
            frames::encode(Body::IdentityConflict(IdentityLog {
                inbox_id: inbox.clone(),
                updates,
            })),
        );
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(node_log(&b.node, &inbox), held);
    assert_eq!(b.node.replacements_for_test(), 0);
    assert!(hub.is_linked("b", "c"), "a bad conflict is not fatal");
}

/// A single-update, later-ranked, genuinely wallet-signed "losing" log for
/// `wallet`'s inbox `I`, built by forking a fresh node onto the same
/// wallet 1 s later (S1 whole-second ranking). Used as the candidate a
/// peer sends in an `IdentityConflict`.
async fn losing_fork(
    hub: &LoopbackHub,
    wallet: &PrivateKeySigner,
    inbox: &str,
) -> Vec<IdentityUpdateLog> {
    tokio::time::sleep(Duration::from_secs(1)).await;
    let a2 = peer_on(hub, "loser", MeshNode::in_memory().unwrap(), wallet).await;
    a2.node.identity_log(inbox).unwrap()
}

/// Review 2026-09-24 C1/N1 (re-review 1): a failed claimed-inbox proof
/// must disconnect immediately (fatal `PeerNotMember`), the same as when
/// we hold nothing for the claimed inbox -- before this fix, a failed
/// proof left the stranger connected, unverified, until the 10 s
/// deadline, so *how long* it stayed connected (immediately dropped vs.
/// 10 s later) itself revealed whether we held the inbox, an oracle
/// through disconnect timing alone even though no frame is ever sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_claimed_inbox_proof_disconnects_immediately_like_an_unheld_inbox() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    let (b, rec) = recorded_peer(&hub, "b").await;
    hub.link("a", "b");
    eventually("b verifies a", || async { verifies(&b.node, &a) }).await;
    hub.unlink("a", "b");
    a.node.stop_sync();

    // A genuine, later-ranked (losing) fork of I -- captured the way a
    // real stranger would (a restored phone broadcasts its fork to
    // every authenticated peer it meets, via send_own_identity).
    let losing = losing_fork(&hub, &wallet, &inbox).await;

    // A stranger whose Hello lies about claiming I, but whose real,
    // authenticated installation (from its own unrelated client) is not
    // among the fork's installations. `suppress_identity_log_for_test`
    // stops its own (empty) log for I from going out automatically on
    // connect, so the test can inject the exact frame under test.
    let stranger = peer(&hub, "stranger").await;
    stranger.node.set_local_inbox_for_test(&inbox);
    stranger.node.suppress_identity_log_for_test();
    hub.link("b", "stranger");
    eventually("b authenticates the stranger", || async {
        b.node
            .authenticated_peers()
            .contains(&"stranger".to_string())
    })
    .await;

    let before = rec.sent_to("stranger").len();
    hub.inject(
        "stranger",
        "b",
        frames::encode(Body::IdentityLog(IdentityLog {
            inbox_id: inbox.clone(),
            updates: losing,
        })),
    );
    eventually_for(
        "b drops the stranger promptly, not at the 10 s verification deadline",
        3,
        || async { !hub.is_linked("b", "stranger") },
    )
    .await;
    assert_eq!(
        rec.sent_to("stranger").len(),
        before,
        "no frame is ever sent to a stranger with a failed proof"
    );
}

/// Review 2026-09-24 C1/R5, fix round 1: a verified peer that shares no
/// group with an inbox `b` holds gets no `IdentityConflict` reply, even
/// when its submitted log genuinely verifies and legitimately loses -- the
/// same silence as if `b` held nothing for that inbox at all (Review Focus
/// 1: "the stranger also learns nothing").
#[tokio::test(flavor = "multi_thread")]
async fn a_verified_stranger_sending_a_conflict_gets_no_reply() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    let (b, rec) = recorded_peer(&hub, "b").await;
    let c = peer(&hub, "c").await;
    let d = peer(&hub, "d").await;
    hub.link("a", "b");
    hub.link("b", "c");
    hub.link("b", "d");
    has_key_package(&b.node, &a).await;
    has_key_package(&b.node, &c).await;
    eventually("b verifies a, c and d", || async {
        verifies(&b.node, &a) && verifies(&b.node, &c) && verifies(&b.node, &d)
    })
    .await;
    // B (the creator) shares a group with a and c, but never with d.
    b.client
        .create_group_with_members(&[a.client.inbox_id(), c.client.inbox_id()], None, None)
        .await
        .unwrap();
    hub.unlink("a", "b");
    a.node.stop_sync();

    let losing = losing_fork(&hub, &wallet, &inbox).await;
    let before = rec.sent_to("d").len();
    hub.inject(
        "d",
        "b",
        frames::encode(Body::IdentityConflict(IdentityLog {
            inbox_id: inbox.clone(),
            updates: losing,
        })),
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        rec.sent_to("d").len(),
        before,
        "a verified stranger must get no reply, the same as if b held nothing for the inbox"
    );
    assert_eq!(b.node.replacements_for_test(), 0);
}

/// Review 2026-09-24 C1/R5, fix round 1: a verified peer that shares a
/// group with the inbox gets the reply when its submitted log genuinely
/// loses -- and review I1: repeated conflict frames for the same inbox in
/// the same session get at most one reply, not one per frame.
#[tokio::test(flavor = "multi_thread")]
async fn a_shared_group_peer_gets_exactly_one_conflict_reply_per_inbox() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    let (b, rec) = recorded_peer(&hub, "b").await;
    let c = peer(&hub, "c").await;
    hub.link("a", "b");
    hub.link("b", "c");
    has_key_package(&b.node, &a).await;
    has_key_package(&b.node, &c).await;
    eventually("b verifies a and c", || async {
        verifies(&b.node, &a) && verifies(&b.node, &c)
    })
    .await;
    // B (the creator) has full local knowledge of the group with no
    // welcome round trip needed -- the same reason relay_scope()'s
    // sender-side tests work reliably.
    b.client
        .create_group_with_members(&[a.client.inbox_id(), c.client.inbox_id()], None, None)
        .await
        .unwrap();
    hub.unlink("a", "b");
    a.node.stop_sync();

    let losing = losing_fork(&hub, &wallet, &inbox).await;
    let is_reply_for_inbox =
        |body: &Body| matches!(body, Body::IdentityConflict(log) if log.inbox_id == inbox);
    let before = rec.sent_to("c").len();
    for _ in 0..3 {
        hub.inject(
            "c",
            "b",
            frames::encode(Body::IdentityConflict(IdentityLog {
                inbox_id: inbox.clone(),
                updates: losing.clone(),
            })),
        );
    }
    eventually("b replies to c, who shares a's group", || async {
        rec.sent_to("c").iter().skip(before).any(is_reply_for_inbox)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await; // let any extra (buggy) replies land
    let replies = rec
        .sent_to("c")
        .iter()
        .skip(before)
        .filter(|body| is_reply_for_inbox(body))
        .count();
    assert_eq!(
        replies, 1,
        "at most one conflict reply per inbox per session (review I1)"
    );
}

/// §4.7 after a restore: A created the A–B DM, so its node was the
/// sequencer. A′ restores alone, meets B, gets the conflict, re-bases and
/// revokes A; B takes over sequencing the DM, and it resumes with B
/// sending first.
#[tokio::test(flavor = "multi_thread")]
async fn a_dm_the_original_phone_created_resumes_after_a_restore() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    let b = peer(&hub, "b").await;
    b.node
        .set_peer_verify_timeout_for_test(Duration::from_secs(60));
    hub.link("a", "b");
    has_key_package(&a.node, &b).await;
    has_key_package(&b.node, &a).await;
    let (_a_ab, b_ab) = dm_both_ways(&a, &b, "ab").await;
    hub.unlink("a", "b");
    a.node.stop_sync();

    // S1 (whole-second winner rule, progress.md): a's and a2's CreateInbox
    // signatures must land in different whole seconds for a's origin to
    // reliably rank earlier than a2's fork (deviation from the brief's 2 ms,
    // same as Task 4's convergence.rs tests).
    tokio::time::sleep(Duration::from_secs(1)).await;
    let a2 = peer_on(&hub, "a2", MeshNode::in_memory().unwrap(), &wallet).await;
    let mut a2_events = a2.node.subscribe_events();
    hub.link("a2", "b");
    assert_eq!(
        next_resync(&mut a2_events, &inbox).await,
        ResyncOutcome::RebaseNeeded
    );
    rebase_and_revoke(&a2, &wallet).await;
    eventually("b verifies a2", || async { verifies(&b.node, &a2) }).await;
    eventually("b takes over the DM A created", || async {
        b.node.group_sequencer_for_test(&b_ab.group_id).unwrap() == Some(b.installation())
    })
    .await;
    has_key_package(&b.node, &a2).await;
    b_ab.update_installations().await.unwrap();
    send_and_see_new(&b_ab, &a2, "b-first").await;
}

/// `peer`'s client adds a fresh installation (another device) to its inbox,
/// signed by the recovery `wallet`: one more update on the log.
async fn add_device(peer: &TestPeer, wallet: &PrivateKeySigner) {
    use xmtp_cryptography::XmtpInstallationCredential;
    use xmtp_id::associations::MemberIdentifier;
    use xmtp_id::associations::builder::SignatureRequestBuilder;
    use xmtp_id::associations::test_utils::{
        WalletTestExt, add_installation_key_signature, add_wallet_signature,
    };
    let key = XmtpInstallationCredential::new();
    let mut add = SignatureRequestBuilder::new(peer.client.inbox_id())
        .add_association(
            MemberIdentifier::installation(key.public_slice().to_vec()),
            wallet.member_identifier(),
        )
        .build();
    add_installation_key_signature(&mut add, &key).await;
    add_wallet_signature(&mut add, wallet).await;
    peer.client
        .identity_updates()
        .apply_signature_request(add)
        .await
        .unwrap();
}

/// Ruling S4 (final review I1): A registers (seq 1), C meets A then, and A
/// adds two devices (seq 2 and 3), which B sees. The restored A′ forks, meets
/// the stale C first (holding only seq 1), replaces its log with that
/// prefix and re-bases at seq 2′. When A′ then meets B, who holds the full
/// log 1..3, the two logs first differ at seq 2, where B's genuine update is
/// older: A′ replaces its log again and re-bases at seq 4, so B verifies it
/// (before S4, B kept dropping A′ as `PeerNotMember` forever). C heals too
/// the next time it meets A′.
#[tokio::test(flavor = "multi_thread")]
async fn a_restored_owner_that_re_based_onto_a_stale_log_re_bases_again_on_the_full_log() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let inbox = a.client.inbox_id().to_string();

    let c = peer(&hub, "c").await;
    c.node
        .set_peer_verify_timeout_for_test(Duration::from_secs(60));
    hub.link("a", "c");
    eventually("c verifies a", || async { verifies(&c.node, &a) }).await;
    hub.unlink("a", "c");
    let stale = node_log(&c.node, &inbox);
    assert_eq!(stale.len(), 1, "c holds only seq 1");

    add_device(&a, &wallet).await;
    add_device(&a, &wallet).await;
    let full = node_log(&a.node, &inbox);
    assert_eq!(full.len(), 3);
    let b = peer(&hub, "b").await;
    b.node
        .set_peer_verify_timeout_for_test(Duration::from_secs(60));
    hub.link("a", "b");
    eventually("b verifies a on the full log", || async {
        verifies(&b.node, &a) && node_log(&b.node, &inbox) == full
    })
    .await;
    hub.unlink("a", "b");
    a.node.stop_sync();

    // Whole seconds (S1): a2's CreateInbox, and later its re-base at seq 2′,
    // land in strictly later seconds than A's genuine updates.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let a2 = peer_on(&hub, "a2", MeshNode::in_memory().unwrap(), &wallet).await;
    // A′ replaces twice in this test, well inside the 60 s flap window.
    a2.node.set_replace_flap_window_for_test(Duration::ZERO);
    let mut a2_events = a2.node.subscribe_events();

    // A′ meets the stale C: C's seq 1 is older, so A′ takes the prefix and
    // re-bases onto it at seq 2′.
    hub.link("a2", "c");
    assert_eq!(
        next_resync(&mut a2_events, &inbox).await,
        ResyncOutcome::RebaseNeeded
    );
    assert!(rebase(&a2, &wallet).await);
    eventually("c appends the re-base at 2′ and verifies a2", || async {
        verifies(&c.node, &a2) && node_log(&c.node, &inbox).len() == 2
    })
    .await;
    hub.unlink("a2", "c");
    let on_stale = node_log(&a2.node, &inbox);
    assert_eq!(on_stale[0], full[0]);
    assert_ne!(on_stale[1], full[1], "a2's seq 2′ is its own re-base");

    // A′ meets B: first difference at seq 2, B's genuine update is older.
    hub.link("a2", "b");
    assert_eq!(
        next_resync(&mut a2_events, &inbox).await,
        ResyncOutcome::RebaseNeeded,
        "a2 must take B's full log and re-base again"
    );
    assert_eq!(client_log(&a2, &inbox), full, "no hybrid on the owner");
    assert!(rebase(&a2, &wallet).await);
    eventually("b appends the re-base at 4 and verifies a2", || async {
        verifies(&b.node, &a2) && node_log(&b.node, &inbox).len() == 4
    })
    .await;
    hub.unlink("a2", "b");
    let healed = node_log(&a2.node, &inbox);
    assert_eq!(healed.len(), 4);
    assert_eq!(healed[..3], full[..], "re-based at n+1 on the full log");
    assert_eq!(node_log(&b.node, &inbox), healed);
    assert_eq!(client_log(&a2, &inbox), healed);

    // C, still on the stale prefix plus 2′, heals when it meets A′ again.
    hub.link("a2", "c");
    eventually("c replaces its log with the full one", || async {
        node_log(&c.node, &inbox) == healed
    })
    .await;
    eventually("c verifies the re-based a2", || async {
        verifies(&c.node, &a2)
    })
    .await;

    assert_eq!(a2.node.replacements_for_test(), 2);
    assert_eq!(b.node.replacements_for_test(), 0);
    assert_eq!(c.node.replacements_for_test(), 1);
}

/// The candidate an attacker builds from a healed log's genuine prefix plus
/// one update taken from an abandoned re-base branch, renumbered to follow
/// the prefix (re-review 1, N1).
fn prefix_plus(
    prefix: &[IdentityUpdateLog],
    abandoned: &IdentityUpdateLog,
) -> Vec<IdentityUpdateLog> {
    let mut log = prefix.to_vec();
    log.push(IdentityUpdateLog {
        sequence_id: prefix.len() as u64 + 1,
        ..abandoned.clone()
    });
    log
}

/// Re-review 2 N4 (owner ruling: drop the tombstone half of S6, keep the
/// app's re-assert (b)). Without tombstones, a wallet-less attacker who
/// captured an update from an abandoned re-base branch (S4's first re-base
/// onto a stale copy) can still make a node -- even the healed owner's own
/// node -- adopt `[o1, o2, o3, 2′]`, dropping the healed log's R2 revoke.
/// But that node's app then reacts exactly as it does to any own-inbox
/// resync (Ruling S6/(b)): it re-asserts R2, appending a fresh revoke r5′.
/// From there every node converges on `[o1, o2, o3, 2′, r5′]`, with the lost
/// installation revoked again: a node that took the bare attack (V) by a
/// strict-prefix append, and a node still on the pre-attack healed log (C)
/// by a normal replace, because 2′ still outranks r4 at seq 4. The exposure
/// is transient (spec §7), not permanent: this is what N4 found tombstones
/// broke.
#[tokio::test(flavor = "multi_thread")]
async fn an_owner_re_assert_after_the_same_attack_converges_every_node() {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let inbox = a.client.inbox_id().to_string();

    let c = peer(&hub, "c").await;
    c.node
        .set_peer_verify_timeout_for_test(Duration::from_secs(60));
    hub.link("a", "c");
    eventually("c verifies a", || async { verifies(&c.node, &a) }).await;
    hub.unlink("a", "c");

    add_device(&a, &wallet).await;
    add_device(&a, &wallet).await;
    let full = node_log(&a.node, &inbox);
    assert_eq!(full.len(), 3);
    let b = peer(&hub, "b").await;
    b.node
        .set_peer_verify_timeout_for_test(Duration::from_secs(60));
    hub.link("a", "b");
    eventually("b verifies a on the full log", || async {
        verifies(&b.node, &a) && node_log(&b.node, &inbox) == full
    })
    .await;
    hub.unlink("a", "b");
    a.node.stop_sync();

    // Whole seconds (S1): A′'s updates rank after A's; its first re-base
    // branch (2′) ranks before its second (r4, r5).
    tokio::time::sleep(Duration::from_secs(1)).await;
    let a2 = peer_on(&hub, "a2", MeshNode::in_memory().unwrap(), &wallet).await;
    a2.node.set_replace_flap_window_for_test(Duration::ZERO);
    c.node.set_replace_flap_window_for_test(Duration::ZERO);
    let mut a2_events = a2.node.subscribe_events();

    // The stale branch: [o1, 2′ (re-base), 3′ (R2 revokes A)].
    hub.link("a2", "c");
    assert_eq!(
        next_resync(&mut a2_events, &inbox).await,
        ResyncOutcome::RebaseNeeded
    );
    rebase_and_revoke(&a2, &wallet).await;
    eventually("c appends 2′ and 3′", || async {
        node_log(&c.node, &inbox).len() == 3
    })
    .await;
    hub.unlink("a2", "c");
    let stale_branch = a2.node.identity_log(&inbox).unwrap();
    assert_eq!(stale_branch.len(), 3);
    let re_base_2 = stale_branch[1].clone();

    // The heal: [o1, o2, o3, r4 (re-base), r5 (R2)].
    tokio::time::sleep(Duration::from_secs(1)).await;
    hub.link("a2", "b");
    assert_eq!(
        next_resync(&mut a2_events, &inbox).await,
        ResyncOutcome::RebaseNeeded
    );
    rebase_and_revoke(&a2, &wallet).await;
    eventually("b appends r4 and r5", || async {
        node_log(&b.node, &inbox).len() == 5
    })
    .await;
    let healed_log = a2.node.identity_log(&inbox).unwrap();
    let healed = node_log(&a2.node, &inbox);
    assert_eq!(healed.len(), 5);
    assert_eq!(healed[..3], full[..]);
    hub.unlink("a2", "b");

    // C, a witness, heals too the next time it meets A′ -- from here it
    // holds "the old healed log", not the attack.
    hub.link("a2", "c");
    eventually("c replaces its log with the healed one", || async {
        node_log(&c.node, &inbox) == healed
    })
    .await;
    hub.unlink("a2", "c");

    // V never held the stale branch. A wallet-less attacker still hands it
    // [o1, o2, o3, 2′] directly (the claimed-inbox path), and V, holding
    // nothing for this inbox yet, just ingests it (no fork to resolve).
    let v = peer(&hub, "v").await;
    let attack = prefix_plus(&healed_log[..3], &re_base_2);
    v.node
        .ingest_identity_log_for_test(&inbox, attack.clone())
        .await
        .unwrap();
    let attacked = node_log(&v.node, &inbox);
    assert_eq!(attacked.len(), 4, "v adopts the attack log");
    assert_eq!(attacked[..3], full[..]);
    assert_ne!(
        attacked[3], healed[3],
        "v's seq 4 is the abandoned re-base, not r4"
    );

    // Without tombstones, the owner's own node takes the same attack too:
    // 2′ still outranks r4 at seq 4.
    a2.node
        .replace_identity_log(&inbox, attack.clone())
        .await
        .unwrap();
    let outcome = next_resync(&mut a2_events, &inbox).await;
    assert!(
        matches!(
            outcome,
            ResyncOutcome::Reloaded | ResyncOutcome::RebaseNeeded
        ),
        "{outcome:?}"
    );
    assert_eq!(
        node_log(&a2.node, &inbox),
        attacked,
        "the owner's own node adopts the same attack"
    );

    // The app's reaction to any own-inbox resync (Ruling S6/(b), no
    // tombstones needed): re-base first if this installation dropped out,
    // then re-assert R2.
    if outcome == ResyncOutcome::RebaseNeeded {
        assert!(rebase(&a2, &wallet).await);
    }
    revoke_all_other_installations(&a2, &wallet).await;
    let reasserted = node_log(&a2.node, &inbox);
    assert_eq!(reasserted.len(), attacked.len() + 1, "r5′ appended");
    assert_eq!(reasserted[..attacked.len()], attacked[..]);

    // V takes the owner's extension by a strict-prefix append.
    hub.link("a2", "v");
    eventually("v converges on the reasserted log", || async {
        node_log(&v.node, &inbox) == reasserted
    })
    .await;

    // C, still on the old healed log, converges too: 2′ outranks r4 at seq
    // 4, so C takes the owner's whole log by a normal replace.
    hub.link("a2", "c");
    eventually("c converges on the reasserted log", || async {
        node_log(&c.node, &inbox) == reasserted
    })
    .await;

    // Everyone ends on [o1, o2, o3, 2′, r5′] with the lost installation
    // revoked, not just the owner's own node.
    assert_eq!(
        association_state(&v.node, &inbox).await.installation_ids(),
        vec![a2.installation()]
    );
    assert_eq!(
        association_state(&c.node, &inbox).await.installation_ids(),
        vec![a2.installation()]
    );
}
