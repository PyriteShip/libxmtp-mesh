#![recursion_limit = "256"]
//! Restore convergence at the client (DESIGN.md §C4.3–§C4.4). After the
//! node replaces an inbox's log, every
//! libxmtp client that loaded it drops its copy and reloads, so it never
//! holds a hybrid of the fork and the winner. The owner's installation then
//! re-bases onto the winner. The node-side replace and the client resync
//! are driven by hand here, with sync stopped; the node's identity task
//! wires them up in production.
mod common;

use std::time::Duration;

use alloy::signers::local::PrivateKeySigner;
use common::{
    TestPeer, association_state, client_log, eventually, next_resync, node_log, peer, peer_on,
    rebase, restart_sync,
};
use xmtp_cryptography::XmtpInstallationCredential;
use xmtp_cryptography::utils::generate_local_wallet;
use xmtp_id::associations::MemberIdentifier;
use xmtp_id::associations::builder::SignatureRequestBuilder;
use xmtp_id::associations::test_utils::{
    WalletTestExt, add_installation_key_signature, add_wallet_signature,
};
use xmtp_mesh::{
    ClientGroupMembership, GroupMembership, LoopbackHub, MeshNode, NodeEvent, ResyncOutcome,
};
use xmtp_mls::client::ClientError;
use xmtp_mls::identity::IdentityError;

/// A registered inbox I on node `a`. Then the same wallet on an empty node
/// `a2` (a restore with no old node) forks I at sequence 1. Contact `c` met
/// only `a2`, so its node and its client hold the fork. Afterwards every
/// node's sync is stopped.
struct Forked {
    hub: LoopbackHub,
    wallet: PrivateKeySigner,
    inbox: String,
    a: TestPeer,
    a2: TestPeer,
    c: TestPeer,
}

async fn forked() -> Forked {
    let hub = LoopbackHub::new();
    let wallet = generate_local_wallet();
    let a = peer_on(&hub, "a", MeshNode::in_memory().unwrap(), &wallet).await;
    let inbox = a.client.inbox_id().to_string();
    // §C4.1 ranks a sequence-1 update on signed content only, at whole-second
    // precision (D24). A 1 s sleep, not 2 ms, guarantees a2's
    // CreateInbox lands in a strictly later signed second than a's, so a's
    // origin is reliably earlier and wins (node/test_logs.rs's `origin()`
    // uses the same margin for the same reason).
    tokio::time::sleep(Duration::from_secs(1)).await;
    let a2 = peer_on(&hub, "a2", MeshNode::in_memory().unwrap(), &wallet).await;
    assert_eq!(a2.client.inbox_id(), inbox);
    assert_ne!(
        node_log(&a2.node, &inbox),
        node_log(&a.node, &inbox),
        "a2 forked I at seq 1"
    );

    let c = peer(&hub, "c").await;
    hub.link("a2", "c");
    eventually("c verifies a2", || async {
        c.node
            .verified_peers()
            .iter()
            .any(|p| p.installation == a2.installation())
    })
    .await;
    c.client
        .inbox_addresses(true, vec![inbox.as_str()])
        .await
        .unwrap();
    assert_eq!(
        client_log(&c, &inbox),
        node_log(&a2.node, &inbox),
        "c's client holds the fork"
    );
    hub.unlink("a2", "c");
    for node in [&a.node, &a2.node, &c.node] {
        node.stop_sync();
    }
    Forked {
        hub,
        wallet,
        inbox,
        a,
        a2,
        c,
    }
}

/// §C4.3 (no hybrid log): on the owner and on a contact, the client ends
/// with exactly the winning log, not the fork's seq 1 plus the winner's
/// later updates.
#[tokio::test(flavor = "multi_thread")]
async fn after_a_replace_each_client_holds_exactly_the_winning_log() {
    let f = forked().await;
    let winner = f.a.node.identity_log(&f.inbox).unwrap();
    for p in [&f.a2, &f.c] {
        p.node
            .replace_identity_log(&f.inbox, winner.clone())
            .await
            .unwrap();
        p.client
            .identity_updates()
            .resync_identity_log(&f.inbox)
            .await
            .unwrap();
        assert_eq!(
            client_log(p, &f.inbox),
            node_log(&f.a.node, &f.inbox),
            "{}",
            p.name
        );
    }
    let state =
        f.c.client
            .inbox_addresses(false, vec![f.inbox.as_str()])
            .await
            .unwrap()
            .remove(0);
    assert_eq!(state.installation_ids(), vec![f.a.installation()]);
}

/// The adapter the node's identity task calls: a re-base only for
/// our own inbox, and only while this installation is missing.
#[tokio::test(flavor = "multi_thread")]
async fn the_client_adapter_asks_for_a_rebase_only_for_its_own_missing_installation() {
    let f = forked().await;
    let winner = f.a.node.identity_log(&f.inbox).unwrap();
    for p in [&f.a2, &f.c] {
        p.node
            .replace_identity_log(&f.inbox, winner.clone())
            .await
            .unwrap();
    }
    let owner = ClientGroupMembership(f.a2.client.clone());
    let contact = ClientGroupMembership(f.c.client.clone());
    assert_eq!(
        owner.identity_log_replaced(&f.inbox).await.unwrap(),
        ResyncOutcome::RebaseNeeded
    );
    assert_eq!(
        contact.identity_log_replaced(&f.inbox).await.unwrap(),
        ResyncOutcome::Reloaded
    );
    assert!(rebase(&f.a2, &f.wallet).await);
    assert_eq!(
        owner.identity_log_replaced(&f.inbox).await.unwrap(),
        ResyncOutcome::Reloaded
    );
}

/// §C4.4: AddAssociation(a2) onto the winner at seq 2, with the wallet's
/// signature; a second call has nothing to do.
#[tokio::test(flavor = "multi_thread")]
async fn the_owner_rebases_onto_the_winning_log_once() {
    let f = forked().await;
    f.a2.node
        .replace_identity_log(&f.inbox, f.a.node.identity_log(&f.inbox).unwrap())
        .await
        .unwrap();
    f.a2.client
        .identity_updates()
        .resync_identity_log(&f.inbox)
        .await
        .unwrap();

    assert!(
        rebase(&f.a2, &f.wallet).await,
        "a2 is not in the winning log"
    );
    let log = node_log(&f.a2.node, &f.inbox);
    assert_eq!(log.len(), 2);
    assert_eq!(
        log[0],
        node_log(&f.a.node, &f.inbox)[0],
        "added onto the winner, not a new CreateInbox"
    );
    let ids = association_state(&f.a2.node, &f.inbox)
        .await
        .installation_ids();
    assert!(ids.contains(&f.a.installation()) && ids.contains(&f.a2.installation()));
    assert!(
        !rebase(&f.a2, &f.wallet).await,
        "a second call finds a2 in the log"
    );
}

/// §C4.4 error: the winner reached MAX_INSTALLATIONS_PER_INBOX
/// (10) after the replace; the re-base is refused, and the adapter reports it.
#[tokio::test(flavor = "multi_thread")]
async fn a_rebase_onto_a_full_log_is_too_many_installations() {
    let f = forked().await;
    f.a2.node
        .replace_identity_log(&f.inbox, f.a.node.identity_log(&f.inbox).unwrap())
        .await
        .unwrap();
    f.a2.client
        .identity_updates()
        .resync_identity_log(&f.inbox)
        .await
        .unwrap();
    for _ in 0..9 {
        let key = XmtpInstallationCredential::new();
        let mut add = SignatureRequestBuilder::new(&f.inbox)
            .add_association(
                MemberIdentifier::installation(key.public_slice().to_vec()),
                f.wallet.member_identifier(),
            )
            .build();
        add_installation_key_signature(&mut add, &key).await;
        add_wallet_signature(&mut add, &f.wallet).await;
        f.a2.client
            .identity_updates()
            .apply_signature_request(add)
            .await
            .unwrap();
    }
    assert_eq!(
        association_state(&f.a2.node, &f.inbox)
            .await
            .installation_ids()
            .len(),
        10
    );

    let err =
        f.a2.client
            .identity_updates()
            .rebase_installation_signature_request()
            .await
            .unwrap_err();
    assert!(
        matches!(
            err,
            ClientError::Identity(IdentityError::TooManyInstallations {
                count: 10,
                max: 10,
                ..
            })
        ),
        "{err:?}"
    );
    assert_eq!(
        ClientGroupMembership(f.a2.client.clone())
            .identity_log_replaced(&f.inbox)
            .await
            .unwrap(),
        ResyncOutcome::TooManyInstallations
    );
}

/// No IdentityResynced for `inbox` arrives on `events` within 1 s.
async fn no_resync_for_a_second(
    events: &mut tokio::sync::broadcast::Receiver<NodeEvent>,
    inbox: &str,
) -> bool {
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut resynced = false;
    while let Ok(event) = events.try_recv() {
        resynced |=
            matches!(event, NodeEvent::IdentityResynced { inbox_id, .. } if inbox_id == inbox);
    }
    !resynced
}

/// The node's replace commits, then the process dies (the
/// test hook) before the identity task resyncs the client, so the node holds
/// the winner and the client still holds the fork. The next start_sync
/// replays the pending resync: the client reloads the winner and asks for
/// the re-base. Once done, a further restart replays nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_crash_between_the_replace_and_the_client_resync_heals_at_the_next_start() {
    let f = forked().await;
    let winner = f.a.node.identity_log(&f.inbox).unwrap();
    let fork = client_log(&f.a2, &f.inbox);
    restart_sync(&f.a2, f.hub.transport_for("a2"));
    let mut events = f.a2.node.subscribe_events();

    f.a2.node.suppress_client_resync_for_test(true);
    f.a2.node
        .replace_identity_log(&f.inbox, winner)
        .await
        .unwrap();
    assert!(no_resync_for_a_second(&mut events, &f.inbox).await);
    assert_eq!(
        client_log(&f.a2, &f.inbox),
        fork,
        "the crash left the client on the fork"
    );
    f.a2.node.stop_sync();

    // The next launch.
    f.a2.node.suppress_client_resync_for_test(false);
    restart_sync(&f.a2, f.hub.transport_for("a2"));
    assert_eq!(
        next_resync(&mut events, &f.inbox).await,
        ResyncOutcome::RebaseNeeded
    );
    assert_eq!(client_log(&f.a2, &f.inbox), node_log(&f.a.node, &f.inbox));

    f.a2.node.stop_sync();
    restart_sync(&f.a2, f.hub.transport_for("a2"));
    assert!(
        no_resync_for_a_second(&mut events, &f.inbox).await,
        "the pending resync was cleared once it succeeded"
    );
}
