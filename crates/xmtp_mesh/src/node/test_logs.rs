//! Real, signed identity-update logs for this crate's unit tests.
use std::time::Duration;

use alloy::signers::local::PrivateKeySigner;
use tokio::sync::broadcast;
use xmtp_cryptography::XmtpInstallationCredential;
use xmtp_cryptography::utils::generate_local_wallet;
use xmtp_id::associations::MemberIdentifier;
use xmtp_id::associations::builder::{SignatureRequest, SignatureRequestBuilder};
use xmtp_id::associations::test_utils::{
    WalletTestExt, add_installation_key_signature, add_wallet_signature,
};
use xmtp_proto::xmtp::identity::api::v1::get_identity_updates_response::IdentityUpdateLog;
use xmtp_proto::xmtp::identity::associations::IdentityUpdate as IdentityUpdateProto;

use super::{MeshNode, NodeEvent};

/// `request` (fully signed) as the log entry at `seq`, server time 1_000 + seq.
pub(crate) fn logged(seq: u64, request: SignatureRequest) -> IdentityUpdateLog {
    IdentityUpdateLog {
        sequence_id: seq,
        server_timestamp_ns: 1_000 + seq,
        update: Some(IdentityUpdateProto::from(
            request.build_identity_update().unwrap(),
        )),
    }
}

/// `owner` adds a fresh wallet to `inbox_id`: a real update, numbered `seq`.
pub(crate) async fn added_wallet(
    owner: &PrivateKeySigner,
    inbox_id: &str,
    seq: u64,
    ts: u64,
) -> IdentityUpdateLog {
    let added = generate_local_wallet();
    let mut add = SignatureRequestBuilder::new(inbox_id)
        .add_association(added.member_identifier(), owner.member_identifier())
        .build();
    add_wallet_signature(&mut add, owner).await;
    add_wallet_signature(&mut add, &added).await;
    let mut entry = logged(seq, add);
    entry.server_timestamp_ns = ts;
    entry
}

/// A real three-update log for one inbox (create it, then add two
/// wallets), with its owner. Timestamps are 1_000 + sequence id.
pub(crate) async fn owned_three_update_log() -> (PrivateKeySigner, String, Vec<IdentityUpdateLog>) {
    let owner = generate_local_wallet();
    let inbox_id = owner.get_inbox_id(0);
    let log = vec![
        origin(&owner).await,
        added_wallet(&owner, &inbox_id, 2, 1_002).await,
        added_wallet(&owner, &inbox_id, 3, 1_003).await,
    ];
    (owner, inbox_id, log)
}

/// [`owned_three_update_log`] without the owner.
pub(crate) async fn three_update_log() -> (String, Vec<IdentityUpdateLog>) {
    let (_, inbox_id, log) = owned_three_update_log().await;
    (inbox_id, log)
}

pub(crate) fn timestamps(node: &MeshNode, inbox_id: &str) -> Vec<i64> {
    let rows = node.inner.store.lock().identity_rows(inbox_id, 0).unwrap();
    rows.iter().map(|r| r.server_timestamp_ns).collect()
}

/// A signed `CreateInbox` for `owner`'s inbox (nonce 0) at sequence 1.
/// Two calls for the same owner fork the inbox at sequence 1 (a restore on
/// an empty node); the later call has the strictly later client timestamp,
/// in a strictly later whole second.
///
/// §C4.1 ranks a sequence-1 update on signed content only, at second
/// precision (D24). The 1 s sleep
/// guarantees two calls fall in different whole seconds, so a
/// test that wants a genuine ranking difference between them gets one
/// reliably. A test that wants two updates in the *same* signed second
/// instead restamps one `origin()` call's result within its own second
/// (see `convergence.rs`'s restamp attack tests) rather than calling this twice.
pub(crate) async fn origin(owner: &PrivateKeySigner) -> IdentityUpdateLog {
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut create = SignatureRequestBuilder::new(owner.get_inbox_id(0))
        .create_inbox(owner.identifier(), 0)
        .build();
    add_wallet_signature(&mut create, owner).await;
    logged(1, create)
}

/// `owner` adds installation `key` to `inbox_id` at `seq`.
pub(crate) async fn added_installation(
    owner: &PrivateKeySigner,
    inbox_id: &str,
    seq: u64,
    key: &XmtpInstallationCredential,
) -> IdentityUpdateLog {
    let mut add = SignatureRequestBuilder::new(inbox_id)
        .add_association(
            MemberIdentifier::installation(key.public_slice().to_vec()),
            owner.member_identifier(),
        )
        .build();
    add_wallet_signature(&mut add, owner).await;
    add_installation_key_signature(&mut add, key).await;
    logged(seq, add)
}

/// `owner` (the recovery wallet) revokes installation `key` at `seq`.
///
/// `#[allow(dead_code)]`: not every build that compiles this module calls
/// it; the §C4.7 sequencer handover tests do.
#[allow(dead_code)]
pub(crate) async fn revoked_installation(
    owner: &PrivateKeySigner,
    inbox_id: &str,
    seq: u64,
    key: &XmtpInstallationCredential,
) -> IdentityUpdateLog {
    let mut revoke = SignatureRequestBuilder::new(inbox_id)
        .revoke_association(
            owner.member_identifier(),
            MemberIdentifier::installation(key.public_slice().to_vec()),
        )
        .build();
    add_wallet_signature(&mut revoke, owner).await;
    logged(seq, revoke)
}

/// Every event already queued on `rx`.
pub(crate) fn drain(rx: &mut broadcast::Receiver<NodeEvent>) -> Vec<NodeEvent> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        out.push(event);
    }
    out
}
