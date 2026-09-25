//! Identity-log convergence (restore spec 2026-09-24 §4.1–§4.3). When two
//! logs of one inbox start with different sequence-1 updates, every node
//! keeps the one with the earlier origin, with no coordination: a node
//! holding the losing log replaces it. Only the wallet holder can sign a
//! `CreateInbox`, so every fork of an inbox comes from its owner.
//!
//! **Rank on signed content only (mesh.8 Task 1 review C1, 2026-09-24).**
//! `client_timestamp_ns`'s signature only covers whole seconds
//! (`pretty_timestamp`, `SecondsFormat::Secs` in
//! `xmtp_id::associations::unsigned_actions`); the raw update bytes, and the
//! sub-second digits of the timestamp, are unsigned. Ranking on either lets
//! anyone holding a copy of the genuine origin — no wallet needed — re-encode
//! it with different unsigned bytes, pair it with a truncated prefix of the
//! genuine log, and win permanently, dropping every later update (including
//! a revocation). So `origin_rank`/`same_origin` work only on
//! [`UnverifiedIdentityUpdate::signature_text`](xmtp_id::associations::unverified::UnverifiedIdentityUpdate::signature_text),
//! never on raw bytes or nanoseconds.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use futures::future::try_join_all;
use prost::Message;
use tokio::sync::broadcast;
use xmtp_configuration::MAX_INSTALLATIONS_PER_INBOX;
use xmtp_id::associations;
use xmtp_id::associations::unverified::UnverifiedIdentityUpdate;
use xmtp_proto::types::ApiIdentifier;
use xmtp_proto::xmtp::identity::api::v1::get_identity_updates_response::IdentityUpdateLog;
use xmtp_proto::xmtp::identity::associations::IdentityUpdate as IdentityUpdateProto;

use super::identity::verify;
use super::sync_api::MAX_PEER_IDENTITY_LOG;
use super::{MeshNode, NodeEvent};
use crate::MeshError;
use crate::store::{IdentityRow, sha256};
use crate::sync::GroupMembership;

/// At most one replace per inbox in this window (flap guard, §4.3). Kept in
/// memory only (`NodeInner::replaced_at`): it resets on node restart and is
/// never pruned. The spec's "per 60 s" allows this (M2, review 2026-09-24).
pub(crate) const REPLACE_FLAP_WINDOW: Duration = Duration::from_secs(60);

/// Most held logs a session relays to one verified peer (§4.2).
pub(crate) const MAX_RELAYED_IDENTITY_LOGS: usize = 32;

/// How often the identity task retries a client resync that failed with a
/// `LocalClient` error (Task 2 review carry). Matches
/// `sync::session::MEMBERSHIP_RETRY_INTERVAL`'s cadence.
pub(crate) const IDENTITY_TASK_RETRY_INTERVAL: Duration = Duration::from_millis(500);

/// Completes at `deadline`, or never when there is none (mirrors
/// `sync::session::until`). M1 (review 2026-09-24): a fixed
/// `tokio::time::Instant`, not a duration re-measured from "now" -- see
/// [`MeshNode::spawn_identity_task`].
async fn identity_task_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// The exact text `proto`'s signatures cover
/// ([`UnverifiedIdentityUpdate::signature_text`]). This is the only content
/// §4.1 may compare: never raw update bytes, never sub-second time.
fn signature_text(proto: &IdentityUpdateProto) -> Result<String, MeshError> {
    let unverified = UnverifiedIdentityUpdate::try_from(proto.clone())
        .map_err(|e| MeshError::IdentityRejected(e.to_string()))?;
    Ok(unverified.signature_text())
}

/// §4.1 rule 1: `a` and `b` have the identical signed text, so they are the
/// **same origin**, whatever their bytes are (an attacker without the wallet
/// can re-encode unsigned digits, e.g. `client_timestamp_ns`'s sub-second
/// part, without changing this). Never a replace; a later divergence is D7's.
fn same_origin(a: &IdentityUpdateProto, b: &IdentityUpdateProto) -> Result<bool, MeshError> {
    Ok(signature_text(a)? == signature_text(b)?)
}

/// How a sequence-1 update ranks under §4.1, once [`same_origin`] has ruled
/// out an exact match: the lower whole second of `client_timestamp_ns` (the
/// precision the signature actually covers) wins; on a tie, the lower
/// sha256 of the signed text wins. Lower wins.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OriginRank {
    whole_seconds: u64,
    text_hash: Vec<u8>,
}

pub(crate) fn origin_rank(proto: &IdentityUpdateProto) -> Result<OriginRank, MeshError> {
    let text = signature_text(proto)?;
    Ok(OriginRank {
        whole_seconds: proto.client_timestamp_ns / 1_000_000_000,
        text_hash: sha256(text.as_bytes()),
    })
}

/// What a peer's copy of an inbox's identity log meant for ours.
#[derive(Debug, Clone)]
pub enum Resolution {
    /// Same sequence-1 update, or we held none: ingested as before (Rule B).
    SameOrigin,
    /// Theirs has the earlier origin: ours was replaced by it.
    Replaced,
    /// Ours has the earlier origin: nothing changed. Carries the peer's
    /// fully verified candidate state (review 2026-09-24 C1/R5): a
    /// `Resolution` is never produced from unverified content, and a
    /// caller must never reply with our log based on rank alone -- the
    /// session uses this state to prove a restoring owner's own claimed-
    /// inbox candidate actually lists its authenticated installation
    /// before ever sending our log back.
    OursWins(Box<associations::AssociationState>),
}

/// Verifies `updates` in isolation (no store access): caps at
/// [`MAX_PEER_IDENTITY_LOG`], sorts and checks a contiguous 1..=N with
/// every update's `inbox_id` matching, verifies every signature, and
/// computes the resulting `AssociationState`. Shared by
/// `MeshNode::{replace_identity_log, resolve_identity_log,
/// claimed_log_proves_installation}` (review 2026-09-24 C1/R5): a
/// candidate log is never ranked, replied to or replaced before it
/// verifies.
async fn verify_candidate_log(
    inbox_id: &str,
    mut updates: Vec<IdentityUpdateLog>,
) -> Result<
    (
        Vec<IdentityUpdateLog>,
        Vec<IdentityUpdateProto>,
        associations::AssociationState,
    ),
    MeshError,
> {
    if updates.is_empty() || updates.len() as i64 > MAX_PEER_IDENTITY_LOG {
        return Err(MeshError::IdentityRejected(format!(
            "replacement log for {inbox_id} has {} updates (1..={MAX_PEER_IDENTITY_LOG} allowed)",
            updates.len()
        )));
    }
    updates.sort_by_key(|u| u.sequence_id);
    let mut protos = Vec::with_capacity(updates.len());
    for (i, u) in updates.iter().enumerate() {
        if u.sequence_id != i as u64 + 1 {
            return Err(MeshError::IdentityRejected(format!(
                "replacement log for {inbox_id} has a gap before sequence {}",
                i + 1
            )));
        }
        let proto = u
            .update
            .clone()
            .ok_or_else(|| MeshError::InvalidRequest("empty identity update".into()))?;
        if proto.inbox_id != inbox_id {
            return Err(MeshError::IdentityRejected(
                "update inbox id mismatch".into(),
            ));
        }
        protos.push(proto);
    }
    let verified = try_join_all(protos.iter().map(verify)).await?;
    let state = associations::get_state(&verified)
        .map_err(|e| MeshError::IdentityRejected(e.to_string()))?;
    Ok((updates, protos, state))
}

/// What the local client did after the node replaced an inbox's log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResyncOutcome {
    /// The client dropped its copy and loaded the winner; nothing else to do.
    Reloaded,
    /// Our own inbox, and this installation is not in the winning log: the
    /// app should re-base (`rebase_installation_signature_request`, §4.4).
    RebaseNeeded,
    /// Our own inbox, and the winning log is already full: no re-base.
    TooManyInstallations,
}

impl MeshNode {
    /// §4.2: reconcile a peer's copy of `inbox_id`'s log with ours.
    ///
    /// Review 2026-09-24 C1/R5: a candidate whose sequence-1 update starts
    /// a different origin from ours is never ranked, replaced or reported
    /// as a winner before it fully verifies (every signature, contiguous
    /// 1..=N, every update's `inbox_id`) -- an unverified log can never
    /// produce [`Resolution::OursWins`], which is what a session may reply
    /// with. M4: a candidate that would rank earlier by the cheap,
    /// unverified comparison alone is refused outright, skipping that
    /// verification, when the inbox is still inside its flap window: a
    /// genuinely verified winner would be refused by the same guard in
    /// [`Self::replace_identity_log_verified`] anyway.
    pub(crate) async fn resolve_identity_log(
        &self,
        inbox_id: &str,
        updates: Vec<IdentityUpdateLog>,
    ) -> Result<Resolution, MeshError> {
        let ours = self
            .inner
            .store
            .lock()
            .identity_rows(inbox_id, 0)?
            .into_iter()
            .next();
        let Some(ours) = ours else {
            self.ingest_identity_log(inbox_id, updates).await?;
            return Ok(Resolution::SameOrigin);
        };
        let ours_proto = IdentityUpdateProto::decode(ours.update_bytes.as_slice())?;
        let theirs_first = updates
            .iter()
            .find(|u| u.sequence_id == 1)
            .and_then(|u| u.update.clone());
        let Some(theirs_first) = theirs_first else {
            self.ingest_identity_log(inbox_id, updates).await?;
            return Ok(Resolution::SameOrigin);
        };
        if same_origin(&ours_proto, &theirs_first)? {
            self.ingest_identity_log(inbox_id, updates).await?;
            return Ok(Resolution::SameOrigin);
        }
        if origin_rank(&theirs_first)? < origin_rank(&ours_proto)? && self.flap_blocked(inbox_id) {
            return Err(self.flap_blocked_error(inbox_id));
        }
        let (updates, protos, state) = verify_candidate_log(inbox_id, updates).await?;
        if origin_rank(&protos[0])? < origin_rank(&ours_proto)? {
            self.replace_identity_log_verified(updates, protos, state)
                .await?;
            Ok(Resolution::Replaced)
        } else {
            Ok(Resolution::OursWins(Box::new(state)))
        }
    }

    /// Whether `updates` (the peer's own claim for `inbox_id`, e.g. on the
    /// `IdentityConflict` claimed-inbox path, review C1/R5) fully verifies
    /// and its resulting state lists `installation` -- the restoring
    /// owner's bootstrap proof: a genuine installation on a genuine fork.
    /// Touches no store state; a verification failure is `Ok(false)`, not
    /// an error, so the caller can stay silent either way.
    pub(crate) async fn claimed_log_proves_installation(
        &self,
        inbox_id: &str,
        updates: &[IdentityUpdateLog],
        installation: &[u8],
    ) -> Result<bool, MeshError> {
        match verify_candidate_log(inbox_id, updates.to_vec()).await {
            Ok((_, _, state)) => Ok(state.installation_ids().contains(&installation.to_vec())),
            Err(_) => Ok(false),
        }
    }

    /// The flap guard (§4.3), checked from just `inbox_id` alone: cheap,
    /// and content-independent, so it can run before the expensive
    /// per-update signature verification (M4, review 2026-09-24).
    fn flap_blocked(&self, inbox_id: &str) -> bool {
        let window = *self.inner.replace_flap_window.lock();
        self.inner
            .replaced_at
            .lock()
            .get(inbox_id)
            .is_some_and(|at| at.elapsed() < window)
    }

    fn flap_blocked_error(&self, inbox_id: &str) -> MeshError {
        let window = *self.inner.replace_flap_window.lock();
        MeshError::IdentityRejected(format!(
            "identity log of {inbox_id} was replaced less than {}s ago",
            window.as_secs()
        ))
    }

    /// Replace this node's log of `inbox_id` with `updates` (restore
    /// convergence §4.3). Refused unless `updates`:
    /// - has at most [`MAX_PEER_IDENTITY_LOG`] entries,
    /// - runs 1..=N with no gap, all for `inbox_id`,
    /// - verifies (every signature, every update applying to the one before),
    /// - wins under §4.1 against the stored log, ranked on signed content
    ///   only (a stored log must exist, and the two must have different
    ///   signature text: [`same_origin`] is D7's later-divergence case),
    /// - and this inbox was not replaced in the last [`REPLACE_FLAP_WINDOW`].
    ///
    /// M4 (review 2026-09-24): the flap guard needs only `inbox_id`, so it
    /// is checked before the expensive per-update verification -- a
    /// forged or repeated candidate for a just-replaced inbox is refused
    /// without paying for signatures that could never matter.
    ///
    /// Swaps the log and its identifier mappings in one transaction and
    /// emits `IdentityLogReplaced` after it commits. Never touches groups,
    /// messages, welcomes or key packages. The mesh store keeps no
    /// association-state cache; the libxmtp client's copy is dropped on the
    /// event (see `GroupMembership::identity_log_replaced`).
    pub async fn replace_identity_log(
        &self,
        inbox_id: &str,
        updates: Vec<IdentityUpdateLog>,
    ) -> Result<(), MeshError> {
        if self.flap_blocked(inbox_id) {
            return Err(self.flap_blocked_error(inbox_id));
        }
        let (updates, protos, state) = verify_candidate_log(inbox_id, updates).await?;
        self.replace_identity_log_verified(updates, protos, state)
            .await
    }

    /// The rest of [`Self::replace_identity_log`], given an already fully
    /// verified candidate (its protos and resulting `AssociationState`):
    /// wins under §4.1 against the stored log (a stored log must exist,
    /// and the two must have different signature text: [`same_origin`] is
    /// D7's later-divergence case), and this inbox was not replaced in the
    /// last [`REPLACE_FLAP_WINDOW`] (re-checked here under the store lock,
    /// even though callers already made the cheap check above -- this is
    /// the authoritative check against a concurrent replace).
    ///
    /// Only once the candidate has actually won those checks (I1, review
    /// 2026-09-24) does it also have to clear the owner's-own-inbox cap
    /// guard: for our own inbox, a winner that is full
    /// ([`MAX_INSTALLATIONS_PER_INBOX`]) and omits this installation is
    /// refused, and `IdentityResynced { TooManyInstallations }` is reported:
    /// keeping our log keeps the phone usable with contacts on it (§4.4). A
    /// losing, same-origin or flap-blocked full log never raises that
    /// banner, since (`F11`) it clears only after a successful re-base,
    /// which a losing log will never trigger.
    async fn replace_identity_log_verified(
        &self,
        updates: Vec<IdentityUpdateLog>,
        protos: Vec<IdentityUpdateProto>,
        state: associations::AssociationState,
    ) -> Result<(), MeshError> {
        let inbox_id = protos[0].inbox_id.as_str();
        let rows: Vec<IdentityRow> = updates
            .iter()
            .zip(&protos)
            .map(|(u, p)| IdentityRow {
                sequence_id: u.sequence_id as i64,
                server_timestamp_ns: u.server_timestamp_ns as i64,
                update_bytes: p.encode_to_vec(),
            })
            .collect();
        let identifiers: Vec<(String, i32)> = state
            .identifiers()
            .into_iter()
            .map(|id| {
                let api: ApiIdentifier = (&id).into();
                (api.identifier, api.identifier_kind as i32)
            })
            .collect();

        // M1/I1: the D7, win and flap checks, and the owner's-own-inbox cap
        // guard, all run under one store lock (removes the
        // time-of-check/time-of-use window the separate `self.local_inbox()`
        // / `self.local_installation()` calls used to leave open).
        let mut store = self.inner.store.lock();
        let Some(held) = store.identity_rows(inbox_id, 0)?.into_iter().next() else {
            return Err(MeshError::InvalidRequest(format!(
                "no identity log of {inbox_id} to replace"
            )));
        };
        let held_proto = IdentityUpdateProto::decode(held.update_bytes.as_slice())?;
        if same_origin(&held_proto, &protos[0])? {
            return Err(MeshError::IdentityRejected(format!(
                "the logs of {inbox_id} share their first update; a later divergence is not \
                 replaced (D7)"
            )));
        }
        if origin_rank(&protos[0])? >= origin_rank(&held_proto)? {
            return Err(MeshError::IdentityRejected(format!(
                "replacement log for {inbox_id} does not have the earlier origin"
            )));
        }
        let window = *self.inner.replace_flap_window.lock();
        let mut replaced_at = self.inner.replaced_at.lock();
        if replaced_at
            .get(inbox_id)
            .is_some_and(|at| at.elapsed() < window)
        {
            return Err(MeshError::IdentityRejected(format!(
                "identity log of {inbox_id} was replaced less than {}s ago",
                window.as_secs()
            )));
        }

        // I1: only a candidate that has already won (D7, rank and flap all
        // passed) can be refused for costing us our own installation, so a
        // losing, same-origin or flap-blocked full log never raises the
        // banner (see doc comment above).
        if store.local_inbox()?.as_deref() == Some(inbox_id)
            && let Some(local) = store.local_installation()?
        {
            let installations = state.installation_ids();
            if !installations.contains(&local) && installations.len() >= MAX_INSTALLATIONS_PER_INBOX
            {
                drop(replaced_at);
                drop(store);
                self.emit(vec![NodeEvent::IdentityResynced {
                    inbox_id: inbox_id.to_string(),
                    outcome: ResyncOutcome::TooManyInstallations,
                }]);
                return Err(MeshError::IdentityRejected(format!(
                    "the winning log of {inbox_id} is full ({} installations) and omits this \
                     installation; keeping ours",
                    installations.len()
                )));
            }
        }

        store.replace_identity(inbox_id, &rows, &identifiers)?;
        replaced_at.insert(inbox_id.to_string(), Instant::now());
        drop(replaced_at);
        drop(store);

        self.inner.replacements.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            inbox_id,
            updates = rows.len(),
            "replaced an identity log by one with an earlier origin (restore convergence)"
        );
        self.emit(vec![NodeEvent::IdentityLogReplaced(inbox_id.to_string())]);
        Ok(())
    }

    /// Whether this node holds any identity log for `inbox_id`.
    pub(crate) fn holds_identity_log(&self, inbox_id: &str) -> Result<bool, MeshError> {
        Ok(self.inner.store.lock().identity_len(inbox_id)? > 0)
    }

    /// Every inbox whose log this node holds, except those in `skip`. The
    /// session narrows this to inboxes that share a group with the peer
    /// (§4.2) and caps it at [`MAX_RELAYED_IDENTITY_LOGS`].
    pub(crate) fn relayable_inboxes(&self, skip: &[&str]) -> Result<Vec<String>, MeshError> {
        Ok(self
            .inner
            .store
            .lock()
            .identity_inboxes()?
            .into_iter()
            .filter(|inbox| !skip.contains(&inbox.as_str()))
            .collect())
    }

    /// The groups this node knows (every group the local client used).
    pub(crate) fn known_group_ids(&self) -> Result<Vec<Vec<u8>>, MeshError> {
        self.inner.store.lock().known_groups()
    }

    /// Inboxes replaced within the flap window, which a lagged identity task
    /// must resync again in case it missed their IdentityLogReplaced.
    pub(crate) fn recently_replaced(&self) -> Vec<String> {
        let window = *self.inner.replace_flap_window.lock();
        self.inner
            .replaced_at
            .lock()
            .iter()
            .filter(|(_, at)| at.elapsed() < window.max(REPLACE_FLAP_WINDOW))
            .map(|(inbox, _)| inbox.clone())
            .collect()
    }

    pub(crate) fn legacy_identity(&self) -> bool {
        self.inner.legacy_identity.load(Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn set_legacy_identity_for_test(&self) {
        self.inner.legacy_identity.store(true, Ordering::Relaxed);
    }

    /// Runs between start_sync and stop_sync: after this node replaced an
    /// inbox's log, the local client drops its copy and reloads (§4.3), and
    /// the outcome is reported as IdentityResynced; the owner's re-base
    /// (§4.4) starts from it. Holds the client (through `membership`), so
    /// stop_sync aborts it.
    ///
    /// Task 2 review carry: if the client adapter fails with a `LocalClient`
    /// error (its database was busy or briefly unreachable, not a rejection
    /// of the log itself), the inbox is queued and retried every
    /// [`IDENTITY_TASK_RETRY_INTERVAL`] until it succeeds, so a transient
    /// failure never leaves the local client stuck on a purged or forked
    /// copy of the inbox's log -- including our own.
    ///
    /// M1 (review 2026-09-24): the retry deadline is a fixed
    /// `tokio::time::Instant`, not a duration re-measured from "now" on
    /// every loop iteration. The old code rebuilt a relative sleep every
    /// time `select!` ran, so any event -- including this task's own
    /// `IdentityResynced` -- restarted the wait, and steady event traffic
    /// starved the retry forever. A fixed deadline fires on schedule
    /// regardless of how many times the surrounding future is
    /// reconstructed. A sustained `LocalClient` outage is logged once,
    /// then every 10th attempt, not on every retry.
    ///
    /// Also runs the §4.7 sequencer handover after every identity-log
    /// change (a replace, a plain append such as a revoke, or a lagged
    /// resync), so a group whose pinned sequencer was just revoked is
    /// re-pinned to the lowest live leaf without waiting on anything else.
    pub(crate) fn spawn_identity_task(
        &self,
        runtime: &tokio::runtime::Handle,
        membership: Arc<dyn GroupMembership>,
    ) -> tokio::task::AbortHandle {
        let node = self.clone();
        let mut events = self.subscribe_events();
        runtime
            .spawn(async move {
                let mut pending: HashMap<String, u32> = HashMap::new();
                let mut retry_at: Option<tokio::time::Instant> = None;
                loop {
                    tokio::select! {
                        biased;
                        event = events.recv() => match event {
                            Ok(NodeEvent::IdentityLogReplaced(inbox_id)) => {
                                node.retry_resync(membership.as_ref(), inbox_id, &mut pending).await;
                                node.hand_over(membership.as_ref()).await;
                            }
                            Ok(NodeEvent::IdentityLogChanged(_)) => {
                                node.hand_over(membership.as_ref()).await;
                            }
                            Ok(_) => {}
                            Err(broadcast::error::RecvError::Lagged(_)) => {
                                for inbox_id in node.recently_replaced() {
                                    node.retry_resync(membership.as_ref(), inbox_id, &mut pending).await;
                                }
                                node.hand_over(membership.as_ref()).await;
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        },
                        _ = identity_task_until(retry_at) => {
                            retry_at = None;
                            for inbox_id in pending.keys().cloned().collect::<Vec<_>>() {
                                node.retry_resync(membership.as_ref(), inbox_id, &mut pending).await;
                            }
                        }
                    }
                    // M1: only arm a *new* deadline when none is already
                    // pending -- an unrelated event must never push a
                    // scheduled retry further into the future, or steady
                    // traffic starves it exactly as before this fix.
                    if retry_at.is_none() && !pending.is_empty() {
                        retry_at = Some(tokio::time::Instant::now() + IDENTITY_TASK_RETRY_INTERVAL);
                    }
                }
            })
            .abort_handle()
    }

    /// Calls [`Self::resync_client`] for `inbox_id`; on success (or a
    /// non-retryable error) removes it from `pending`, on a retryable
    /// `LocalClient` error bumps its attempt count so the next retry's log
    /// line (if any) reflects it.
    async fn retry_resync(
        &self,
        membership: &dyn GroupMembership,
        inbox_id: String,
        pending: &mut HashMap<String, u32>,
    ) {
        let attempt = pending.get(&inbox_id).copied().unwrap_or(0) + 1;
        if self
            .resync_client(membership, inbox_id.clone(), attempt)
            .await
        {
            pending.remove(&inbox_id);
        } else {
            pending.insert(inbox_id, attempt);
        }
    }

    /// True when nothing more needs doing for `inbox_id` (it resynced, or
    /// the error is not the transient `LocalClient` kind); false when it
    /// should be retried (see [`Self::spawn_identity_task`]). `attempt` is
    /// 1 for the first try; a `LocalClient` failure is logged only on
    /// attempt 1 and every 10th attempt after that (M1: cap log spam under
    /// a sustained outage).
    async fn resync_client(
        &self,
        membership: &dyn GroupMembership,
        inbox_id: String,
        attempt: u32,
    ) -> bool {
        match membership.identity_log_replaced(&inbox_id).await {
            Ok(outcome) => {
                tracing::info!(
                    inbox_id,
                    ?outcome,
                    "local client reloaded a replaced identity log"
                );
                self.emit(vec![NodeEvent::IdentityResynced { inbox_id, outcome }]);
                true
            }
            Err(e @ MeshError::LocalClient(_)) => {
                if attempt == 1 || attempt % 10 == 0 {
                    tracing::warn!(
                        inbox_id,
                        attempt,
                        error = %e,
                        "local client could not reload a replaced identity log; will retry"
                    );
                }
                false
            }
            Err(e) => {
                tracing::warn!(inbox_id, error = %e, "local client could not reload a replaced identity log");
                true
            }
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn set_replace_flap_window_for_test(&self, window: Duration) {
        *self.inner.replace_flap_window.lock() = window;
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn replacements_for_test(&self) -> u64 {
        self.inner.replacements.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use prost::Message;
    use xmtp_cryptography::XmtpInstallationCredential;
    use xmtp_cryptography::utils::generate_local_wallet;
    use xmtp_id::associations::test_utils::WalletTestExt;
    use xmtp_proto::types::ApiIdentifier;
    use xmtp_proto::xmtp::identity::associations::IdentityUpdate as IdentityUpdateProto;

    use super::*;
    use crate::node::test_logs::{added_installation, added_wallet, drain, origin};
    use crate::store::NewGroupMessage;

    fn first_bytes(node: &MeshNode, inbox_id: &str) -> Vec<u8> {
        node.inner.store.lock().identity_rows(inbox_id, 0).unwrap()[0]
            .update_bytes
            .clone()
    }

    fn bytes(u: &IdentityUpdateLog) -> Vec<u8> {
        u.update.as_ref().unwrap().encode_to_vec()
    }

    /// §4.1 (C1 fix): ranking uses only signed content. The lower whole
    /// second of `client_timestamp_ns` wins; unsigned sub-second digits are
    /// never compared (same second ⇒ same origin, whatever they are). On a
    /// same-second tie between genuinely different signed content, the
    /// lower sha256 of the signature text wins, deterministically and
    /// symmetrically both ways.
    #[test]
    fn the_earlier_second_wins_and_a_same_second_tie_goes_to_the_lower_text_hash() {
        let update = |ts: u64, inbox: &str| IdentityUpdateProto {
            actions: vec![],
            client_timestamp_ns: ts,
            inbox_id: inbox.into(),
        };

        // Different whole seconds: the earlier one wins.
        let (early, late) = (update(5_000_000_000, "x"), update(6_000_000_000, "x"));
        assert!(!same_origin(&early, &late).unwrap());
        assert!(origin_rank(&early).unwrap() < origin_rank(&late).unwrap());

        // Same whole second, sub-second digits differ: same origin. The
        // unsigned nanosecond part must never create a ranking difference.
        let (a, b) = (update(5_000_000_001, "x"), update(5_000_000_999, "x"));
        assert!(
            same_origin(&a, &b).unwrap(),
            "unsigned sub-second digits must not create a fork"
        );

        // Same second, genuinely different signed content (here, standing
        // in for two different signers, a different `inbox_id`): the
        // tie-break is sha256(signature_text), a strict, symmetric order.
        let (one, two) = (update(7_000_000_000, "a"), update(7_000_000_000, "b"));
        assert!(!same_origin(&one, &two).unwrap());
        let one_wins = origin_rank(&one).unwrap() < origin_rank(&two).unwrap();
        let two_wins = origin_rank(&two).unwrap() < origin_rank(&one).unwrap();
        assert_ne!(
            one_wins, two_wins,
            "the tie-break must be a strict, symmetric order on both sides"
        );
        assert_ne!(origin_rank(&one).unwrap(), origin_rank(&two).unwrap());
    }

    /// §4.2/§4.3: a peer log whose sequence 1 is earlier replaces ours (and
    /// the identifier mapping), and IdentityLogReplaced is emitted.
    #[tokio::test]
    async fn a_peer_log_with_an_earlier_origin_replaces_ours() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let older = origin(&owner).await;
        let newer = origin(&owner).await;
        let node = MeshNode::in_memory().unwrap();
        node.ingest_identity_log(&inbox, vec![newer.clone()])
            .await
            .unwrap();

        let mut rx = node.subscribe_events();
        let winner = vec![older.clone(), added_wallet(&owner, &inbox, 2, 1_002).await];
        assert!(matches!(
            node.resolve_identity_log(&inbox, winner.clone())
                .await
                .unwrap(),
            Resolution::Replaced
        ));
        let held: Vec<Vec<u8>> = node
            .identity_log(&inbox)
            .unwrap()
            .iter()
            .map(bytes)
            .collect();
        assert_eq!(held, winner.iter().map(bytes).collect::<Vec<_>>());
        assert!(
            drain(&mut rx)
                .iter()
                .any(|e| matches!(e, NodeEvent::IdentityLogReplaced(i) if *i == inbox))
        );
        let api: ApiIdentifier = (&owner.identifier()).into();
        assert_eq!(
            node.inner
                .store
                .lock()
                .inbox_for_identifier(&api.identifier, api.identifier_kind as i32)
                .unwrap(),
            Some(inbox.clone())
        );
        assert_eq!(node.replacements_for_test(), 1);
    }

    #[tokio::test]
    async fn a_peer_log_with_a_later_origin_changes_nothing() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let older = origin(&owner).await;
        let newer = origin(&owner).await;
        let node = MeshNode::in_memory().unwrap();
        node.ingest_identity_log(&inbox, vec![older.clone()])
            .await
            .unwrap();
        let resolution = node
            .resolve_identity_log(&inbox, vec![newer])
            .await
            .unwrap();
        // review C1/R5: OursWins is only ever produced from a fully
        // verified candidate.
        assert!(
            matches!(resolution, Resolution::OursWins(_)),
            "expected OursWins, got {resolution:?}"
        );
        assert_eq!(first_bytes(&node, &inbox), bytes(&older));
        assert_eq!(node.replacements_for_test(), 0);
    }

    /// Same sequence 1: Rule B ingestion, exactly as before this change.
    #[tokio::test]
    async fn a_log_with_the_same_origin_is_ingested_as_before() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let first = origin(&owner).await;
        let node = MeshNode::in_memory().unwrap();
        node.ingest_identity_log(&inbox, vec![first.clone()])
            .await
            .unwrap();
        let longer = vec![first, added_wallet(&owner, &inbox, 2, 1_002).await];
        assert!(matches!(
            node.resolve_identity_log(&inbox, longer).await.unwrap(),
            Resolution::SameOrigin
        ));
        assert_eq!(node.identity_log(&inbox).unwrap().len(), 2);
    }

    /// A node that holds nothing for the inbox ingests (Rule B), never "replaces".
    #[tokio::test]
    async fn replace_needs_a_stored_log() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let node = MeshNode::in_memory().unwrap();
        let err = node
            .replace_identity_log(&inbox, vec![origin(&owner).await])
            .await
            .unwrap_err();
        assert!(matches!(err, MeshError::InvalidRequest(_)), "{err:?}");
    }

    /// Review Focus 1.
    #[tokio::test]
    async fn replace_refuses_a_losing_log() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let older = origin(&owner).await;
        let newer = origin(&owner).await;
        let node = MeshNode::in_memory().unwrap();
        node.ingest_identity_log(&inbox, vec![older.clone()])
            .await
            .unwrap();
        let err = node
            .replace_identity_log(&inbox, vec![newer])
            .await
            .unwrap_err();
        assert!(matches!(err, MeshError::IdentityRejected(_)), "{err:?}");
        // M6: assert the actual reason, not just the error variant.
        assert!(
            err.to_string().contains("does not have the earlier origin"),
            "{err}"
        );
        assert_eq!(first_bytes(&node, &inbox), bytes(&older));
    }

    /// Review Focus 1.
    #[tokio::test]
    async fn replace_refuses_a_gap() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let older = origin(&owner).await;
        let newer = origin(&owner).await;
        let node = MeshNode::in_memory().unwrap();
        node.ingest_identity_log(&inbox, vec![newer.clone()])
            .await
            .unwrap();
        let gapped = vec![older, added_wallet(&owner, &inbox, 3, 1_003).await];
        let err = node.replace_identity_log(&inbox, gapped).await.unwrap_err();
        assert!(err.to_string().contains("gap"), "{err}");
        assert_eq!(first_bytes(&node, &inbox), bytes(&newer));
    }

    /// Review Focus 1: a tampered later update fails its signature, so the
    /// whole replacement is refused even though its origin would win.
    #[tokio::test]
    async fn replace_refuses_a_bad_signature() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let older = origin(&owner).await;
        let newer = origin(&owner).await;
        let good = vec![older, added_wallet(&owner, &inbox, 2, 1_002).await];
        let mut tampered = good.clone();
        // The signed text renders client_timestamp_ns at second precision
        // (`pretty_timestamp`, `unsigned_actions.rs`), so a 1 ns bump would
        // not change it; bump by a full second so the signed text, and so
        // the signature, actually changes (deviation from the brief's `+= 1`).
        tampered[1].update.as_mut().unwrap().client_timestamp_ns += 1_000_000_000;

        let bad_node = MeshNode::in_memory().unwrap();
        bad_node
            .ingest_identity_log(&inbox, vec![newer.clone()])
            .await
            .unwrap();
        let err = bad_node
            .replace_identity_log(&inbox, tampered)
            .await
            .unwrap_err();
        assert!(matches!(err, MeshError::IdentityRejected(_)), "{err:?}");
        assert_eq!(first_bytes(&bad_node, &inbox), bytes(&newer));

        // The same log untampered is accepted: the signature was the reason.
        let ok_node = MeshNode::in_memory().unwrap();
        ok_node
            .ingest_identity_log(&inbox, vec![newer])
            .await
            .unwrap();
        ok_node.replace_identity_log(&inbox, good).await.unwrap();
    }

    /// C1 (security fix, review 2026-09-24): the signature only covers
    /// `client_timestamp_ns` to the whole second (`pretty_timestamp`,
    /// `SecondsFormat::Secs`). An attacker without the wallet takes the
    /// genuine origin, floors its nanoseconds to the start of its own
    /// signed second (the rendered text, so the signature, is unchanged),
    /// and pairs it with a truncated prefix of the genuine log that drops
    /// a later update. This must never replace the stored log: same
    /// signature text is the same origin (§4.1 rule 1), which is D7's
    /// later-divergence case, not a fork.
    #[tokio::test]
    async fn a_restamped_origin_within_its_signed_second_does_not_replace() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let genuine = origin(&owner).await;
        let later_update = added_wallet(&owner, &inbox, 2, genuine.server_timestamp_ns + 1).await;

        let node = MeshNode::in_memory().unwrap();
        node.ingest_identity_log(&inbox, vec![genuine.clone(), later_update])
            .await
            .unwrap();

        let genuine_ts = genuine.update.as_ref().unwrap().client_timestamp_ns;
        let same_second = (genuine_ts / 1_000_000_000) * 1_000_000_000;
        // Always land in the genuine update's own signed second, strictly
        // lower than its real nanoseconds (or +1 ns, on the vanishingly
        // unlikely chance the real value was already second-aligned).
        let restamped_ts = if same_second < genuine_ts {
            same_second
        } else {
            genuine_ts + 1
        };
        let mut restamped = genuine.clone();
        restamped.update.as_mut().unwrap().client_timestamp_ns = restamped_ts;
        assert_ne!(
            bytes(&restamped),
            bytes(&genuine),
            "the restamped bytes must actually differ from the genuine ones"
        );

        // The truncated "log": just the restamped origin, dropping the
        // later update entirely (e.g. a revocation the attacker wants gone).
        let err = node
            .replace_identity_log(&inbox, vec![restamped])
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("share their first update"),
            "must be refused as D7 (same origin), not ranked as a winner: {err}"
        );
        assert_eq!(first_bytes(&node, &inbox), bytes(&genuine));
        assert_eq!(
            node.identity_log(&inbox).unwrap().len(),
            2,
            "the later update the attacker tried to drop must still be held"
        );
    }

    /// C1: grinding the nanosecond value within the signed second (hoping
    /// for a favourable `sha256(signature_text)` tie-break) does not help:
    /// every value in that second renders the identical signed text, so
    /// every attempt is the same origin (rule 1) and never reaches the
    /// hash tie-break (rule 3) at all.
    #[tokio::test]
    async fn a_tie_break_grind_within_the_signed_second_does_not_replace() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let genuine = origin(&owner).await;
        let node = MeshNode::in_memory().unwrap();
        node.ingest_identity_log(&inbox, vec![genuine.clone()])
            .await
            .unwrap();

        let genuine_ts = genuine.update.as_ref().unwrap().client_timestamp_ns;
        let same_second = (genuine_ts / 1_000_000_000) * 1_000_000_000;
        for offset_ns in [0u64, 1, 500_000_000, 999_999_999] {
            let mut attempt = genuine.clone();
            attempt.update.as_mut().unwrap().client_timestamp_ns = same_second + offset_ns;
            let err = node
                .replace_identity_log(&inbox, vec![attempt])
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("share their first update"),
                "offset {offset_ns}: {err}"
            );
        }
        assert_eq!(first_bytes(&node, &inbox), bytes(&genuine));
        assert_eq!(node.replacements_for_test(), 0);
    }

    /// Review Focus 1: MAX_PEER_IDENTITY_LOG (256) applies, checked before
    /// any signature is verified.
    #[tokio::test]
    async fn replace_refuses_more_than_the_peer_cap() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let older = origin(&owner).await;
        let newer = origin(&owner).await;
        let node = MeshNode::in_memory().unwrap();
        node.ingest_identity_log(&inbox, vec![newer]).await.unwrap();
        let too_long: Vec<IdentityUpdateLog> = (1..=257u64)
            .map(|seq| IdentityUpdateLog {
                sequence_id: seq,
                ..older.clone()
            })
            .collect();
        let err = node
            .replace_identity_log(&inbox, too_long)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("257"), "{err}");
    }

    /// Review Focus 4: at most one replace per inbox per window (60 s).
    #[tokio::test]
    async fn replace_happens_at_most_once_per_inbox_per_window() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let o1 = origin(&owner).await;
        let o2 = origin(&owner).await;
        let o3 = origin(&owner).await;
        let node = MeshNode::in_memory().unwrap();
        node.ingest_identity_log(&inbox, vec![o3]).await.unwrap();

        node.replace_identity_log(&inbox, vec![o2.clone()])
            .await
            .unwrap();
        let err = node
            .replace_identity_log(&inbox, vec![o1.clone()])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("replaced less than"), "{err}");
        assert_eq!(first_bytes(&node, &inbox), bytes(&o2));

        node.set_replace_flap_window_for_test(Duration::ZERO);
        node.replace_identity_log(&inbox, vec![o1.clone()])
            .await
            .unwrap();
        assert_eq!(first_bytes(&node, &inbox), bytes(&o1));
        assert_eq!(node.replacements_for_test(), 2);
    }

    /// §4.3: a replace never deletes group, message or key-package data.
    #[tokio::test]
    async fn replace_keeps_groups_messages_and_key_packages() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let older = origin(&owner).await;
        let newer = origin(&owner).await;
        let node = MeshNode::in_memory().unwrap();
        node.ingest_identity_log(&inbox, vec![newer]).await.unwrap();
        {
            let mut store = node.inner.store.lock();
            store.pin_sequencer(b"group", b"sequencer").unwrap();
            store
                .append_sequenced(
                    &NewGroupMessage {
                        group_id: b"group".to_vec(),
                        data: b"message".to_vec(),
                        sender_hmac: vec![],
                        should_push: false,
                        is_commit: false,
                    },
                    1,
                )
                .unwrap();
            store
                .put_key_package(b"installation", b"key package")
                .unwrap();
        }
        node.replace_identity_log(&inbox, vec![older])
            .await
            .unwrap();
        let mut store = node.inner.store.lock();
        assert_eq!(
            store.sequencer(b"group").unwrap(),
            Some(b"sequencer".to_vec())
        );
        assert_eq!(store.max_group_id(b"group").unwrap(), 1);
        assert_eq!(
            store.key_package(b"installation").unwrap(),
            Some(b"key package".to_vec())
        );
    }

    /// Review Focus 2 (spec §4.4 error): the owner's own node keeps its log
    /// when the winner is full and omits this installation, so the phone
    /// stays usable with contacts on its own log; it reports
    /// TooManyInstallations instead. One installation fewer is replaced.
    #[tokio::test]
    async fn the_local_inbox_keeps_its_log_when_the_winner_is_full_and_omits_this_installation() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let older = origin(&owner).await;
        let newer = origin(&owner).await;
        let mut full = vec![older];
        for seq in 2..=11u64 {
            let key = XmtpInstallationCredential::new();
            full.push(added_installation(&owner, &inbox, seq, &key).await);
        }

        let node = MeshNode::in_memory().unwrap();
        node.ingest_identity_log(&inbox, vec![newer.clone()])
            .await
            .unwrap();
        node.inner
            .store
            .lock()
            .set_local_installation(b"this-installation-is-not-in-full")
            .unwrap();
        node.set_local_inbox_for_test(&inbox);
        let mut rx = node.subscribe_events();

        let err = node
            .replace_identity_log(&inbox, full.clone())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("full"), "{err}");
        assert_eq!(first_bytes(&node, &inbox), bytes(&newer));
        assert!(drain(&mut rx).iter().any(|e| matches!(
            e,
            NodeEvent::IdentityResynced { inbox_id, outcome: ResyncOutcome::TooManyInstallations }
                if *inbox_id == inbox
        )));

        full.pop(); // 9 installations: under the cap
        node.replace_identity_log(&inbox, full).await.unwrap();
    }

    /// I1 (review 2026-09-24): a full log that omits our installation but
    /// has a LATER origin is refused as a plain losing log, before the
    /// owner cap guard ever runs. Emitting `IdentityResynced` here would
    /// raise a banner (`F11`) that a re-base can never clear, since the log
    /// never wins in the first place.
    #[tokio::test]
    async fn a_losing_full_log_that_omits_this_installation_is_refused_without_a_banner() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let older = origin(&owner).await;
        let newer = origin(&owner).await;
        let mut losing_full = vec![newer.clone()]; // starts with the LATER origin: this loses.
        for seq in 2..=11u64 {
            let key = XmtpInstallationCredential::new();
            losing_full.push(added_installation(&owner, &inbox, seq, &key).await);
        }

        let node = MeshNode::in_memory().unwrap();
        node.ingest_identity_log(&inbox, vec![older.clone()])
            .await
            .unwrap(); // holds the EARLIER, winning origin
        node.inner
            .store
            .lock()
            .set_local_installation(b"this-installation-is-not-in-full")
            .unwrap();
        node.set_local_inbox_for_test(&inbox);
        let mut rx = node.subscribe_events();

        let err = node
            .replace_identity_log(&inbox, losing_full)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("does not have the earlier origin"),
            "{err}"
        );
        assert_eq!(first_bytes(&node, &inbox), bytes(&older));
        assert!(
            drain(&mut rx)
                .iter()
                .all(|e| !matches!(e, NodeEvent::IdentityResynced { .. })),
            "a losing full log must never raise the too-many-installations banner"
        );
    }

    /// Every appended update is reported, local or not (sessions and the
    /// §4.7 handover listen for it).
    #[tokio::test]
    async fn ingesting_an_update_reports_the_log_changed() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let node = MeshNode::in_memory().unwrap();
        let mut rx = node.subscribe_events();
        node.ingest_identity_log(&inbox, vec![origin(&owner).await])
            .await
            .unwrap();
        assert!(
            drain(&mut rx)
                .iter()
                .any(|e| matches!(e, NodeEvent::IdentityLogChanged(i) if *i == inbox))
        );
    }

    /// A [`GroupMembership`] whose `identity_log_replaced` fails with
    /// `LocalClient` the first `fail_times` calls, then succeeds.
    struct FlakyLocalClient {
        remaining_failures: std::sync::atomic::AtomicUsize,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl GroupMembership for FlakyLocalClient {
        async fn member_inboxes(&self, _group_id: &[u8]) -> Result<Option<Vec<String>>, MeshError> {
            Ok(None)
        }

        async fn identity_log_replaced(&self, _inbox_id: &str) -> Result<ResyncOutcome, MeshError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let prev = self.remaining_failures.load(Ordering::Relaxed);
            if prev > 0 {
                self.remaining_failures.fetch_sub(1, Ordering::Relaxed);
                return Err(MeshError::LocalClient("db busy".into()));
            }
            Ok(ResyncOutcome::Reloaded)
        }
    }

    /// Task 2 review carry: a `LocalClient` error from the client adapter is
    /// retried later, so the own inbox is not left empty/unresynced forever.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_local_client_error_is_retried_until_it_succeeds() {
        let node = MeshNode::in_memory().unwrap();
        let membership = Arc::new(FlakyLocalClient {
            remaining_failures: std::sync::atomic::AtomicUsize::new(2),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut rx = node.subscribe_events();
        let handle =
            node.spawn_identity_task(&tokio::runtime::Handle::current(), membership.clone());

        node.emit(vec![NodeEvent::IdentityLogReplaced("inbox".into())]);

        let resynced = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let NodeEvent::IdentityResynced { inbox_id, outcome } = rx.recv().await.unwrap()
                {
                    return (inbox_id, outcome);
                }
            }
        })
        .await
        .expect("the inbox is eventually resynced, not left empty forever");

        assert_eq!(resynced, ("inbox".to_string(), ResyncOutcome::Reloaded));
        assert!(
            membership.calls.load(Ordering::Relaxed) >= 3,
            "expected at least 1 failing call and 1 retry that succeeds, got {}",
            membership.calls.load(Ordering::Relaxed)
        );
        handle.abort();
    }

    /// Review 2026-09-24 C1/R5: `claimed_log_proves_installation` (the
    /// restoring-owner bootstrap proof on the `IdentityConflict`
    /// claimed-inbox path) is `Ok(false)` for a candidate that does not
    /// verify -- a forged claim, however later-ranked, proves nothing and
    /// so a session must never reply to it. The positive case (a genuine
    /// fork that verifies and lists its own installation) is exercised
    /// end-to-end by `tests/convergence.rs`'s
    /// `an_early_clock_on_the_restored_phone_makes_the_original_re_base`
    /// and `a_restored_owner_and_its_contacts_converge_on_the_older_log`,
    /// both of which depend on exactly this proof succeeding for a real
    /// fork.
    #[tokio::test]
    async fn claimed_log_proves_installation_rejects_an_unverifiable_candidate() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let node = MeshNode::in_memory().unwrap();
        let forged = vec![IdentityUpdateLog {
            sequence_id: 1,
            server_timestamp_ns: 1,
            update: Some(IdentityUpdateProto {
                actions: vec![],
                client_timestamp_ns: 1,
                inbox_id: inbox.clone(),
            }),
        }];
        assert!(
            !node
                .claimed_log_proves_installation(&inbox, &forged, b"any-installation-32-bytes!!")
                .await
                .unwrap()
        );
    }

    /// The positive mirror: a genuinely verified candidate that does list
    /// the asked-about installation proves it.
    #[tokio::test]
    async fn claimed_log_proves_installation_accepts_a_genuine_candidate() {
        let owner = generate_local_wallet();
        let inbox = owner.get_inbox_id(0);
        let create = origin(&owner).await;
        let key = XmtpInstallationCredential::new();
        let add = added_installation(&owner, &inbox, 2, &key).await;
        let node = MeshNode::in_memory().unwrap();
        assert!(
            node.claimed_log_proves_installation(
                &inbox,
                &[create, add],
                &key.public_slice().to_vec()
            )
            .await
            .unwrap()
        );
    }
}
