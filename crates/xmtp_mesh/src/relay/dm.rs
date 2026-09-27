//! DM traffic over relay (§R6): the joiner sends `RelayPending`, the
//! sequencer answers `RelaySync` with `Ref`s for the joiner's own rows;
//! both retry on a schedule until acked.
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use tokio::time::Instant;
use xmtp_proto::mls_v1::{GroupMessage, GroupMessageInput, group_message};

use super::engine::{RelayEngine, now_secs};
use super::envelope::{self, MAX_BODY_LEN};
use super::inner::{
    self, RelayPayload, RelayPending, RelayRow, RelaySync, RowRef, SIGNED_OVERHEAD, relay_payload,
    relay_row::Row,
};
use crate::MeshError;
use crate::node::NodeEvent;
use crate::store::{NewGroupMessage, StoredGroupMessage, sha256};

const PAYLOAD_BUDGET: usize = MAX_BODY_LEN - SIGNED_OVERHEAD;

#[derive(Debug, Default, Clone)]
pub(crate) struct Schedule {
    pub(crate) attempt: usize,
    pub(crate) next_at: Option<Instant>,
    pub(crate) ack_due: bool,
    /// Bumped by every [`Schedule::now`]. A send that finds it changed when
    /// it finishes leaves the newer schedule (and `ack_due`) alone.
    pub(crate) generation: u64,
    /// Joiner: the last applied `RelaySync` stopped at a `Ref` we could not
    /// resolve, so the next `RelayPending` asks for `Full` rows.
    pub(crate) stalled: bool,
    /// Sequencer: the joiner asked for `Full` rows after this id.
    pub(crate) full_after: Option<i64>,
}

impl Schedule {
    /// New content: send now and restart the retry schedule.
    pub(crate) fn now(&mut self, at: Instant) {
        self.attempt = 0;
        self.next_at = Some(at);
        self.generation = self.generation.wrapping_add(1);
    }

    /// A delivery calls for an answer: send after `delay` (§R9, answer
    /// timing), or at the already scheduled time if that is sooner; that
    /// time does not depend on the delivery. Restarts the retry schedule.
    pub(crate) fn answer(&mut self, now: Instant, delay: Duration) {
        let at = now + delay;
        let at = self.next_at.map_or(at, |t| t.min(at));
        self.now(at);
    }

    pub(crate) fn after_send(&mut self, at: Instant, retry_after: &[Duration]) {
        self.attempt += 1;
        self.next_at = retry_after.get(self.attempt - 1).map(|d| at + *d);
    }
}

/// Envelopes whose signer we cannot place yet (§R6.4).
pub(crate) struct Quarantine {
    max: usize,
    keep: Duration,
    entries: VecDeque<(Instant, Vec<u8>)>,
}

impl Quarantine {
    pub(crate) fn new(max: usize, keep: Duration) -> Self {
        Self {
            max,
            keep,
            entries: VecDeque::new(),
        }
    }

    pub(crate) fn push(&mut self, sealed: Vec<u8>, now: Instant) {
        if self.max == 0 {
            return;
        }
        while self.entries.len() >= self.max {
            self.entries.pop_front();
        }
        self.entries.push_back((now, sealed));
    }

    /// Everything not yet expired, removed from the quarantine.
    #[cfg(test)]
    pub(crate) fn take_live(&mut self, now: Instant) -> Vec<Vec<u8>> {
        self.take_live_since(now)
            .into_iter()
            .map(|(_, s)| s)
            .collect()
    }

    /// As `take_live`, with each envelope's first quarantine time: a
    /// re-check that fails again pushes it back with that time, so an
    /// envelope expires `keep` after it first arrived, not after its last
    /// re-check (§R6.4: at most 10 min).
    pub(crate) fn take_live_since(&mut self, now: Instant) -> Vec<(Instant, Vec<u8>)> {
        let keep = self.keep;
        self.entries
            .drain(..)
            .filter(|(at, _)| now.duration_since(*at) <= keep)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Rows to ingest, in order, and whether the list stopped early. `Ref`s at
/// or below `have` are already held and skipped; the first unresolvable
/// `Ref` above `have` ends the list (`stalled`): the joiner then asks for
/// `Full` rows after `have` (`RelayPending.need_full_after`).
pub(crate) fn resolve_rows(
    rows: Vec<RelayRow>,
    have: i64,
    pending: impl Fn(&[u8]) -> Option<NewGroupMessage>,
    group_id: &[u8],
) -> (Vec<GroupMessage>, bool) {
    let mut out = Vec::new();
    for row in rows {
        match row.row {
            Some(Row::Full(m)) => out.push(m),
            Some(Row::Reference(r)) if (r.id as i64) <= have => {}
            Some(Row::Reference(r)) => match pending(&r.data_hash) {
                Some(p) => out.push(GroupMessage {
                    version: Some(group_message::Version::V1(group_message::V1 {
                        id: r.id,
                        created_ns: r.created_ns,
                        group_id: group_id.to_vec(),
                        data: p.data,
                        sender_hmac: p.sender_hmac,
                        should_push: p.should_push,
                        is_commit: p.is_commit,
                    })),
                }),
                None => return (out, true),
            },
            None => {}
        }
    }
    (out, false)
}

/// Sequencer: pack `(row, from_peer)` in order while the encoded sync stays
/// within `budget`. A `from_peer` row goes as a `Ref`, unless the joiner
/// asked for `Full` rows after `full_after` and the row is past it.
/// Returns the sync and how many `Ref`s it carries.
pub(crate) fn pack_sync(
    group_id: &[u8],
    rows: Vec<(StoredGroupMessage, bool)>,
    full_after: Option<i64>,
    budget: usize,
) -> (RelaySync, u64) {
    let mut sync = RelaySync {
        group_id: group_id.to_vec(),
        rows: vec![],
    };
    let mut refs = 0;
    for (row, from_peer) in rows {
        let as_ref = from_peer && full_after.is_none_or(|n| row.id <= n);
        let relay_row = if as_ref {
            RelayRow {
                row: Some(Row::Reference(RowRef {
                    id: row.id as u64,
                    created_ns: row.created_ns as u64,
                    data_hash: sha256(&row.data),
                })),
            }
        } else {
            RelayRow {
                row: Some(Row::Full(row.to_proto())),
            }
        };
        sync.rows.push(relay_row);
        if sync.encoded_len() > budget {
            sync.rows.pop();
            break;
        }
        refs += as_ref as u64;
    }
    (sync, refs)
}

/// Joiner: pack pending `inputs` in order while the encoded message stays
/// within `budget`. The flag is true when the first input alone does not
/// fit (it must not silently turn the send into a pure ack).
pub(crate) fn pack_pending(
    group_id: &[u8],
    inputs: Vec<GroupMessageInput>,
    acked_high: u64,
    need_full_after: Option<u64>,
    budget: usize,
) -> (RelayPending, bool) {
    let had_inputs = !inputs.is_empty();
    let mut pending = RelayPending {
        group_id: group_id.to_vec(),
        messages: vec![],
        acked_high,
        need_full_after,
    };
    for m in inputs {
        pending.messages.push(m);
        if pending.encoded_len() > budget {
            pending.messages.pop();
            break;
        }
    }
    let oversized = had_inputs && pending.messages.is_empty();
    (pending, oversized)
}

/// Sequencer: a `need_full_after` request is servable only at or above the
/// stored peer ack. Syncs start after that ack, so a request below it (a
/// lagging installation; out of scope per D7) cannot be met, and
/// answering it would restart a ping-pong.
pub(crate) fn servable_full_request(need_full_after: Option<i64>, peer_acked: i64) -> Option<i64> {
    need_full_after.filter(|n| *n >= peer_acked)
}

/// Sequencer, after applying a `RelayPending`: answer only when it changed
/// something (new rows, a higher ack) or made a servable request for `Full`
/// rows (see [`servable_full_request`]). A repeated Pending that changes
/// nothing leaves the retry schedule as it is, so two nodes cannot
/// ping-pong outside it.
pub(crate) fn pending_needs_answer(inserted: bool, ack_rose: bool, servable_full: bool) -> bool {
    inserted || ack_rose || servable_full
}

/// Joiner, after applying a `RelaySync`: ack when it stored new rows, when
/// it stopped at an unresolvable `Ref` (it must ask for `Full` rows), or
/// when the sync carried a row it already held: the sequencer's ack is
/// stale (e.g. our pure ack was lost), and our ack raises it, so this
/// cannot ping-pong.
pub(crate) fn sync_needs_ack(stored: bool, stalled: bool, carried_held: bool) -> bool {
    stored || stalled || carried_held
}

fn row_id(row: &RelayRow) -> Option<u64> {
    match &row.row {
        Some(Row::Full(GroupMessage {
            version: Some(group_message::Version::V1(v1)),
        })) => Some(v1.id),
        Some(Row::Reference(r)) => Some(r.id),
        _ => None,
    }
}

/// Whether `rows` include one at or below `have`.
pub(crate) fn carries_held(rows: &[RelayRow], have: i64) -> bool {
    rows.iter()
        .filter_map(row_id)
        .any(|id| i64::try_from(id).is_ok_and(|id| id <= have))
}

/// What a delivered relay payload may do (§R4.6, §R6.4).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Ignore,
    /// The signer is not (yet) an installation of the other member.
    Quarantine,
    /// A joiner's `RelayPending` for us, the DM's sequencer.
    Pending,
    /// The sequencer's `RelaySync` for us, the joiner.
    Sync,
}

/// Authorize a verified payload for the DM `key_gid` whose relay key
/// opened it. `other_installations`: the other member's installations, or
/// `None` when the DM has no single other member.
pub(crate) fn authorize(
    key_gid: &[u8],
    body: Option<&relay_payload::Body>,
    signer: &[u8],
    local: &[u8],
    sequencer: Option<&[u8]>,
    other_installations: Option<&[Vec<u8>]>,
) -> Verdict {
    if signer == local {
        return Verdict::Ignore; // our own envelope coming back
    }
    let Some(others) = other_installations else {
        return Verdict::Ignore;
    };
    if !others.iter().any(|i| i == signer) {
        return Verdict::Quarantine;
    }
    match body {
        Some(relay_payload::Body::Pending(p))
            if p.group_id == key_gid && sequencer == Some(local) =>
        {
            Verdict::Pending
        }
        Some(relay_payload::Body::Sync(s))
            if s.group_id == key_gid && sequencer == Some(signer) =>
        {
            Verdict::Sync
        }
        _ => Verdict::Ignore,
    }
}

/// `(force_refs, no_full_request, drop_pure_acks)`; all off outside tests.
fn hooks(st: &super::engine::EngineState) -> (bool, bool, bool) {
    #[cfg(any(test, feature = "test-utils"))]
    {
        (
            st.hooks.force_refs,
            st.hooks.no_full_request,
            st.hooks.drop_pure_acks,
        )
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        let _ = st;
        (false, false, false)
    }
}

impl RelayEngine {
    pub(crate) fn schedule_now(&self, gid: &[u8]) {
        self.state
            .lock()
            .dm
            .entry(gid.to_vec())
            .or_default()
            .now(Instant::now());
    }

    /// A random answer delay from `answer_delay_ms` (§R9).
    pub(crate) fn answer_delay(&self) -> Duration {
        use rand::RngExt;
        let (lo, hi) = self.cfg.answer_delay_ms;
        Duration::from_millis(rand::rng().random_range(lo..=hi.max(lo)))
    }

    /// Stop `gid`'s schedule, unless new content re-armed it since
    /// `generation` was read.
    fn clear(&self, gid: &[u8], generation: u64) {
        if let Some(s) = self.state.lock().dm.get_mut(gid)
            && s.generation == generation
        {
            s.next_at = None;
        }
    }

    /// A send (or a skipped one) is done: advance the schedule, unless new
    /// content re-armed it meanwhile. `sent_ack` clears `ack_due` (it was
    /// set when the send read it).
    fn finish_send(&self, gid: &[u8], generation: u64, sent_ack: bool, retry: bool) {
        let at = Instant::now();
        let mut st = self.state.lock();
        let s = st.dm.entry(gid.to_vec()).or_default();
        if s.generation != generation {
            return;
        }
        if sent_ack {
            s.ack_due = false;
        }
        if retry {
            s.after_send(at, &self.cfg.retry_after);
        } else {
            s.next_at = None;
        }
    }

    pub(crate) fn on_event_dm(self: &Arc<Self>, event: NodeEvent) {
        let Some(node) = self.node() else { return };
        match event {
            NodeEvent::PeerVerified { peer, inbox_id, .. } => {
                self.state.lock().direct.insert(peer, inbox_id);
            }
            NodeEvent::PeerLost { peer } => {
                let lost = {
                    let mut st = self.state.lock();
                    st.direct
                        .remove(&peer)
                        .filter(|inbox| !st.direct.values().any(|i| i == inbox))
                };
                if let Some(inbox) = lost {
                    self.fall_back_to_relay(inbox);
                }
            }
            NodeEvent::PendingAdded(gid) => self.schedule_now(&gid),
            NodeEvent::GroupSequenced(row) => {
                let local = node.local_installation().ok().flatten();
                if local.is_some() && node.sequencer_of(&row.group_id).ok().flatten() == local {
                    self.schedule_now(&row.group_id);
                }
            }
            _ => {}
        }
    }

    /// The last direct link to `inbox` is gone: its DMs go back to relay
    /// (§R6.1). While it was direct, `send_dm` left them to the session,
    /// which may not have synced everything before the link dropped.
    fn fall_back_to_relay(self: &Arc<Self>, inbox: String) {
        let engine = self.clone();
        self.runtime.spawn(async move {
            let Some(node) = engine.node() else { return };
            let keys = node.inner.store.lock().relay_keys().unwrap_or_default();
            for (gid, _, confirmed) in keys {
                if confirmed && engine.other_member(&gid).await.as_deref() == Some(inbox.as_str()) {
                    engine.schedule_now(&gid);
                }
            }
        });
    }

    /// Missed node events: resync every relayed DM.
    pub(crate) fn on_lagged_dm(self: &Arc<Self>) {
        let Some(node) = self.node() else { return };
        let keys = node.inner.store.lock().relay_keys().unwrap_or_default();
        for (gid, _, _) in keys {
            self.schedule_now(&gid);
        }
    }

    pub(crate) async fn on_tick_dm(self: &Arc<Self>) {
        let now = Instant::now();
        let due: Vec<(Vec<u8>, u64)> = self
            .state
            .lock()
            .dm
            .iter()
            .filter(|(_, s)| s.next_at.is_some_and(|t| t <= now))
            .map(|(g, s)| (g.clone(), s.generation))
            .collect();
        for (gid, generation) in due {
            if let Err(e) = self.send_dm(&gid, generation).await {
                tracing::warn!(error = %e, "relay: DM send failed");
                self.clear(&gid, generation);
            }
        }
        let quarantined = self.state.lock().quarantine.take_live_since(now);
        for (since, sealed) in quarantined {
            self.deliver_logged(&sealed, since).await;
        }
    }

    /// `generation`: the schedule's generation when it came due.
    async fn send_dm(self: &Arc<Self>, gid: &[u8], generation: u64) -> Result<(), MeshError> {
        let (ack_due, stalled, full_after, force_refs, drop_pure_acks) = {
            let st = self.state.lock();
            let s = st.dm.get(gid).cloned().unwrap_or_default();
            let (force_refs, no_full_request, drop_pure_acks) = hooks(&st);
            (
                s.ack_due,
                s.stalled && !no_full_request,
                s.full_after,
                force_refs,
                drop_pure_acks,
            )
        };
        let node = self
            .node()
            .ok_or_else(|| MeshError::Relay("node gone".into()))?;
        let local = node.local_installation()?.ok_or(MeshError::NotRegistered)?;
        let sequencer = node.sequencer_of(gid)?;
        let is_sequencer = sequencer.as_deref() == Some(local.as_slice());
        // Bound first: the store guard must be gone before `clear` locks state.
        let key = node.inner.store.lock().relay_key(gid)?;
        let Some((key, true)) = key else {
            self.clear(gid, generation);
            return Ok(());
        };
        let Some(other) = self.other_member(gid).await else {
            self.clear(gid, generation);
            return Ok(());
        };
        if node.verified_peers().iter().any(|p| p.inbox_id == other) {
            self.clear(gid, generation); // direct link: the session syncs it
            return Ok(());
        }
        let (payload, sent_ack, retry) = if is_sequencer {
            let (acked, rows) = {
                let mut store = node.inner.store.lock();
                let acked = store.peer_acked_high(gid)?;
                (acked, store.rows_after_with_origin(gid, acked, 64)?)
            };
            let full_after = match full_after {
                Some(n) if acked > n => {
                    // The joiner holds everything it asked for in full.
                    if let Some(s) = self.state.lock().dm.get_mut(gid)
                        && s.full_after == Some(n)
                    {
                        s.full_after = None;
                    }
                    None
                }
                other => other,
            };
            if rows.is_empty() {
                self.clear(gid, generation); // everything acked
                return Ok(());
            }
            let rows = rows
                .into_iter()
                .map(|(row, from_peer)| (row, from_peer || force_refs))
                .collect();
            let (sync, refs) = pack_sync(gid, rows, full_after, PAYLOAD_BUDGET);
            if sync.rows.is_empty() {
                tracing::warn!(after = acked, "relay: next row too large to relay");
                self.clear(gid, generation);
                return Ok(());
            }
            self.state.lock().stats.refs_sent += refs;
            let payload = RelayPayload {
                body: Some(relay_payload::Body::Sync(sync)),
            };
            (payload, false, true)
        } else if sequencer.is_some() {
            let inputs = node.pending_inputs(gid)?;
            if inputs.is_empty() && !ack_due {
                self.clear(gid, generation);
                return Ok(());
            }
            let have = node.inner.store.lock().max_group_id(gid)?.max(0) as u64;
            let (pending, oversized) =
                pack_pending(gid, inputs, have, stalled.then_some(have), PAYLOAD_BUDGET);
            if oversized {
                // Not a silent pure ack: keep the retry schedule.
                tracing::warn!(
                    after = have,
                    "relay: next pending message too large to relay"
                );
                if !ack_due {
                    self.finish_send(gid, generation, false, true);
                    return Ok(());
                }
            }
            // A pure ack is never retried; anything else is.
            let retry = !pending.messages.is_empty() || oversized;
            let payload = RelayPayload {
                body: Some(relay_payload::Body::Pending(pending)),
            };
            (payload, ack_due, retry)
        } else {
            self.clear(gid, generation); // no sequencer pinned yet
            return Ok(());
        };
        let signer = self.signer().ok_or(MeshError::SyncNotStarted)?;
        let body = inner::sign(signer.as_ref(), &payload)?;
        let now = now_secs();
        let sealed = envelope::seal(
            &key,
            envelope::coarse_expiry(now as u64, self.cfg.hold.as_secs()),
            &body,
        )?;
        // Only a pure ack is ever not retried; the hook loses exactly those.
        if retry || !drop_pure_acks {
            self.originate(sealed);
        }
        self.finish_send(gid, generation, sent_ack, retry);
        Ok(())
    }

    /// Whether `sealed` matched one of our DM relay keys (whether or not
    /// it then applied).
    pub(crate) async fn try_deliver_dm(self: &Arc<Self>, sealed: &[u8]) -> bool {
        self.deliver_logged(sealed, Instant::now()).await
    }

    /// `since`: when the envelope first arrived (quarantine age). Returns
    /// whether `sealed` matched one of our DM relay keys.
    async fn deliver_logged(self: &Arc<Self>, sealed: &[u8], since: Instant) -> bool {
        let Some((gid, key)) = self.matching_key(sealed) else {
            return false; // not for us: just relayed
        };
        if let Err(e) = self.deliver(gid, key, sealed, since).await {
            tracing::debug!(error = %e, "relay: envelope not delivered");
        }
        true
    }

    /// The DM (`group_id`, relay key) whose tag `sealed` carries, if any.
    fn matching_key(&self, sealed: &[u8]) -> Option<(Vec<u8>, [u8; 32])> {
        let node = self.node()?;
        let keys = match node.inner.store.lock().relay_keys() {
            Ok(keys) => keys,
            Err(e) => {
                tracing::warn!(error = %e, "relay: keys unavailable");
                return None;
            }
        };
        keys.into_iter()
            .find(|(_, k, _)| envelope::matches(k, sealed))
            .map(|(gid, key, _)| (gid, key))
    }

    async fn deliver(
        self: &Arc<Self>,
        gid: Vec<u8>,
        key: [u8; 32],
        sealed: &[u8],
        since: Instant,
    ) -> Result<(), MeshError> {
        let node = self
            .node()
            .ok_or_else(|| MeshError::Relay("node gone".into()))?;
        let (signer, payload) = inner::verify(&envelope::open(&key, sealed)?)?;
        let local = node.local_installation()?.ok_or(MeshError::NotRegistered)?;
        if signer == local {
            return Ok(());
        }
        let others = match self.other_member(&gid).await {
            Some(other) => Some(node.installations_of(&other).await?),
            None => None,
        };
        let sequencer = node.sequencer_of(&gid)?;
        let verdict = authorize(
            &gid,
            payload.body.as_ref(),
            &signer,
            &local,
            sequencer.as_deref(),
            others.as_deref(),
        );
        match (verdict, payload.body) {
            (Verdict::Quarantine, _) => {
                self.state.lock().quarantine.push(sealed.to_vec(), since);
            }
            (Verdict::Pending, Some(relay_payload::Body::Pending(p))) => {
                // The ack first (clamped to what we hold), so one bad input
                // below cannot discard it.
                let (acked_before, max_before) = {
                    let mut store = node.inner.store.lock();
                    let before = store.peer_acked_high(&gid)?;
                    let max = store.max_group_id(&gid)?;
                    let acked = i64::try_from(p.acked_high).unwrap_or(i64::MAX).min(max);
                    store.note_peer_acked_high(&gid, acked)?;
                    (before, max)
                };
                let sequenced = node.sequence_from_peer(&gid, p.messages);
                let (acked_after, max_after) = {
                    let mut store = node.inner.store.lock();
                    (store.peer_acked_high(&gid)?, store.max_group_id(&gid)?)
                };
                let asked = p
                    .need_full_after
                    .map(|n| i64::try_from(n).unwrap_or(i64::MAX));
                let wants_full = servable_full_request(asked, acked_after);
                if let (Some(n), None) = (asked, wants_full) {
                    tracing::debug!(
                        need_full_after = n,
                        peer_acked = acked_after,
                        "relay: Full rows asked below the peer ack; not servable"
                    );
                }
                let delay = self.answer_delay();
                {
                    let mut st = self.state.lock();
                    st.stats.delivered += 1;
                    let s = st.dm.entry(gid.clone()).or_default();
                    if let Some(n) = wants_full {
                        s.full_after = Some(s.full_after.map_or(n, |m| m.min(n)));
                    }
                    if pending_needs_answer(
                        max_after > max_before,
                        acked_after > acked_before,
                        wants_full.is_some(),
                    ) {
                        s.answer(Instant::now(), delay);
                    }
                }
                sequenced?;
            }
            (Verdict::Sync, Some(relay_payload::Body::Sync(s))) => {
                let have = node.inner.store.lock().max_group_id(&gid)?;
                let carried_held = carries_held(&s.rows, have);
                let (rows, stalled) = resolve_rows(
                    s.rows,
                    have,
                    |h| {
                        node.inner
                            .store
                            .lock()
                            .pending_by_hash(&gid, h)
                            .ok()
                            .flatten()
                    },
                    &gid,
                );
                // A gap is filled by the sequencer's retry.
                let _gap = node.ingest_sequenced(&gid, rows)?;
                let stored = node.inner.store.lock().max_group_id(&gid)? > have;
                let delay = self.answer_delay();
                let mut st = self.state.lock();
                st.stats.delivered += 1;
                let s = st.dm.entry(gid.clone()).or_default();
                s.stalled = stalled;
                if sync_needs_ack(stored, stalled, carried_held) {
                    s.ack_due = true;
                    s.answer(Instant::now(), delay);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::inner::{RelayRow, RowRef, relay_row::Row};
    use crate::store::{NewGroupMessage, sha256};

    fn full(id: u64, data: &[u8]) -> RelayRow {
        RelayRow {
            row: Some(Row::Full(GroupMessage {
                version: Some(group_message::Version::V1(group_message::V1 {
                    id,
                    created_ns: id,
                    group_id: vec![1],
                    data: data.to_vec(),
                    sender_hmac: vec![],
                    should_push: true,
                    is_commit: false,
                })),
            })),
        }
    }

    fn reference(id: u64, data: &[u8]) -> RelayRow {
        RelayRow {
            row: Some(Row::Reference(RowRef {
                id,
                created_ns: id,
                data_hash: sha256(data),
            })),
        }
    }

    fn pending(data: &[u8]) -> NewGroupMessage {
        NewGroupMessage {
            group_id: vec![1],
            data: data.to_vec(),
            sender_hmac: vec![],
            should_push: true,
            is_commit: false,
        }
    }

    fn ids(v: &[GroupMessage]) -> Vec<u64> {
        v.iter()
            .map(|m| match &m.version {
                Some(group_message::Version::V1(v1)) => v1.id,
                None => 0,
            })
            .collect()
    }

    /// §R6.3: `Ref` rows are rebuilt from the joiner's own pending copies.
    #[test]
    fn resolve_rows_rebuilds_refs_from_pending() {
        let rows = vec![full(3, b"a"), reference(4, b"mine"), full(5, b"b")];
        let (out, stalled) = resolve_rows(
            rows,
            2,
            |h| (h == sha256(b"mine")).then(|| pending(b"mine")),
            &[1],
        );
        assert_eq!(ids(&out), vec![3, 4, 5]);
        assert!(!stalled);
    }

    #[test]
    fn resolve_rows_skips_refs_already_held_and_stops_at_an_unknown_one() {
        let rows = vec![
            reference(2, b"settled"),
            full(3, b"a"),
            reference(4, b"lost"),
            full(5, b"b"),
        ];
        let (out, stalled) = resolve_rows(rows, 2, |_| None, &[1]);
        assert_eq!(
            ids(&out),
            vec![3],
            "ref 2 is held; ref 4 unresolvable: stop before a gap"
        );
        assert!(
            stalled,
            "the stop is reported: the joiner asks for Full rows"
        );
    }

    #[test]
    fn schedule_retries_then_stops() {
        let t = Instant::now();
        let retry = [Duration::from_secs(1), Duration::from_secs(2)];
        let mut s = Schedule::default();
        s.now(t);
        assert_eq!(s.next_at, Some(t));
        s.after_send(t, &retry);
        assert_eq!(s.next_at, Some(t + retry[0]));
        s.after_send(t, &retry);
        assert_eq!(s.next_at, Some(t + retry[1]));
        s.after_send(t, &retry);
        assert_eq!(s.next_at, None, "1 + retry_after.len() sends, then stop");
        s.now(t);
        assert_eq!(
            (s.attempt, s.next_at),
            (0, Some(t)),
            "new content restarts it"
        );
    }

    #[test]
    fn quarantine_is_capped_and_expires() {
        let t = Instant::now();
        let mut q = Quarantine::new(2, Duration::from_secs(10));
        q.push(vec![1], t);
        q.push(vec![2], t);
        q.push(vec![3], t);
        assert_eq!(q.len(), 2, "oldest dropped at the cap");
        assert_eq!(
            q.take_live(t + Duration::from_secs(5)),
            vec![vec![2], vec![3]]
        );
        assert_eq!(q.len(), 0);
        q.push(vec![4], t);
        assert!(
            q.take_live(t + Duration::from_secs(11)).is_empty(),
            "expired"
        );
    }

    #[test]
    fn a_zero_sized_quarantine_holds_nothing() {
        let t = Instant::now();
        let mut q = Quarantine::new(0, Duration::from_secs(10));
        q.push(vec![1], t);
        assert_eq!(q.len(), 0);
        assert!(q.take_live(t).is_empty());
    }

    fn stored(id: i64, data: &[u8]) -> StoredGroupMessage {
        StoredGroupMessage {
            group_id: vec![1],
            id,
            created_ns: id,
            data: data.to_vec(),
            sender_hmac: vec![],
            should_push: true,
            is_commit: false,
            seq_signer: None,
            seq_signature: None,
        }
    }

    fn refs_of(sync: &RelaySync) -> Vec<bool> {
        sync.rows
            .iter()
            .map(|r| matches!(r.row, Some(Row::Reference(_))))
            .collect()
    }

    /// After the joiner reports a stall at id 4,
    /// its own rows past 4 go `Full`, not `Ref`.
    #[test]
    fn pack_sync_sends_full_rows_past_need_full_after() {
        let rows = || {
            vec![
                (stored(4, b"a"), true),
                (stored(5, b"b"), true),
                (stored(6, b"c"), false),
            ]
        };
        let (sync, refs) = pack_sync(&[1], rows(), None, PAYLOAD_BUDGET);
        assert_eq!((refs_of(&sync), refs), (vec![true, true, false], 2));
        let (sync, refs) = pack_sync(&[1], rows(), Some(4), PAYLOAD_BUDGET);
        assert_eq!((refs_of(&sync), refs), (vec![true, false, false], 1));
        let (sync, refs) = pack_sync(&[1], rows(), Some(0), PAYLOAD_BUDGET);
        assert_eq!(
            (refs_of(&sync), refs),
            (vec![false, false, false], 0),
            "a fresh installation (have 0) gets every row Full"
        );
    }

    #[test]
    fn pack_sync_stops_at_the_budget() {
        let rows = vec![(stored(1, &[0; 300]), false), (stored(2, &[0; 300]), false)];
        let (sync, _) = pack_sync(&[1], rows, None, 400);
        assert_eq!(sync.rows.len(), 1);
    }

    fn input(len: usize) -> GroupMessageInput {
        use xmtp_proto::mls_v1::group_message_input;
        GroupMessageInput {
            version: Some(group_message_input::Version::V1(group_message_input::V1 {
                data: vec![0; len],
                sender_hmac: vec![],
                should_push: true,
            })),
        }
    }

    /// An input too large on its own is reported,
    /// not silently turned into a pure ack.
    #[test]
    fn pack_pending_reports_an_oversized_first_input() {
        let (p, oversized) = pack_pending(&[1], vec![input(10), input(10)], 3, Some(3), 1000);
        assert_eq!((p.messages.len(), oversized), (2, false));
        assert_eq!((p.acked_high, p.need_full_after), (3, Some(3)));
        let (p, oversized) = pack_pending(&[1], vec![input(2000)], 3, None, 1000);
        assert_eq!((p.messages.len(), oversized), (0, true));
        let (p, oversized) = pack_pending(&[1], vec![], 3, None, 1000);
        assert_eq!((p.messages.len(), oversized), (0, false), "a real pure ack");
    }

    /// A Pending or Sync that changes nothing
    /// does not restart the other side's schedule (no ack ping-pong).
    #[test]
    fn only_progress_or_a_stall_reschedules() {
        assert!(
            !pending_needs_answer(false, false, false),
            "repeat Pending: schedule untouched"
        );
        assert!(pending_needs_answer(true, false, false));
        assert!(pending_needs_answer(false, true, false));
        assert!(pending_needs_answer(false, false, true));
        assert!(
            !sync_needs_ack(false, false, false),
            "nothing new, nothing held: no ack"
        );
        assert!(sync_needs_ack(true, false, false));
        assert!(sync_needs_ack(false, true, false));
    }

    /// A `need_full_after` below the stored peer
    /// ack cannot be served (syncs start after the ack), so it neither sets
    /// `full_after` nor re-arms the sequencer.
    #[test]
    fn a_full_request_below_the_peer_ack_is_not_answered() {
        assert_eq!(servable_full_request(Some(5), 10), None);
        assert!(!pending_needs_answer(
            false,
            false,
            servable_full_request(Some(5), 10).is_some()
        ));
        assert_eq!(servable_full_request(Some(10), 10), Some(10));
        assert_eq!(servable_full_request(Some(12), 10), Some(12));
        assert_eq!(servable_full_request(None, 10), None);
        assert!(pending_needs_answer(
            false,
            false,
            servable_full_request(Some(10), 10).is_some()
        ));
    }

    /// A sync carrying rows we already hold proves
    /// the sequencer's ack is stale (our pure ack was lost): ack again.
    #[test]
    fn a_sync_with_held_rows_is_acked() {
        let rows = vec![full(3, b"a"), reference(4, b"b")];
        assert!(carries_held(&rows, 3));
        assert!(carries_held(&rows, 9));
        assert!(!carries_held(&rows, 2));
        assert!(!carries_held(&[], 9));
        assert!(sync_needs_ack(false, false, carries_held(&rows, 4)));
        assert!(!sync_needs_ack(false, false, carries_held(&rows, 2)));
    }

    /// `now` bumps the generation a finishing send
    /// checks before overwriting the schedule.
    #[test]
    fn now_bumps_the_generation() {
        let mut s = Schedule::default();
        let g = s.generation;
        s.now(Instant::now());
        assert_ne!(s.generation, g);
    }

    /// An answer a delivery triggered waits the
    /// answer delay, unless the schedule was already due sooner.
    #[test]
    fn a_delivery_triggered_answer_waits() {
        let t = Instant::now();
        let mut s = Schedule::default();
        s.answer(t, Duration::from_secs(5));
        assert_eq!(
            (s.next_at, s.attempt),
            (Some(t + Duration::from_secs(5)), 0)
        );
        let g = s.generation;
        s.after_send(t, &[Duration::from_secs(1)]);
        s.answer(t, Duration::from_secs(5));
        assert_eq!(
            (s.next_at, s.attempt),
            (Some(t + Duration::from_secs(1)), 0),
            "a sooner retry is kept"
        );
        assert_ne!(s.generation, g);
    }

    fn pending_body(gid: &[u8]) -> relay_payload::Body {
        relay_payload::Body::Pending(RelayPending {
            group_id: gid.to_vec(),
            messages: vec![],
            acked_high: 0,
            need_full_after: None,
        })
    }

    fn sync_body(gid: &[u8]) -> relay_payload::Body {
        relay_payload::Body::Sync(RelaySync {
            group_id: gid.to_vec(),
            rows: vec![],
        })
    }

    /// Authorization (§R4.6/§R6.4): who may send what.
    #[test]
    fn relayed_payloads_are_authorized() {
        let (gid, me, them, them2) = (
            b"dm".as_slice(),
            b"me".as_slice(),
            b"them".to_vec(),
            b"them2".to_vec(),
        );
        let others = vec![them.clone()];
        let pending = pending_body(gid);
        let sync = sync_body(gid);
        // We sequence: their Pending is ours to apply.
        assert_eq!(
            authorize(gid, Some(&pending), &them, me, Some(me), Some(&others)),
            Verdict::Pending
        );
        // A Pending reaching a node that is not the sequencer is ignored.
        assert_eq!(
            authorize(gid, Some(&pending), &them, me, Some(&them), Some(&others)),
            Verdict::Ignore
        );
        // They sequence: their Sync is ours to apply.
        assert_eq!(
            authorize(gid, Some(&sync), &them, me, Some(&them), Some(&others)),
            Verdict::Sync
        );
        // A Sync signed by a member installation that is not the sequencer.
        let both = vec![them.clone(), them2.clone()];
        assert_eq!(
            authorize(gid, Some(&sync), &them2, me, Some(&them), Some(&both)),
            Verdict::Ignore
        );
        // A payload for another DM than the key's.
        assert_eq!(
            authorize(
                gid,
                Some(&pending_body(b"other")),
                &them,
                me,
                Some(me),
                Some(&others)
            ),
            Verdict::Ignore
        );
        assert_eq!(
            authorize(
                gid,
                Some(&sync_body(b"other")),
                &them,
                me,
                Some(&them),
                Some(&others)
            ),
            Verdict::Ignore
        );
        // Our own envelope, no other member, an empty payload.
        assert_eq!(
            authorize(gid, Some(&pending), me, me, Some(me), Some(&others)),
            Verdict::Ignore
        );
        assert_eq!(
            authorize(gid, Some(&pending), &them, me, Some(me), None),
            Verdict::Ignore
        );
        assert_eq!(
            authorize(gid, None, &them, me, Some(me), Some(&others)),
            Verdict::Ignore
        );
        // An unknown signer waits in quarantine, and is released (applied)
        // once its installation appears in the other member's log.
        let mut q = Quarantine::new(4, Duration::from_secs(600));
        let t = Instant::now();
        assert_eq!(
            authorize(gid, Some(&pending), &them2, me, Some(me), Some(&others)),
            Verdict::Quarantine
        );
        q.push(b"sealed".to_vec(), t);
        let released = q.take_live_since(t + Duration::from_secs(1));
        assert_eq!(released.len(), 1);
        assert_eq!(
            authorize(gid, Some(&pending), &them2, me, Some(me), Some(&both)),
            Verdict::Pending,
            "re-checked after the log grew: applied"
        );
    }

    /// §R6.4 (at most 10 min): a failed re-check puts the envelope back
    /// with its first arrival time, so re-checks do not keep it alive.
    #[test]
    fn requarantined_envelopes_keep_their_first_arrival_time() {
        let t = Instant::now();
        let mut q = Quarantine::new(4, Duration::from_secs(10));
        q.push(vec![1], t);
        for (since, sealed) in q.take_live_since(t + Duration::from_secs(6)) {
            assert_eq!(since, t);
            q.push(sealed, since);
        }
        assert!(q.take_live(t + Duration::from_secs(11)).is_empty());
    }
}
