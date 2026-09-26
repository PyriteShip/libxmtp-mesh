//! The node-level relay engine (spec §5, §4.5). Sessions hand it relay
//! frames and link up/down; it owns the spool policy, per-link knowledge,
//! rate limits, delayed pushes, relay-key pinning and (Task 8) DM traffic.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};

use parking_lot::Mutex;
use rand::RngExt;
use tokio::sync::{broadcast, oneshot};
use tokio::time::Instant;

use super::RelayConfig;
use super::envelope::{self, short_id};
use super::keys::{RelayExporter, unwrap_key, wrap_key};
use super::spool::{self, Accept, DropReason, TokenBucket};
use crate::MeshError;
use crate::node::{MeshNode, NodeEvent, NodeInner};
use crate::sync::frames::{
    self, RelayEnvelope, RelayKeyAck, RelayKeyOffer, SpoolDigest, SpoolWant, frame::Body,
};
use crate::sync::{GroupMembership, HelloSigner, MeshTransport};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayStats {
    pub accepted: u64,
    pub duplicate: u64,
    pub dropped_invalid: u64,
    pub dropped_expired: u64,
    pub dropped_share: u64,
    pub dropped_rate: u64,
    pub pushed: u64,
    pub originated: u64,
    pub delivered: u64,
    pub refs_sent: u64,
}

pub(crate) struct Link {
    pub(crate) installation: Vec<u8>,
    pub(crate) inbox: String,
    holds: HashSet<[u8; 8]>,
    next_offer: Instant,
}

/// Rate budget of one neighbour phone, shared by all its links (D18).
struct Neighbour {
    envelopes: TokenBucket,
    bytes: TokenBucket,
}

pub(crate) struct EngineState {
    pub(crate) links: HashMap<String, Link>,
    /// Keyed by verified installation key.
    neighbours: HashMap<Vec<u8>, Neighbour>,
    global_envelopes: TokenBucket,
    global_bytes: TokenBucket,
    pub(crate) stats: RelayStats,
}

pub(crate) struct RelayEngine {
    node: Weak<NodeInner>,
    pub(crate) cfg: RelayConfig,
    exporter: Arc<dyn RelayExporter>,
    /// The sync runtime: every engine spawn runs here, so callers (e.g.
    /// `originate`) may be on any thread.
    runtime: tokio::runtime::Handle,
    pub(crate) state: Mutex<EngineState>,
    _stop: oneshot::Sender<()>,
}

/// The sync config's signer, transport and membership, cloned out.
type SyncParts = (
    Arc<dyn HelloSigner>,
    Arc<dyn MeshTransport>,
    Arc<dyn GroupMembership>,
);

pub(crate) fn now_secs() -> i64 {
    xmtp_common::time::now_ns() / 1_000_000_000
}

impl RelayEngine {
    pub(crate) fn node(&self) -> Option<MeshNode> {
        self.node.upgrade().map(|inner| MeshNode { inner })
    }

    fn parts(&self) -> Option<SyncParts> {
        let node = self.node()?;
        let sync = node.inner.sync.lock();
        let c = sync.as_ref()?;
        Some((c.signer.clone(), c.transport.clone(), c.membership.clone()))
    }

    // Task 8 (DM traffic) is the caller.
    #[allow(dead_code)]
    pub(crate) fn signer(&self) -> Option<Arc<dyn HelloSigner>> {
        self.parts().map(|p| p.0)
    }

    /// Whether this engine is still the node's engine: a replaced or
    /// disabled engine's pending work (delayed pushes, offers) sends nothing.
    fn is_current(&self) -> bool {
        let Some(node) = self.node() else {
            return false;
        };
        node.inner
            .relay
            .lock()
            .as_ref()
            .is_some_and(|e| std::ptr::eq(Arc::as_ptr(e), self))
    }

    fn send(&self, peer: &str, body: Body) {
        if !self.is_current() {
            return;
        }
        if let Some((_, transport, _)) = self.parts() {
            transport.send(&peer.to_string(), frames::encode(body));
        }
    }

    /// The DM's only other member inbox, or `None` (unknown group, not a
    /// DM, or the client could not say).
    pub(crate) async fn other_member(&self, group_id: &[u8]) -> Option<String> {
        let node = self.node()?;
        let own = node.local_inbox().ok().flatten()?;
        let (_, _, membership) = self.parts()?;
        let members = membership.member_inboxes(group_id).await.ok().flatten()?;
        let others: Vec<String> = members.into_iter().filter(|m| *m != own).collect();
        (others.len() == 1).then(|| others[0].clone())
    }

    // ---- links ----

    fn link_up(self: &Arc<Self>, peer: &str, installation: Vec<u8>, inbox: String) {
        let now = Instant::now();
        {
            let mut st = self.state.lock();
            st.neighbours
                .entry(installation.clone())
                .or_insert_with(|| Neighbour {
                    envelopes: TokenBucket::new(
                        self.cfg.share_cap() as f64,
                        self.cfg.neighbour_envelopes_per_min as f64,
                        now,
                    ),
                    bytes: TokenBucket::new(
                        self.cfg.share_cap_bytes() as f64,
                        self.cfg.neighbour_bytes_per_min as f64,
                        now,
                    ),
                });
            st.links.insert(
                peer.to_string(),
                Link {
                    installation,
                    inbox,
                    holds: HashSet::new(),
                    next_offer: now,
                },
            );
        }
        let Some(node) = self.node() else { return };
        let ids: Vec<Vec<u8>> = match node.inner.store.lock().spool_pushable() {
            Ok(entries) => entries
                .into_iter()
                .take(self.cfg.max_entries)
                .filter_map(|e| e.hash.get(..8).map(<[u8]>::to_vec))
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "relay: spool unavailable");
                vec![]
            }
        };
        self.send(peer, Body::SpoolDigest(SpoolDigest { ids }));
        let engine = self.clone();
        let peer = peer.to_string();
        self.runtime
            .spawn(async move { engine.offer_keys(&peer).await });
    }

    fn link_down(&self, peer: &str) {
        let mut st = self.state.lock();
        let Some(link) = st.links.remove(peer) else {
            return;
        };
        if !st
            .links
            .values()
            .any(|l| l.installation == link.installation)
        {
            st.neighbours.remove(&link.installation);
        }
    }

    // ---- frames ----

    pub(crate) async fn on_frame(self: &Arc<Self>, peer: &str, body: Body) {
        let result = match body {
            Body::SpoolDigest(d) => self.on_digest(peer, d),
            Body::SpoolWant(w) => self.on_want(peer, w),
            Body::Relay(env) => self.on_relay(peer, env).await,
            Body::RelayKeyOffer(o) => self.on_key_offer(peer, o).await,
            Body::RelayKeyAck(a) => self.on_key_ack(peer, a).await,
            _ => Ok(()),
        };
        match result {
            Ok(()) => {}
            // Peer-caused (bad envelope, key, seal, signature).
            Err(e @ MeshError::Relay(_)) => {
                tracing::debug!(peer, error = %e, "relay frame not used")
            }
            // Ours (store, membership, ...): worth seeing.
            Err(e) => tracing::warn!(peer, error = %e, "relay frame failed"),
        }
    }

    fn on_digest(&self, peer: &str, d: SpoolDigest) -> Result<(), MeshError> {
        let ids: Vec<[u8; 8]> = d
            .ids
            .iter()
            .take(self.cfg.max_entries)
            .filter_map(|id| id.as_slice().try_into().ok())
            .collect();
        if let Some(link) = self.state.lock().links.get_mut(peer) {
            link.holds.extend(ids.iter().copied());
        }
        let node = self
            .node()
            .ok_or_else(|| MeshError::Relay("node gone".into()))?;
        let mut want = Vec::new();
        {
            let mut store = node.inner.store.lock();
            for id in &ids {
                if !store.relay_is_seen_short(id)? {
                    want.push(id.to_vec());
                }
            }
        }
        if !want.is_empty() {
            self.send(peer, Body::SpoolWant(SpoolWant { ids: want }));
        }
        Ok(())
    }

    fn on_want(&self, peer: &str, w: SpoolWant) -> Result<(), MeshError> {
        let node = self
            .node()
            .ok_or_else(|| MeshError::Relay("node gone".into()))?;
        for id in w.ids.iter().take(self.cfg.max_entries) {
            let Some(entry) = node.inner.store.lock().spool_by_short(id)? else {
                continue;
            };
            if entry.ttl <= 0 {
                continue;
            }
            if let (Some(link), Ok(short)) = (
                self.state.lock().links.get_mut(peer),
                <[u8; 8]>::try_from(id.as_slice()),
            ) {
                link.holds.insert(short);
            }
            self.send(
                peer,
                Body::Relay(RelayEnvelope {
                    ttl: entry.ttl as u32,
                    copies: 0,
                    sealed: entry.sealed,
                }),
            );
            self.state.lock().stats.pushed += 1;
        }
        Ok(())
    }

    async fn on_relay(self: &Arc<Self>, peer: &str, env: RelayEnvelope) -> Result<(), MeshError> {
        let hash = envelope::hash(&env.sealed);
        let len = env.sealed.len() as f64;
        {
            let now = Instant::now();
            let mut st = self.state.lock();
            let EngineState {
                links,
                neighbours,
                global_envelopes,
                global_bytes,
                stats,
                ..
            } = &mut *st;
            let Some(link) = links.get_mut(peer) else {
                return Ok(());
            };
            link.holds.insert(short_id(&hash));
            let Some(nb) = neighbours.get_mut(&link.installation) else {
                return Ok(());
            };
            let ok = nb.envelopes.allows(1.0, now)
                && nb.bytes.allows(len, now)
                && global_envelopes.allows(1.0, now)
                && global_bytes.allows(len, now);
            if !ok {
                stats.dropped_rate += 1;
                return Ok(());
            }
            nb.envelopes.take(1.0);
            nb.bytes.take(len);
            global_envelopes.take(1.0);
            global_bytes.take(len);
        }
        let from = match self.state.lock().links.get(peer) {
            Some(l) => l.installation.clone(),
            None => return Ok(()),
        };
        let node = self
            .node()
            .ok_or_else(|| MeshError::Relay("node gone".into()))?;
        let outcome = {
            let mut store = node.inner.store.lock();
            spool::accept(
                &mut store,
                &self.cfg,
                env.ttl,
                &env.sealed,
                &from,
                now_secs(),
            )?
        };
        {
            let mut st = self.state.lock();
            match outcome {
                Accept::New { .. } => st.stats.accepted += 1,
                Accept::Duplicate => st.stats.duplicate += 1,
                Accept::Dropped(DropReason::Invalid) => st.stats.dropped_invalid += 1,
                Accept::Dropped(DropReason::Expired) => st.stats.dropped_expired += 1,
                Accept::Dropped(DropReason::Share) => st.stats.dropped_share += 1,
            }
        }
        if let Accept::New { hash } = outcome {
            self.try_deliver(&env.sealed).await;
            self.schedule_push(hash, peer.to_string());
        }
        Ok(())
    }

    /// Open `sealed` if it is for one of our DMs and act on it (Task 8).
    pub(crate) async fn try_deliver(self: &Arc<Self>, _sealed: &[u8]) {}

    // ---- pushing ----

    fn schedule_push(self: &Arc<Self>, hash: [u8; 32], from_link: String) {
        let (lo, hi) = self.cfg.push_delay_ms;
        let delay = std::time::Duration::from_millis(rand::rng().random_range(lo..=hi.max(lo)));
        // Captured now: if `from_link` goes down during the delay, its
        // sibling links to the same phone are still excluded.
        let source = self
            .state
            .lock()
            .links
            .get(&from_link)
            .map(|l| l.installation.clone());
        let engine = self.clone();
        self.runtime.spawn(async move {
            tokio::time::sleep(delay).await;
            engine.push(hash, &from_link, source.as_deref());
        });
    }

    fn push(&self, hash: [u8; 32], from_link: &str, source: Option<&[u8]>) {
        if !self.is_current() {
            return;
        }
        let Some(node) = self.node() else { return };
        let entry = match node.inner.store.lock().spool_get(&hash) {
            Ok(Some(e)) if e.ttl > 0 => e,
            _ => return,
        };
        let short = short_id(&hash);
        let targets: Vec<String> = {
            let mut st = self.state.lock();
            let mut out = Vec::new();
            for (peer, link) in st.links.iter_mut() {
                if peer == from_link
                    || source == Some(link.installation.as_slice())
                    || link.holds.contains(&short)
                {
                    continue;
                }
                link.holds.insert(short);
                out.push(peer.clone());
            }
            st.stats.pushed += out.len() as u64;
            out
        };
        for peer in targets {
            self.send(
                &peer,
                Body::Relay(RelayEnvelope {
                    ttl: entry.ttl as u32,
                    copies: 0,
                    sealed: entry.sealed.clone(),
                }),
            );
        }
    }

    /// Put an envelope this node sealed into the spool and push it on.
    // Task 8 (DM traffic) is the caller.
    #[allow(dead_code)]
    pub(crate) fn originate(self: &Arc<Self>, sealed: Vec<u8>) {
        let (lo, hi) = self.cfg.origin_ttl;
        let ttl = rand::rng().random_range(lo..=hi.max(lo));
        self.originate_with_ttl(sealed, ttl);
    }

    pub(crate) fn originate_with_ttl(self: &Arc<Self>, sealed: Vec<u8>, ttl: u32) {
        let Some(node) = self.node() else { return };
        let outcome = {
            let mut store = node.inner.store.lock();
            spool::accept(&mut store, &self.cfg, ttl, &sealed, b"", now_secs())
        };
        match outcome {
            Ok(Accept::New { hash }) => {
                self.state.lock().stats.originated += 1;
                self.schedule_push(hash, String::new());
            }
            Ok(other) => tracing::warn!(?other, "relay: own envelope not spooled"),
            Err(e) => tracing::warn!(error = %e, "relay: own envelope not spooled"),
        }
    }

    // ---- relay-key pinning (spec §4.5) ----

    async fn offer_keys(&self, peer: &str) {
        let Some(node) = self.node() else { return };
        let (inbox, due) = {
            let mut st = self.state.lock();
            let Some(link) = st.links.get_mut(peer) else {
                return;
            };
            let now = Instant::now();
            if now < link.next_offer {
                return;
            }
            link.next_offer = now + self.cfg.key_reoffer;
            (link.inbox.clone(), true)
        };
        if !due {
            return;
        }
        let Ok(Some(local)) = node.local_installation() else {
            return;
        };
        let groups = node.inner.store.lock().known_groups().unwrap_or_default();
        for gid in groups {
            if node.sequencer_of(&gid).ok().flatten().as_deref() != Some(local.as_slice()) {
                continue;
            }
            if self.other_member(&gid).await.as_deref() != Some(inbox.as_str()) {
                continue;
            }
            let existing = node.inner.store.lock().relay_key(&gid).ok().flatten();
            if matches!(existing, Some((_, true))) {
                continue;
            }
            let Ok(Some((epoch, secret))) = self.exporter.exporter_secret(&gid).await else {
                continue;
            };
            // Create-if-absent in one store call: two concurrent offers
            // (two links to one phone) must offer the same key.
            let key = match node
                .inner
                .store
                .lock()
                .relay_key_or_insert(&gid, &rand::random())
            {
                Ok((_, true)) => continue,
                Ok((k, false)) => k,
                Err(e) => {
                    tracing::warn!(error = %e, "relay: could not store a relay key");
                    continue;
                }
            };
            let (nonce, ciphertext) = wrap_key(&secret, &gid, epoch, &key);
            self.send(
                peer,
                Body::RelayKeyOffer(RelayKeyOffer {
                    group_id: gid,
                    epoch,
                    nonce: nonce.to_vec(),
                    ciphertext,
                }),
            );
        }
    }

    fn link_identity(&self, peer: &str) -> Option<(Vec<u8>, String)> {
        let st = self.state.lock();
        let l = st.links.get(peer)?;
        Some((l.installation.clone(), l.inbox.clone()))
    }

    async fn on_key_offer(&self, peer: &str, o: RelayKeyOffer) -> Result<(), MeshError> {
        let node = self
            .node()
            .ok_or_else(|| MeshError::Relay("node gone".into()))?;
        let Some((installation, inbox)) = self.link_identity(peer) else {
            return Ok(());
        };
        if node.sequencer_of(&o.group_id)?.as_deref() != Some(installation.as_slice())
            || self.other_member(&o.group_id).await.as_deref() != Some(inbox.as_str())
        {
            return Ok(());
        }
        let Some((epoch, secret)) = self.exporter.exporter_secret(&o.group_id).await? else {
            return Ok(());
        };
        if epoch != o.epoch {
            tracing::debug!(
                ours = epoch,
                theirs = o.epoch,
                "relay key offer at another epoch; waiting for a re-offer"
            );
            return Ok(());
        }
        let key = unwrap_key(&secret, &o.group_id, o.epoch, &o.nonce, &o.ciphertext)?;
        node.inner
            .store
            .lock()
            .set_relay_key(&o.group_id, &key, true)?;
        self.on_key_confirmed(&o.group_id);
        self.send(
            peer,
            Body::RelayKeyAck(RelayKeyAck {
                group_id: o.group_id,
            }),
        );
        Ok(())
    }

    async fn on_key_ack(&self, peer: &str, a: RelayKeyAck) -> Result<(), MeshError> {
        let node = self
            .node()
            .ok_or_else(|| MeshError::Relay("node gone".into()))?;
        let Some((_, inbox)) = self.link_identity(peer) else {
            return Ok(());
        };
        let local = node.local_installation()?;
        if local.is_none() || node.sequencer_of(&a.group_id)? != local {
            return Ok(());
        }
        if self.other_member(&a.group_id).await.as_deref() != Some(inbox.as_str()) {
            return Ok(());
        }
        {
            let mut store = node.inner.store.lock();
            let Some((key, _)) = store.relay_key(&a.group_id)? else {
                return Ok(());
            };
            store.set_relay_key(&a.group_id, &key, true)?;
        }
        self.on_key_confirmed(&a.group_id);
        Ok(())
    }

    // ---- housekeeping ----

    async fn on_tick(self: &Arc<Self>) {
        if let Some(node) = self.node()
            && let Err(e) = node.inner.store.lock().relay_purge(now_secs())
        {
            tracing::warn!(error = %e, "relay purge failed");
        }
        let peers: Vec<String> = self.state.lock().links.keys().cloned().collect();
        for peer in peers {
            self.offer_keys(&peer).await;
        }
        self.on_tick_dm().await;
    }

    /// Task 8 fills this in.
    pub(crate) async fn on_tick_dm(self: &Arc<Self>) {}

    /// Task 8 fills this in.
    pub(crate) fn on_event(self: &Arc<Self>, _event: NodeEvent) {}

    /// Missed node events. Task 8 fills this in.
    pub(crate) fn on_lagged(self: &Arc<Self>) {}

    /// A DM's relay key just became usable on this side. Task 8 fills this in.
    pub(crate) fn on_key_confirmed(&self, _group_id: &[u8]) {}

    /// The engine task. It holds the engine only weakly (and strongly only
    /// for one tick or event at a time), so dropping the node's handle
    /// (`disable_relay`) drops the engine and its `_stop` sender, which ends
    /// this loop.
    async fn run(
        engine: Weak<Self>,
        mut events: broadcast::Receiver<NodeEvent>,
        mut stop: oneshot::Receiver<()>,
    ) {
        let Some(period) = engine.upgrade().map(|e| e.cfg.tick) else {
            return;
        };
        let mut tick = tokio::time::interval(period);
        loop {
            tokio::select! {
                _ = &mut stop => break,
                _ = tick.tick() => {
                    let Some(e) = engine.upgrade() else { break };
                    e.on_tick().await;
                }
                event = events.recv() => {
                    let Some(e) = engine.upgrade() else { break };
                    match event {
                        Ok(event) => e.on_event(event),
                        Err(broadcast::error::RecvError::Lagged(_)) => e.on_lagged(),
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
    }
}

impl MeshNode {
    fn relay_engine(&self) -> Option<Arc<RelayEngine>> {
        self.inner.relay.lock().clone()
    }

    pub fn enable_relay(&self, exporter: Arc<dyn RelayExporter>) -> Result<(), MeshError> {
        self.enable_relay_with(exporter, RelayConfig::default())
    }

    /// Start relaying (spec phase 1). Call after `start_sync` and before
    /// links come up: only sessions started afterwards advertise relay.
    pub fn enable_relay_with(
        &self,
        exporter: Arc<dyn RelayExporter>,
        cfg: RelayConfig,
    ) -> Result<(), MeshError> {
        let runtime = self
            .inner
            .sync
            .lock()
            .as_ref()
            .map(|c| c.runtime.clone())
            .ok_or(MeshError::SyncNotStarted)?;
        let (stop_tx, stop_rx) = oneshot::channel();
        let now = Instant::now();
        let engine = Arc::new(RelayEngine {
            node: Arc::downgrade(&self.inner),
            state: Mutex::new(EngineState {
                links: HashMap::new(),
                neighbours: HashMap::new(),
                global_envelopes: TokenBucket::new(
                    cfg.global_envelopes_per_min as f64,
                    cfg.global_envelopes_per_min as f64,
                    now,
                ),
                global_bytes: TokenBucket::new(
                    cfg.global_bytes_per_min as f64,
                    cfg.global_bytes_per_min as f64,
                    now,
                ),
                stats: RelayStats::default(),
            }),
            cfg,
            exporter,
            runtime: runtime.clone(),
            _stop: stop_tx,
        });
        let events = self.subscribe_events();
        let old = self.inner.relay.lock().replace(engine.clone());
        drop(old);
        runtime.spawn(RelayEngine::run(Arc::downgrade(&engine), events, stop_rx));
        Ok(())
    }

    /// Stop relaying: no pushes, relay frames ignored, nothing originated.
    pub fn disable_relay(&self) {
        let old = self.inner.relay.lock().take();
        drop(old); // dropping `_stop` ends the engine task
    }

    pub fn relay_enabled(&self) -> bool {
        self.inner.relay.lock().is_some()
    }

    pub fn relay_stats(&self) -> RelayStats {
        self.relay_engine()
            .map(|e| e.state.lock().stats.clone())
            .unwrap_or_default()
    }

    pub(crate) fn relay_link_up(&self, peer: &str, installation: Vec<u8>, inbox: String) {
        if let Some(e) = self.relay_engine() {
            e.link_up(peer, installation, inbox);
        }
    }

    pub(crate) fn relay_link_down(&self, peer: &str) {
        if let Some(e) = self.relay_engine() {
            e.link_down(peer);
        }
    }

    pub(crate) async fn on_relay_frame(&self, peer: &str, body: Body) {
        if let Some(e) = self.relay_engine() {
            e.on_frame(peer, body).await;
        }
    }

    pub(crate) fn relay_note_peer_high(&self, group_id: &[u8], high: i64) {
        if let Err(e) = self.inner.store.lock().note_peer_acked_high(group_id, high) {
            tracing::warn!(error = %e, "relay: could not note peer high");
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn originate_random_for_test(&self, body_len: usize, ttl: u32) -> Vec<u8> {
        let engine = self.relay_engine().expect("relay enabled");
        let expires = envelope::coarse_expiry(now_secs() as u64, 60);
        let sealed = envelope::seal(&rand::random(), expires, &vec![0; body_len]).unwrap();
        let hash = envelope::hash(&sealed).to_vec();
        engine.originate_with_ttl(sealed, ttl);
        hash
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn relay_spool_has_for_test(&self, hash: &[u8]) -> bool {
        self.inner.store.lock().spool_get(hash).unwrap().is_some()
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn relay_spool_count_from_for_test(&self, installation: &[u8]) -> i64 {
        self.inner
            .store
            .lock()
            .spool_count_from(installation)
            .unwrap()
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn relay_key_for_test(&self, group_id: &[u8]) -> Option<([u8; 32], bool)> {
        self.inner.store.lock().relay_key(group_id).unwrap()
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn relay_seen_for_test(&self, hash: &[u8]) -> bool {
        self.inner.store.lock().relay_is_seen(hash).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoExporter;

    #[async_trait::async_trait]
    impl RelayExporter for NoExporter {
        async fn exporter_secret(
            &self,
            _group_id: &[u8],
        ) -> Result<Option<(u64, [u8; 32])>, MeshError> {
            Ok(None)
        }
    }

    struct StubSigner(Vec<u8>);

    impl HelloSigner for StubSigner {
        fn installation_key(&self) -> Vec<u8> {
            self.0.clone()
        }
        fn sign(&self, _text: &str) -> Result<Vec<u8>, MeshError> {
            Ok(vec![])
        }
    }

    /// Records every frame sent.
    #[derive(Default)]
    struct Sent(Mutex<Vec<(String, Vec<u8>)>>);

    impl MeshTransport for Sent {
        fn send(&self, peer: &crate::PeerId, frame: Vec<u8>) {
            self.0.lock().push((peer.clone(), frame));
        }
        fn disconnect(&self, _peer: &crate::PeerId) {}
    }

    /// Every group is a DM of "me" and "them".
    struct Dm;

    #[async_trait::async_trait]
    impl GroupMembership for Dm {
        async fn member_inboxes(&self, _g: &[u8]) -> Result<Option<Vec<String>>, MeshError> {
            Ok(Some(vec!["me".into(), "them".into()]))
        }
    }

    /// A fixed secret, returned after a pause so concurrent callers overlap.
    struct SlowExporter;

    #[async_trait::async_trait]
    impl RelayExporter for SlowExporter {
        async fn exporter_secret(
            &self,
            _group_id: &[u8],
        ) -> Result<Option<(u64, [u8; 32])>, MeshError> {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            Ok(Some((1, [7; 32])))
        }
    }

    /// Review fix round 1 (Important): two links to one phone (D18) come
    /// up at once; both offers for the DM must carry the one stored key.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_offers_for_one_dm_offer_one_key() {
        let local = vec![1; 32];
        let gid = b"dm".to_vec();
        let node = MeshNode::in_memory().unwrap();
        {
            let mut store = node.inner.store.lock();
            store.set_local_installation(&local).unwrap();
            store.set_local_inbox("me").unwrap();
            store.pin_sequencer(&gid, &local).unwrap();
        }
        let sent = Arc::new(Sent::default());
        *node.inner.sync.lock() = Some(crate::node::SyncConfig {
            signer: Arc::new(StubSigner(local)),
            transport: sent.clone(),
            membership: Arc::new(Dm),
            runtime: tokio::runtime::Handle::current(),
        });
        let cfg = RelayConfig {
            tick: std::time::Duration::from_secs(3600),
            key_reoffer: std::time::Duration::from_secs(3600),
            ..RelayConfig::default()
        };
        node.enable_relay_with(Arc::new(SlowExporter), cfg).unwrap();
        node.relay_link_up("p1", vec![2; 32], "them".into());
        node.relay_link_up("p2", vec![2; 32], "them".into());

        let offered = || -> Vec<[u8; 32]> {
            sent.0
                .lock()
                .iter()
                .filter_map(|(_, f)| match frames::decode(f).ok()? {
                    Body::RelayKeyOffer(o) => Some(
                        unwrap_key(&[7; 32], &o.group_id, o.epoch, &o.nonce, &o.ciphertext)
                            .unwrap(),
                    ),
                    _ => None,
                })
                .collect()
        };
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        while offered().len() < 2 {
            assert!(Instant::now() < deadline, "two offers");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let keys = offered();
        let stored = node.inner.store.lock().relay_key(&gid).unwrap().unwrap().0;
        assert!(
            keys.iter().all(|k| *k == stored),
            "one key offered on both links"
        );
        node.disable_relay();
    }

    /// Item 12: `disable_relay` drops the node's engine handle, and that
    /// alone must end the engine task (the task must not keep the engine,
    /// and so its stop sender, alive).
    #[tokio::test]
    async fn dropping_the_engine_stops_its_task() {
        let cfg = RelayConfig {
            tick: std::time::Duration::from_millis(10),
            ..RelayConfig::default()
        };
        let now = Instant::now();
        let (stop_tx, stop_rx) = oneshot::channel();
        let (events_tx, events) = broadcast::channel(4);
        let engine = Arc::new(RelayEngine {
            node: Weak::new(),
            state: Mutex::new(EngineState {
                links: HashMap::new(),
                neighbours: HashMap::new(),
                global_envelopes: TokenBucket::new(1.0, 1.0, now),
                global_bytes: TokenBucket::new(1.0, 1.0, now),
                stats: RelayStats::default(),
            }),
            cfg,
            exporter: Arc::new(NoExporter),
            runtime: tokio::runtime::Handle::current(),
            _stop: stop_tx,
        });
        let task = tokio::spawn(RelayEngine::run(Arc::downgrade(&engine), events, stop_rx));
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        drop(engine);
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("the engine task stops once the engine is dropped")
            .unwrap();
        drop(events_tx);
    }
}
