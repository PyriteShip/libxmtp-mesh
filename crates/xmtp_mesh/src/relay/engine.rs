//! The node-level relay engine (§R5, §R4.5). Sessions hand it relay
//! frames and link up/down; it owns the spool policy, per-link knowledge,
//! rate limits, delayed pushes, relay-key pinning and DM traffic.
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
    /// Entries pushed out of a neighbour's full share to admit its newer
    /// envelope (newest wins, §R5.4); nothing is refused for the share.
    pub dropped_share: u64,
    pub dropped_rate: u64,
    pub pushed: u64,
    pub originated: u64,
    /// Relay DM payloads applied here (every delivery, spooled or not).
    pub delivered: u64,
    /// Envelopes for one of our DMs that a rate or admission limit kept
    /// out of the spool and that were delivered anyway (§R5.4); a
    /// subset of the envelopes behind `delivered`.
    pub delivered_unspooled: u64,
    pub refs_sent: u64,
}

pub(crate) struct Link {
    pub(crate) installation: Vec<u8>,
    pub(crate) inbox: String,
    /// What the peer phone holds, as far as this link knows.
    holds: HashSet<[u8; 8]>,
    /// Ids this link asked the peer for (`SpoolWant`), so a sibling link to
    /// the same phone does not ask again (D18).
    wanted: HashSet<[u8; 8]>,
    next_offer: Instant,
}

/// Rate budget of one neighbour phone, shared by all its links (D18). It
/// outlives the phone's links until it has refilled, so reconnecting does
/// not reset it.
struct Neighbour {
    envelopes: TokenBucket,
    bytes: TokenBucket,
}

impl Neighbour {
    fn is_full(&mut self, now: Instant) -> bool {
        self.envelopes.is_full(now) && self.bytes.is_full(now)
    }
}

/// Most neighbour budgets kept; beyond it the fullest unlinked one goes.
const MAX_NEIGHBOURS: usize = 256;

pub(crate) struct EngineState {
    pub(crate) links: HashMap<String, Link>,
    /// Keyed by verified installation key.
    neighbours: HashMap<Vec<u8>, Neighbour>,
    global_envelopes: TokenBucket,
    global_bytes: TokenBucket,
    pub(crate) stats: RelayStats,
    /// Per relayed DM: its send/retry schedule (§R6.1).
    pub(crate) dm: HashMap<Vec<u8>, super::dm::Schedule>,
    /// Envelopes from a signer we cannot place yet (§R6.4).
    pub(crate) quarantine: super::dm::Quarantine,
    /// Verified direct peers and their inboxes, from node events: a lost
    /// one sends its DMs back to relay (§R6.1).
    pub(crate) direct: HashMap<String, String>,
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) hooks: TestHooks,
}

impl EngineState {
    fn new(cfg: &RelayConfig, now: Instant) -> Self {
        Self {
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
            dm: HashMap::new(),
            quarantine: super::dm::Quarantine::new(cfg.quarantine_max, cfg.quarantine_for),
            direct: HashMap::new(),
            #[cfg(any(test, feature = "test-utils"))]
            hooks: TestHooks::default(),
        }
    }

    /// The installation behind `peer`'s link, if it is a relay link.
    fn installation_of(&self, peer: &str) -> Option<Vec<u8>> {
        self.links.get(peer).map(|l| l.installation.clone())
    }

    /// Record that the phone `installation` holds `short`, on all its links.
    fn mark_held(&mut self, installation: &[u8], short: [u8; 8]) {
        for link in self.links.values_mut() {
            if link.installation == installation {
                link.holds.insert(short);
            }
        }
    }

    fn phone_holds(&self, installation: &[u8], short: &[u8; 8]) -> bool {
        self.links
            .values()
            .any(|l| l.installation == installation && l.holds.contains(short))
    }

    /// Drop budgets of phones with no link that have refilled: a fresh one
    /// would be the same.
    fn prune_neighbours(&mut self, now: Instant) {
        let linked: HashSet<Vec<u8>> = self
            .links
            .values()
            .map(|l| l.installation.clone())
            .collect();
        self.neighbours
            .retain(|inst, nb| linked.contains(inst) || !nb.is_full(now));
    }

    /// Make room for one more budget: evict the fullest unlinked one.
    fn bound_neighbours(&mut self, now: Instant) {
        while self.neighbours.len() >= MAX_NEIGHBOURS {
            let linked: HashSet<Vec<u8>> = self
                .links
                .values()
                .map(|l| l.installation.clone())
                .collect();
            let fullest = self
                .neighbours
                .iter_mut()
                .filter(|(inst, _)| !linked.contains(*inst))
                .map(|(inst, nb)| (inst.clone(), nb.envelopes.level(now)))
                .max_by(|a, b| a.1.total_cmp(&b.1))
                .map(|(inst, _)| inst);
            match fullest {
                Some(inst) => {
                    self.neighbours.remove(&inst);
                }
                None => break,
            }
        }
    }
}

/// Switches that let integration tests force relay DM edge cases.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Default)]
pub(crate) struct TestHooks {
    /// Sequencer: send every row as a `Ref`, as if the joiner had sent it,
    /// to exercise the joiner's `need_full_after` fallback.
    pub(crate) force_refs: bool,
    /// Joiner: never ask for `Full` rows, so a stall persists.
    pub(crate) no_full_request: bool,
    /// Joiner: seal pure acks but do not originate them (lost acks).
    pub(crate) drop_pure_acks: bool,
}

pub(crate) struct RelayEngine {
    node: Weak<NodeInner>,
    pub(crate) cfg: RelayConfig,
    exporter: Arc<dyn RelayExporter>,
    /// The sync runtime: every engine spawn runs here, so callers (e.g.
    /// `originate`) may be on any thread.
    pub(crate) runtime: tokio::runtime::Handle,
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
            if !st.neighbours.contains_key(&installation) {
                st.bound_neighbours(now);
                st.neighbours.insert(
                    installation.clone(),
                    Neighbour {
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
                    },
                );
            }
            st.links.insert(
                peer.to_string(),
                Link {
                    installation,
                    inbox,
                    holds: HashSet::new(),
                    wanted: HashSet::new(),
                    next_offer: now,
                },
            );
        }
        let Some(node) = self.node() else { return };
        let ids = match node
            .inner
            .store
            .lock()
            .spool_pushable_ids(self.cfg.max_entries)
        {
            Ok(ids) => ids,
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

    /// The phone's rate budget stays (pruned on tick once refilled), so a
    /// reconnect does not reset it (D18).
    fn link_down(&self, peer: &str) {
        self.state.lock().links.remove(peer);
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
        match self.state.lock().links.get_mut(peer) {
            Some(link) => link.holds.extend(ids.iter().copied()),
            None => return Ok(()), // not a relay link (yet): ignored
        }
        let node = self
            .node()
            .ok_or_else(|| MeshError::Relay("node gone".into()))?;
        let mut unseen = Vec::new();
        {
            let mut store = node.inner.store.lock();
            for id in ids {
                if !store.relay_is_seen_short(&id)? {
                    unseen.push(id);
                }
            }
        }
        // Ask once per phone: skip what a sibling link already asked for.
        let want: Vec<Vec<u8>> = {
            let mut st = self.state.lock();
            let Some(installation) = st.installation_of(peer) else {
                return Ok(());
            };
            let asked: HashSet<[u8; 8]> = st
                .links
                .iter()
                .filter(|(p, l)| p.as_str() != peer && l.installation == installation)
                .flat_map(|(_, l)| l.wanted.iter().copied())
                .collect();
            let unseen: Vec<[u8; 8]> = unseen
                .into_iter()
                .filter(|id| !asked.contains(id))
                .collect();
            if let Some(link) = st.links.get_mut(peer) {
                link.wanted.extend(unseen.iter().copied());
            }
            unseen.into_iter().map(|id| id.to_vec()).collect()
        };
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
            let Ok(short) = <[u8; 8]>::try_from(id.as_slice()) else {
                continue;
            };
            // Once per phone: a sibling link's want (or an earlier push)
            // already covers it. Checked and marked in one step.
            {
                let mut st = self.state.lock();
                let Some(installation) = st.installation_of(peer) else {
                    return Ok(()); // not a relay link: ignored
                };
                if st.phone_holds(&installation, &short) {
                    continue;
                }
                st.mark_held(&installation, short);
            }
            let Some(entry) = node.inner.store.lock().spool_by_short(id)? else {
                continue;
            };
            if entry.ttl <= 0 {
                continue;
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
        let within_rate = {
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
            let Some(installation) = links.get(peer).map(|l| l.installation.clone()) else {
                return Ok(());
            };
            let short = short_id(&hash);
            for l in links.values_mut() {
                if l.installation == installation {
                    l.holds.insert(short);
                }
            }
            let Some(nb) = neighbours.get_mut(&installation) else {
                return Ok(());
            };
            let ok = nb.envelopes.allows(1.0, now)
                && nb.bytes.allows(len, now)
                && global_envelopes.allows(1.0, now)
                && global_bytes.allows(len, now);
            if ok {
                nb.envelopes.take(1.0);
                nb.bytes.take(len);
                global_envelopes.take(1.0);
                global_bytes.take(len);
            } else {
                stats.dropped_rate += 1;
            }
            ok
        };
        if !within_rate {
            // Not stored or pushed, but a recipient never misses its own
            // message to relay limits.
            self.deliver_unspooled(&hash, &env.sealed).await;
            return Ok(());
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
                Accept::New { share_evicted, .. } => {
                    st.stats.accepted += 1;
                    st.stats.dropped_share += u64::from(share_evicted);
                }
                Accept::Duplicate => st.stats.duplicate += 1,
                Accept::Dropped(DropReason::Invalid) => st.stats.dropped_invalid += 1,
                Accept::Dropped(DropReason::Expired) => st.stats.dropped_expired += 1,
            }
        }
        match outcome {
            Accept::New { hash, .. } => {
                self.try_deliver(&env.sealed).await;
                self.schedule_push(hash, peer.to_string());
            }
            Accept::Dropped(_) => self.deliver_unspooled(&hash, &env.sealed).await,
            Accept::Duplicate => {}
        }
        Ok(())
    }

    /// Try to deliver a live envelope the limits kept out of the spool,
    /// unless it was already seen. One that matched our keys is then marked
    /// seen, so a replay of it is a no-op rather than more delivery work.
    async fn deliver_unspooled(self: &Arc<Self>, hash: &[u8; 32], sealed: &[u8]) {
        let Ok(expires_at) = spool::live_expiry(sealed, now_secs()) else {
            return;
        };
        let Some(node) = self.node() else { return };
        let seen = node.inner.store.lock().relay_is_seen(hash);
        match seen {
            Ok(false) => {
                if self.try_deliver(sealed).await {
                    self.state.lock().stats.delivered_unspooled += 1;
                    let marked = node.inner.store.lock().relay_mark_seen(
                        hash,
                        expires_at,
                        self.cfg.max_seen,
                    );
                    if let Err(e) = marked {
                        tracing::warn!(error = %e, "relay: seen-set unavailable");
                    }
                }
            }
            Ok(true) => {}
            Err(e) => tracing::warn!(error = %e, "relay: seen-set unavailable"),
        }
    }

    /// Open `sealed` if it is for one of our DMs and act on it (§R6.2).
    /// Returns whether it matched one of our DM relay keys.
    pub(crate) async fn try_deliver(self: &Arc<Self>, sealed: &[u8]) -> bool {
        self.try_deliver_dm(sealed).await
    }

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
        // One link per phone (D18): its sibling links are marked as holding
        // it too, so they neither push it again nor ask for it.
        let targets: Vec<String> = {
            let mut st = self.state.lock();
            let holding: HashSet<Vec<u8>> = st
                .links
                .values()
                .filter(|l| l.holds.contains(&short))
                .map(|l| l.installation.clone())
                .collect();
            let mut chosen: HashSet<Vec<u8>> = HashSet::new();
            let mut out = Vec::new();
            for (peer, link) in st.links.iter_mut() {
                if peer == from_link || source == Some(link.installation.as_slice()) {
                    continue;
                }
                let first = !holding.contains(&link.installation)
                    && chosen.insert(link.installation.clone());
                link.holds.insert(short);
                if first {
                    out.push(peer.clone());
                }
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
            Ok(Accept::New { hash, .. }) => {
                self.state.lock().stats.originated += 1;
                self.schedule_push(hash, String::new());
            }
            Ok(other) => tracing::warn!(?other, "relay: own envelope not spooled"),
            Err(e) => tracing::warn!(error = %e, "relay: own envelope not spooled"),
        }
    }

    // ---- relay-key pinning (§R4.5) ----

    /// Offer each DM we sequence with `peer`'s inbox its relay key, unless
    /// `peer`'s installation already confirmed it. A key confirmed by
    /// another installation (the other member reinstalled) or unconfirmed
    /// by a sequencer re-pin is offered again, the same key (§R4.5).
    async fn offer_keys(&self, peer: &str) {
        let Some(node) = self.node() else { return };
        let (inbox, installation) = {
            let mut st = self.state.lock();
            let Some(link) = st.links.get_mut(peer) else {
                return;
            };
            let now = Instant::now();
            if now < link.next_offer {
                return;
            }
            link.next_offer = now + self.cfg.key_reoffer;
            (link.inbox.clone(), link.installation.clone())
        };
        let Ok(Some(local)) = node.local_installation() else {
            return;
        };
        let groups = node.inner.store.lock().known_groups().unwrap_or_default();
        for gid in groups {
            if node.sequencer_of(&gid).ok().flatten().as_deref() != Some(local.as_slice()) {
                continue;
            }
            // Cheap store checks before the async membership lookup.
            let confirmed_here = {
                let mut store = node.inner.store.lock();
                match store.relay_key(&gid) {
                    Ok(Some((_, true))) => store
                        .relay_key_confirmed_by(&gid)
                        .ok()
                        .flatten()
                        .is_some_and(|by| by.is_empty() || by == installation),
                    _ => false,
                }
            };
            if confirmed_here {
                continue;
            }
            if self.other_member(&gid).await.as_deref() != Some(inbox.as_str()) {
                continue;
            }
            let Ok(Some((epoch, secret))) = self.exporter.exporter_secret(&gid).await else {
                continue;
            };
            // Create-if-absent in one store call: two concurrent offers
            // (two links to one phone) must offer the same key; a stored
            // key is re-offered as it is.
            let key = match node
                .inner
                .store
                .lock()
                .relay_key_or_insert(&gid, &rand::random())
            {
                Ok((k, _)) => k,
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
            .confirm_relay_key(&o.group_id, &key, &installation)?;
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
        let Some((installation, inbox)) = self.link_identity(peer) else {
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
            // A new confirming installation resets the peer ack (reinstall).
            store.confirm_relay_key(&a.group_id, &key, &installation)?;
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
        let peers: Vec<String> = {
            let mut st = self.state.lock();
            st.prune_neighbours(Instant::now());
            st.links.keys().cloned().collect()
        };
        for peer in peers {
            self.offer_keys(&peer).await;
        }
        self.on_tick_dm().await;
    }

    pub(crate) fn on_event(self: &Arc<Self>, event: NodeEvent) {
        self.on_event_dm(event);
    }

    /// Missed node events.
    pub(crate) fn on_lagged(self: &Arc<Self>) {
        self.on_lagged_dm();
    }

    /// A DM's relay key just became usable on this side. A message sent
    /// before then was dropped from the schedule; this picks it up.
    pub(crate) fn on_key_confirmed(&self, group_id: &[u8]) {
        self.schedule_now(group_id);
    }

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

    /// Start relaying (phase 1, §R11). Call after `start_sync` and before
    /// links come up: only sessions started afterwards advertise relay.
    ///
    /// Live sessions whose Hellos both offered relay (e.g. from before a
    /// `disable_relay`) link up at once, and every relayed DM is scheduled,
    /// so content left unsent by a restart or a disable goes out.
    pub fn enable_relay_with(
        &self,
        exporter: Arc<dyn RelayExporter>,
        cfg: RelayConfig,
    ) -> Result<(), MeshError> {
        // Serialized with start_sync/stop_sync: a concurrent stop_sync
        // cannot leave an engine running without sync.
        let _lifecycle = self.inner.sync_lifecycle.lock();
        let runtime = self
            .inner
            .sync
            .lock()
            .as_ref()
            .map(|c| c.runtime.clone())
            .ok_or(MeshError::SyncNotStarted)?;
        let (stop_tx, stop_rx) = oneshot::channel();
        let engine = Arc::new(RelayEngine {
            node: Arc::downgrade(&self.inner),
            state: Mutex::new(EngineState::new(&cfg, Instant::now())),
            cfg,
            exporter,
            runtime: runtime.clone(),
            _stop: stop_tx,
        });
        let events = self.subscribe_events();
        let verified = self.verified_peers();
        {
            let mut st = engine.state.lock();
            for p in verified {
                st.direct.insert(p.peer, p.inbox_id);
            }
        }
        let old = self.inner.relay.lock().replace(engine.clone());
        drop(old);
        runtime.spawn(RelayEngine::run(Arc::downgrade(&engine), events, stop_rx));
        let live: Vec<(String, (Vec<u8>, String))> = self
            .inner
            .relay_links
            .lock()
            .iter()
            .map(|(p, v)| (p.clone(), v.clone()))
            .collect();
        for (peer, (installation, inbox)) in live {
            engine.link_up(&peer, installation, inbox);
        }
        engine.on_lagged_dm();
        Ok(())
    }

    /// Stop relaying: no pushes, relay frames ignored, nothing originated.
    pub fn disable_relay(&self) {
        let _lifecycle = self.inner.sync_lifecycle.lock();
        self.disable_relay_locked();
    }

    /// `disable_relay` for a caller already holding `sync_lifecycle`.
    pub(crate) fn disable_relay_locked(&self) {
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

    /// [`Self::relay_link_up`] for the verified session `session_id`,
    /// unless it is no longer `peer`'s current session.
    pub(crate) fn relay_session_link_up(
        &self,
        peer: &str,
        session_id: u64,
        installation: Vec<u8>,
        inbox: String,
    ) {
        {
            let sessions = self.inner.sessions.lock();
            if sessions.get(peer).is_none_or(|h| h.id != session_id) {
                return;
            }
        }
        self.relay_link_up(peer, installation, inbox);
    }

    /// A verified session whose Hellos both offered relay. Remembered for
    /// the session's life, so a later `enable_relay` links it up too.
    pub(crate) fn relay_link_up(&self, peer: &str, installation: Vec<u8>, inbox: String) {
        self.inner
            .relay_links
            .lock()
            .insert(peer.to_string(), (installation.clone(), inbox.clone()));
        if let Some(e) = self.relay_engine() {
            e.link_up(peer, installation, inbox);
        }
    }

    pub(crate) fn relay_link_down(&self, peer: &str) {
        self.inner.relay_links.lock().remove(peer);
        if let Some(e) = self.relay_engine() {
            e.link_down(peer);
        }
    }

    pub(crate) async fn on_relay_frame(&self, peer: &str, body: Body) {
        if let Some(e) = self.relay_engine() {
            e.on_frame(peer, body).await;
        }
    }

    /// A direct peer's `Interest` says it holds rows up to `high`; clamped
    /// to what we hold, so a bogus claim cannot skip rows it lacks.
    pub(crate) fn relay_note_peer_high(&self, group_id: &[u8], high: i64) {
        let mut store = self.inner.store.lock();
        let noted = store
            .max_group_id(group_id)
            .and_then(|max| store.note_peer_acked_high(group_id, high.min(max)));
        if let Err(e) = noted {
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

    /// Relay DM syncs this node sequences carry every row as a `Ref`.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn relay_force_refs_for_test(&self, on: bool) {
        if let Some(e) = self.relay_engine() {
            e.state.lock().hooks.force_refs = on;
        }
    }

    /// This node, as a relay DM joiner, never asks for `Full` rows.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn relay_no_full_request_for_test(&self, on: bool) {
        if let Some(e) = self.relay_engine() {
            e.state.lock().hooks.no_full_request = on;
        }
    }

    /// This node, as a relay DM joiner, loses its pure acks while `on`.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn relay_drop_pure_acks_for_test(&self, on: bool) {
        if let Some(e) = self.relay_engine() {
            e.state.lock().hooks.drop_pure_acks = on;
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn relay_peer_acked_high_for_test(&self, group_id: &[u8]) -> i64 {
        self.inner.store.lock().peer_acked_high(group_id).unwrap()
    }

    /// Raise the stored peer ack, as a direct session's `relay_note_peer_high` would.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn relay_note_peer_acked_high_for_test(&self, group_id: &[u8], high: i64) {
        self.relay_note_peer_high(group_id, high);
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

    /// Two links to one phone (D18) come
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

    const GID: &[u8] = b"dm";

    /// A node whose local installation is `[1; 32]` in inbox "me",
    /// sequencing the DM `GID` with "them", relay enabled with `cfg` (long
    /// tick and re-offer unless set), every frame sent recorded.
    fn relay_node(cfg: RelayConfig) -> (MeshNode, Arc<Sent>) {
        let local = vec![1; 32];
        let node = MeshNode::in_memory().unwrap();
        {
            let mut store = node.inner.store.lock();
            store.set_local_installation(&local).unwrap();
            store.set_local_inbox("me").unwrap();
            store.pin_sequencer(GID, &local).unwrap();
        }
        let sent = Arc::new(Sent::default());
        *node.inner.sync.lock() = Some(crate::node::SyncConfig {
            signer: Arc::new(StubSigner(local)),
            transport: sent.clone(),
            membership: Arc::new(Dm),
            runtime: tokio::runtime::Handle::current(),
        });
        node.enable_relay_with(Arc::new(SlowExporter), cfg).unwrap();
        (node, sent)
    }

    fn quiet() -> RelayConfig {
        RelayConfig {
            tick: std::time::Duration::from_secs(3600),
            key_reoffer: std::time::Duration::from_secs(3600),
            push_delay_ms: (0, 10),
            ..RelayConfig::default()
        }
    }

    fn live_sealed() -> Vec<u8> {
        let expires = envelope::coarse_expiry(now_secs() as u64, 60);
        envelope::seal(&rand::random(), expires, &[0; 100]).unwrap()
    }

    fn relay(sealed: &[u8]) -> Body {
        Body::Relay(RelayEnvelope {
            ttl: 3,
            copies: 0,
            sealed: sealed.to_vec(),
        })
    }

    /// Frames sent to `peers`, decoded.
    fn frames_to(sent: &Sent, peers: &[&str]) -> Vec<Body> {
        sent.0
            .lock()
            .iter()
            .filter(|(p, _)| peers.contains(&p.as_str()))
            .filter_map(|(_, f)| frames::decode(f).ok())
            .collect()
    }

    fn count(bodies: &[Body], f: impl Fn(&Body) -> bool) -> usize {
        bodies.iter().filter(|b| f(b)).count()
    }

    fn engine(node: &MeshNode) -> Arc<RelayEngine> {
        node.relay_engine().unwrap()
    }

    async fn settle() {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    /// D18: two links to one phone share one
    /// budget, and a reconnect does not refill it. The budget is pruned only
    /// once it has refilled with no link, and the map is bounded.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reconnect_does_not_refill_the_rate_budget() {
        let cfg = RelayConfig {
            max_entries: 8, // share cap 2 = the bucket's burst
            neighbour_envelopes_per_min: 1,
            ..quiet()
        };
        let (node, _sent) = relay_node(cfg);
        let them = vec![2; 32];
        node.relay_link_up("p1", them.clone(), "them".into());
        node.relay_link_up("p2", them.clone(), "them".into());
        node.on_relay_frame("p1", relay(&live_sealed())).await;
        node.on_relay_frame("p2", relay(&live_sealed())).await;
        node.on_relay_frame("p1", relay(&live_sealed())).await;
        let s = node.relay_stats();
        assert_eq!(
            (s.accepted, s.dropped_rate),
            (2, 1),
            "one budget, two links"
        );

        node.relay_link_down("p1");
        node.relay_link_down("p2");
        node.relay_link_up("p1", them.clone(), "them".into());
        node.on_relay_frame("p1", relay(&live_sealed())).await;
        let s = node.relay_stats();
        assert_eq!(
            (s.accepted, s.dropped_rate),
            (2, 2),
            "reconnecting did not refill the budget"
        );

        let e = engine(&node);
        node.relay_link_down("p1");
        let now = Instant::now();
        e.state.lock().prune_neighbours(now);
        assert!(
            e.state.lock().neighbours.contains_key(&them),
            "not refilled yet"
        );
        e.state
            .lock()
            .prune_neighbours(now + std::time::Duration::from_secs(600));
        assert!(
            !e.state.lock().neighbours.contains_key(&them),
            "refilled: pruned"
        );

        for i in 0..(MAX_NEIGHBOURS + 10) {
            let inst = (i as u32).to_be_bytes().to_vec();
            node.relay_link_up("px", inst, "x".into());
            node.relay_link_down("px");
        }
        assert!(e.state.lock().neighbours.len() <= MAX_NEIGHBOURS);
        node.disable_relay();
    }

    /// D18, §R5.3: two links to one phone
    /// carry each envelope once: one push, one want, one answer; a receipt
    /// on one link marks the sibling as holding it.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_links_to_one_phone_carry_each_envelope_once() {
        let (node, sent) = relay_node(quiet());
        let them = vec![2; 32];
        node.relay_link_up("p1", them.clone(), "them".into());
        node.relay_link_up("p2", them.clone(), "them".into());
        node.relay_link_up("p3", vec![3; 32], "other".into());
        settle().await;
        sent.0.lock().clear();
        let is_relay = |b: &Body| matches!(b, Body::Relay(_));

        // Push: once to the two-link phone, once to the other.
        node.originate_random_for_test(100, 5);
        settle().await;
        assert_eq!(count(&frames_to(&sent, &["p1", "p2"]), is_relay), 1);
        assert_eq!(count(&frames_to(&sent, &["p3"]), is_relay), 1);

        // Digest: the same id offered on both links is asked for once.
        let id = vec![0xAB; 8];
        let digest = || {
            Body::SpoolDigest(SpoolDigest {
                ids: vec![id.clone()],
            })
        };
        sent.0.lock().clear();
        node.on_relay_frame("p1", digest()).await;
        node.on_relay_frame("p2", digest()).await;
        let wants = frames_to(&sent, &["p1", "p2"]);
        assert_eq!(count(&wants, |b| matches!(b, Body::SpoolWant(_))), 1);

        // Want: both links ask for one entry; it is sent once.
        let sealed = live_sealed();
        let hash = envelope::hash(&sealed);
        node.inner
            .store
            .lock()
            .spool_insert(&crate::store::SpoolEntry {
                hash: hash.to_vec(),
                sealed,
                ttl: 3,
                drop_at: now_secs() + 60,
                from_installation: vec![9; 32],
            })
            .unwrap();
        let want = || {
            Body::SpoolWant(SpoolWant {
                ids: vec![short_id(&hash).to_vec()],
            })
        };
        sent.0.lock().clear();
        node.on_relay_frame("p1", want()).await;
        node.on_relay_frame("p2", want()).await;
        assert_eq!(count(&frames_to(&sent, &["p1", "p2"]), is_relay), 1);

        // Receipt on p1: p2 is known to hold it too.
        let incoming = live_sealed();
        node.on_relay_frame("p1", relay(&incoming)).await;
        let short = short_id(&envelope::hash(&incoming));
        assert!(
            engine(&node).state.lock().links["p2"]
                .holds
                .contains(&short)
        );
        node.disable_relay();
    }

    /// A peer without a registered relay link
    /// gets no answer to a digest or a want.
    #[tokio::test(flavor = "multi_thread")]
    async fn frames_from_a_peer_without_a_relay_link_are_ignored() {
        let (node, sent) = relay_node(quiet());
        let hash = node.originate_random_for_test(100, 5);
        settle().await;
        sent.0.lock().clear();
        node.on_relay_frame(
            "stranger",
            Body::SpoolDigest(SpoolDigest {
                ids: vec![vec![0xCD; 8]],
            }),
        )
        .await;
        node.on_relay_frame(
            "stranger",
            Body::SpoolWant(SpoolWant {
                ids: vec![hash[..8].to_vec()],
            }),
        )
        .await;
        assert!(sent.0.lock().is_empty(), "no SpoolWant, no Relay");
        node.disable_relay();
    }

    fn offered_keys(sent: &Sent, peer: &str) -> Vec<[u8; 32]> {
        frames_to(sent, &[peer])
            .into_iter()
            .filter_map(|b| match b {
                Body::RelayKeyOffer(o) => Some(
                    unwrap_key(&[7; 32], &o.group_id, o.epoch, &o.nonce, &o.ciphertext).unwrap(),
                ),
                _ => None,
            })
            .collect()
    }

    /// §R4.5: a key confirmed by the other
    /// member's old installation is offered, unchanged, to its new one; the
    /// new confirmation resets the peer ack. A sequencer re-pin unconfirms
    /// the key, so it is offered again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reinstalled_member_is_offered_the_same_key() {
        let (node, sent) = relay_node(quiet());
        let (old, new) = (vec![2; 32], vec![3; 32]);
        {
            let mut store = node.inner.store.lock();
            store.confirm_relay_key(GID, &[9; 32], &old).unwrap();
            store.note_peer_acked_high(GID, 5).unwrap();
        }
        node.relay_link_up("p_old", old.clone(), "them".into());
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(offered_keys(&sent, "p_old").is_empty(), "confirmed by it");

        node.relay_link_up("p_new", new.clone(), "them".into());
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        while offered_keys(&sent, "p_new").is_empty() {
            assert!(Instant::now() < deadline, "offer to the new installation");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(offered_keys(&sent, "p_new"), vec![[9; 32]], "the same key");
        node.on_relay_frame(
            "p_new",
            Body::RelayKeyAck(RelayKeyAck {
                group_id: GID.to_vec(),
            }),
        )
        .await;
        {
            let mut store = node.inner.store.lock();
            assert_eq!(
                store.relay_key_confirmed_by(GID).unwrap(),
                Some(new.clone())
            );
            assert_eq!(store.peer_acked_high(GID).unwrap(), 0, "ack starts over");
        }

        // Re-pin (handover back to us): unconfirmed, so offered again.
        node.inner
            .store
            .lock()
            .repin_sequencer(GID, &[1; 32])
            .unwrap();
        sent.0.lock().clear();
        node.relay_link_up("p_new", new, "them".into());
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        while offered_keys(&sent, "p_new").is_empty() {
            assert!(Instant::now() < deadline, "offer after a re-pin");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(offered_keys(&sent, "p_new"), vec![[9; 32]]);
        node.disable_relay();
    }

    /// A direct peer's claimed high is clamped to the
    /// rows we hold.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_high_is_clamped_to_what_we_hold() {
        let node = MeshNode::in_memory().unwrap();
        node.relay_note_peer_high(GID, 1000);
        assert_eq!(node.inner.store.lock().peer_acked_high(GID).unwrap(), 0);
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
            state: Mutex::new(EngineState::new(&cfg, now)),
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
