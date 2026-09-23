use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use tokio::sync::mpsc;

use super::transport::{MeshTransport, PeerId};
use crate::MeshNode;

/// How long a dropped link stays down before the hub re-links it.
const RELINK_AFTER: Duration = Duration::from_millis(500);

/// Timing and loss model for a [`LoopbackHub`] link, roughly shaped like BLE.
/// While a link is up it stays reliable and ordered; degradation comes only
/// from delay and from whole-link drops.
#[derive(Clone, Debug, PartialEq)]
pub struct LinkProfile {
    pub bytes_per_sec: u32,
    pub latency_ms: u64,
    pub jitter_ms: u64,
    /// Chance, per frame, that the frame kills the whole link instead of arriving.
    pub drop_link_per_frame: f64,
    pub seed: u64,
}

impl LinkProfile {
    pub fn ble_1m() -> Self {
        Self {
            bytes_per_sec: 20_000,
            latency_ms: 30,
            jitter_ms: 20,
            drop_link_per_frame: 0.0,
            seed: 1,
        }
    }

    pub fn ble_flaky() -> Self {
        Self {
            drop_link_per_frame: 0.02,
            ..Self::ble_1m()
        }
    }
}

/// In-process stand-in for the BLE radio. Links are bidirectional and
/// deliver frames in order: instantly with [`LoopbackHub::new`], or delayed
/// and occasionally dropped per a [`LinkProfile`] with [`LoopbackHub::with_profile`].
#[derive(Clone, Default)]
pub struct LoopbackHub {
    inner: Arc<Mutex<HubInner>>,
}

#[derive(Default)]
struct HubInner {
    nodes: HashMap<PeerId, MeshNode>,
    /// Live links, keyed by unordered pair, with the generation of this link-up.
    links: HashMap<(PeerId, PeerId), u64>,
    next_generation: u64,
    sim: Option<Sim>,
}

struct Sim {
    profile: LinkProfile,
    rng: StdRng,
    /// One FIFO per directed link `(from, to)`, drained by its own task.
    queues: HashMap<(PeerId, PeerId), mpsc::UnboundedSender<Queued>>,
    /// Automatic re-links waiting to fire, by unordered pair. An explicit
    /// `link`/`unlink` removes the entry, which cancels the re-link.
    pending_relinks: HashMap<(PeerId, PeerId), u64>,
    next_relink: u64,
    link_drops: u64,
}

struct Queued {
    generation: u64,
    frame: Vec<u8>,
    /// `latency + jitter + len / rate`, drawn at enqueue time.
    delay: Duration,
    drops_link: bool,
}

fn key(a: &str, b: &str) -> (PeerId, PeerId) {
    if a < b {
        (a.into(), b.into())
    } else {
        (b.into(), a.into())
    }
}

impl LoopbackHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// A hub whose links behave per `profile`. Timing draws come from an
    /// `StdRng` seeded with `profile.seed`; tokio scheduling still varies
    /// between runs, so only outcomes (not timings) are reproducible.
    ///
    /// Panics unless `drop_link_per_frame` is in `[0.0, 1.0]` (NaN rejected)
    /// and `bytes_per_sec > 0`.
    pub fn with_profile(profile: LinkProfile) -> Self {
        assert!(
            (0.0..=1.0).contains(&profile.drop_link_per_frame),
            "drop_link_per_frame must be in [0.0, 1.0], got {}",
            profile.drop_link_per_frame
        );
        assert!(profile.bytes_per_sec > 0, "bytes_per_sec must be > 0");
        let sim = Sim {
            rng: StdRng::seed_from_u64(profile.seed),
            profile,
            queues: HashMap::new(),
            pending_relinks: HashMap::new(),
            next_relink: 0,
            link_drops: 0,
        };
        let hub = Self::default();
        hub.inner.lock().sim = Some(sim);
        hub
    }

    pub fn register(&self, name: &str, node: &MeshNode) {
        self.inner.lock().nodes.insert(name.into(), node.clone());
    }

    pub fn transport_for(&self, name: &str) -> Arc<dyn MeshTransport> {
        Arc::new(LoopbackTransport {
            hub: self.clone(),
            me: name.into(),
        })
    }

    pub fn link(&self, a: &str, b: &str) {
        let (na, nb) = {
            let mut inner = self.inner.lock();
            if let Some(sim) = inner.sim.as_mut() {
                sim.pending_relinks.remove(&key(a, b));
            }
            inner.link_up(a, b);
            (inner.nodes[a].clone(), inner.nodes[b].clone())
        };
        na.on_peer_connected(b);
        nb.on_peer_connected(a);
    }

    pub fn unlink(&self, a: &str, b: &str) {
        let nodes = {
            let mut inner = self.inner.lock();
            // Also when already down: an explicit unlink keeps the pair apart.
            if let Some(sim) = inner.sim.as_mut() {
                sim.pending_relinks.remove(&key(a, b));
            }
            if !inner.link_down(a, b) {
                return;
            }
            (inner.nodes.get(a).cloned(), inner.nodes.get(b).cloned())
        };
        notify_lost(nodes, a, b);
    }

    /// Whether `a` and `b` are currently linked (a disconnect unlinks them).
    pub fn is_linked(&self, a: &str, b: &str) -> bool {
        self.inner.lock().links.contains_key(&key(a, b))
    }

    #[cfg(any(test, feature = "test-utils"))]
    /// Simulated link drops so far (0 without a profile).
    #[doc(hidden)]
    pub fn link_drops_for_test(&self) -> u64 {
        self.inner
            .lock()
            .sim
            .as_ref()
            .map_or(0, |sim| sim.link_drops)
    }

    #[cfg(any(test, feature = "test-utils"))]
    /// Deliver a raw frame as if `from` sent it, ignoring links (tests only).
    pub fn inject(&self, from: &str, to: &str, frame: Vec<u8>) {
        let node = self.inner.lock().nodes.get(to).cloned();
        if let Some(node) = node {
            node.on_frame(from, frame);
        }
    }

    fn send(&self, from: &str, to: &str, frame: Vec<u8>) {
        let node = {
            let mut inner = self.inner.lock();
            let Some(&generation) = inner.links.get(&key(from, to)) else {
                return;
            };
            match inner.sim.as_mut() {
                Some(sim) => {
                    sim.enqueue(self, from, to, generation, frame);
                    return;
                }
                None => inner.nodes.get(to).cloned(),
            }
        };
        if let Some(node) = node {
            node.on_frame(from, frame);
        }
    }

    /// Deliver a frame that waited in the `(from, to)` queue, unless the link
    /// it was sent on has since gone down (or been replaced by a new link-up).
    fn deliver_queued(&self, from: &str, to: &str, generation: u64, frame: Vec<u8>) {
        let node = {
            let inner = self.inner.lock();
            if !inner.is_current(from, to, generation) {
                return;
            }
            inner.nodes.get(to).cloned()
        };
        if let Some(node) = node {
            node.on_frame(from, frame);
        }
    }

    /// The link carrying `generation` drops: unlink now, re-link after
    /// `RELINK_AFTER` unless someone links or unlinks the pair explicitly first.
    fn drop_link(&self, from: &str, to: &str, generation: u64) {
        let (nodes, token) = {
            let mut inner = self.inner.lock();
            if !inner.is_current(from, to, generation) {
                return;
            }
            inner.link_down(from, to);
            let sim = inner.sim.as_mut().expect("only simulated links drop");
            let token = sim.next_relink;
            sim.next_relink += 1;
            sim.link_drops += 1;
            sim.pending_relinks.insert(key(from, to), token);
            (
                (inner.nodes.get(from).cloned(), inner.nodes.get(to).cloned()),
                token,
            )
        };
        tracing::debug!(from, to, "loopback: simulated link drop");
        notify_lost(nodes, from, to);

        let hub = self.clone();
        let (from, to) = (from.to_string(), to.to_string());
        tokio::spawn(async move {
            tokio::time::sleep(RELINK_AFTER).await;
            let (nf, nt) = {
                let mut inner = hub.inner.lock();
                let pair = key(&from, &to);
                let sim = inner.sim.as_mut().expect("simulated hub");
                if sim.pending_relinks.get(&pair) != Some(&token) {
                    return; // cancelled by an explicit link/unlink
                }
                sim.pending_relinks.remove(&pair);
                inner.link_up(&from, &to);
                (inner.nodes[&from].clone(), inner.nodes[&to].clone())
            };
            tracing::debug!(from, to, "loopback: simulated re-link");
            nf.on_peer_connected(&to);
            nt.on_peer_connected(&from);
        });
    }
}

impl HubInner {
    /// Bring the pair's link up; a link that is already up keeps its generation.
    fn link_up(&mut self, a: &str, b: &str) {
        if !self.links.contains_key(&key(a, b)) {
            self.next_generation += 1;
            self.links.insert(key(a, b), self.next_generation);
        }
    }

    /// Take the pair's link down, discarding both directed queues. Returns
    /// whether it was up.
    fn link_down(&mut self, a: &str, b: &str) -> bool {
        if let Some(sim) = self.sim.as_mut() {
            // Dropping the senders lets each queue's task drain and exit; the
            // generation check keeps whatever it still holds from arriving.
            sim.queues.remove(&(a.into(), b.into()));
            sim.queues.remove(&(b.into(), a.into()));
        }
        self.links.remove(&key(a, b)).is_some()
    }

    fn is_current(&self, a: &str, b: &str, generation: u64) -> bool {
        self.links.get(&key(a, b)) == Some(&generation)
    }
}

impl Sim {
    fn enqueue(
        &mut self,
        hub: &LoopbackHub,
        from: &str,
        to: &str,
        generation: u64,
        frame: Vec<u8>,
    ) {
        let p = &self.profile;
        let jitter = if p.jitter_ms == 0 {
            0
        } else {
            self.rng.random_range(0..=p.jitter_ms)
        };
        let transmit_ms = frame.len() as u64 * 1000 / u64::from(p.bytes_per_sec);
        let queued = Queued {
            generation,
            delay: Duration::from_millis(p.latency_ms + jitter + transmit_ms),
            drops_link: p.drop_link_per_frame > 0.0 && self.rng.random_bool(p.drop_link_per_frame),
            frame,
        };
        let tx = self
            .queues
            .entry((from.into(), to.into()))
            .or_insert_with(|| {
                let (tx, rx) = mpsc::unbounded_channel();
                tokio::spawn(run_link(hub.clone(), from.into(), to.into(), rx));
                tx
            });
        let _ = tx.send(queued);
    }
}

/// Drains one directed link's FIFO: each frame in turn waits its own
/// `latency + jitter + len * 1000 / bytes_per_sec` ms and is then delivered
/// (or drops the link). Frames are handled one at a time, so delays add up
/// along the queue and order is kept.
async fn run_link(
    hub: LoopbackHub,
    from: PeerId,
    to: PeerId,
    mut rx: mpsc::UnboundedReceiver<Queued>,
) {
    while let Some(q) = rx.recv().await {
        if !hub.inner.lock().is_current(&from, &to, q.generation) {
            continue; // the link it was queued on is gone
        }
        tokio::time::sleep(q.delay).await;
        if q.drops_link {
            hub.drop_link(&from, &to, q.generation);
        } else {
            hub.deliver_queued(&from, &to, q.generation, q.frame);
        }
    }
}

fn notify_lost(nodes: (Option<MeshNode>, Option<MeshNode>), a: &str, b: &str) {
    if let Some(n) = nodes.0 {
        n.on_peer_lost(b);
    }
    if let Some(n) = nodes.1 {
        n.on_peer_lost(a);
    }
}

struct LoopbackTransport {
    hub: LoopbackHub,
    me: PeerId,
}

impl MeshTransport for LoopbackTransport {
    fn send(&self, peer: &PeerId, frame: Vec<u8>) {
        self.hub.send(&self.me, peer, frame);
    }
    fn disconnect(&self, peer: &PeerId) {
        self.hub.unlink(&self.me, peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every frame kills the link; no latency, so timing is transmit time only
    /// (`len / 20` ms at 20 kB/s).
    fn always_drops() -> LinkProfile {
        LinkProfile {
            drop_link_per_frame: 1.0,
            latency_ms: 0,
            jitter_ms: 0,
            ..LinkProfile::ble_1m()
        }
    }

    /// `a` and `b` registered but not syncing, so link events are inert.
    fn hub_with_two(profile: LinkProfile) -> LoopbackHub {
        let hub = LoopbackHub::with_profile(profile);
        hub.register("a", &MeshNode::in_memory().unwrap());
        hub.register("b", &MeshNode::in_memory().unwrap());
        hub
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn ble_profiles_match_spec() {
        assert_eq!(
            LinkProfile::ble_1m(),
            LinkProfile {
                bytes_per_sec: 20_000,
                latency_ms: 30,
                jitter_ms: 20,
                drop_link_per_frame: 0.0,
                seed: 1
            }
        );
        assert_eq!(
            LinkProfile::ble_flaky(),
            LinkProfile {
                drop_link_per_frame: 0.02,
                ..LinkProfile::ble_1m()
            }
        );
    }

    #[tokio::test]
    async fn dropped_link_relinks_after_500ms() {
        let hub = hub_with_two(always_drops());
        hub.link("a", "b");
        hub.transport_for("a").send(&"b".into(), vec![0; 10]);
        tokio::time::sleep(ms(200)).await;
        assert!(!hub.is_linked("a", "b"));
        assert_eq!(hub.link_drops_for_test(), 1);
        tokio::time::sleep(ms(600)).await;
        assert!(hub.is_linked("a", "b"));
    }

    #[test]
    #[should_panic(expected = "drop_link_per_frame")]
    fn nan_drop_rate_is_rejected() {
        LoopbackHub::with_profile(LinkProfile {
            drop_link_per_frame: f64::NAN,
            ..LinkProfile::ble_1m()
        });
    }

    #[test]
    #[should_panic(expected = "drop_link_per_frame")]
    fn drop_rate_above_one_is_rejected() {
        LoopbackHub::with_profile(LinkProfile {
            drop_link_per_frame: 1.5,
            ..LinkProfile::ble_1m()
        });
    }

    #[test]
    #[should_panic(expected = "bytes_per_sec")]
    fn zero_rate_is_rejected() {
        LoopbackHub::with_profile(LinkProfile {
            bytes_per_sec: 0,
            ..LinkProfile::ble_1m()
        });
    }

    #[tokio::test]
    async fn explicit_unlink_cancels_pending_relink() {
        let hub = hub_with_two(always_drops());
        hub.link("a", "b");
        hub.transport_for("a").send(&"b".into(), vec![0; 10]);
        tokio::time::sleep(ms(200)).await;
        assert!(!hub.is_linked("a", "b"));
        hub.unlink("a", "b");
        tokio::time::sleep(ms(1000)).await;
        assert!(!hub.is_linked("a", "b"));
    }

    #[tokio::test]
    async fn frame_in_flight_across_a_relink_is_discarded() {
        // A 10 kB frame takes 500 ms to transmit. Cut and restore the link
        // while it is in flight: it belongs to the old link, so it must not
        // arrive on (and here, drop) the new one.
        let hub = hub_with_two(always_drops());
        hub.link("a", "b");
        hub.transport_for("a").send(&"b".into(), vec![0; 10_000]);
        tokio::time::sleep(ms(100)).await;
        hub.unlink("a", "b");
        hub.link("a", "b");
        tokio::time::sleep(ms(800)).await;
        assert!(hub.is_linked("a", "b"));
    }
}
