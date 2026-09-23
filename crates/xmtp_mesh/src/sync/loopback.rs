use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::Mutex;

use super::transport::{MeshTransport, PeerId};
use crate::MeshNode;

/// In-process stand-in for the BLE radio. Links are bidirectional and
/// deliver frames in order.
#[derive(Clone, Default)]
pub struct LoopbackHub {
    inner: Arc<Mutex<HubInner>>,
}

#[derive(Default)]
struct HubInner {
    nodes: HashMap<PeerId, MeshNode>,
    links: HashSet<(PeerId, PeerId)>,
}

fn key(a: &str, b: &str) -> (PeerId, PeerId) {
    if a < b { (a.into(), b.into()) } else { (b.into(), a.into()) }
}

impl LoopbackHub {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, name: &str, node: &MeshNode) {
        self.inner.lock().nodes.insert(name.into(), node.clone());
    }

    pub fn transport_for(&self, name: &str) -> Arc<dyn MeshTransport> {
        Arc::new(LoopbackTransport { hub: self.clone(), me: name.into() })
    }

    pub fn link(&self, a: &str, b: &str) {
        let (na, nb) = {
            let mut inner = self.inner.lock();
            inner.links.insert(key(a, b));
            (inner.nodes[a].clone(), inner.nodes[b].clone())
        };
        na.on_peer_connected(b);
        nb.on_peer_connected(a);
    }

    pub fn unlink(&self, a: &str, b: &str) {
        let nodes = {
            let mut inner = self.inner.lock();
            if !inner.links.remove(&key(a, b)) {
                return;
            }
            (inner.nodes.get(a).cloned(), inner.nodes.get(b).cloned())
        };
        if let Some(n) = nodes.0 {
            n.on_peer_lost(b);
        }
        if let Some(n) = nodes.1 {
            n.on_peer_lost(a);
        }
    }

    /// Whether `a` and `b` are currently linked (a disconnect unlinks them).
    pub fn is_linked(&self, a: &str, b: &str) -> bool {
        self.inner.lock().links.contains(&key(a, b))
    }

    /// Deliver a raw frame as if `from` sent it, ignoring links (tests only).
    pub fn inject(&self, from: &str, to: &str, frame: Vec<u8>) {
        let node = self.inner.lock().nodes.get(to).cloned();
        if let Some(node) = node {
            node.on_frame(from, frame);
        }
    }

    fn deliver(&self, from: &str, to: &str, frame: Vec<u8>) {
        let node = {
            let inner = self.inner.lock();
            if !inner.links.contains(&key(from, to)) {
                return;
            }
            inner.nodes.get(to).cloned()
        };
        if let Some(node) = node {
            node.on_frame(from, frame);
        }
    }
}

struct LoopbackTransport {
    hub: LoopbackHub,
    me: PeerId,
}

impl MeshTransport for LoopbackTransport {
    fn send(&self, peer: &PeerId, frame: Vec<u8>) {
        self.hub.deliver(&self.me, peer, frame);
    }
    fn disconnect(&self, peer: &PeerId) {
        self.hub.unlink(&self.me, peer);
    }
}
