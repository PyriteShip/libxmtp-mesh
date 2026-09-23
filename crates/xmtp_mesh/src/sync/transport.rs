/// Opaque, radio-assigned id for a connected peer.
pub type PeerId = String;

/// A reliable, ordered byte pipe per peer. The radio (BLE in sub-project 2)
/// does chunking and reassembly; the node always sends whole frames.
pub trait MeshTransport: Send + Sync {
    fn send(&self, peer: &PeerId, frame: Vec<u8>);
    fn disconnect(&self, peer: &PeerId);
}
