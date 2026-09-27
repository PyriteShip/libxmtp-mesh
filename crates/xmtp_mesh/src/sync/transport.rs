/// Opaque, radio-assigned id for one connection to a peer.
pub type PeerId = String;

/// The radio, as the node sees it (BLE in sub-project 2). The radio does
/// chunking and reassembly; the node always sends whole link messages: a
/// 128-byte handshake message 1, the other handshake messages, then sealed
/// records of at most 65 535 bytes (DESIGN.md §B14.3).
///
/// Contract a transport must keep:
/// - Each `PeerId` names ONE reliable, ordered byte pipe. Ids are
///   connection-scoped: a transport MUST use a fresh `PeerId` for every new
///   connection (for example `"<shortid>#<n>"`), even to the same device, and
///   never reuses an id after reporting `on_peer_lost` for it.
/// - `MeshNode::on_peer_connected(p, role)` means a new pipe `p` is up; the
///   node starts a fresh session for it (replacing any session it holds for
///   `p`). `role` says who dialed and what the dialer believes the other
///   phone is (`LinkRole`, DESIGN.md §B14.2). Report the accepting side's
///   `Accept` before the dialer can send on the pipe.
/// - `MeshNode::on_frame(p, ..)` delivers whole link messages in order. A
///   message may arrive just before `on_peer_connected(p)`; the node then
///   creates an accepting session on the first message, and a later
///   `on_peer_connected(p, Accept)` keeps it.
/// - `MeshNode::on_peer_lost(p)` means the pipe is gone.
/// - `send` must not block (queue and return); `disconnect` asks the radio to
///   drop the pipe and later report `on_peer_lost`.
///
/// A session that does not authenticate its peer within the handshake
/// deadline (15 s) is disconnected, and so is a relay link that carries no
/// relay frame for a minute, so stray frames, devices that never speak the
/// protocol and idle strangers cannot hold a session (or a radio slot)
/// forever.
///
/// [`LoopbackHub`](super::LoopbackHub) reuses node names as `PeerId`s across
/// re-links for test readability; the node tolerates that (a re-link starts a
/// fresh session), but real transports must not rely on it.
pub trait MeshTransport: Send + Sync {
    fn send(&self, peer: &PeerId, frame: Vec<u8>);
    fn disconnect(&self, peer: &PeerId);
}
