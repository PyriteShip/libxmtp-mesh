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
/// - `send` and `disconnect` must never call back into the node
///   synchronously (no `on_frame`, `on_peer_lost` or any other node call
///   from inside them): the node calls them while holding its locks, so a
///   re-entrant call can deadlock. Queue the work and report it from the
///   radio's own thread.
///
/// A session that does not authenticate its peer within the handshake
/// deadline (15 s) is disconnected, and so is a relay link that brings no
/// new relayed envelope for a minute, or that reached its 10-minute
/// lifetime, so stray frames, devices that never speak the protocol and
/// strangers cannot hold a session (or a radio slot) forever. The node
/// reports each open link's kind (`MeshNode::link_kind`) so the radio can
/// keep slots for contacts.
///
/// A radio that reuses a `PeerId` for the same device (only the test hub
/// does) also gets a short back-off after a stranger's relay link closes;
/// with fresh ids it never matches, so it is best effort, not a bound.
///
/// [`LoopbackHub`](super::LoopbackHub) reuses node names as `PeerId`s across
/// re-links for test readability; the node tolerates that (a re-link starts a
/// fresh session), but real transports must not rely on it.
pub trait MeshTransport: Send + Sync {
    fn send(&self, peer: &PeerId, frame: Vec<u8>);
    fn disconnect(&self, peer: &PeerId);
}
