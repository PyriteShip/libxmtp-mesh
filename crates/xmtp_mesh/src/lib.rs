//! Serverless XMTP: an in-process v3 node synced peer-to-peer.
//!
//! # Group-traffic scoping (DESIGN.md §B5.2, Rule A)
//!
//! A node cannot map a welcome to a group id (the group id is inside the
//! encrypted welcome), and delivering a welcome proves nothing about who
//! belongs to which group. Sync sessions therefore scope all group traffic by
//! the group's membership as the local libxmtp client sees it
//! ([`GroupMembership`]; production: [`ClientGroupMembership`], the member
//! inbox ids of the group in the client's database). A verified peer counts as
//! a member of a group only if the inbox it proved (its installation is in
//! that inbox's identity log) is one of the group's members and is not our own
//! inbox. Then:
//!
//! - a sequencer claim (`Interest.i_am_sequencer`, `Sequenced.sender_is_sequencer`)
//!   is pinned, trust-on-first-use, only from a member;
//! - a group is announced (`Interest`) only to members, and only while it is
//!   unpinned or pinned to us or to that peer;
//! - as sequencer we serve history, push new rows and accept `Pending`
//!   messages only for members; our own pending messages go only to a member
//!   sequencer.
//!
//! So a verified stranger (anyone can create an inbox offline), even one that
//! delivered us a welcome, learns no group ids, cannot pin itself as a
//! sequencer, cannot get junk sequenced and cannot pull ciphertext history.
//!
//! Liveness: a joiner's node may hear from the sequencer before its client
//! has processed the welcome (membership unknown), and a creator's node may
//! hear from the joiner before its client merged the commit that added it.
//! Such frames are not acted on; the session remembers what was asked and
//! re-checks membership every 500 ms for up to a minute, when the group
//! becomes known to the client (`GroupKnown`), and on every later frame about
//! the group, then acts on it (pin, serve, flush or announce). Membership
//! lookups run on the session task with no store lock held.
//!
//! # Multi-hop relay (DESIGN.md Part R)
//!
//! Off unless [`MeshNode::enable_relay`] is called after `start_sync`. Each
//! node keeps a bounded spool of sealed envelopes and floods it to relay
//! neighbours (digest on connect, delayed split-horizon pushes, per-neighbour
//! rate and share limits). An envelope shows relays only a per-envelope tag,
//! a coarse expiry, a TTL and a padded size: it hardens linkability, it does
//! not give anonymity (no cover traffic). DM traffic is sealed under a per-DM relay
//! key that the sequencer hands the joiner over a direct link, encrypted
//! under the MLS exporter secret. Relay frames are never fatal to a session.
//! Not protest-safe until rotating-token discovery and Noise ship: `Hello`
//! still carries the inbox id in the clear, and spool digests are readable.
//!
//! Limits are per neighbour phone (keyed by its verified installation key),
//! shared across all of that phone's links, not per link. The tag is
//! per envelope, not per DM: `expires_at` is coarse (600 s buckets plus
//! random jitter), so two envelopes of one DM share no visible bytes and
//! nothing in the header says how many envelopes a DM has sent. A
//! neighbour's share of the spool is capped by entry count (25% of
//! entries); its bytes are bounded separately, by its per-neighbour byte
//! rate, not by the share. The share is not a hard admission refusal: once
//! a neighbour is at its share, a newcomer envelope from that neighbour
//! evicts that neighbour's own soonest-drop entry (newest wins), so a
//! burst of relayed spam cannot lock the neighbour's slot and starve its
//! later honest traffic. Rate buckets (envelope and byte) still bound how
//! fast a neighbour can push, independent of the share. An envelope
//! addressed to this node is delivered even when the rate or share limit
//! kept it out of the spool, as long as it is still live (not expired) and
//! has not been seen before; it is then marked seen so a replay is a no-op,
//! but it is never stored in the spool or pushed onward. Known limit:
//! honest traffic relayed through a phone that also forwards spam competes
//! with that spam inside that phone's share, at phones that are not the
//! message's recipient; this is Sybil-cheap like the rest of the relay
//! limits (N radios get N budgets) and relationship-tiered shares are the
//! planned phase-2 mitigation.
//!
//! The DM relay protocol (`RelayPending`/`RelaySync`) retries on a fixed
//! schedule and acks only on progress or when the sequencer's ack looks
//! stale (e.g. a lost pure ack), never as a ping-pong. A joiner that cannot
//! resolve a `Ref` against its local store asks the sequencer for sealed
//! `Full` rows instead (`need_full_after`). Lag across a peer's own multiple
//! installations is out of scope here, per D7. An answer that a
//! delivery triggers waits a random 2–10 s (`answer_delay_ms`): this blurs,
//! but does not remove, what a phone next to the recipient can see (an
//! envelope going in, a fresh one coming out). A DM whose last direct link
//! drops falls back to relay, and enabling relay schedules every relayed
//! DM, so nothing waits for new content. The relay key is re-offered (the
//! same key) when the other member's installation changes or the
//! sequencer is re-pinned. The seen-set is capped by entry count
//! (`max_seen`); its entries expire with the envelope's own expiry.
mod error;
pub mod link;
mod mls_parse;
pub mod node;
mod relay;
pub mod store;
pub mod sync;
mod verifier;

pub use error::MeshError;
pub use link::{AdvertMatch, AdvertState, LinkKeyInfo, LinkKind};
pub use node::{MeshNode, MeshStream, NodeEvent, Resolution, ResyncOutcome, VerifiedPeer};
pub use relay::{ClientRelayExporter, RelayConfig, RelayExporter, RelayStats};
pub use store::{
    Contact, ContactUpdate, InsertOutcome, MeshStore, NewGroupMessage, StoredGroupMessage,
    StoredWelcome,
};
pub use sync::frames::MAX_FRAME_LEN;
pub use sync::seq::{Equivocation, MeshStats, SeqProof, SeqRecord, SeqReject};
pub use sync::{
    ClientGroupMembership, ClientHelloSigner, GroupMembership, HelloSigner, LinkOp, LinkProfile,
    LoopbackHub, MeshTransport, PeerId, churn_schedule, frames, random_topology,
};
pub use verifier::EoaOnlyVerifier;
