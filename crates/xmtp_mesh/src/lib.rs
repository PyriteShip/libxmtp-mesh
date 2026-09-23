//! Serverless XMTP: an in-process v3 node synced peer-to-peer.
//!
//! # Group-traffic scoping (spec §5, Rule A)
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
mod error;
mod mls_parse;
pub mod node;
pub mod store;
pub mod sync;
mod verifier;

pub use error::MeshError;
pub use node::{MeshNode, MeshStream, NodeEvent, VerifiedPeer};
pub use store::{InsertOutcome, MeshStore, NewGroupMessage, StoredGroupMessage, StoredWelcome};
pub use sync::frames::MAX_FRAME_LEN;
pub use sync::{
    ClientGroupMembership, ClientHelloSigner, GroupMembership, HelloSigner, LinkProfile,
    LoopbackHub, MeshTransport, PeerId, frames,
};
pub use verifier::EoaOnlyVerifier;
