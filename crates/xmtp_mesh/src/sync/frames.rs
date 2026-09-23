use prost::Message;
use xmtp_proto::mls_v1::{GroupMessage, GroupMessageInput, WelcomeMessageInput};
use xmtp_proto::xmtp::identity::api::v1::get_identity_updates_response::IdentityUpdateLog;

use crate::MeshError;

pub const FRAME_VERSION: u32 = 1;

/// One unit on the wire between two mesh nodes. `ttl`/`hops` are reserved
/// for multi-hop relay and ignored in v1.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Frame {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(uint32, tag = "2")]
    pub ttl: u32,
    #[prost(uint32, tag = "3")]
    pub hops: u32,
    #[prost(oneof = "frame::Body", tags = "10, 11, 12, 13, 14, 15, 16, 17, 18")]
    pub body: Option<frame::Body>,
}

pub mod frame {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "10")]
        Hello(super::Hello),
        #[prost(message, tag = "11")]
        Auth(super::Auth),
        #[prost(message, tag = "12")]
        IdentityLog(super::IdentityLog),
        #[prost(message, tag = "13")]
        KeyPackage(super::KeyPackage),
        #[prost(message, tag = "14")]
        Welcome(super::Welcome),
        #[prost(message, tag = "15")]
        WelcomeAck(super::WelcomeAck),
        #[prost(message, tag = "16")]
        Interest(super::Interest),
        #[prost(message, tag = "17")]
        Sequenced(super::Sequenced),
        #[prost(message, tag = "18")]
        Pending(super::Pending),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Hello {
    #[prost(bytes = "vec", tag = "1")]
    pub installation_key: Vec<u8>,
    #[prost(string, tag = "2")]
    pub inbox_id: String,
    #[prost(bytes = "vec", tag = "3")]
    pub challenge: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Auth {
    #[prost(bytes = "vec", tag = "1")]
    pub signature: Vec<u8>,
    /// The verifier's challenge this answers (echoed from its Hello), so a
    /// stray Auth from a previous connection is ignored instead of failing.
    #[prost(bytes = "vec", tag = "2")]
    pub challenge: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct IdentityLog {
    #[prost(string, tag = "1")]
    pub inbox_id: String,
    #[prost(message, repeated, tag = "2")]
    pub updates: Vec<IdentityUpdateLog>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct KeyPackage {
    #[prost(bytes = "vec", tag = "1")]
    pub installation_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub key_package: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Welcome {
    #[prost(bytes = "vec", tag = "1")]
    pub envelope_hash: Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub input: Option<WelcomeMessageInput>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct WelcomeAck {
    #[prost(bytes = "vec", tag = "1")]
    pub envelope_hash: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Interest {
    #[prost(bytes = "vec", tag = "1")]
    pub group_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub high_id: u64,
    #[prost(bool, tag = "3")]
    pub i_am_sequencer: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Sequenced {
    #[prost(bytes = "vec", tag = "1")]
    pub group_id: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub messages: Vec<GroupMessage>,
    #[prost(bool, tag = "3")]
    pub sender_is_sequencer: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Pending {
    #[prost(bytes = "vec", tag = "1")]
    pub group_id: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub messages: Vec<GroupMessageInput>,
}

pub fn encode(body: frame::Body) -> Vec<u8> {
    Frame { version: FRAME_VERSION, ttl: 0, hops: 0, body: Some(body) }.encode_to_vec()
}

pub fn decode(bytes: &[u8]) -> Result<frame::Body, MeshError> {
    let frame = Frame::decode(bytes)?;
    if frame.version != FRAME_VERSION {
        return Err(MeshError::InvalidRequest(format!("unsupported frame version {}", frame.version)));
    }
    frame.body.ok_or_else(|| MeshError::InvalidRequest("empty frame".into()))
}
