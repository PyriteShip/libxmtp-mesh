use prost::Message;
use xmtp_proto::mls_v1::{
    GroupMessage, GroupMessageInput, WelcomeMessageInput, group_message, group_message_input,
};
use xmtp_proto::xmtp::identity::api::v1::get_identity_updates_response::IdentityUpdateLog;

use crate::MeshError;

pub const FRAME_VERSION: u32 = 1;

/// Largest encoded frame a node sends or accepts.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// A list-bearing frame (`Sequenced`, `Pending`) carries at most this many
/// messages...
pub(crate) const MAX_MESSAGES_PER_FRAME: usize = 64;
/// ...and at most this much message data, except that a single larger
/// message goes alone (it still has to fit in [`MAX_FRAME_LEN`]).
pub(crate) const MAX_MESSAGE_BYTES_PER_FRAME: usize = 128 * 1024;

/// Split `items` (in order) into frame-sized pages, `size` giving each item's
/// message data length. Never returns an empty page.
pub(crate) fn pages<T>(items: Vec<T>, size: impl Fn(&T) -> usize) -> Vec<Vec<T>> {
    let mut pages = Vec::new();
    let mut page: Vec<T> = Vec::new();
    let mut bytes = 0;
    for item in items {
        let n = size(&item);
        if !page.is_empty()
            && (page.len() == MAX_MESSAGES_PER_FRAME || bytes + n > MAX_MESSAGE_BYTES_PER_FRAME)
        {
            pages.push(std::mem::take(&mut page));
            bytes = 0;
        }
        bytes += n;
        page.push(item);
    }
    if !page.is_empty() {
        pages.push(page);
    }
    pages
}

/// Encoded length of the larger of the two frames that carry `input` alone
/// for `group_id`: `Pending` (to the sequencer) and `Sequenced` (from it,
/// with worst-case id and timestamp). A message for which this exceeds
/// [`MAX_FRAME_LEN`] could never be synced.
pub(crate) fn single_message_frame_len(group_id: &[u8], input: &group_message_input::V1) -> usize {
    let frame_len = |body| {
        Frame {
            version: FRAME_VERSION,
            ttl: 0,
            hops: 0,
            body: Some(body),
        }
        .encoded_len()
    };
    let pending = frame_len(frame::Body::Pending(Pending {
        group_id: group_id.to_vec(),
        messages: vec![GroupMessageInput {
            version: Some(group_message_input::Version::V1(input.clone())),
        }],
    }));
    let sequenced = frame_len(frame::Body::Sequenced(Sequenced {
        group_id: group_id.to_vec(),
        messages: vec![GroupMessage {
            version: Some(group_message::Version::V1(group_message::V1 {
                id: u64::MAX,
                created_ns: u64::MAX,
                group_id: group_id.to_vec(),
                data: input.data.clone(),
                sender_hmac: input.sender_hmac.clone(),
                should_push: true,
                is_commit: true,
            })),
        }],
        sender_is_sequencer: true,
    }));
    pending.max(sequenced)
}

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
    Frame {
        version: FRAME_VERSION,
        ttl: 0,
        hops: 0,
        body: Some(body),
    }
    .encode_to_vec()
}

pub fn decode(bytes: &[u8]) -> Result<frame::Body, MeshError> {
    if bytes.len() > MAX_FRAME_LEN {
        return Err(MeshError::InvalidRequest(format!(
            "frame of {} bytes exceeds {MAX_FRAME_LEN}",
            bytes.len()
        )));
    }
    let frame = Frame::decode(bytes)?;
    if frame.version != FRAME_VERSION {
        return Err(MeshError::InvalidRequest(format!(
            "unsupported frame version {}",
            frame.version
        )));
    }
    frame
        .body
        .ok_or_else(|| MeshError::InvalidRequest("empty frame".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lens(pages: &[Vec<usize>]) -> Vec<usize> {
        pages.iter().map(Vec::len).collect()
    }

    #[test]
    fn pages_hold_at_most_64_messages() {
        let pages = pages(vec![10usize; 200], |n| *n);
        assert_eq!(lens(&pages), vec![64, 64, 64, 8]);
        assert!(super::pages(Vec::<usize>::new(), |n| *n).is_empty());
    }

    #[test]
    fn pages_hold_at_most_128_kib_but_a_large_message_goes_alone() {
        let kib = 1024;
        let pages = pages(
            vec![50 * kib, 50 * kib, 50 * kib, 200 * kib, 10 * kib],
            |n| *n,
        );
        assert_eq!(
            pages,
            vec![
                vec![50 * kib, 50 * kib],
                vec![50 * kib],
                vec![200 * kib],
                vec![10 * kib]
            ]
        );
    }

    #[test]
    fn oversized_input_is_rejected() {
        let err = decode(&vec![0u8; MAX_FRAME_LEN + 1]).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }
}
