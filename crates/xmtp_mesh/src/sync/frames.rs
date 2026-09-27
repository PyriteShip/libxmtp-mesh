use prost::Message;
use xmtp_proto::mls_v1::{
    GroupMessage, GroupMessageInput, WelcomeMessageInput, group_message, group_message_input,
};
use xmtp_proto::xmtp::identity::api::v1::get_identity_updates_response::IdentityUpdateLog;

use super::seq::SeqProof;
use crate::MeshError;

pub const FRAME_VERSION: u32 = 1;

/// Relay protocol version (§R5.2, §R7).
pub const RELAY_V1: u32 = 1;

/// Signed-sequencing version (§B13). A peer whose Hello says less is
/// refused: mesh.10 syncs only with mesh.10.
pub const SEQ_V1: u32 = 1;

/// Link version (§B14). A peer whose Hello says less is refused: mesh.11
/// talks only to mesh.11.
pub const LINK_V1: u32 = 1;

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

/// The `Sequenced` frame for one page of rows and their proofs, in order.
pub(crate) fn sequenced_frame(group_id: &[u8], page: Vec<(GroupMessage, SeqProof)>) -> Sequenced {
    let (messages, proofs) = page.into_iter().unzip();
    Sequenced {
        group_id: group_id.to_vec(),
        messages,
        sender_is_sequencer: true,
        proofs,
    }
}

/// Encoded length of the larger of the two frames that carry `input` alone
/// for `group_id`: `Pending` (to the sequencer) and `Sequenced` (from it,
/// with worst-case id, timestamp and proof). A message for which this exceeds
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
        // The largest proof a row carries (§B13): an attestation.
        proofs: vec![SeqProof {
            signer: vec![0; 32],
            signature: vec![0; 64],
            attested: true,
        }],
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
    #[prost(
        oneof = "frame::Body",
        tags = "10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25"
    )]
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
        /// Restore convergence (§C4.2): our log of `inbox_id` beats the one
        /// the peer sent or holds (earlier sequence-1 origin). Old nodes
        /// decode this as an empty frame and ignore it.
        #[prost(message, tag = "19")]
        IdentityConflict(super::IdentityLog),
        #[prost(message, tag = "20")]
        Relay(super::RelayEnvelope),
        #[prost(message, tag = "21")]
        SpoolDigest(super::SpoolDigest),
        #[prost(message, tag = "22")]
        SpoolWant(super::SpoolWant),
        #[prost(message, tag = "23")]
        RelayKeyOffer(super::RelayKeyOffer),
        #[prost(message, tag = "24")]
        RelayKeyAck(super::RelayKeyAck),
        /// A contact's discovery card (§B14.4). Contact and pairing links only.
        #[prost(message, tag = "25")]
        ContactCard(super::ContactCard),
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
    /// Relay protocol version the sender speaks (0: none; [`RELAY_V1`]).
    #[prost(uint32, tag = "4")]
    pub relay: u32,
    /// Signed-sequencing version the sender speaks (0: none; [`SEQ_V1`]).
    #[prost(uint32, tag = "5")]
    pub seq: u32,
    /// Link version the sender speaks (0: none; [`LINK_V1`]).
    #[prost(uint32, tag = "6")]
    pub link: u32,
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
    /// One sequencing proof per entry in `messages`, same order (§B13).
    #[prost(message, repeated, tag = "4")]
    pub proofs: Vec<SeqProof>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Pending {
    #[prost(bytes = "vec", tag = "1")]
    pub group_id: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub messages: Vec<GroupMessageInput>,
}

/// One relayed envelope (§R4.2). `ttl`/`copies` change per hop;
/// `sealed` is forwarded byte-for-byte and never re-encoded.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RelayEnvelope {
    #[prost(uint32, tag = "1")]
    pub ttl: u32,
    #[prost(uint32, tag = "2")]
    pub copies: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub sealed: Vec<u8>,
}

/// "What I hold": 8-byte envelope ids (§R5.2). Link-local, never relayed.
#[derive(Clone, PartialEq, prost::Message)]
pub struct SpoolDigest {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub ids: Vec<Vec<u8>>,
}

/// The ids from a peer's digest that we lack. Link-local, never relayed.
#[derive(Clone, PartialEq, prost::Message)]
pub struct SpoolWant {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub ids: Vec<Vec<u8>>,
}

/// The DM sequencer's relay key, encrypted under the exporter secret at
/// `epoch` (§R4.5). Direct links only.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RelayKeyOffer {
    #[prost(bytes = "vec", tag = "1")]
    pub group_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub epoch: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RelayKeyAck {
    #[prost(bytes = "vec", tag = "1")]
    pub group_id: Vec<u8>,
}

/// What a phone needs to recognise and dial a contact (§B14.4): its Noise
/// static key and its discovery key at `generation`. `Debug` omits the
/// discovery key: it is a shared secret between contacts.
#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
pub struct ContactCard {
    #[prost(string, tag = "1")]
    pub inbox_id: String,
    #[prost(bytes = "vec", tag = "2")]
    pub noise_static_pub: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub discovery_key: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub generation: u32,
}

impl std::fmt::Debug for ContactCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContactCard")
            .field("inbox_id", &self.inbox_id)
            .field("noise_static_pub", &hex::encode(&self.noise_static_pub))
            .field("discovery_key", &"<redacted>")
            .field("generation", &self.generation)
            .finish()
    }
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

    fn message(id: u64, len: usize) -> GroupMessage {
        GroupMessage {
            version: Some(group_message::Version::V1(group_message::V1 {
                id,
                created_ns: id,
                group_id: b"g".to_vec(),
                data: vec![0; len],
                sender_hmac: vec![],
                should_push: true,
                is_commit: false,
            })),
        }
    }

    fn data_len(m: &GroupMessage) -> usize {
        match &m.version {
            Some(group_message::Version::V1(v1)) => v1.data.len(),
            None => 0,
        }
    }

    /// §B13: a page cut by bytes (two 100 KiB rows mid-batch) keeps every
    /// proof next to its own message.
    #[test]
    fn sequenced_pages_keep_each_proof_with_its_message() {
        let kib = 1024;
        let batch: Vec<(GroupMessage, SeqProof)> = (1..=70u64)
            .map(|id| {
                let len = if id == 11 || id == 12 { 100 * kib } else { 10 };
                let proof = SeqProof {
                    signer: vec![1; 32],
                    signature: id.to_be_bytes().repeat(8),
                    attested: false,
                };
                (message(id, len), proof)
            })
            .collect();
        let frames: Vec<Sequenced> = pages(batch, |(m, _)| data_len(m))
            .into_iter()
            .map(|page| sequenced_frame(b"g", page))
            .collect();
        assert_eq!(
            frames.iter().map(|f| f.messages.len()).collect::<Vec<_>>(),
            vec![11, 59],
            "cut by bytes, not by count"
        );
        let mut seen = 0;
        for f in &frames {
            assert!(f.sender_is_sequencer);
            assert_eq!(f.messages.len(), f.proofs.len());
            for (m, p) in f.messages.iter().zip(&f.proofs) {
                let Some(group_message::Version::V1(v1)) = &m.version else {
                    panic!("no V1");
                };
                assert_eq!(p.signature[..8], v1.id.to_be_bytes());
                seen += 1;
            }
        }
        assert_eq!(seen, 70);
    }

    /// §B13: the single-message bound counts the proof, so a message whose
    /// frame fits only without one is refused at publish.
    #[test]
    fn the_single_message_frame_bound_counts_the_proof() {
        let input = |len: usize| group_message_input::V1 {
            data: vec![0; len],
            sender_hmac: vec![],
            should_push: true,
        };
        let unproven_len = |len: usize| {
            encode(frame::Body::Sequenced(Sequenced {
                group_id: b"g".to_vec(),
                messages: vec![GroupMessage {
                    version: Some(group_message::Version::V1(group_message::V1 {
                        id: u64::MAX,
                        created_ns: u64::MAX,
                        group_id: b"g".to_vec(),
                        data: vec![0; len],
                        sender_hmac: vec![],
                        should_push: true,
                        is_commit: true,
                    })),
                }],
                sender_is_sequencer: true,
                proofs: vec![],
            }))
            .len()
        };
        // The largest message whose frame would fit without a proof.
        let mut len = MAX_FRAME_LEN;
        while unproven_len(len) > MAX_FRAME_LEN {
            len -= 1;
        }
        assert!(single_message_frame_len(b"g", &input(len)) > MAX_FRAME_LEN);
        assert!(single_message_frame_len(b"g", &input(len - 128)) <= MAX_FRAME_LEN);
    }

    #[test]
    fn oversized_input_is_rejected() {
        let err = decode(&vec![0u8; MAX_FRAME_LEN + 1]).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    /// Backward compatibility (§C4.2): an older node's Frame has no tag 19, so
    /// it decodes an IdentityConflict as an empty frame, a non-fatal error
    /// that the session logs and ignores.
    #[test]
    fn an_old_node_reads_identity_conflict_as_an_empty_frame() {
        #[derive(Clone, PartialEq, prost::Message)]
        struct OldFrame {
            #[prost(uint32, tag = "1")]
            version: u32,
            #[prost(uint32, tag = "2")]
            ttl: u32,
            #[prost(uint32, tag = "3")]
            hops: u32,
            #[prost(oneof = "old::Body", tags = "10, 11, 12, 13, 14, 15, 16, 17, 18")]
            body: Option<old::Body>,
        }
        mod old {
            #[derive(Clone, PartialEq, prost::Oneof)]
            pub enum Body {
                #[prost(message, tag = "10")]
                Hello(crate::sync::frames::Hello),
                #[prost(message, tag = "11")]
                Auth(crate::sync::frames::Auth),
                #[prost(message, tag = "12")]
                IdentityLog(crate::sync::frames::IdentityLog),
                #[prost(message, tag = "13")]
                KeyPackage(crate::sync::frames::KeyPackage),
                #[prost(message, tag = "14")]
                Welcome(crate::sync::frames::Welcome),
                #[prost(message, tag = "15")]
                WelcomeAck(crate::sync::frames::WelcomeAck),
                #[prost(message, tag = "16")]
                Interest(crate::sync::frames::Interest),
                #[prost(message, tag = "17")]
                Sequenced(crate::sync::frames::Sequenced),
                #[prost(message, tag = "18")]
                Pending(crate::sync::frames::Pending),
            }
        }
        let bytes = encode(frame::Body::IdentityConflict(IdentityLog {
            inbox_id: "inbox".into(),
            updates: vec![],
        }));
        let old = OldFrame::decode(bytes.as_slice()).unwrap();
        assert_eq!(old.version, FRAME_VERSION);
        assert!(old.body.is_none(), "the old node sees no body");
        assert!(!MeshError::InvalidRequest("empty frame".into()).is_fatal());
        assert!(matches!(
            decode(&bytes).unwrap(),
            frame::Body::IdentityConflict(IdentityLog { inbox_id, .. }) if inbox_id == "inbox"
        ));
    }

    #[test]
    fn hello_without_relay_field_decodes_as_zero() {
        // An older build's Hello: fields 1-3 only.
        #[derive(Clone, PartialEq, prost::Message)]
        struct OldHello {
            #[prost(bytes = "vec", tag = "1")]
            installation_key: Vec<u8>,
            #[prost(string, tag = "2")]
            inbox_id: String,
            #[prost(bytes = "vec", tag = "3")]
            challenge: Vec<u8>,
        }
        let old = OldHello {
            installation_key: vec![1; 32],
            inbox_id: "i".into(),
            challenge: vec![2; 32],
        };
        let hello = Hello::decode(old.encode_to_vec().as_slice()).unwrap();
        assert_eq!(hello.relay, 0);
    }

    #[test]
    fn relay_frames_round_trip() {
        for body in [
            frame::Body::Relay(RelayEnvelope {
                ttl: 3,
                copies: 0,
                sealed: vec![9; 512],
            }),
            frame::Body::SpoolDigest(SpoolDigest {
                ids: vec![vec![1; 8]],
            }),
            frame::Body::SpoolWant(SpoolWant {
                ids: vec![vec![2; 8]],
            }),
            frame::Body::RelayKeyOffer(RelayKeyOffer {
                group_id: vec![3],
                epoch: 4,
                nonce: vec![5; 12],
                ciphertext: vec![6; 48],
            }),
            frame::Body::RelayKeyAck(RelayKeyAck { group_id: vec![3] }),
        ] {
            assert_eq!(decode(&encode(body.clone())).unwrap(), body);
        }
    }

    /// A mesh.9 Hello (fields 1–4) reads as `seq` 0: refused (§B13).
    #[test]
    fn hello_without_seq_field_decodes_as_zero() {
        #[derive(Clone, PartialEq, prost::Message)]
        struct Mesh9Hello {
            #[prost(bytes = "vec", tag = "1")]
            installation_key: Vec<u8>,
            #[prost(string, tag = "2")]
            inbox_id: String,
            #[prost(bytes = "vec", tag = "3")]
            challenge: Vec<u8>,
            #[prost(uint32, tag = "4")]
            relay: u32,
        }
        let old = Mesh9Hello {
            installation_key: vec![1; 32],
            inbox_id: "i".into(),
            challenge: vec![2; 32],
            relay: RELAY_V1,
        };
        let hello = Hello::decode(old.encode_to_vec().as_slice()).unwrap();
        assert_eq!((hello.relay, hello.seq), (RELAY_V1, 0));
        assert!(MeshError::IncompatibleVersion("seq 0".into()).is_fatal());
    }

    #[test]
    fn contact_cards_round_trip_as_tag_25() {
        let body = frame::Body::ContactCard(ContactCard {
            inbox_id: "i".into(),
            noise_static_pub: vec![1; 32],
            discovery_key: vec![2; 32],
            generation: 3,
        });
        let bytes = encode(body.clone());
        assert_eq!(decode(&bytes).unwrap(), body);
        // Frame field 25, wire type 2: varint key (25 << 3) | 2 = 202 = 0xca 0x01.
        assert_eq!(&bytes[..2], &[0x08, 0x01], "version first");
        assert!(bytes.windows(2).any(|w| w == [0xca, 0x01]));
        assert!(MeshError::LinkAuthFailed("x".into()).is_fatal());
        assert!(!MeshError::NoAccountKey.is_fatal());
    }
}
