//! Noise handshakes for mesh links (§B14.3, §B14.4, D31, D33, D35).
//!
//! Message 1 is always [`FIRST_MESSAGE_LEN`] bytes: a kind byte, then the
//! Noise message padded to 127 bytes. Kind 0 means contact-or-relay: the
//! responder tries IK with its static key, then NN. Kind 1 is pairing
//! (XX), accepted only in pairing mode.
//!
//! Payloads, all of exact length (anything else fails the handshake):
//! - IK message 1: 31 encrypted bytes, `u64_be(advert window) ‖ 16 random
//!   bytes ‖ 7 zero bytes`. The responder accepts it only from a dialer
//!   its node allows (a live contact, or any dialer while the node has no
//!   contacts), dated `w - 1 ..= w + 1`, and only once ([`ReplayCache`]).
//!   Any other message 1 of kind 0 is answered exactly like a stranger's,
//!   by NN on a fresh state.
//! - NN message 1: 95 random bytes, in the clear. NN message 2: empty.
//! - XX (commit-then-reveal): message 1 carries, in the clear,
//!   `SHA-256("xmtp-mesh-pair-commit-v1" ‖ Na)` and 63 random bytes;
//!   message 2 a random 32-byte `Nb`; message 3 `Na`, which the responder
//!   checks against the commitment. The code both people compare is
//!   [`short_code`] of the handshake hash after message 2 (`h2`), `Na` and
//!   `Nb`, so message 3 cannot steer it.
use std::collections::VecDeque;
use std::sync::Arc;

use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use snow::params::NoiseParams;
use snow::{Builder, HandshakeState, TransportState};
use zeroize::Zeroizing;

use super::LinkKind;
use crate::MeshError;

const PROLOGUE: &[u8] = b"xmtp-mesh-link-v1";
const IK: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
const NN: &str = "Noise_NN_25519_ChaChaPoly_SHA256";
const XX: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const PAIR_COMMIT_PREFIX: &[u8] = b"xmtp-mesh-pair-commit-v1";
const PAIR_CODE_PREFIX: &[u8] = b"xmtp-mesh-pair-code-v1";

pub(crate) const FIRST_MESSAGE_LEN: usize = 128;
const KIND_CONTACT_OR_RELAY: u8 = 0;
const KIND_PAIRING: u8 = 1;
/// IK message 1 payload: e (32) + encrypted s (48) + payload + tag (16).
const IK_PAYLOAD: usize = FIRST_MESSAGE_LEN - 1 - 96;
const IK_WINDOW: usize = 8;
const IK_NONCE: usize = 16;
/// NN and XX message 1 payload (in the clear, after e).
const EPHEMERAL_PAYLOAD: usize = FIRST_MESSAGE_LEN - 1 - 32;
const NONCE_LEN: usize = 32;
const XX_PAD: usize = EPHEMERAL_PAYLOAD - NONCE_LEN;
/// Longer than any handshake message (XX message 2 is 128 bytes).
const MAX_HANDSHAKE_MESSAGE: usize = 256;
/// Most IK message-1 digests remembered (§B14.2).
pub(crate) const REPLAY_CACHE_MAX: usize = 4096;

/// Whom the dialer believes it is calling (the radio's decision, §B14.2).
pub(crate) enum DialTarget {
    Contact { remote_static: [u8; 32] },
    Relay,
    Pairing,
}

/// A finished handshake.
pub(crate) struct LinkOpen {
    pub(crate) kind: LinkKind,
    pub(crate) transport: TransportState,
    /// The peer's static key (IK, XX); `None` on a relay link.
    ///
    /// On the responder side of a contact link this is not key-confirmed
    /// until the first inbound record authenticates: IK message 1 alone
    /// could be a replay. The dialer speaks first; the responder sends
    /// nothing identifying (Hello, ContactCard) before that record.
    pub(crate) remote_static: Option<[u8; 32]>,
    /// Binds the inner Auth to this link (§B14.4).
    pub(crate) handshake_hash: [u8; 32],
    /// The 6-digit code both people compare; pairing links only.
    pub(crate) pairing_code: Option<String>,
    pub(crate) initiator: bool,
}

/// What one handshake message produced: a message to send back, and/or
/// the open link.
pub(crate) struct Step {
    pub(crate) reply: Option<Vec<u8>>,
    pub(crate) open: Option<LinkOpen>,
}

/// IK message-1 digests seen in the last three windows, so a captured
/// message 1 cannot be replayed to ask "are you this contact?" (§B14.2).
/// One per node, shared by all its responders.
pub(crate) struct ReplayCache {
    seen: Mutex<VecDeque<([u8; 32], u64)>>,
}

impl ReplayCache {
    pub(crate) fn new() -> Self {
        Self {
            seen: Mutex::new(VecDeque::new()),
        }
    }

    /// True if `digest` was not seen. Every kind-0 message 1 comes through
    /// here once, accepted or not, so the work does not depend on the
    /// outcome; only a message accepted as a contact's (`remember` = the
    /// window it is dated) is remembered, so strangers cannot flush the
    /// cache. Entries dated before `now_window - 1` are forgotten (they fail
    /// the window check anyway), and the oldest go past
    /// [`REPLAY_CACHE_MAX`]. One lock: two responders cannot both accept
    /// the same message.
    pub(crate) fn check_and_remember(
        &self,
        digest: [u8; 32],
        now_window: u64,
        remember: Option<u64>,
    ) -> bool {
        let mut seen = self.seen.lock();
        seen.retain(|&(_, w)| w.saturating_add(1) >= now_window);
        let fresh = !seen.iter().any(|(d, _)| *d == digest);
        if let (true, Some(window)) = (fresh, remember) {
            if seen.len() >= REPLAY_CACHE_MAX {
                seen.pop_front();
            }
            seen.push_back((digest, window));
        }
        fresh
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.seen.lock().len()
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

/// What a responder asks its node when message 1 arrives (§B14.2).
pub(crate) trait ResponderContext: Send + Sync {
    /// The current advert window, read when message 1 arrives.
    fn window(&self) -> u64;
    /// May this IK dialer have a contact link? The node answers yes for a
    /// live (not removed) contact, or for anyone while it has no contacts
    /// at all (a restored phone). Anyone else is answered as a stranger.
    fn is_allowed_dialer(&self, dialer_static: &[u8; 32]) -> bool;
    /// The node's one replay cache.
    fn replay_cache(&self) -> &ReplayCache;
}

enum Phase {
    DialerAwait2 {
        hs: HandshakeState,
        kind: LinkKind,
        /// Pairing: our reveal, `Na`.
        na: Option<Zeroizing<[u8; NONCE_LEN]>>,
    },
    ResponderAwait1 {
        local_secret: Zeroizing<[u8; 32]>,
        pairing_mode: bool,
        relay_on: bool,
        context: Arc<dyn ResponderContext>,
    },
    ResponderAwait3 {
        hs: HandshakeState,
        commitment: [u8; 32],
        nb: [u8; NONCE_LEN],
        h2: [u8; 32],
    },
    Done,
}

pub(crate) struct Handshake {
    phase: Phase,
}

fn params(name: &str) -> NoiseParams {
    name.parse().expect("a valid Noise protocol name")
}

fn fail(what: &'static str) -> impl FnOnce(snow::Error) -> MeshError {
    move |e| MeshError::LinkAuthFailed(format!("{what}: {e}"))
}

fn refuse(what: &str) -> MeshError {
    MeshError::LinkAuthFailed(what.to_string())
}

fn build(
    pattern: &str,
    local_secret: Option<&[u8; 32]>,
    remote_static: Option<&[u8; 32]>,
    initiator: bool,
) -> Result<HandshakeState, MeshError> {
    let mut builder = Builder::new(params(pattern))
        .prologue(PROLOGUE)
        .map_err(fail("prologue"))?;
    if let Some(secret) = local_secret {
        builder = builder
            .local_private_key(secret)
            .map_err(fail("static key"))?;
    }
    if let Some(remote) = remote_static {
        builder = builder
            .remote_public_key(remote)
            .map_err(fail("remote key"))?;
    }
    if initiator {
        builder.build_initiator().map_err(fail("initiator"))
    } else {
        builder.build_responder().map_err(fail("responder"))
    }
}

fn write(
    hs: &mut HandshakeState,
    payload: &[u8],
    what: &'static str,
) -> Result<Vec<u8>, MeshError> {
    let mut buf = [0u8; MAX_HANDSHAKE_MESSAGE];
    let n = hs.write_message(payload, &mut buf).map_err(fail(what))?;
    Ok(buf[..n].to_vec())
}

/// Reads one handshake message; returns its payload.
fn read(
    hs: &mut HandshakeState,
    message: &[u8],
    what: &'static str,
) -> Result<Zeroizing<Vec<u8>>, MeshError> {
    let mut payload = Zeroizing::new(vec![0u8; MAX_HANDSHAKE_MESSAGE]);
    let n = hs.read_message(message, &mut payload).map_err(fail(what))?;
    payload.truncate(n);
    Ok(payload)
}

/// Reads one handshake message whose payload must be exactly `len` bytes.
fn read_exact(
    hs: &mut HandshakeState,
    message: &[u8],
    len: usize,
    what: &'static str,
) -> Result<Zeroizing<Vec<u8>>, MeshError> {
    let payload = read(hs, message, what)?;
    if payload.len() != len {
        return Err(refuse(what));
    }
    Ok(payload)
}

fn hash32(hs: &HandshakeState) -> [u8; 32] {
    let mut h = [0u8; 32];
    h.copy_from_slice(hs.get_handshake_hash());
    h
}

fn finish(
    hs: HandshakeState,
    kind: LinkKind,
    pairing_code: Option<String>,
) -> Result<LinkOpen, MeshError> {
    let remote_static = match hs.get_remote_static() {
        Some(key) => Some(<[u8; 32]>::try_from(key).map_err(|_| refuse("remote static length"))?),
        None => None,
    };
    let handshake_hash = hash32(&hs);
    let initiator = hs.is_initiator();
    let transport = hs.into_transport_mode().map_err(fail("transport mode"))?;
    Ok(LinkOpen {
        kind,
        transport,
        remote_static,
        handshake_hash,
        pairing_code,
        initiator,
    })
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::fill(&mut bytes[..]);
    bytes
}

/// `SHA-256("xmtp-mesh-pair-commit-v1" ‖ Na)`.
fn pair_commitment(na: &[u8; NONCE_LEN]) -> [u8; 32] {
    Sha256::new()
        .chain_update(PAIR_COMMIT_PREFIX)
        .chain_update(na)
        .finalize()
        .into()
}

/// IK message 1 payload: `u64_be(window) ‖ 16 random bytes ‖ zeros`.
fn ik_payload(window: u64) -> [u8; IK_PAYLOAD] {
    let mut payload = [0u8; IK_PAYLOAD];
    payload[..IK_WINDOW].copy_from_slice(&window.to_be_bytes());
    payload[IK_WINDOW..IK_WINDOW + IK_NONCE].copy_from_slice(&random::<IK_NONCE>());
    payload
}

/// The IK attempt on message 1: `Some` only for a well-formed IK message
/// 1 to our static, from a dialer the node allows, dated `w - 1 ..= w + 1`
/// and not seen before. Any failure drops the state it built, and leaves
/// no trace a stranger's message would not: the digest is checked against
/// the replay cache for every kind-0 message 1 and remembered only when
/// accepted.
fn try_ik(
    local_secret: &[u8; 32],
    message: &[u8],
    context: &dyn ResponderContext,
) -> Result<Option<HandshakeState>, MeshError> {
    let now = context.window();
    let digest: [u8; 32] = Sha256::digest(message).into();
    let mut ik = build(IK, Some(local_secret), None, false)?;
    let accepted = match read(&mut ik, &message[1..], "IK message 1") {
        Ok(payload) => ik_window(&payload, now).filter(|_| {
            ik.get_remote_static()
                .and_then(|key| <[u8; 32]>::try_from(key).ok())
                .is_some_and(|key| context.is_allowed_dialer(&key))
        }),
        Err(_) => None,
    };
    let fresh = context
        .replay_cache()
        .check_and_remember(digest, now, accepted);
    Ok(match accepted {
        Some(_) if fresh => Some(ik),
        _ => None,
    })
}

/// The window an IK message 1 payload is dated, if well-formed and within
/// one window of `now`.
fn ik_window(payload: &[u8], now: u64) -> Option<u64> {
    if payload.len() != IK_PAYLOAD || payload[IK_WINDOW + IK_NONCE..].iter().any(|&b| b != 0) {
        return None;
    }
    let sent = u64::from_be_bytes(payload[..IK_WINDOW].try_into().expect("8 bytes"));
    (sent.saturating_add(1) >= now && sent <= now.saturating_add(1)).then_some(sent)
}

impl Handshake {
    /// Start dialing in advert window `window`: returns the handshake and
    /// message 1 to send.
    pub(crate) fn dial(
        target: &DialTarget,
        local_secret: &[u8; 32],
        window: u64,
    ) -> Result<(Self, Vec<u8>), MeshError> {
        let (mut hs, kind, kind_byte, payload, na) = match target {
            DialTarget::Contact { remote_static } => (
                build(IK, Some(local_secret), Some(remote_static), true)?,
                LinkKind::Contact,
                KIND_CONTACT_OR_RELAY,
                ik_payload(window).to_vec(),
                None,
            ),
            DialTarget::Relay => (
                build(NN, None, None, true)?,
                LinkKind::Relay,
                KIND_CONTACT_OR_RELAY,
                random::<EPHEMERAL_PAYLOAD>().to_vec(),
                None,
            ),
            DialTarget::Pairing => {
                let na = Zeroizing::new(random::<NONCE_LEN>());
                let mut payload = pair_commitment(&na).to_vec();
                payload.extend_from_slice(&random::<XX_PAD>());
                (
                    build(XX, Some(local_secret), None, true)?,
                    LinkKind::Pairing,
                    KIND_PAIRING,
                    payload,
                    Some(na),
                )
            }
        };
        let noise = write(&mut hs, &payload, "handshake message 1")?;
        let mut message = Vec::with_capacity(FIRST_MESSAGE_LEN);
        message.push(kind_byte);
        message.extend_from_slice(&noise);
        if message.len() != FIRST_MESSAGE_LEN {
            return Err(refuse("handshake message 1 has the wrong length"));
        }
        Ok((
            Self {
                phase: Phase::DialerAwait2 { hs, kind, na },
            },
            message,
        ))
    }

    /// Wait for a dialer's message 1. `context` answers for the node when
    /// it arrives: the window, which IK dialers are allowed, the replay
    /// cache.
    pub(crate) fn accept(
        local_secret: &[u8; 32],
        pairing_mode: bool,
        relay_on: bool,
        context: Arc<dyn ResponderContext>,
    ) -> Self {
        Self {
            phase: Phase::ResponderAwait1 {
                local_secret: Zeroizing::new(*local_secret),
                pairing_mode,
                relay_on,
                context,
            },
        }
    }

    /// A pairing (XX) handshake past message 1: a code is at stake.
    pub(crate) fn is_pairing(&self) -> bool {
        matches!(
            self.phase,
            Phase::ResponderAwait3 { .. } | Phase::DialerAwait2 { na: Some(_), .. }
        )
    }

    /// Process one handshake message from the peer. Any error ends the
    /// handshake.
    pub(crate) fn read(&mut self, message: &[u8]) -> Result<Step, MeshError> {
        if message.len() > MAX_HANDSHAKE_MESSAGE {
            self.phase = Phase::Done;
            return Err(refuse("handshake message too long"));
        }
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::DialerAwait2 { mut hs, kind, na } => match na {
                None => {
                    read_exact(&mut hs, message, 0, "handshake message 2")?;
                    Ok(Step {
                        reply: None,
                        open: Some(finish(hs, kind, None)?),
                    })
                }
                Some(na) => {
                    let payload = read_exact(&mut hs, message, NONCE_LEN, "XX message 2")?;
                    let nb: [u8; NONCE_LEN] = payload[..].try_into().expect("checked length");
                    let code = short_code(&hash32(&hs), &na, &nb);
                    let reply = write(&mut hs, &na[..], "XX message 3")?;
                    Ok(Step {
                        reply: Some(reply),
                        open: Some(finish(hs, kind, Some(code))?),
                    })
                }
            },
            Phase::ResponderAwait1 {
                local_secret,
                pairing_mode,
                relay_on,
                context,
            } => {
                if message.len() != FIRST_MESSAGE_LEN {
                    return Err(refuse("handshake message 1 has the wrong length"));
                }
                match message[0] {
                    KIND_CONTACT_OR_RELAY => {
                        let (mut hs, kind) = match try_ik(&local_secret, message, &*context)? {
                            Some(ik) => (ik, LinkKind::Contact),
                            None => {
                                if !relay_on {
                                    return Err(refuse("not a contact, and relay is off"));
                                }
                                let mut nn = build(NN, None, None, false)?;
                                read_exact(
                                    &mut nn,
                                    &message[1..],
                                    EPHEMERAL_PAYLOAD,
                                    "NN message 1",
                                )?;
                                (nn, LinkKind::Relay)
                            }
                        };
                        let reply = write(&mut hs, &[], "handshake message 2")?;
                        Ok(Step {
                            reply: Some(reply),
                            open: Some(finish(hs, kind, None)?),
                        })
                    }
                    KIND_PAIRING => {
                        if !pairing_mode {
                            return Err(refuse("pairing link while not in pairing mode"));
                        }
                        let mut hs = build(XX, Some(&local_secret), None, false)?;
                        let payload =
                            read_exact(&mut hs, &message[1..], EPHEMERAL_PAYLOAD, "XX message 1")?;
                        let commitment: [u8; 32] =
                            payload[..32].try_into().expect("checked length");
                        let nb = random::<NONCE_LEN>();
                        let reply = write(&mut hs, &nb, "XX message 2")?;
                        let h2 = hash32(&hs);
                        self.phase = Phase::ResponderAwait3 {
                            hs,
                            commitment,
                            nb,
                            h2,
                        };
                        Ok(Step {
                            reply: Some(reply),
                            open: None,
                        })
                    }
                    other => Err(MeshError::LinkAuthFailed(format!(
                        "unknown link kind {other}"
                    ))),
                }
            }
            Phase::ResponderAwait3 {
                mut hs,
                commitment,
                nb,
                h2,
            } => {
                let payload = read_exact(&mut hs, message, NONCE_LEN, "XX message 3")?;
                let na: Zeroizing<[u8; NONCE_LEN]> =
                    Zeroizing::new(payload[..].try_into().expect("checked length"));
                if pair_commitment(&na) != commitment {
                    return Err(refuse("XX message 3 does not match the commitment"));
                }
                let code = short_code(&h2, &na, &nb);
                Ok(Step {
                    reply: None,
                    open: Some(finish(hs, LinkKind::Pairing, Some(code))?),
                })
            }
            Phase::Done => Err(refuse("handshake message after the handshake")),
        }
    }
}

/// The 6-digit code both people compare when pairing (§B14.4):
/// `u32_be(SHA-256("xmtp-mesh-pair-code-v1" ‖ h2 ‖ Na ‖ Nb)[0..4]) mod
/// 1 000 000`, zero-padded, where `h2` is the handshake hash after XX
/// message 2.
pub fn short_code(h2: &[u8; 32], na: &[u8; 32], nb: &[u8; 32]) -> String {
    let digest = Sha256::new()
        .chain_update(PAIR_CODE_PREFIX)
        .chain_update(h2)
        .chain_update(na)
        .chain_update(nb)
        .finalize();
    let n = u32::from_be_bytes(digest[..4].try_into().expect("4 bytes")) % 1_000_000;
    format!("{n:06}")
}

/// Two ends of an NN link, for record tests.
#[cfg(test)]
pub(crate) fn test_pair() -> (TransportState, TransportState) {
    let mut a = build(NN, None, None, true).unwrap();
    let mut b = build(NN, None, None, false).unwrap();
    let m1 = write(&mut a, &[], "1").unwrap();
    read(&mut b, &m1, "1").unwrap();
    let m2 = write(&mut b, &[], "2").unwrap();
    read(&mut a, &m2, "2").unwrap();
    (
        a.into_transport_mode().unwrap(),
        b.into_transport_mode().unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::link::keys::noise_public_key;

    /// The responder's advert window.
    const W: u64 = 1_966_000;

    fn keypair(n: u8) -> ([u8; 32], [u8; 32]) {
        let secret = [n; 32];
        (secret, noise_public_key(&secret))
    }

    fn dial(target: &DialTarget, secret: &[u8; 32]) -> (Handshake, Vec<u8>) {
        Handshake::dial(target, secret, W).unwrap()
    }

    /// A node's answers: its window, its live contacts' statics (none:
    /// allow any dialer, as a node with no contacts does), its cache.
    struct TestContext {
        window: AtomicU64,
        contacts: Vec<[u8; 32]>,
        cache: ReplayCache,
    }

    impl TestContext {
        fn new(contacts: Vec<[u8; 32]>) -> Arc<Self> {
            Arc::new(Self {
                window: AtomicU64::new(W),
                contacts,
                cache: ReplayCache::new(),
            })
        }
    }

    impl ResponderContext for TestContext {
        fn window(&self) -> u64 {
            self.window.load(Ordering::SeqCst)
        }
        fn is_allowed_dialer(&self, dialer_static: &[u8; 32]) -> bool {
            self.contacts.is_empty() || self.contacts.contains(dialer_static)
        }
        fn replay_cache(&self) -> &ReplayCache {
            &self.cache
        }
    }

    fn accept(secret: &[u8; 32], pairing_mode: bool, relay_on: bool) -> Handshake {
        Handshake::accept(secret, pairing_mode, relay_on, TestContext::new(Vec::new()))
    }

    /// Runs a handshake to the end: (dialer's open link, responder's).
    fn run(
        dialer: (Handshake, Vec<u8>),
        mut responder: Handshake,
    ) -> Result<(LinkOpen, LinkOpen), MeshError> {
        let (mut d, msg1) = dialer;
        let step = responder.read(&msg1)?;
        let msg2 = step.reply.expect("the responder answers message 1");
        let d_step = d.read(&msg2)?;
        match (step.open, d_step.open) {
            (Some(r), Some(dialer)) => Ok((dialer, r)),
            (None, Some(dialer)) => {
                let msg3 = d_step.reply.expect("XX message 3");
                let r = responder.read(&msg3)?.open.expect("the XX responder opens");
                Ok((dialer, r))
            }
            _ => panic!("unexpected handshake shape"),
        }
    }

    /// First-message size: IK and NN (and XX) message 1 look the
    /// same size on the air, and contact and relay share the kind byte.
    #[test]
    fn every_first_message_is_128_bytes() {
        let (s, _) = keypair(1);
        let (_, remote) = keypair(2);
        let targets = [
            DialTarget::Contact {
                remote_static: remote,
            },
            DialTarget::Relay,
            DialTarget::Pairing,
        ];
        let firsts: Vec<Vec<u8>> = targets.iter().map(|t| dial(t, &s).1).collect();
        assert!(firsts.iter().all(|m| m.len() == FIRST_MESSAGE_LEN));
        assert_eq!(
            firsts[0][0], firsts[1][0],
            "contact and relay links start alike"
        );
        assert_ne!(firsts[1][0], firsts[2][0], "pairing is visible (in person)");
    }

    #[test]
    fn cleartext_padding_is_random() {
        let (s, _) = keypair(1);
        for target in [DialTarget::Relay, DialTarget::Pairing] {
            let (_, a) = dial(&target, &s);
            let (_, b) = dial(&target, &s);
            assert_ne!(a[33..], b[33..]);
            // XX: the 32-byte commitment, then 63 random bytes.
            assert_ne!(a[65..], b[65..]);
            assert!(a[65..].iter().any(|&x| x != 0));
        }
    }

    /// An IK contact link (handshake level).
    #[test]
    fn a_contact_link_authenticates_both_statics() {
        let (a, a_pub) = keypair(1);
        let (b, b_pub) = keypair(2);
        let (dialer, responder) = run(
            dial(
                &DialTarget::Contact {
                    remote_static: b_pub,
                },
                &a,
            ),
            accept(&b, false, false),
        )
        .unwrap();
        assert_eq!(
            (dialer.kind, responder.kind),
            (LinkKind::Contact, LinkKind::Contact)
        );
        assert_eq!(responder.remote_static, Some(a_pub));
        assert_eq!(dialer.remote_static, Some(b_pub));
        assert_eq!(dialer.handshake_hash, responder.handshake_hash);
        assert_eq!((dialer.pairing_code, responder.pairing_code), (None, None));
        assert!(dialer.initiator && !responder.initiator);
    }

    /// Wrong static: the dialer takes a stranger for a contact.
    /// The stranger reads a relay link; the dialer's IK fails cleanly, and
    /// its static key never appears in the clear.
    #[test]
    fn a_wrong_static_falls_back_to_relay_and_hides_the_dialer() {
        let (a, a_pub) = keypair(1);
        let (b, _) = keypair(2);
        let (_, c_pub) = keypair(3);
        let (mut dialer, msg1) = dial(
            &DialTarget::Contact {
                remote_static: c_pub,
            },
            &a,
        );
        assert!(!msg1.windows(32).any(|w| w == a_pub));
        let mut stranger = accept(&b, false, true);
        let step = stranger.read(&msg1).unwrap();
        let open = step.open.expect("read as a relay link");
        assert_eq!((open.kind, open.remote_static), (LinkKind::Relay, None));
        assert!(matches!(
            dialer.read(&step.reply.unwrap()),
            Err(MeshError::LinkAuthFailed(_))
        ));
    }

    #[test]
    fn a_relay_link_learns_no_static_and_needs_relay_on() {
        let (a, _) = keypair(1);
        let (b, _) = keypair(2);
        let (dialer, responder) =
            run(dial(&DialTarget::Relay, &a), accept(&b, false, true)).unwrap();
        assert_eq!(
            (dialer.kind, responder.kind),
            (LinkKind::Relay, LinkKind::Relay)
        );
        assert_eq!(
            (dialer.remote_static, responder.remote_static),
            (None, None)
        );
        let (_, msg1) = dial(&DialTarget::Relay, &a);
        assert!(matches!(
            accept(&b, false, false).read(&msg1),
            Err(MeshError::LinkAuthFailed(_))
        ));
    }

    /// §B14.2 freshness: a replayed IK message 1 is answered exactly like a
    /// stranger's (NN on a fresh state), never as the contact again.
    #[test]
    fn a_replayed_contact_message_1_is_answered_as_a_stranger() {
        let (a, a_pub) = keypair(1);
        let (b, b_pub) = keypair(2);
        let node = TestContext::new(Vec::new());
        let (_, msg1) = dial(
            &DialTarget::Contact {
                remote_static: b_pub,
            },
            &a,
        );
        let first = Handshake::accept(&b, false, true, node.clone())
            .read(&msg1)
            .unwrap();
        let open = first.open.unwrap();
        assert_eq!(
            (open.kind, open.remote_static),
            (LinkKind::Contact, Some(a_pub))
        );

        let replay = Handshake::accept(&b, false, true, node.clone())
            .read(&msg1)
            .unwrap();
        let open = replay.open.unwrap();
        assert_eq!((open.kind, open.remote_static), (LinkKind::Relay, None));
        let (_, relay_msg1) = dial(&DialTarget::Relay, &a);
        let stranger_reply = accept(&b, false, true)
            .read(&relay_msg1)
            .unwrap()
            .reply
            .unwrap();
        assert_eq!(
            replay.reply.unwrap().len(),
            stranger_reply.len(),
            "same reply shape"
        );

        assert!(matches!(
            Handshake::accept(&b, false, false, node).read(&msg1),
            Err(MeshError::LinkAuthFailed(_))
        ));
    }

    #[test]
    fn contact_message_1_is_accepted_only_one_window_either_side() {
        let (a, _) = keypair(1);
        let (b, b_pub) = keypair(2);
        let target = DialTarget::Contact {
            remote_static: b_pub,
        };
        for (window, kind) in [
            (W - 2, LinkKind::Relay),
            (W - 1, LinkKind::Contact),
            (W, LinkKind::Contact),
            (W + 1, LinkKind::Contact),
            (W + 2, LinkKind::Relay),
        ] {
            let (_, msg1) = Handshake::dial(&target, &a, window).unwrap();
            let open = accept(&b, false, true).read(&msg1).unwrap().open.unwrap();
            assert_eq!(
                open.kind, kind,
                "dialer window {window}, responder window {W}"
            );
        }
    }

    #[test]
    fn the_replay_cache_is_bounded_and_forgets_old_windows() {
        let cache = ReplayCache::new();
        let digest = |i: usize| {
            let mut d = [0u8; 32];
            d[..8].copy_from_slice(&(i as u64).to_be_bytes());
            d
        };
        for i in 0..=REPLAY_CACHE_MAX {
            assert!(cache.check_and_remember(digest(i), W, Some(W)));
        }
        assert_eq!(cache.len(), REPLAY_CACHE_MAX);
        assert!(
            !cache.check_and_remember(digest(REPLAY_CACHE_MAX), W, Some(W)),
            "newest kept"
        );
        assert!(
            cache.check_and_remember(digest(0), W, None),
            "oldest dropped"
        );
        assert!(
            cache.check_and_remember(digest(0), W, None),
            "not remembered unless accepted"
        );

        let cache = ReplayCache::new();
        assert!(cache.check_and_remember(digest(1), W, Some(W - 1)));
        assert!(cache.check_and_remember(digest(2), W + 1, Some(W + 1)));
        assert_eq!(
            cache.len(),
            1,
            "a message from window W - 1 is gone at W + 1"
        );
    }

    /// Pairing (XX): one code on both phones; a middle phone that
    /// relays the pairing runs two handshakes and shows two codes.
    #[test]
    fn pairing_shows_one_code_and_a_middle_phone_two() {
        let (a, a_pub) = keypair(1);
        let (b, b_pub) = keypair(2);
        let (m, _) = keypair(3);
        let (dialer, responder) =
            run(dial(&DialTarget::Pairing, &a), accept(&b, true, false)).unwrap();
        assert_eq!(
            (dialer.kind, responder.kind),
            (LinkKind::Pairing, LinkKind::Pairing)
        );
        assert_eq!(
            (dialer.remote_static, responder.remote_static),
            (Some(b_pub), Some(a_pub))
        );
        assert!(dialer.pairing_code.is_some());
        assert_eq!(dialer.pairing_code, responder.pairing_code);
        let (a_side, m_left) =
            run(dial(&DialTarget::Pairing, &a), accept(&m, true, false)).unwrap();
        let (m_right, b_side) =
            run(dial(&DialTarget::Pairing, &m), accept(&b, true, false)).unwrap();
        assert_eq!(a_side.pairing_code, m_left.pairing_code);
        assert_eq!(m_right.pairing_code, b_side.pairing_code);
        assert_ne!(a_side.pairing_code, b_side.pairing_code);
    }

    /// A middle phone plays the dialer by hand (§B14.4 commit-then-reveal).
    struct HandDialer {
        hs: HandshakeState,
        na: [u8; 32],
    }

    impl HandDialer {
        fn start(secret: &[u8; 32]) -> (Self, Vec<u8>) {
            let mut hs = build(XX, Some(secret), None, true).unwrap();
            let na: [u8; 32] = rand::random();
            let mut payload = pair_commitment(&na).to_vec();
            payload.extend_from_slice(&[7u8; XX_PAD]);
            let mut msg1 = vec![KIND_PAIRING];
            msg1.extend(write(&mut hs, &payload, "1").unwrap());
            (Self { hs, na }, msg1)
        }

        /// Reads message 2; returns Nb and the code, fixed before message 3.
        fn read2(&mut self, msg2: &[u8]) -> ([u8; 32], String) {
            let nb: [u8; 32] = read(&mut self.hs, msg2, "2").unwrap()[..]
                .try_into()
                .unwrap();
            let h2: [u8; 32] = self.hs.get_handshake_hash().try_into().unwrap();
            (nb, short_code(&h2, &self.na, &nb))
        }
    }

    /// Message 3 cannot steer the code: whatever static a middle phone puts
    /// in it, the code both sides show was fixed by messages 1 and 2.
    #[test]
    fn message_3_cannot_change_the_pairing_code() {
        let (b, _) = keypair(2);
        for m in [3u8, 4] {
            let (m_secret, m_pub) = keypair(m);
            let mut responder = accept(&b, true, false);
            let (mut hand, msg1) = HandDialer::start(&m_secret);
            let msg2 = responder.read(&msg1).unwrap().reply.unwrap();
            let (_, predicted) = hand.read2(&msg2);
            let na = hand.na;
            let msg3 = write(&mut hand.hs, &na, "3").unwrap();
            let open = responder.read(&msg3).unwrap().open.unwrap();
            assert_eq!(open.remote_static, Some(m_pub));
            assert_eq!(open.pairing_code, Some(predicted));
        }
    }

    /// A middle phone between `a` and `b` (a dials m, m dials b) that
    /// controls its message 3 to `b` cannot make the two codes match: `b`
    /// takes only the committed `Na`, so `b`'s code is fixed at message 2,
    /// before m can learn `a`'s code (a's `Na` arrives in a's message 3).
    /// Each try costs m a whole handshake, shown to `b` as a failure.
    #[test]
    fn a_middle_phone_cannot_steer_message_3_to_match_the_codes() {
        let (a, _) = keypair(1);
        let (b, _) = keypair(2);
        let (m, _) = keypair(3);
        for _ in 0..8 {
            let mut to_b = accept(&b, true, false);
            let (mut hand, msg1) = HandDialer::start(&m);
            let msg2 = to_b.read(&msg1).unwrap().reply.unwrap();
            let (_, b_code) = hand.read2(&msg2);
            let (a_side, m_left) =
                run(dial(&DialTarget::Pairing, &a), accept(&m, true, false)).unwrap();
            let a_code = a_side.pairing_code.unwrap();
            assert_eq!(m_left.pairing_code.as_deref(), Some(a_code.as_str()));
            // A message 3 other than the committed one fails (shown here on a
            // second handshake); the committed one gives b_code.
            let mut probe = pairing_past_msg2(&b, &m);
            let mut forged = probe.1.na;
            forged[0] ^= 1;
            let bad = write(&mut probe.1.hs, &forged, "3").unwrap();
            assert!(probe.0.read(&bad).is_err());
            let na = hand.na;
            let msg3 = write(&mut hand.hs, &na, "3").unwrap();
            let open = to_b.read(&msg3).unwrap().open.unwrap();
            assert_eq!(open.pairing_code.as_deref(), Some(b_code.as_str()));
            if b_code != a_code {
                return;
            }
            // A 1-in-a-million coincidence: try again.
        }
        panic!("the codes matched eight times in a row");
    }

    /// A responder for `b` past message 2 of a pairing from `m`, and m's side.
    fn pairing_past_msg2(b: &[u8; 32], m: &[u8; 32]) -> (Handshake, HandDialer) {
        let mut to_b = accept(b, true, false);
        let (mut hand, msg1) = HandDialer::start(m);
        let msg2 = to_b.read(&msg1).unwrap().reply.unwrap();
        hand.read2(&msg2);
        (to_b, hand)
    }

    #[test]
    fn a_message_3_that_breaks_the_commitment_fails() {
        let (b, _) = keypair(2);
        let (m, _) = keypair(3);
        for bad in [vec![0u8; 32], vec![1u8; 31], Vec::new()] {
            let mut responder = accept(&b, true, false);
            let (mut hand, msg1) = HandDialer::start(&m);
            let msg2 = responder.read(&msg1).unwrap().reply.unwrap();
            hand.read2(&msg2);
            let msg3 = write(&mut hand.hs, &bad, "3").unwrap();
            assert!(matches!(
                responder.read(&msg3),
                Err(MeshError::LinkAuthFailed(_))
            ));
        }
    }

    /// Handshake payloads have exact lengths; anything else fails.
    #[test]
    fn handshake_payloads_have_exact_lengths() {
        let (a, _) = keypair(1);
        let (b, _) = keypair(2);
        // XX message 2 with a 31-byte Nb.
        let (mut d, msg1) = dial(&DialTarget::Pairing, &a);
        let mut r = build(XX, Some(&b), None, false).unwrap();
        read(&mut r, &msg1[1..], "1").unwrap();
        let msg2 = write(&mut r, &[5u8; 31], "2").unwrap();
        assert!(matches!(d.read(&msg2), Err(MeshError::LinkAuthFailed(_))));
        // NN message 2 with a payload.
        let (mut d, msg1) = dial(&DialTarget::Relay, &a);
        let mut r = build(NN, None, None, false).unwrap();
        read(&mut r, &msg1[1..], "1").unwrap();
        let msg2 = write(&mut r, &[0u8], "2").unwrap();
        assert!(matches!(d.read(&msg2), Err(MeshError::LinkAuthFailed(_))));
    }

    /// Flipping the kind byte of any message 1 never yields a link that is
    /// open on both sides.
    #[test]
    fn a_flipped_kind_byte_never_opens_both_sides() {
        let (a, _) = keypair(1);
        let (b, b_pub) = keypair(2);
        for target in [
            DialTarget::Contact {
                remote_static: b_pub,
            },
            DialTarget::Relay,
            DialTarget::Pairing,
        ] {
            let (mut d, mut msg1) = dial(&target, &a);
            msg1[0] ^= 1;
            let mut r = accept(&b, true, true);
            let Ok(step) = r.read(&msg1) else { continue };
            let Some(msg2) = step.reply else { continue };
            let d_step = d.read(&msg2);
            let both = match d_step {
                Err(_) => false,
                Ok(Step { open: None, .. }) => false,
                Ok(Step {
                    open: Some(_),
                    reply,
                }) => match (step.open, reply) {
                    (Some(_), _) => true,
                    (None, Some(msg3)) => matches!(r.read(&msg3), Ok(Step { open: Some(_), .. })),
                    (None, None) => false,
                },
            };
            assert!(!both, "a flipped kind byte opened a link");
        }
    }

    #[test]
    fn pairing_needs_pairing_mode() {
        let (a, _) = keypair(1);
        let (b, _) = keypair(2);
        let (_, msg1) = dial(&DialTarget::Pairing, &a);
        assert!(matches!(
            accept(&b, false, true).read(&msg1),
            Err(MeshError::LinkAuthFailed(_))
        ));
    }

    #[test]
    fn malformed_handshake_messages_are_refused() {
        let (b, _) = keypair(2);
        assert!(accept(&b, true, true).read(&[0; 127]).is_err(), "too short");
        let mut unknown = vec![9u8; FIRST_MESSAGE_LEN];
        unknown[0] = 9;
        assert!(
            accept(&b, true, true).read(&unknown).is_err(),
            "unknown kind"
        );
        let (a, _) = keypair(1);
        let (mut d, msg1) = dial(&DialTarget::Relay, &a);
        let mut r = accept(&b, false, true);
        let reply = r.read(&msg1).unwrap().reply.unwrap();
        d.read(&reply).unwrap();
        assert!(d.read(&reply).is_err(), "a message after the handshake");
    }

    /// `u32_be(SHA-256("xmtp-mesh-pair-code-v1" ‖ h2 ‖ Na ‖ Nb)[0..4]) mod 10^6`.
    #[test]
    fn the_short_code_is_six_digits_of_the_code_hash() {
        assert_eq!(short_code(&[0xab; 32], &[1; 32], &[2; 32]), "617800");
        assert_eq!(short_code(&[0; 32], &[0; 32], &[0; 32]), "487015");
    }

    /// §B14.2: only a dialer the node allows gets a contact link; anyone
    /// else holding our static key is answered like a stranger, and leaves
    /// nothing in the replay cache.
    #[test]
    fn only_allowed_dialers_get_a_contact_link() {
        let (a, a_pub) = keypair(1);
        let (b, b_pub) = keypair(2);
        let (_, c_pub) = keypair(3);
        let target = DialTarget::Contact {
            remote_static: b_pub,
        };

        let allowed = TestContext::new(vec![a_pub]);
        let (_, msg1) = dial(&target, &a);
        let open = Handshake::accept(&b, false, true, allowed)
            .read(&msg1)
            .unwrap()
            .open
            .unwrap();
        assert_eq!(
            (open.kind, open.remote_static),
            (LinkKind::Contact, Some(a_pub))
        );

        let refused = TestContext::new(vec![c_pub]);
        let (mut dialer, msg1) = dial(&target, &a);
        let step = Handshake::accept(&b, false, true, refused.clone())
            .read(&msg1)
            .unwrap();
        let open = step.open.unwrap();
        assert_eq!((open.kind, open.remote_static), (LinkKind::Relay, None));
        let (_, relay_msg1) = dial(&DialTarget::Relay, &a);
        let stranger_reply = accept(&b, false, true)
            .read(&relay_msg1)
            .unwrap()
            .reply
            .unwrap();
        let reply = step.reply.unwrap();
        assert_eq!(reply.len(), stranger_reply.len(), "same reply shape");
        assert!(matches!(
            dialer.read(&reply),
            Err(MeshError::LinkAuthFailed(_))
        ));
        assert_eq!(refused.cache.len(), 0, "a refused dialer leaves no trace");
        assert!(matches!(
            Handshake::accept(&b, false, false, refused).read(&msg1),
            Err(MeshError::LinkAuthFailed(_))
        ));

        let no_contacts = TestContext::new(Vec::new());
        let (_, msg1) = dial(&target, &a);
        let open = Handshake::accept(&b, false, false, no_contacts)
            .read(&msg1)
            .unwrap()
            .open
            .unwrap();
        assert_eq!(
            open.kind,
            LinkKind::Contact,
            "a node with no contacts allows any dialer"
        );
    }

    /// The window is read when message 1 arrives, not when the responder
    /// was set up.
    #[test]
    fn the_window_is_read_when_message_1_arrives() {
        let (a, _) = keypair(1);
        let (b, b_pub) = keypair(2);
        let node = TestContext::new(Vec::new());
        let mut responder = Handshake::accept(&b, false, true, node.clone());
        node.window.store(W + 2, Ordering::SeqCst);
        let (_, msg1) = dial(
            &DialTarget::Contact {
                remote_static: b_pub,
            },
            &a,
        );
        let open = responder.read(&msg1).unwrap().open.unwrap();
        assert_eq!(open.kind, LinkKind::Relay, "dated W, read at W + 2");
    }
}
