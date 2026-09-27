//! Noise handshakes for mesh links (§B14.3, D31, D33, D35).
//!
//! Message 1 is always [`FIRST_MESSAGE_LEN`] bytes: a kind byte, then the
//! Noise message padded (IK's 96 bytes + 31 encrypted zero bytes; NN's and
//! XX's 32 bytes + 95 random bytes, which travel in the clear). Kind 0
//! means contact-or-relay: the responder tries IK with its static key,
//! then NN. Kind 1 is pairing (XX), accepted only in pairing mode.
use snow::params::NoiseParams;
use snow::{Builder, HandshakeState, TransportState};
use zeroize::Zeroizing;

use super::LinkKind;
use crate::MeshError;

const PROLOGUE: &[u8] = b"xmtp-mesh-link-v1";
const IK: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
const NN: &str = "Noise_NN_25519_ChaChaPoly_SHA256";
const XX: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

pub(crate) const FIRST_MESSAGE_LEN: usize = 128;
const KIND_CONTACT_OR_RELAY: u8 = 0;
const KIND_PAIRING: u8 = 1;
const IK_PAD: usize = FIRST_MESSAGE_LEN - 1 - 96;
const EPHEMERAL_PAD: usize = FIRST_MESSAGE_LEN - 1 - 32;
/// Longest handshake message (XX message 2 is 96 bytes).
const MAX_HANDSHAKE_MESSAGE: usize = 256;

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
    pub(crate) remote_static: Option<[u8; 32]>,
    /// Binds the inner Auth to this link (§B14.4).
    pub(crate) handshake_hash: [u8; 32],
    pub(crate) initiator: bool,
}

/// What one handshake message produced: a message to send back, and/or
/// the open link.
pub(crate) struct Step {
    pub(crate) reply: Option<Vec<u8>>,
    pub(crate) open: Option<LinkOpen>,
}

enum Phase {
    DialerAwait2 {
        hs: HandshakeState,
        kind: LinkKind,
    },
    ResponderAwait1 {
        local_secret: Zeroizing<[u8; 32]>,
        pairing_mode: bool,
        relay_on: bool,
    },
    ResponderAwait3 {
        hs: HandshakeState,
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

fn read(hs: &mut HandshakeState, message: &[u8], what: &'static str) -> Result<(), MeshError> {
    let mut payload = [0u8; MAX_HANDSHAKE_MESSAGE];
    hs.read_message(message, &mut payload).map_err(fail(what))?;
    Ok(())
}

fn finish(hs: HandshakeState, kind: LinkKind) -> Result<LinkOpen, MeshError> {
    let remote_static = match hs.get_remote_static() {
        Some(key) => Some(<[u8; 32]>::try_from(key).map_err(|_| refuse("remote static length"))?),
        None => None,
    };
    let mut handshake_hash = [0u8; 32];
    handshake_hash.copy_from_slice(hs.get_handshake_hash());
    let initiator = hs.is_initiator();
    let transport = hs.into_transport_mode().map_err(fail("transport mode"))?;
    Ok(LinkOpen {
        kind,
        transport,
        remote_static,
        handshake_hash,
        initiator,
    })
}

impl Handshake {
    /// Start dialing: returns the handshake and message 1 to send.
    pub(crate) fn dial(
        target: &DialTarget,
        local_secret: &[u8; 32],
    ) -> Result<(Self, Vec<u8>), MeshError> {
        let (mut hs, kind, kind_byte, pad) = match target {
            DialTarget::Contact { remote_static } => (
                build(IK, Some(local_secret), Some(remote_static), true)?,
                LinkKind::Contact,
                KIND_CONTACT_OR_RELAY,
                vec![0u8; IK_PAD],
            ),
            DialTarget::Relay => (
                build(NN, None, None, true)?,
                LinkKind::Relay,
                KIND_CONTACT_OR_RELAY,
                random_pad(),
            ),
            DialTarget::Pairing => (
                build(XX, Some(local_secret), None, true)?,
                LinkKind::Pairing,
                KIND_PAIRING,
                random_pad(),
            ),
        };
        let noise = write(&mut hs, &pad, "handshake message 1")?;
        let mut message = Vec::with_capacity(FIRST_MESSAGE_LEN);
        message.push(kind_byte);
        message.extend_from_slice(&noise);
        debug_assert_eq!(message.len(), FIRST_MESSAGE_LEN);
        Ok((
            Self {
                phase: Phase::DialerAwait2 { hs, kind },
            },
            message,
        ))
    }

    /// Wait for a dialer's message 1.
    pub(crate) fn accept(local_secret: &[u8; 32], pairing_mode: bool, relay_on: bool) -> Self {
        Self {
            phase: Phase::ResponderAwait1 {
                local_secret: Zeroizing::new(*local_secret),
                pairing_mode,
                relay_on,
            },
        }
    }

    /// Process one handshake message from the peer.
    pub(crate) fn read(&mut self, message: &[u8]) -> Result<Step, MeshError> {
        if message.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(refuse("handshake message too long"));
        }
        match std::mem::replace(&mut self.phase, Phase::Done) {
            Phase::DialerAwait2 { mut hs, kind } => {
                read(&mut hs, message, "handshake message 2")?;
                let reply = if kind == LinkKind::Pairing {
                    Some(write(&mut hs, &[], "XX message 3")?)
                } else {
                    None
                };
                Ok(Step {
                    reply,
                    open: Some(finish(hs, kind)?),
                })
            }
            Phase::ResponderAwait1 {
                local_secret,
                pairing_mode,
                relay_on,
            } => {
                if message.len() != FIRST_MESSAGE_LEN {
                    return Err(refuse("handshake message 1 has the wrong length"));
                }
                let (kind_byte, body) = (message[0], &message[1..]);
                match kind_byte {
                    KIND_CONTACT_OR_RELAY => {
                        let mut ik = build(IK, Some(&*local_secret), None, false)?;
                        let (mut hs, kind) = if read(&mut ik, body, "IK message 1").is_ok() {
                            (ik, LinkKind::Contact)
                        } else {
                            if !relay_on {
                                return Err(refuse("not a contact, and relay is off"));
                            }
                            let mut nn = build(NN, None, None, false)?;
                            read(&mut nn, body, "NN message 1")?;
                            (nn, LinkKind::Relay)
                        };
                        let reply = write(&mut hs, &[], "handshake message 2")?;
                        Ok(Step {
                            reply: Some(reply),
                            open: Some(finish(hs, kind)?),
                        })
                    }
                    KIND_PAIRING => {
                        if !pairing_mode {
                            return Err(refuse("pairing link while not in pairing mode"));
                        }
                        let mut hs = build(XX, Some(&*local_secret), None, false)?;
                        read(&mut hs, body, "XX message 1")?;
                        let reply = write(&mut hs, &[], "XX message 2")?;
                        self.phase = Phase::ResponderAwait3 { hs };
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
            Phase::ResponderAwait3 { mut hs } => {
                read(&mut hs, message, "XX message 3")?;
                Ok(Step {
                    reply: None,
                    open: Some(finish(hs, LinkKind::Pairing)?),
                })
            }
            Phase::Done => Err(refuse("handshake message after the handshake")),
        }
    }
}

fn random_pad() -> Vec<u8> {
    let mut pad = vec![0u8; EPHEMERAL_PAD];
    rand::fill(&mut pad[..]);
    pad
}

/// The 6-digit code both people compare when pairing (§B14.4):
/// `u32_be(handshake_hash[0..4]) mod 1 000 000`, zero-padded.
pub fn short_code(handshake_hash: &[u8; 32]) -> String {
    let n = u32::from_be_bytes(handshake_hash[..4].try_into().expect("4 bytes")) % 1_000_000;
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
    use crate::link::keys::noise_public_key;

    fn keypair(n: u8) -> ([u8; 32], [u8; 32]) {
        let secret = [n; 32];
        (secret, noise_public_key(&secret))
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

    /// Spec §10 "first-message size": IK and NN (and XX) message 1 look the
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
        let firsts: Vec<Vec<u8>> = targets
            .iter()
            .map(|t| Handshake::dial(t, &s).unwrap().1)
            .collect();
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
        let (_, a) = Handshake::dial(&DialTarget::Relay, &s).unwrap();
        let (_, b) = Handshake::dial(&DialTarget::Relay, &s).unwrap();
        assert_ne!(a[33..], b[33..]);
        assert!(a[33..].iter().any(|&x| x != 0));
    }

    /// Spec §10 "IK contact link" (handshake level).
    #[test]
    fn a_contact_link_authenticates_both_statics() {
        let (a, a_pub) = keypair(1);
        let (b, b_pub) = keypair(2);
        let (dialer, responder) = run(
            Handshake::dial(
                &DialTarget::Contact {
                    remote_static: b_pub,
                },
                &a,
            )
            .unwrap(),
            Handshake::accept(&b, false, false),
        )
        .unwrap();
        assert_eq!(
            (dialer.kind, responder.kind),
            (LinkKind::Contact, LinkKind::Contact)
        );
        assert_eq!(responder.remote_static, Some(a_pub));
        assert_eq!(dialer.remote_static, Some(b_pub));
        assert_eq!(dialer.handshake_hash, responder.handshake_hash);
        assert!(dialer.initiator && !responder.initiator);
    }

    /// Spec §10 "wrong static": the dialer takes a stranger for a contact.
    /// The stranger reads a relay link; the dialer's IK fails cleanly, and
    /// its static key never appears in the clear.
    #[test]
    fn a_wrong_static_falls_back_to_relay_and_hides_the_dialer() {
        let (a, a_pub) = keypair(1);
        let (b, _) = keypair(2);
        let (_, c_pub) = keypair(3);
        let (mut dialer, msg1) = Handshake::dial(
            &DialTarget::Contact {
                remote_static: c_pub,
            },
            &a,
        )
        .unwrap();
        assert!(!msg1.windows(32).any(|w| w == a_pub));
        let mut stranger = Handshake::accept(&b, false, true);
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
        let (dialer, responder) = run(
            Handshake::dial(&DialTarget::Relay, &a).unwrap(),
            Handshake::accept(&b, false, true),
        )
        .unwrap();
        assert_eq!(
            (dialer.kind, responder.kind),
            (LinkKind::Relay, LinkKind::Relay)
        );
        assert_eq!(
            (dialer.remote_static, responder.remote_static),
            (None, None)
        );
        let (_, msg1) = Handshake::dial(&DialTarget::Relay, &a).unwrap();
        assert!(matches!(
            Handshake::accept(&b, false, false).read(&msg1),
            Err(MeshError::LinkAuthFailed(_))
        ));
    }

    /// Spec §10 "pairing XX": one code on both phones; a middle phone that
    /// relays the pairing runs two handshakes and shows two codes.
    #[test]
    fn pairing_shows_one_code_and_a_middle_phone_two() {
        let (a, a_pub) = keypair(1);
        let (b, b_pub) = keypair(2);
        let (m, _) = keypair(3);
        let (dialer, responder) = run(
            Handshake::dial(&DialTarget::Pairing, &a).unwrap(),
            Handshake::accept(&b, true, false),
        )
        .unwrap();
        assert_eq!(
            (dialer.kind, responder.kind),
            (LinkKind::Pairing, LinkKind::Pairing)
        );
        assert_eq!(
            (dialer.remote_static, responder.remote_static),
            (Some(b_pub), Some(a_pub))
        );
        assert_eq!(
            short_code(&dialer.handshake_hash),
            short_code(&responder.handshake_hash)
        );
        let (a_side, m_left) = run(
            Handshake::dial(&DialTarget::Pairing, &a).unwrap(),
            Handshake::accept(&m, true, false),
        )
        .unwrap();
        let (m_right, b_side) = run(
            Handshake::dial(&DialTarget::Pairing, &m).unwrap(),
            Handshake::accept(&b, true, false),
        )
        .unwrap();
        assert_eq!(
            short_code(&a_side.handshake_hash),
            short_code(&m_left.handshake_hash)
        );
        assert_eq!(
            short_code(&m_right.handshake_hash),
            short_code(&b_side.handshake_hash)
        );
        assert_ne!(
            short_code(&a_side.handshake_hash),
            short_code(&b_side.handshake_hash)
        );
    }

    #[test]
    fn pairing_needs_pairing_mode() {
        let (a, _) = keypair(1);
        let (b, _) = keypair(2);
        let (_, msg1) = Handshake::dial(&DialTarget::Pairing, &a).unwrap();
        assert!(matches!(
            Handshake::accept(&b, false, true).read(&msg1),
            Err(MeshError::LinkAuthFailed(_))
        ));
    }

    #[test]
    fn malformed_handshake_messages_are_refused() {
        let (b, _) = keypair(2);
        assert!(
            Handshake::accept(&b, true, true).read(&[0; 127]).is_err(),
            "too short"
        );
        let mut unknown = vec![9u8; FIRST_MESSAGE_LEN];
        unknown[0] = 9;
        assert!(
            Handshake::accept(&b, true, true).read(&unknown).is_err(),
            "unknown kind"
        );
        let (a, _) = keypair(1);
        let (mut d, msg1) = Handshake::dial(&DialTarget::Relay, &a).unwrap();
        let mut r = Handshake::accept(&b, false, true);
        let reply = r.read(&msg1).unwrap().reply.unwrap();
        d.read(&reply).unwrap();
        assert!(d.read(&reply).is_err(), "a message after the handshake");
    }

    #[test]
    fn the_short_code_is_six_digits_of_the_hash() {
        assert_eq!(short_code(&[0xab; 32]), "154539");
        assert_eq!(short_code(&[0; 32]), "000000");
    }
}
