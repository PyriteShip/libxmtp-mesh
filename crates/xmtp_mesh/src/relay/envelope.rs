//! Sealing a relay envelope (spec §4.2–§4.3). Layout of `sealed`:
//! `tag (16) ‖ expires_at (u64 BE) ‖ reserved (16) ‖ nonce (12) ‖ AES-256-GCM(len (u32 BE) ‖ body ‖ zero padding)`,
//! padded so the whole is exactly one of [`BUCKETS`]. The first 40 bytes
//! (the header) are what relays see; they are the GCM associated data.
//! The tag is per envelope: `HMAC(relay_key, TAG_INFO ‖ nonce)`, so two
//! envelopes of one DM share no visible bytes (spec §4.3). `expires_at` is
//! coarse: a multiple of 600 s past the hold plus random jitter (§4.2).
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use rand::RngExt;

use crate::MeshError;

pub(crate) const BUCKETS: [usize; 4] = [512, 1024, 4096, 16384];
pub(crate) const TAG_LEN: usize = 16;
pub(crate) const HEADER_LEN: usize = TAG_LEN + 8 + 16;
const NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;
const LEN_PREFIX: usize = 4;
/// Bytes of a sealed envelope that are not body.
pub(crate) const OVERHEAD: usize = HEADER_LEN + NONCE_LEN + GCM_TAG_LEN + LEN_PREFIX;
pub(crate) const MAX_BODY_LEN: usize = BUCKETS[3] - OVERHEAD;
/// Largest hop budget an envelope may carry (spec §8).
pub(crate) const MAX_TTL: u32 = 7;

const TAG_INFO: &[u8] = b"xmtp-mesh relay tag v1";
const SEAL_INFO: &[u8] = b"xmtp-mesh relay seal v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub tag: [u8; TAG_LEN],
    pub expires_at: u64,
    /// Random, ignored; keeps the layout stable for a later header field.
    pub reserved: [u8; 16],
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..16].copy_from_slice(&self.tag);
        out[16..24].copy_from_slice(&self.expires_at.to_be_bytes());
        out[24..40].copy_from_slice(&self.reserved);
        out
    }
}

/// Expiry bucket size in seconds (spec §4.2; phase 2 raises it to 3600).
pub(crate) const EXPIRY_BUCKET_SECS: u64 = 600;

/// A coarse expiry: `now + hold + jitter`, rounded up to the next
/// [`EXPIRY_BUCKET_SECS`] boundary, so the value never reveals the origin
/// time to better than a bucket.
pub(crate) fn coarse_expiry(now_secs: u64, hold_secs: u64) -> u64 {
    let jitter = rand::rng().random_range(0..EXPIRY_BUCKET_SECS);
    let raw = now_secs + hold_secs + jitter;
    raw.div_ceil(EXPIRY_BUCKET_SECS) * EXPIRY_BUCKET_SECS
}

fn tag_mac(relay_key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(relay_key).expect("HMAC takes any key");
    mac.update(TAG_INFO);
    mac.update(nonce);
    mac
}

/// `HMAC-SHA256(relay_key, TAG_INFO ‖ nonce)`, first 16 bytes.
pub(crate) fn tag_for(relay_key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; TAG_LEN] {
    let out = tag_mac(relay_key, nonce).finalize().into_bytes();
    out[..TAG_LEN].try_into().expect("16 of 32 bytes")
}

fn seal_cipher(relay_key: &[u8; 32]) -> Aes256Gcm {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, relay_key)
        .expand(SEAL_INFO, &mut key)
        .expect("32 bytes is a valid HKDF length");
    Aes256Gcm::new_from_slice(&key).expect("32-byte key")
}

fn bucket_for(body_len: usize) -> Option<usize> {
    BUCKETS.into_iter().find(|b| body_len + OVERHEAD <= *b)
}

/// Seal `body` for the DM whose key is `relay_key`. `expires_at` should
/// come from [`coarse_expiry`].
pub(crate) fn seal(
    relay_key: &[u8; 32],
    expires_at: u64,
    body: &[u8],
) -> Result<Vec<u8>, MeshError> {
    let bucket = bucket_for(body.len()).ok_or_else(|| {
        MeshError::Relay(format!(
            "relay body of {} bytes exceeds {MAX_BODY_LEN}",
            body.len()
        ))
    })?;
    let nonce: [u8; NONCE_LEN] = rand::random();
    let header = Header {
        tag: tag_for(relay_key, &nonce),
        expires_at,
        reserved: rand::random(),
    }
    .encode();
    let plain_len = bucket - HEADER_LEN - NONCE_LEN - GCM_TAG_LEN;
    let mut plaintext = Vec::with_capacity(plain_len);
    plaintext.extend_from_slice(&(body.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(body);
    plaintext.resize(plain_len, 0);
    let ciphertext = seal_cipher(relay_key)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| MeshError::Relay("seal failed".into()))?;
    let mut sealed = Vec::with_capacity(bucket);
    sealed.extend_from_slice(&header);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    debug_assert_eq!(sealed.len(), bucket);
    Ok(sealed)
}

/// The relay-visible header, or `None` when `sealed` is not a bucket size.
pub(crate) fn header(sealed: &[u8]) -> Option<Header> {
    if !BUCKETS.contains(&sealed.len()) {
        return None;
    }
    Some(Header {
        tag: sealed[..16].try_into().ok()?,
        expires_at: u64::from_be_bytes(sealed[16..24].try_into().ok()?),
        reserved: sealed[24..40].try_into().ok()?,
    })
}

/// Whether `sealed` is tagged for `relay_key`: recompute the tag from the
/// envelope's nonce and compare in constant time (`verify_truncated_left`
/// is the constant-time check for a truncated MAC).
pub(crate) fn matches(relay_key: &[u8; 32], sealed: &[u8]) -> bool {
    let Some(h) = header(sealed) else {
        return false;
    };
    let nonce: [u8; NONCE_LEN] = match sealed[HEADER_LEN..HEADER_LEN + NONCE_LEN].try_into() {
        Ok(n) => n,
        Err(_) => return false,
    };
    tag_mac(relay_key, &nonce)
        .verify_truncated_left(&h.tag)
        .is_ok()
}

pub(crate) fn open(relay_key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, MeshError> {
    if header(sealed).is_none() {
        return Err(MeshError::Relay("not a relay bucket size".into()));
    }
    let (hdr, rest) = sealed.split_at(HEADER_LEN);
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    let plaintext = seal_cipher(relay_key)
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: hdr,
            },
        )
        .map_err(|_| MeshError::Relay("open failed".into()))?;
    let len = u32::from_be_bytes(plaintext[..LEN_PREFIX].try_into().expect("4 bytes")) as usize;
    if len > plaintext.len() - LEN_PREFIX {
        return Err(MeshError::Relay("bad relay body length".into()));
    }
    Ok(plaintext[LEN_PREFIX..LEN_PREFIX + len].to_vec())
}

pub(crate) fn hash(sealed: &[u8]) -> [u8; 32] {
    Sha256::digest(sealed).into()
}

/// The 8-byte id used in `SpoolDigest` / `SpoolWant` (spec §5.2).
pub(crate) fn short_id(hash: &[u8; 32]) -> [u8; 8] {
    hash[..8].try_into().expect("8 of 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    #[test]
    fn sealed_sizes_are_exactly_a_bucket() {
        for (body_len, bucket) in [
            (0, 512),
            (512 - OVERHEAD, 512),
            (512 - OVERHEAD + 1, 1024),
            (4096 - OVERHEAD, 4096),
            (MAX_BODY_LEN, 16384),
        ] {
            let sealed = seal(&KEY, 99, &vec![1u8; body_len]).unwrap();
            assert_eq!(sealed.len(), bucket, "body {body_len}");
            assert!(header(&sealed).is_some());
        }
        assert!(seal(&KEY, 99, &vec![1u8; MAX_BODY_LEN + 1]).is_err());
    }

    #[test]
    fn open_round_trips_and_needs_the_key() {
        let body = b"hello relay".to_vec();
        let sealed = seal(&KEY, 1_000, &body).unwrap();
        assert_eq!(open(&KEY, &sealed).unwrap(), body);
        assert!(open(&[8; 32], &sealed).is_err());
        assert_eq!(header(&sealed).unwrap().expires_at, 1_000);
    }

    #[test]
    fn header_is_authenticated() {
        let mut sealed = seal(&KEY, 1_000, b"x").unwrap();
        sealed[20] ^= 1; // expires_at, inside the AAD
        assert!(open(&KEY, &sealed).is_err());
    }

    #[test]
    fn tag_is_per_envelope_and_keyed() {
        let a = seal(&KEY, 1, b"x").unwrap();
        let b = seal(&KEY, 1, b"x").unwrap();
        assert!(matches(&KEY, &a));
        assert!(matches(&KEY, &b));
        assert!(!matches(&[8; 32], &a));
        assert_ne!(
            header(&a).unwrap().tag,
            header(&b).unwrap().tag,
            "fresh nonce, fresh tag"
        );
        let mut tampered = a.clone();
        tampered[41] ^= 1; // nonce byte: the tag no longer matches
        assert!(!matches(&KEY, &tampered));
        assert!(!matches(&KEY, &[0u8; 511]));
    }

    #[test]
    fn coarse_expiry_is_a_600s_multiple_past_the_hold() {
        for _ in 0..50 {
            let e = coarse_expiry(1_000_000, 600);
            assert_eq!(e % 600, 0);
            assert!(e >= 1_000_000 + 600, "never before now + hold");
            assert!(
                e <= 1_000_000 + 600 + 600 + 600,
                "at most hold + jitter + rounding"
            );
        }
    }

    #[test]
    fn non_bucket_sizes_have_no_header() {
        assert!(header(&[0u8; 511]).is_none());
        assert!(header(&[0u8; 513]).is_none());
        assert!(header(&[0u8; 20000]).is_none());
    }

    /// Spec §10.3: nothing of the body is visible in the sealed bytes.
    #[test]
    fn body_bytes_never_appear_in_the_clear() {
        let marker = [0xAB; 32];
        let sealed = seal(&KEY, 1, &marker).unwrap();
        assert!(!sealed.windows(8).any(|w| marker.windows(8).any(|m| m == w)));
    }

    #[test]
    fn two_seals_of_one_body_differ() {
        let a = seal(&KEY, 1, b"same").unwrap();
        let b = seal(&KEY, 1, b"same").unwrap();
        assert_ne!(
            hash(&a),
            hash(&b),
            "fresh nonce and ack commit: a retry is a new envelope"
        );
    }
}
