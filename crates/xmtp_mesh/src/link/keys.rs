//! Link keys derived from the account key, and advert tokens (§B14.1,
//! §B14.2, D32, D34). The account key itself is never stored.
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::MeshError;

/// Discovery window: tokens rotate every 15 minutes (D32).
pub const WINDOW_SECS: u64 = 900;
/// Service-data version of private discovery (§B14.2).
pub const ADVERT_VERSION: u8 = 2;
/// Service data: `version ‖ flags ‖ token`.
pub const ADVERT_LEN: usize = 10;
pub const TOKEN_LEN: usize = 8;
/// Advert flag: this phone is in pairing mode.
pub const FLAG_PAIRING: u8 = 0x01;
/// Advert flag: this phone relays for strangers.
pub const FLAG_RELAY: u8 = 0x02;

pub type Token = [u8; TOKEN_LEN];

const KEYS_SALT: &[u8] = b"xmtp-mesh-keys-v1";

/// HKDF-Extract of the account key (§B14.1). Held in memory only.
pub(crate) struct AccountPrk(Zeroizing<[u8; 32]>);

impl AccountPrk {
    pub(crate) fn extract(account_secret: &[u8]) -> Result<Self, MeshError> {
        if account_secret.len() != 32 {
            return Err(MeshError::InvalidRequest(
                "account key must be 32 bytes".into(),
            ));
        }
        let (prk, _) = Hkdf::<Sha256>::extract(Some(KEYS_SALT), account_secret);
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&prk);
        Ok(Self(out))
    }

    fn expand(&self, info: &[&[u8]]) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::from_prk(self.0.as_slice()).expect("a 32-byte PRK is valid");
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand_multi_info(info, okm.as_mut_slice())
            .expect("32 bytes is a valid HKDF output length");
        okm
    }
}

/// This phone's link keys for one inbox and discovery generation (§B14.1).
pub(crate) struct MeshKeys {
    /// X25519 secret of the Noise static key (clamped by the DH, not here).
    pub(crate) noise_secret: Zeroizing<[u8; 32]>,
    pub(crate) noise_public: [u8; 32],
    pub(crate) discovery_key: Zeroizing<[u8; 32]>,
    pub(crate) generation: u32,
    pub(crate) inbox_id: String,
}

impl MeshKeys {
    pub(crate) fn derive(prk: &AccountPrk, inbox_id: &str, generation: u32) -> Self {
        let noise_secret = prk.expand(&[b"noise-static", inbox_id.as_bytes()]);
        let noise_public = noise_public_key(&noise_secret);
        let discovery_key =
            prk.expand(&[b"discovery", inbox_id.as_bytes(), &generation.to_be_bytes()]);
        Self {
            noise_secret,
            noise_public,
            discovery_key,
            generation,
            inbox_id: inbox_id.to_string(),
        }
    }

    pub(crate) fn own_token(&self, window: u64) -> Token {
        advert_token(&*self.discovery_key, window)
    }
}

/// The X25519 public key of `secret`, as snow computes it.
pub(crate) fn noise_public_key(secret: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).to_bytes()
}

/// `floor(unix_secs / 900)` (§B14.2).
pub fn window_at(unix_secs: u64) -> u64 {
    unix_secs / WINDOW_SECS
}

/// `trunc8(HMAC-SHA256(discovery_key, u64_be(window)))` (§B14.2).
pub fn advert_token(discovery_key: &[u8], window: u64) -> Token {
    let mut mac = Hmac::<Sha256>::new_from_slice(discovery_key).expect("HMAC takes any key length");
    mac.update(&window.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    let mut token = [0u8; TOKEN_LEN];
    token.copy_from_slice(&tag[..TOKEN_LEN]);
    token
}

/// The advert's service data: `2 ‖ flags ‖ token`.
pub fn service_data(flags: u8, token: &Token) -> [u8; ADVERT_LEN] {
    let mut out = [0u8; ADVERT_LEN];
    out[0] = ADVERT_VERSION;
    out[1] = flags;
    out[2..].copy_from_slice(token);
    out
}

/// `(flags, token)` of a version-2 advert; `None` for anything else.
pub fn parse_service_data(bytes: &[u8]) -> Option<(u8, Token)> {
    if bytes.len() != ADVERT_LEN || bytes[0] != ADVERT_VERSION {
        return None;
    }
    let mut token = [0u8; TOKEN_LEN];
    token.copy_from_slice(&bytes[2..]);
    Some((bytes[1], token))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INBOX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER_INBOX: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn prk() -> AccountPrk {
        AccountPrk::extract(&[0x11; 32]).unwrap()
    }

    /// Fixed vectors (§B14.1): HKDF-SHA256 with the salt and info labels of §B14.1.
    #[test]
    fn keys_derive_from_the_account_key() {
        let k = MeshKeys::derive(&prk(), INBOX, 0);
        assert_eq!(
            hex::encode(*k.noise_secret),
            "d882c72abdfddce3d64758b80d279d98b7c34f750216c676ed3a02f1622788b0"
        );
        assert_eq!(
            hex::encode(k.noise_public),
            "8e5c143a1d65d455f9eb786c96b4c488b2b12390867c4b61ccb758e4afb75b66"
        );
        assert_eq!(
            hex::encode(*k.discovery_key),
            "2714879bd59af8710652bf7fdf8dd73ed4969d49e8f6ed6e35d2199015ce951b"
        );
        let k1 = MeshKeys::derive(&prk(), INBOX, 1);
        assert_eq!(
            hex::encode(*k1.discovery_key),
            "d1507a17e4ee689aff81ea96c84ac397103663b414d6cd1fc5b372d448040158"
        );
        assert_eq!(
            k1.noise_public, k.noise_public,
            "a reset keeps the static key"
        );
        let other_inbox = MeshKeys::derive(&prk(), OTHER_INBOX, 0);
        assert_eq!(
            hex::encode(*other_inbox.noise_secret),
            "862f7e6d01e77985ccdfef1db99ec0327ee9eb9f1d3b5de558a1b4e7f3b5e31c"
        );
        assert_ne!(*other_inbox.discovery_key, *k.discovery_key);
        let other_account = MeshKeys::derive(&AccountPrk::extract(&[0x12; 32]).unwrap(), INBOX, 0);
        assert_ne!(other_account.noise_public, k.noise_public);
        assert_ne!(*other_account.discovery_key, *k.discovery_key);
    }

    #[test]
    fn tokens_are_the_first_8_bytes_of_hmac_of_the_window() {
        let k0 = MeshKeys::derive(&prk(), INBOX, 0);
        assert_eq!(hex::encode(k0.own_token(0)), "cbc32251a36ef46e");
        assert_eq!(hex::encode(k0.own_token(1_966_000)), "621f0e0371a79d09");
        let k1 = MeshKeys::derive(&prk(), INBOX, 1);
        assert_eq!(hex::encode(k1.own_token(0)), "887aec40cd9d9e8c");
        assert_eq!(hex::encode(k1.own_token(1_966_000)), "6d2c149c09de86c4");
        assert_eq!(k0.own_token(5), advert_token(&*k0.discovery_key, 5));
    }

    #[test]
    fn windows_are_fifteen_minutes() {
        assert_eq!(window_at(0), 0);
        assert_eq!(window_at(899), 0);
        assert_eq!(window_at(900), 1);
        assert_eq!(window_at(1_769_400_000), 1_966_000);
    }

    #[test]
    fn service_data_is_version_flags_token() {
        let token = [7u8; TOKEN_LEN];
        let data = service_data(FLAG_PAIRING | FLAG_RELAY, &token);
        assert_eq!(data, [2, 3, 7, 7, 7, 7, 7, 7, 7, 7]);
        assert_eq!(parse_service_data(&data), Some((3, token)));
        assert_eq!(
            parse_service_data(&[1, 0, 7, 7, 7, 7, 7, 7, 7, 7]),
            None,
            "a version-1 (short id) advert"
        );
        assert_eq!(parse_service_data(&data[..9]), None);
    }

    #[test]
    fn an_account_key_must_be_32_bytes() {
        assert!(AccountPrk::extract(&[1; 31]).is_err());
        assert!(AccountPrk::extract(&[1; 33]).is_err());
    }
}
