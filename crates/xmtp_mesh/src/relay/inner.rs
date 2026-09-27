//! What a relay envelope carries (§R4.6), readable only by the two DM
//! members. Relays never see or check any of it.
use prost::Message;
use xmtp_proto::mls_v1::GroupMessageInput;

use crate::MeshError;
use crate::store::sha256;
use crate::sync::HelloSigner;
use crate::sync::auth;

/// Upper bound on what [`sign`] adds around a payload: 32 B key, 64 B
/// signature, prost tags and lengths.
pub(crate) const SIGNED_OVERHEAD: usize = 160;

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct SignedRelayBody {
    #[prost(bytes = "vec", tag = "1")]
    pub payload: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signer_installation: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct RelayPayload {
    #[prost(oneof = "relay_payload::Body", tags = "1, 2")]
    pub body: Option<relay_payload::Body>,
}

pub(crate) mod relay_payload {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(crate) enum Body {
        #[prost(message, tag = "1")]
        Pending(super::RelayPending),
        #[prost(message, tag = "2")]
        Sync(super::RelaySync),
    }
}

/// Joiner → sequencer: unsequenced messages plus the highest sequenced id
/// the joiner holds (its ack). Empty `messages` is a pure ack.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct RelayPending {
    #[prost(bytes = "vec", tag = "1")]
    pub group_id: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub messages: Vec<GroupMessageInput>,
    #[prost(uint64, tag = "3")]
    pub acked_high: u64,
    /// Set when the joiner could not resolve a `Ref` after this id (it
    /// lacks the pending copy, e.g. another installation of its inbox sent
    /// it): the sequencer answers with `Full` rows after it. Optional, not
    /// `0 = none`: a fresh installation stalls with `acked_high` 0.
    #[prost(uint64, optional, tag = "4")]
    pub need_full_after: Option<u64>,
}

/// Sequencer → joiner: sequenced rows after the joiner's last acked id, in order.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct RelaySync {
    #[prost(bytes = "vec", tag = "1")]
    pub group_id: Vec<u8>,
    #[prost(message, repeated, tag = "2")]
    pub rows: Vec<RelayRow>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct RelayRow {
    #[prost(oneof = "relay_row::Row", tags = "1, 2")]
    pub row: Option<relay_row::Row>,
    /// The row's sequencing proof (§B13). An empty `signer` means the
    /// `SignedRelayBody`'s `signer_installation`.
    #[prost(message, optional, tag = "3")]
    pub proof: Option<crate::sync::seq::SeqProof>,
}

pub(crate) mod relay_row {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(crate) enum Row {
        #[prost(message, tag = "1")]
        Full(xmtp_proto::mls_v1::GroupMessage),
        /// A row the joiner itself sent: it rebuilds it from its pending copy.
        #[prost(message, tag = "2")]
        Reference(super::RowRef),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct RowRef {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(uint64, tag = "2")]
    pub created_ns: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub data_hash: Vec<u8>,
}

fn signing_text(payload: &[u8]) -> String {
    format!("xmtp-mesh-relay-v1:{}", hex::encode(sha256(payload)))
}

pub(crate) fn sign(signer: &dyn HelloSigner, payload: &RelayPayload) -> Result<Vec<u8>, MeshError> {
    let payload = payload.encode_to_vec();
    let signature = signer
        .sign(&signing_text(&payload))
        .map_err(|e| MeshError::Relay(e.to_string()))?;
    Ok(SignedRelayBody {
        payload,
        signer_installation: signer.installation_key(),
        signature,
    }
    .encode_to_vec())
}

pub(crate) fn verify(body: &[u8]) -> Result<(Vec<u8>, RelayPayload), MeshError> {
    let signed = SignedRelayBody::decode(body).map_err(|e| MeshError::Relay(e.to_string()))?;
    auth::verify(
        &signing_text(&signed.payload),
        &signed.signature,
        &signed.signer_installation,
    )
    .map_err(|e| MeshError::Relay(e.to_string()))?;
    let payload = RelayPayload::decode(signed.payload.as_slice())
        .map_err(|e| MeshError::Relay(e.to_string()))?;
    Ok((signed.signer_installation, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmtp_cryptography::{CredentialSign, XmtpInstallationCredential};

    struct KeySigner(XmtpInstallationCredential);

    impl HelloSigner for KeySigner {
        fn installation_key(&self) -> Vec<u8> {
            self.0.public_slice().to_vec()
        }
        fn sign(&self, text: &str) -> Result<Vec<u8>, MeshError> {
            self.0
                .credential_sign::<xmtp_id::associations::signature::PublicContext>(text)
                .map_err(|e| MeshError::AuthFailed(e.to_string()))
        }
    }

    fn pending() -> RelayPayload {
        RelayPayload {
            body: Some(relay_payload::Body::Pending(RelayPending {
                group_id: vec![1; 16],
                messages: vec![],
                acked_high: 9,
                need_full_after: None,
            })),
        }
    }

    #[test]
    fn sign_then_verify_returns_signer_and_payload() {
        let signer = KeySigner(XmtpInstallationCredential::new());
        let body = sign(&signer, &pending()).unwrap();
        let (who, payload) = verify(&body).unwrap();
        assert_eq!(who, signer.installation_key());
        assert_eq!(payload, pending());
        assert!(body.len() <= pending().encoded_len() + SIGNED_OVERHEAD);
    }

    #[test]
    fn tampered_payload_or_swapped_signer_fails() {
        let signer = KeySigner(XmtpInstallationCredential::new());
        let mut signed =
            SignedRelayBody::decode(sign(&signer, &pending()).unwrap().as_slice()).unwrap();
        signed.payload.push(0);
        assert!(verify(&signed.encode_to_vec()).is_err());

        let mut signed =
            SignedRelayBody::decode(sign(&signer, &pending()).unwrap().as_slice()).unwrap();
        signed.signer_installation = XmtpInstallationCredential::new().public_slice().to_vec();
        assert!(verify(&signed.encode_to_vec()).is_err());
    }

    #[test]
    fn verify_errors_are_relay_errors_never_fatal() {
        let err = verify(b"garbage").unwrap_err();
        assert!(!err.is_fatal(), "{err}");
    }
}
