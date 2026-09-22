use openmls::framing::ContentType;
use openmls::prelude::{MlsMessageIn, ProtocolMessage, tls_codec::Deserialize};
use openmls_rust_crypto::RustCrypto;
use xmtp_mls::verified_key_package_v2::VerifiedKeyPackageV2;

use crate::MeshError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedGroupMessage {
    pub group_id: Vec<u8>,
    pub is_commit: bool,
    pub epoch: u64,
}

/// Read the plaintext MLS framing: group id, content type and epoch.
pub(crate) fn parse_group_message(data: &[u8]) -> Result<ParsedGroupMessage, MeshError> {
    let message = MlsMessageIn::tls_deserialize(&mut &data[..])
        .map_err(|e| MeshError::InvalidMls(e.to_string()))?;
    let protocol: ProtocolMessage = message
        .try_into_protocol_message()
        .map_err(|e| MeshError::InvalidMls(e.to_string()))?;
    Ok(ParsedGroupMessage {
        group_id: protocol.group_id().as_slice().to_vec(),
        is_commit: protocol.content_type() == ContentType::Commit,
        epoch: protocol.epoch().as_u64(),
    })
}

/// Verify a TLS-serialized key package and return its installation public key.
pub(crate) fn verify_key_package(bytes: &[u8]) -> Result<Vec<u8>, MeshError> {
    let crypto = RustCrypto::default();
    let kp = VerifiedKeyPackageV2::from_bytes(&crypto, bytes)
        .map_err(|e| MeshError::InvalidKeyPackage(e.to_string()))?;
    Ok(kp.installation_public_key)
}
