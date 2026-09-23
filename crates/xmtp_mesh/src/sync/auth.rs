use xmtp_id::associations::verify_signed_with_public_context;

use crate::MeshError;

/// Signs hello challenges with this device's XMTP installation key.
pub trait HelloSigner: Send + Sync {
    fn installation_key(&self) -> Vec<u8>;
    fn sign(&self, text: &str) -> Result<Vec<u8>, MeshError>;
}

/// Text the responder signs: binds the challenger's nonce to both parties'
/// installation keys, so a signature made for one verifier (or reflected back
/// at its own signer) never verifies for another.
pub(crate) fn hello_text(challenge: &[u8], signer_installation: &[u8], verifier_installation: &[u8]) -> String {
    format!(
        "pyrechat-mesh-hello-v1:{}:{}:{}",
        hex::encode(challenge),
        hex::encode(signer_installation),
        hex::encode(verifier_installation)
    )
}

pub(crate) fn verify(text: &str, signature: &[u8], installation: &[u8]) -> Result<(), MeshError> {
    let signature: &[u8; 64] = signature
        .try_into()
        .map_err(|_| MeshError::AuthFailed("signature must be 64 bytes".into()))?;
    let key: &[u8; 32] = installation
        .try_into()
        .map_err(|_| MeshError::AuthFailed("installation key must be 32 bytes".into()))?;
    verify_signed_with_public_context(text, signature, key)
        .map_err(|e| MeshError::AuthFailed(e.to_string()))
}
