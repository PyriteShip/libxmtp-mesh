use xmtp_id::associations::verify_signed_with_public_context;
use xmtp_mls::context::XmtpSharedContext;

use crate::MeshError;

/// Signs hello challenges with this device's XMTP installation key.
pub trait HelloSigner: Send + Sync {
    fn installation_key(&self) -> Vec<u8>;
    fn sign(&self, text: &str) -> Result<Vec<u8>, MeshError>;
}

/// The production [`HelloSigner`]: signs with an xmtp_mls client's
/// installation key (`sign_with_public_context`).
pub struct ClientHelloSigner<C>(pub xmtp_mls::Client<C>);

impl<C> HelloSigner for ClientHelloSigner<C>
where
    C: XmtpSharedContext + Send + Sync,
{
    fn installation_key(&self) -> Vec<u8> {
        self.0.installation_public_key().to_vec()
    }

    fn sign(&self, text: &str) -> Result<Vec<u8>, MeshError> {
        self.0
            .context
            .identity()
            .sign_with_public_context(text)
            .map_err(|e| MeshError::AuthFailed(e.to_string()))
    }
}

/// Text the responder signs: binds the challenger's nonce, both parties'
/// installation keys and the link's Noise handshake hash (§B14.4), so a
/// signature made for one verifier, reflected back at its own signer, or
/// relayed from another link never verifies.
pub(crate) fn hello_text(
    challenge: &[u8],
    signer_installation: &[u8],
    verifier_installation: &[u8],
    binding: &[u8; 32],
) -> String {
    format!(
        "xmtp-mesh-hello-v2:{}:{}:{}:{}",
        hex::encode(challenge),
        hex::encode(signer_installation),
        hex::encode(verifier_installation),
        hex::encode(binding)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// §B14.4: the Auth signature covers the Noise handshake hash, so an
    /// Auth made on one link never verifies on another.
    #[test]
    fn the_hello_text_binds_the_link() {
        let text = hello_text(&[1; 2], &[2; 2], &[3; 2], &[4; 32]);
        assert_eq!(
            text,
            format!("xmtp-mesh-hello-v2:0101:0202:0303:{}", "04".repeat(32))
        );
        assert_ne!(text, hello_text(&[1; 2], &[2; 2], &[3; 2], &[5; 32]));
    }
}
