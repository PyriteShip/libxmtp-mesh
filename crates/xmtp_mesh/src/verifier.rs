use alloy::primitives::{BlockNumber, Bytes};
use xmtp_id::scw_verifier::{SmartContractSignatureVerifier, ValidationResponse, VerifierError};

/// The mesh supports only EOA identities. EOA and installation signatures are
/// verified locally by xmtp_id; any smart-contract-wallet check is answered "invalid".
#[derive(Clone, Copy, Debug, Default)]
pub struct EoaOnlyVerifier;

#[xmtp_common::async_trait]
impl SmartContractSignatureVerifier for EoaOnlyVerifier {
    async fn is_valid_signature(
        &self,
        _account_id: xmtp_id::associations::AccountId,
        _hash: [u8; 32],
        _signature: Bytes,
        _block_number: Option<BlockNumber>,
    ) -> Result<ValidationResponse, VerifierError> {
        Ok(ValidationResponse {
            is_valid: false,
            block_number: None,
            error: Some("smart contract wallets are not supported on the mesh".into()),
        })
    }
}
