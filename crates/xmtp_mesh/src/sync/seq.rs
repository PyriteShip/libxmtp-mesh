//! Signed sequencing records (DESIGN.md §B13, D30). The installation that
//! gives a row its id signs a record of it; every node checks that
//! signature before it stores a row from someone else. The record follows
//! XMTP d14n's `UnsignedOriginatorEnvelope` field names; the key is the
//! installation's ed25519 key. Only the proof travels: a verifier rebuilds
//! the record from the row it received.
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use prost::Message;

use super::auth::{self, HelloSigner};
use crate::MeshError;
use crate::store::sha256;

/// Prefix of the text a sequencing record's signature covers. Distinct from
/// the handshake's and the relay's, so no signature verifies as another kind.
pub const SEQ_TEXT_PREFIX: &str = "xmtp-mesh-seq-v1:";

/// What the installation that ordered a row signs (§B13).
#[derive(Clone, PartialEq, prost::Message)]
pub struct SeqRecord {
    /// The signer's 32-byte installation key.
    #[prost(bytes = "vec", tag = "1")]
    pub originator_installation: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub group_id: Vec<u8>,
    /// The row's id.
    #[prost(uint64, tag = "3")]
    pub originator_sequence_id: u64,
    /// The row's `created_ns`.
    #[prost(uint64, tag = "4")]
    pub originator_ns: u64,
    /// `sha256(GroupMessage.data)`.
    #[prost(bytes = "vec", tag = "5")]
    pub payload_hash: Vec<u8>,
}

/// A row's signature and who made it. Travels next to the row; `signer`
/// may be empty on a relayed row, meaning the envelope's signer (§R4.6).
#[derive(Clone, PartialEq, prost::Message)]
pub struct SeqProof {
    #[prost(bytes = "vec", tag = "1")]
    pub signer: Vec<u8>,
    /// 64-byte ed25519 signature over [`SeqRecord::signing_text`].
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
}

impl SeqRecord {
    pub fn new(
        signer: &[u8],
        group_id: &[u8],
        id: u64,
        created_ns: u64,
        payload_hash: Vec<u8>,
    ) -> Self {
        Self {
            originator_installation: signer.to_vec(),
            group_id: group_id.to_vec(),
            originator_sequence_id: id,
            originator_ns: created_ns,
            payload_hash,
        }
    }

    /// `"xmtp-mesh-seq-v1:" + hex(sha256(encoded record))`.
    pub fn signing_text(&self) -> String {
        format!(
            "{SEQ_TEXT_PREFIX}{}",
            hex::encode(sha256(&self.encode_to_vec()))
        )
    }

    /// Whether `signature` is `originator_installation`'s over this record.
    pub fn verify(&self, signature: &[u8]) -> bool {
        auth::verify(
            &self.signing_text(),
            signature,
            &self.originator_installation,
        )
        .is_ok()
    }
}

/// Sign the row `(group_id, id, created_ns, data)` as `signer`.
pub fn sign_row(
    signer: &dyn HelloSigner,
    group_id: &[u8],
    id: u64,
    created_ns: u64,
    data: &[u8],
) -> Result<SeqProof, MeshError> {
    let key = signer.installation_key();
    let record = SeqRecord::new(&key, group_id, id, created_ns, sha256(data));
    let signature = signer.sign(&record.signing_text())?;
    Ok(SeqProof {
        signer: key,
        signature,
    })
}

/// Whether `proof` is a valid signature by `proof.signer` over the row.
pub fn verify_proof(
    group_id: &[u8],
    id: u64,
    created_ns: u64,
    data: &[u8],
    proof: &SeqProof,
) -> bool {
    SeqRecord::new(&proof.signer, group_id, id, created_ns, sha256(data)).verify(&proof.signature)
}

/// `(seq_signer, seq_signature)` to store for a received row. No proof, or
/// an empty signature, is `(None, None)`. An empty signer takes
/// `default_signer` (a relayed row signed by the envelope's signer).
pub(crate) fn proof_fields(
    proof: Option<&SeqProof>,
    default_signer: Option<&[u8]>,
) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let Some(proof) = proof.filter(|p| !p.signature.is_empty()) else {
        return (None, None);
    };
    let signer = if proof.signer.is_empty() {
        default_signer.map(<[u8]>::to_vec)
    } else {
        Some(proof.signer.clone())
    };
    (signer, Some(proof.signature.clone()))
}

/// Why a sequenced row was refused (§B13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqReject {
    /// No proof, an empty signature or signer, or fewer proofs than rows.
    MissingProof,
    /// The signature does not verify over the rebuilt record.
    BadSignature,
    /// The signer is not a member's installation, or may not order this row.
    WrongSigner,
    /// The same signer signed two different rows under one id.
    Equivocation,
}

impl fmt::Display for SeqReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SeqReject::MissingProof => "missing proof",
            SeqReject::BadSignature => "bad signature",
            SeqReject::WrongSigner => "wrong signer",
            SeqReject::Equivocation => "equivocation",
        })
    }
}

/// Two different records one signer signed under one `(group_id, id)`,
/// kept as proof. `record_*` are encoded [`SeqRecord`]s; `a` is the stored row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Equivocation {
    pub group_id: Vec<u8>,
    pub id: i64,
    pub signer: Vec<u8>,
    pub record_a: Vec<u8>,
    pub signature_a: Vec<u8>,
    pub record_b: Vec<u8>,
    pub signature_b: Vec<u8>,
}

/// Signed-sequencing counters since the node was opened (§B13). A snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MeshStats {
    pub seq_rows_signed: u64,
    pub seq_rows_verified: u64,
    pub seq_rejected_missing_proof: u64,
    pub seq_rejected_bad_signature: u64,
    pub seq_rejected_wrong_signer: u64,
    pub seq_equivocations: u64,
    pub peers_rejected_version: u64,
}

#[derive(Debug, Default)]
pub(crate) struct SeqCounters {
    signed: AtomicU64,
    verified: AtomicU64,
    missing_proof: AtomicU64,
    bad_signature: AtomicU64,
    wrong_signer: AtomicU64,
    equivocations: AtomicU64,
    rejected_version: AtomicU64,
}

impl SeqCounters {
    pub(crate) fn count_signed(&self, n: u64) {
        self.signed.fetch_add(n, Ordering::Relaxed);
    }

    pub(crate) fn count_verified(&self, n: u64) {
        self.verified.fetch_add(n, Ordering::Relaxed);
    }

    pub(crate) fn count_rejected(&self, reason: SeqReject) {
        let counter = match reason {
            SeqReject::MissingProof => &self.missing_proof,
            SeqReject::BadSignature => &self.bad_signature,
            SeqReject::WrongSigner => &self.wrong_signer,
            SeqReject::Equivocation => &self.equivocations,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn count_rejected_version(&self) {
        self.rejected_version.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> MeshStats {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        MeshStats {
            seq_rows_signed: get(&self.signed),
            seq_rows_verified: get(&self.verified),
            seq_rejected_missing_proof: get(&self.missing_proof),
            seq_rejected_bad_signature: get(&self.bad_signature),
            seq_rejected_wrong_signer: get(&self.wrong_signer),
            seq_equivocations: get(&self.equivocations),
            peers_rejected_version: get(&self.rejected_version),
        }
    }
}

/// A [`HelloSigner`] over a bare installation key, for this crate's tests.
#[cfg(test)]
pub(crate) struct KeySigner(pub xmtp_cryptography::XmtpInstallationCredential);

#[cfg(test)]
impl KeySigner {
    pub(crate) fn new() -> Self {
        Self(xmtp_cryptography::XmtpInstallationCredential::new())
    }
}

#[cfg(test)]
impl HelloSigner for KeySigner {
    fn installation_key(&self) -> Vec<u8> {
        self.0.public_slice().to_vec()
    }

    fn sign(&self, text: &str) -> Result<Vec<u8>, MeshError> {
        use xmtp_cryptography::CredentialSign;
        self.0
            .credential_sign::<xmtp_id::associations::signature::PublicContext>(text)
            .map_err(|e| MeshError::AuthFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;
    use crate::store::sha256;

    #[test]
    fn the_record_encodes_like_its_proto() {
        let record = SeqRecord::new(&[1; 32], b"g", 5, 6, vec![3; 32]);
        let mut expected = vec![0x0a, 32];
        expected.extend([1; 32]);
        expected.extend([0x12, 1, b'g', 0x18, 5, 0x20, 6, 0x2a, 32]);
        expected.extend([3; 32]);
        assert_eq!(record.encode_to_vec(), expected);
        assert_eq!(
            record.signing_text(),
            format!("xmtp-mesh-seq-v1:{}", hex::encode(sha256(&expected)))
        );
    }

    #[test]
    fn a_signed_row_verifies_and_every_signed_field_matters() {
        let signer = KeySigner::new();
        let proof = sign_row(&signer, b"g", 7, 70, b"data").unwrap();
        assert_eq!(proof.signer, signer.installation_key());
        assert_eq!(proof.signature.len(), 64);
        assert!(verify_proof(b"g", 7, 70, b"data", &proof));
        assert!(!verify_proof(b"h", 7, 70, b"data", &proof), "another group");
        assert!(!verify_proof(b"g", 8, 70, b"data", &proof), "another id");
        assert!(!verify_proof(b"g", 7, 71, b"data", &proof), "another time");
        assert!(
            !verify_proof(b"g", 7, 70, b"Data", &proof),
            "another payload"
        );
        let other = KeySigner::new();
        let claimed = SeqProof {
            signer: other.installation_key(),
            ..proof.clone()
        };
        assert!(
            !verify_proof(b"g", 7, 70, b"data", &claimed),
            "another signer"
        );
        let short = SeqProof {
            signature: proof.signature[..63].to_vec(),
            ..proof
        };
        assert!(!verify_proof(b"g", 7, 70, b"data", &short), "not 64 bytes");
    }

    #[test]
    fn a_sequencing_signature_is_not_a_relay_or_hello_signature() {
        let signer = KeySigner::new();
        let record = SeqRecord::new(&signer.installation_key(), b"g", 1, 1, sha256(b"x"));
        let signature = signer.sign(&record.signing_text()).unwrap();
        assert!(record.verify(&signature));
        let relay_text = format!(
            "xmtp-mesh-relay-v1:{}",
            hex::encode(sha256(&record.encode_to_vec()))
        );
        assert!(
            crate::sync::auth::verify(&relay_text, &signature, &signer.installation_key()).is_err()
        );
        assert!(record.signing_text().starts_with(SEQ_TEXT_PREFIX));
    }

    #[test]
    fn an_empty_signer_takes_the_default_and_an_empty_signature_is_no_proof() {
        let proof = SeqProof {
            signer: vec![],
            signature: vec![9; 64],
        };
        assert_eq!(
            proof_fields(Some(&proof), Some(b"envelope")),
            (Some(b"envelope".to_vec()), Some(vec![9; 64]))
        );
        assert_eq!(proof_fields(Some(&proof), None), (None, Some(vec![9; 64])));
        let explicit = SeqProof {
            signer: b"former".to_vec(),
            ..proof
        };
        assert_eq!(
            proof_fields(Some(&explicit), Some(b"envelope")).0,
            Some(b"former".to_vec())
        );
        let unsigned = SeqProof {
            signer: b"x".to_vec(),
            signature: vec![],
        };
        assert_eq!(proof_fields(Some(&unsigned), None), (None, None));
        assert_eq!(proof_fields(None, Some(b"envelope")), (None, None));
    }

    #[test]
    fn counters_snapshot_by_reason() {
        let c = SeqCounters::default();
        c.count_signed(3);
        c.count_verified(2);
        c.count_rejected(SeqReject::MissingProof);
        c.count_rejected(SeqReject::BadSignature);
        c.count_rejected(SeqReject::BadSignature);
        c.count_rejected(SeqReject::WrongSigner);
        c.count_rejected(SeqReject::Equivocation);
        c.count_rejected_version();
        assert_eq!(
            c.snapshot(),
            MeshStats {
                seq_rows_signed: 3,
                seq_rows_verified: 2,
                seq_rejected_missing_proof: 1,
                seq_rejected_bad_signature: 2,
                seq_rejected_wrong_signer: 1,
                seq_equivocations: 1,
                peers_rejected_version: 1,
            }
        );
    }

    #[test]
    fn a_sequencing_rejection_ends_the_session() {
        for reason in [
            SeqReject::MissingProof,
            SeqReject::BadSignature,
            SeqReject::WrongSigner,
            SeqReject::Equivocation,
        ] {
            let err = MeshError::SequencingRejected(reason);
            assert!(err.is_fatal(), "{err}");
        }
        assert_eq!(
            MeshError::SequencingRejected(SeqReject::WrongSigner).to_string(),
            "sequencing rejected: wrong signer"
        );
    }
}
