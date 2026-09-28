//! Signed sequencing records (DESIGN.md §B13, D30). The installation that
//! gives a row its id signs a record of it; every node checks that
//! signature before it stores a row from someone else. The record follows
//! XMTP d14n's `UnsignedOriginatorEnvelope` field names; the key is the
//! installation's ed25519 key. Only the proof travels: a verifier rebuilds
//! the record from the row it received.
use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use prost::Message;

use super::auth::{self, HelloSigner};
use crate::MeshError;
use crate::store::StoredGroupMessage;
use crate::store::sha256;

/// Prefix of the text a sequencing record's signature covers. Distinct from
/// the handshake's and the relay's, so no signature verifies as another kind.
pub const SEQ_TEXT_PREFIX: &str = "xmtp-mesh-seq-v1:";

/// Prefix of the text an upgrade attestation covers (§B13): a row stored
/// before signed sequencing, signed by the node that held it rather than by
/// the installation that ordered it. Distinct from [`SEQ_TEXT_PREFIX`], so an
/// attestation never passes as a sequencing signature, or the reverse.
pub const SEQ_ATTEST_TEXT_PREFIX: &str = "xmtp-mesh-seq-attest-v1:";

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
    /// 64-byte ed25519 signature over [`SeqRecord::signing_text_as`]`(attested)`.
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
    /// An upgrade attestation rather than a sequencing signature (§B13):
    /// selects the signed text's prefix.
    #[prost(bool, tag = "3")]
    pub attested: bool,
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
        self.signing_text_as(false)
    }

    /// [`Self::signing_text`], or with [`SEQ_ATTEST_TEXT_PREFIX`] for an
    /// upgrade attestation.
    pub fn signing_text_as(&self, attested: bool) -> String {
        let prefix = if attested {
            SEQ_ATTEST_TEXT_PREFIX
        } else {
            SEQ_TEXT_PREFIX
        };
        format!("{prefix}{}", hex::encode(sha256(&self.encode_to_vec())))
    }

    /// Whether `signature` is `originator_installation`'s sequencing
    /// signature over this record.
    pub fn verify(&self, signature: &[u8]) -> bool {
        self.verify_as(signature, false)
    }

    /// [`Self::verify`], or as an attestation when `attested`.
    pub fn verify_as(&self, signature: &[u8], attested: bool) -> bool {
        auth::verify(
            &self.signing_text_as(attested),
            signature,
            &self.originator_installation,
        )
        .is_ok()
    }
}

/// Sign the row `(group_id, id, created_ns, data)` as `signer`, the
/// installation that ordered it.
pub fn sign_row(
    signer: &dyn HelloSigner,
    group_id: &[u8],
    id: u64,
    created_ns: u64,
    data: &[u8],
) -> Result<SeqProof, MeshError> {
    sign_hashed(signer, group_id, id, created_ns, sha256(data), false)
}

/// Sign `(group_id, id, created_ns, sha256(data) = payload_hash)` as
/// `signer`: an upgrade attestation when `attested`, else a sequencing
/// signature.
pub(crate) fn sign_hashed(
    signer: &dyn HelloSigner,
    group_id: &[u8],
    id: u64,
    created_ns: u64,
    payload_hash: Vec<u8>,
    attested: bool,
) -> Result<SeqProof, MeshError> {
    let key = signer.installation_key();
    let record = SeqRecord::new(&key, group_id, id, created_ns, payload_hash);
    let signature = signer.sign(&record.signing_text_as(attested))?;
    Ok(SeqProof {
        signer: key,
        signature,
        attested,
    })
}

/// Whether `proof` is a valid signature by `proof.signer` over the row, of
/// the kind `proof.attested` claims.
pub fn verify_proof(
    group_id: &[u8],
    id: u64,
    created_ns: u64,
    data: &[u8],
    proof: &SeqProof,
) -> bool {
    SeqRecord::new(&proof.signer, group_id, id, created_ns, sha256(data))
        .verify_as(&proof.signature, proof.attested)
}

/// `(seq_signer, seq_signature, seq_attested)` to store for a received
/// row. No proof, or an empty signature, is `(None, None, false)`. An empty
/// signer takes `default_signer` (a relayed row signed by the envelope's
/// signer).
pub(crate) fn proof_fields(
    proof: Option<&SeqProof>,
    default_signer: Option<&[u8]>,
) -> (Option<Vec<u8>>, Option<Vec<u8>>, bool) {
    let Some(proof) = proof.filter(|p| !p.signature.is_empty()) else {
        return (None, None, false);
    };
    let signer = if proof.signer.is_empty() {
        default_signer.map(<[u8]>::to_vec)
    } else {
        Some(proof.signer.clone())
    };
    (signer, Some(proof.signature.clone()), proof.attested)
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
    /// Whether `signature_a` is an upgrade attestation rather than a
    /// sequencing signature (§B13).
    pub attested_a: bool,
    pub record_b: Vec<u8>,
    pub signature_b: Vec<u8>,
    pub attested_b: bool,
}

/// Signed-sequencing (§B13) and link (§B14) counters since the node was
/// opened. A snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MeshStats {
    pub seq_rows_signed: u64,
    pub seq_rows_verified: u64,
    pub seq_rejected_missing_proof: u64,
    pub seq_rejected_bad_signature: u64,
    pub seq_rejected_wrong_signer: u64,
    pub seq_equivocations: u64,
    pub peers_rejected_version: u64,
    /// Links opened, by kind (§B14.3).
    pub links_contact: u64,
    pub links_relay: u64,
    pub links_pairing: u64,
    /// Noise handshakes that failed or timed out.
    pub handshake_failed: u64,
    /// Links closed for a record that failed authentication, a frame not
    /// allowed on the link type, or a card or Hello that does not match it.
    pub link_frame_rejected: u64,
    pub discovery_resets: u64,
    /// Relay links closed after carrying no useful relay traffic for the
    /// idle bound.
    pub relay_links_idle_closed: u64,
    /// Relay links closed while still in use: at the lifetime cap, or when
    /// relay was switched off.
    pub relay_links_force_closed: u64,
    /// Relay links refused or not dialed because this phone closed the same
    /// radio peer's relay link moments ago (the back-off, §B14.3).
    pub relay_links_backoff_refused: u64,
    /// Times the phone left pairing mode after too many unfinished pairing
    /// handshakes (§B14.4).
    pub pairing_attempts_exhausted: u64,
    /// Contacts the phone added by itself during a restore window
    /// (§B14.7).
    pub restore_contacts_added: u64,
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
            ..MeshStats::default()
        }
    }
}

/// Who may have signed a group's rows, as this node sees it (§B13 rule 2).
#[derive(Debug, Clone, Default)]
pub(crate) struct SignerContext {
    /// The group's pinned sequencer.
    pub sequencer: Option<Vec<u8>>,
    /// Every installation a member inbox's held log ever added.
    pub known: HashSet<Vec<u8>>,
    /// The known installations a later update of the same log removed.
    pub revoked: HashSet<Vec<u8>>,
}

/// The stored rows of one group, as [`check_rows`] reads them.
pub(crate) trait RowLookup {
    fn max_id(&mut self) -> Result<i64, MeshError>;
    fn stored_at(&mut self, id: i64) -> Result<Option<StoredGroupMessage>, MeshError>;
}

/// What to do with one frame's (or relayed payload's) rows.
#[derive(Debug, PartialEq)]
pub(crate) enum Verdict {
    /// Store `new_rows` (contiguous, in order). `held` are rows this node
    /// already has, or repeats of an earlier row of the same frame. `gap` is
    /// `Some(highest id held after storing)` when a row skipped ahead: the
    /// sender's retry fills it.
    Accept {
        held: Vec<StoredGroupMessage>,
        new_rows: Vec<StoredGroupMessage>,
        gap: Option<i64>,
    },
    /// Store nothing; keep `equivocation` as proof if set.
    Reject {
        reason: SeqReject,
        equivocation: Option<Equivocation>,
    },
}

/// The record `row` claims and its signature, or `None` without a proof.
fn record_of<'a>(group_id: &[u8], row: &'a StoredGroupMessage) -> Option<(SeqRecord, &'a [u8])> {
    let signer = row.seq_signer.as_deref().filter(|s| !s.is_empty())?;
    let signature = row.seq_signature.as_deref().filter(|s| !s.is_empty())?;
    let record = SeqRecord::new(
        signer,
        group_id,
        row.id as u64,
        row.created_ns as u64,
        sha256(&row.data),
    );
    Some((record, signature))
}

fn equivocation(
    group_id: &[u8],
    stored: &StoredGroupMessage,
    row: &StoredGroupMessage,
) -> Equivocation {
    let encode = |r: &StoredGroupMessage| {
        record_of(group_id, r)
            .map(|(record, _)| record.encode_to_vec())
            .unwrap_or_default()
    };
    Equivocation {
        group_id: group_id.to_vec(),
        id: row.id,
        signer: row.seq_signer.clone().unwrap_or_default(),
        record_a: encode(stored),
        signature_a: stored.seq_signature.clone().unwrap_or_default(),
        attested_a: stored.seq_attested,
        record_b: encode(row),
        signature_b: row.seq_signature.clone().unwrap_or_default(),
        attested_b: row.seq_attested,
    }
}

/// Rule 4 for a row at an id this node already has (`kept`, stored or
/// earlier in the frame): `Some(equivocation)` when the same signer signed a
/// different record there; otherwise the row is a duplicate or §C4.7 id
/// reuse, and `kept` stays.
fn conflicts_with(
    group_id: &[u8],
    kept: &StoredGroupMessage,
    row: &StoredGroupMessage,
) -> Option<Equivocation> {
    (kept.seq_signer == row.seq_signer
        && (kept.created_ns != row.created_ns || kept.data != row.data))
        .then(|| equivocation(group_id, kept, row))
}

/// The §B13 accept rule for rows received for `group_id`, in frame order.
/// Nothing is written; the caller stores an `Accept` and records a
/// `Reject`'s equivocation.
///
/// 1. A proof is present and verifies over the rebuilt record, as an
///    attestation or a sequencing signature as the row says.
/// 2. Its signer is in `ctx.known`.
/// 3. For a new id: the signer (of a sequencing signature or an
///    attestation) is the pinned sequencer, and it is not revoked. A
///    revoked installation never adds a row; after a §C4.7 handover the
///    successor serves the history it holds under its own attestations.
/// 4. For an id already held, or repeated within the frame: the same record
///    is a duplicate; a different record by the same signer is
///    equivocation; another signer is §C4.7 id reuse and the first row
///    stays.
///
/// Order: rules 1–2 run over the whole frame first (one bad row rejects it,
/// including rows after a gap); then rules 3–4 in frame order, up to the
/// first gap. The reason reported is the first failure in that order.
pub(crate) fn check_rows(
    ctx: &SignerContext,
    group_id: &[u8],
    rows: Vec<StoredGroupMessage>,
    lookup: &mut impl RowLookup,
) -> Result<Verdict, MeshError> {
    let reject = |reason: SeqReject| -> Result<Verdict, MeshError> {
        Ok(Verdict::Reject {
            reason,
            equivocation: None,
        })
    };
    let equivocates = |e: Equivocation| -> Result<Verdict, MeshError> {
        Ok(Verdict::Reject {
            reason: SeqReject::Equivocation,
            equivocation: Some(e),
        })
    };
    for row in &rows {
        let Some((record, signature)) = record_of(group_id, row) else {
            return reject(SeqReject::MissingProof);
        };
        if !record.verify_as(signature, row.seq_attested) {
            return reject(SeqReject::BadSignature);
        }
        if !ctx.known.contains(&record.originator_installation) {
            return reject(SeqReject::WrongSigner);
        }
    }
    let have = lookup.max_id()?;
    let mut held = Vec::new();
    let mut new_rows: Vec<StoredGroupMessage> = Vec::new();
    for row in rows {
        if row.id <= have {
            let stored = lookup.stored_at(row.id)?;
            debug_assert!(
                stored.is_some(),
                "no stored row at id {} at or below the group's max id {have}",
                row.id
            );
            if let Some(e) = stored.and_then(|kept| conflicts_with(group_id, &kept, &row)) {
                return equivocates(e);
            }
            held.push(row);
            continue;
        }
        let next = have + new_rows.len() as i64 + 1;
        if row.id < next {
            // Repeats a row accepted earlier in this frame.
            let kept = &new_rows[(row.id - have - 1) as usize];
            if let Some(e) = conflicts_with(group_id, kept, &row) {
                return equivocates(e);
            }
            held.push(row);
            continue;
        }
        if row.id != next {
            return Ok(Verdict::Accept {
                held,
                new_rows,
                gap: Some(next - 1),
            });
        }
        let signer = row.seq_signer.as_deref().unwrap_or_default();
        if ctx.sequencer.as_deref() != Some(signer) || ctx.revoked.contains(signer) {
            return reject(SeqReject::WrongSigner);
        }
        new_rows.push(row);
    }
    Ok(Verdict::Accept {
        held,
        new_rows,
        gap: None,
    })
}

/// A row signed as `signer`, `created_ns = id * 10`, for this crate's tests.
#[cfg(test)]
pub(crate) fn signed_row(
    signer: &dyn HelloSigner,
    group_id: &[u8],
    id: i64,
    data: &[u8],
) -> StoredGroupMessage {
    proven_row(signer, group_id, id, data, false)
}

/// [`signed_row`], as an upgrade attestation.
#[cfg(test)]
pub(crate) fn attested_row(
    signer: &dyn HelloSigner,
    group_id: &[u8],
    id: i64,
    data: &[u8],
) -> StoredGroupMessage {
    proven_row(signer, group_id, id, data, true)
}

#[cfg(test)]
fn proven_row(
    signer: &dyn HelloSigner,
    group_id: &[u8],
    id: i64,
    data: &[u8],
    attested: bool,
) -> StoredGroupMessage {
    let created_ns = id * 10;
    let proof = sign_hashed(
        signer,
        group_id,
        id as u64,
        created_ns as u64,
        sha256(data),
        attested,
    )
    .unwrap();
    StoredGroupMessage {
        group_id: group_id.to_vec(),
        id,
        created_ns,
        data: data.to_vec(),
        sender_hmac: vec![],
        should_push: true,
        is_commit: false,
        seq_signer: Some(proof.signer),
        seq_signature: Some(proof.signature),
        seq_attested: proof.attested,
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
    use std::collections::HashSet;

    use prost::Message;

    use super::*;
    use crate::store::StoredGroupMessage;
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
            attested: false,
        };
        assert_eq!(
            proof_fields(Some(&proof), Some(b"envelope")),
            (Some(b"envelope".to_vec()), Some(vec![9; 64]), false)
        );
        assert_eq!(
            proof_fields(Some(&proof), None),
            (None, Some(vec![9; 64]), false)
        );
        let attested = SeqProof {
            attested: true,
            ..proof.clone()
        };
        assert!(proof_fields(Some(&attested), None).2, "the flag is kept");
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
            attested: true,
        };
        assert_eq!(proof_fields(Some(&unsigned), None), (None, None, false));
        assert_eq!(proof_fields(None, Some(b"envelope")), (None, None, false));
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
                ..MeshStats::default()
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

    #[derive(Default)]
    struct Stored(Vec<StoredGroupMessage>);

    impl RowLookup for Stored {
        fn max_id(&mut self) -> Result<i64, MeshError> {
            Ok(self.0.iter().map(|r| r.id).max().unwrap_or(0))
        }
        fn stored_at(&mut self, id: i64) -> Result<Option<StoredGroupMessage>, MeshError> {
            Ok(self.0.iter().find(|r| r.id == id).cloned())
        }
    }

    const G: &[u8] = b"group";

    fn keys(signers: &[&KeySigner]) -> HashSet<Vec<u8>> {
        signers.iter().map(|s| s.installation_key()).collect()
    }

    fn ctx(sequencer: &KeySigner, known: &[&KeySigner], revoked: &[&KeySigner]) -> SignerContext {
        SignerContext {
            sequencer: Some(sequencer.installation_key()),
            known: keys(known),
            revoked: keys(revoked),
        }
    }

    fn accepted_ids(v: &Verdict) -> Vec<i64> {
        match v {
            Verdict::Accept { new_rows, .. } => new_rows.iter().map(|r| r.id).collect(),
            Verdict::Reject { reason, .. } => panic!("rejected: {reason}"),
        }
    }

    fn reason(v: &Verdict) -> SeqReject {
        match v {
            Verdict::Reject { reason, .. } => *reason,
            Verdict::Accept { .. } => panic!("accepted"),
        }
    }

    #[test]
    fn rows_signed_by_the_pinned_sequencer_are_accepted() {
        let s = KeySigner::new();
        let rows = vec![signed_row(&s, G, 1, b"a"), signed_row(&s, G, 2, b"b")];
        let v = check_rows(&ctx(&s, &[&s], &[]), G, rows, &mut Stored::default()).unwrap();
        assert_eq!(accepted_ids(&v), vec![1, 2]);
    }

    #[test]
    fn a_row_without_a_proof_is_missing_proof() {
        let s = KeySigner::new();
        let mut row = signed_row(&s, G, 1, b"a");
        row.seq_signature = None;
        let v = check_rows(
            &ctx(&s, &[&s], &[]),
            G,
            vec![row.clone()],
            &mut Stored::default(),
        )
        .unwrap();
        assert_eq!(reason(&v), SeqReject::MissingProof);
        row.seq_signature = Some(vec![]);
        let v = check_rows(&ctx(&s, &[&s], &[]), G, vec![row], &mut Stored::default()).unwrap();
        assert_eq!(reason(&v), SeqReject::MissingProof);
    }

    #[test]
    fn a_changed_id_time_payload_or_group_is_a_bad_signature() {
        let s = KeySigner::new();
        let c = ctx(&s, &[&s], &[]);
        let base = signed_row(&s, G, 1, b"a");
        let mut id = base.clone();
        id.id = 2;
        let mut time = base.clone();
        time.created_ns += 1;
        let mut data = base.clone();
        data.data = b"A".to_vec();
        for row in [time, data] {
            let v = check_rows(&c, G, vec![row], &mut Stored::default()).unwrap();
            assert_eq!(reason(&v), SeqReject::BadSignature);
        }
        let v = check_rows(&c, G, vec![id], &mut Stored(vec![base.clone()])).unwrap();
        assert_eq!(reason(&v), SeqReject::BadSignature);
        let other = signed_row(&s, b"another group", 1, b"a");
        let mut moved = base;
        moved.seq_signature = other.seq_signature;
        let v = check_rows(&c, G, vec![moved], &mut Stored::default()).unwrap();
        assert_eq!(reason(&v), SeqReject::BadSignature);
    }

    #[test]
    fn a_signer_outside_the_members_logs_is_a_wrong_signer() {
        let (s, stranger) = (KeySigner::new(), KeySigner::new());
        let row = signed_row(&stranger, G, 1, b"a");
        let v = check_rows(&ctx(&s, &[&s], &[]), G, vec![row], &mut Stored::default()).unwrap();
        assert_eq!(reason(&v), SeqReject::WrongSigner);
    }

    #[test]
    fn a_live_installation_that_is_not_the_sequencer_is_a_wrong_signer() {
        let (s, other) = (KeySigner::new(), KeySigner::new());
        let row = signed_row(&other, G, 1, b"a");
        let v = check_rows(
            &ctx(&s, &[&s, &other], &[]),
            G,
            vec![row],
            &mut Stored::default(),
        )
        .unwrap();
        assert_eq!(reason(&v), SeqReject::WrongSigner);
    }

    /// §B13 rule 3: a revoked former sequencer's rows are refused at new
    /// ids on a node pinned to its successor, whatever lies below them.
    #[test]
    fn a_revoked_former_sequencers_rows_are_refused_at_new_ids() {
        let (old, next) = (KeySigner::new(), KeySigner::new());
        let c = ctx(&next, &[&old, &next], &[&old]);
        let rows = vec![signed_row(&old, G, 1, b"a"), signed_row(&next, G, 2, b"b")];
        let v = check_rows(&c, G, rows, &mut Stored::default()).unwrap();
        assert_eq!(reason(&v), SeqReject::WrongSigner, "on an empty store");
        let stored = vec![attested_row(&next, G, 1, b"a")];
        let late = signed_row(&old, G, 2, b"b");
        let v = check_rows(&c, G, vec![late], &mut Stored(stored)).unwrap();
        assert_eq!(reason(&v), SeqReject::WrongSigner, "after attested rows");
    }

    /// §C4.7: after a handover the successor serves the former sequencer's
    /// rows under its own attestations, then its own rows.
    #[test]
    fn the_successors_attested_history_is_accepted() {
        let (old, next) = (KeySigner::new(), KeySigner::new());
        let c = ctx(&next, &[&old, &next], &[&old]);
        let history = vec![
            attested_row(&next, G, 1, b"attested at the upgrade"),
            attested_row(&next, G, 2, b"old sequencer 2, attested at the handover"),
            attested_row(&next, G, 3, b"old sequencer 3, attested at the handover"),
            signed_row(&next, G, 4, b"successor 4"),
        ];
        let v = check_rows(&c, G, history.clone(), &mut Stored::default()).unwrap();
        assert_eq!(accepted_ids(&v), vec![1, 2, 3, 4]);
        let v = check_rows(
            &c,
            G,
            history[2..].to_vec(),
            &mut Stored(history[..2].to_vec()),
        )
        .unwrap();
        assert_eq!(accepted_ids(&v), vec![3, 4], "across frames too");
        let late = signed_row(&old, G, 5, b"late");
        let v = check_rows(&c, G, vec![late], &mut Stored(history)).unwrap();
        assert_eq!(reason(&v), SeqReject::WrongSigner);
    }

    /// §B13 rule 3: a stolen, revoked phone cannot extend a history that
    /// only live installations ordered, even with a valid signature.
    #[test]
    fn a_revoked_key_cannot_append_after_sequencer_only_history() {
        let (s, stolen) = (KeySigner::new(), KeySigner::new());
        let c = ctx(&s, &[&s, &stolen], &[&stolen]);
        let stored = vec![
            signed_row(&s, G, 1, b"a"),
            signed_row(&s, G, 2, b"b"),
            signed_row(&s, G, 3, b"c"),
        ];
        let forged = signed_row(&stolen, G, 4, b"forged");
        let v = check_rows(&c, G, vec![forged], &mut Stored(stored)).unwrap();
        assert_eq!(reason(&v), SeqReject::WrongSigner);
    }

    #[test]
    fn a_revoked_key_cannot_append_after_sequencer_rows_in_the_same_frame() {
        let (s, stolen) = (KeySigner::new(), KeySigner::new());
        let c = ctx(&s, &[&s, &stolen], &[&stolen]);
        let rows = vec![
            signed_row(&s, G, 1, b"a"),
            signed_row(&s, G, 2, b"b"),
            signed_row(&stolen, G, 3, b"forged"),
        ];
        let v = check_rows(&c, G, rows, &mut Stored::default()).unwrap();
        assert_eq!(reason(&v), SeqReject::WrongSigner);
    }

    /// Right after the upgrade every held history is attestations only;
    /// a revoked key still cannot append to it.
    #[test]
    fn a_revoked_key_cannot_append_after_attestation_only_history() {
        let (s, stolen) = (KeySigner::new(), KeySigner::new());
        let c = ctx(&s, &[&s, &stolen], &[&stolen]);
        let attested: Vec<_> = (1..=3)
            .map(|id| attested_row(&s, G, id, &[id as u8]))
            .collect();
        let forged = signed_row(&stolen, G, 4, b"forged");
        let v = check_rows(&c, G, vec![forged.clone()], &mut Stored(attested.clone())).unwrap();
        assert_eq!(reason(&v), SeqReject::WrongSigner, "stored attestations");
        let mut frame = attested;
        frame.push(forged);
        let v = check_rows(&c, G, frame, &mut Stored::default()).unwrap();
        assert_eq!(reason(&v), SeqReject::WrongSigner, "one frame, fresh store");
    }

    #[test]
    fn a_live_members_attestation_at_a_new_id_is_a_wrong_signer() {
        let (s, member) = (KeySigner::new(), KeySigner::new());
        let c = ctx(&s, &[&s, &member], &[]);
        let row = attested_row(&member, G, 1, b"a");
        let v = check_rows(&c, G, vec![row], &mut Stored::default()).unwrap();
        assert_eq!(reason(&v), SeqReject::WrongSigner);
    }

    /// The node knows the pinned sequencer is revoked: the §C4.7 re-pin is
    /// due, and its rows wait for it.
    #[test]
    fn a_pinned_sequencer_that_is_revoked_is_a_wrong_signer() {
        let s = KeySigner::new();
        let c = ctx(&s, &[&s], &[&s]);
        let v = check_rows(
            &c,
            G,
            vec![signed_row(&s, G, 1, b"a")],
            &mut Stored::default(),
        )
        .unwrap();
        assert_eq!(reason(&v), SeqReject::WrongSigner);
        let stored = vec![signed_row(&s, G, 1, b"a")];
        let v = check_rows(&c, G, stored.clone(), &mut Stored(stored)).unwrap();
        assert!(
            matches!(v, Verdict::Accept { ref held, .. } if held.len() == 1),
            "a held row is still a duplicate"
        );
    }

    #[test]
    fn an_attestation_is_not_a_sequencing_signature_or_the_reverse() {
        let s = KeySigner::new();
        let normal = sign_row(&s, b"g", 1, 10, b"x").unwrap();
        let attested = sign_hashed(&s, b"g", 1, 10, sha256(b"x"), true).unwrap();
        assert!(!normal.attested && attested.attested);
        assert!(verify_proof(b"g", 1, 10, b"x", &normal));
        assert!(verify_proof(b"g", 1, 10, b"x", &attested));
        let as_attested = SeqProof {
            attested: true,
            ..normal
        };
        let as_normal = SeqProof {
            attested: false,
            ..attested
        };
        assert!(!verify_proof(b"g", 1, 10, b"x", &as_attested));
        assert!(!verify_proof(b"g", 1, 10, b"x", &as_normal));
        let record = SeqRecord::new(&s.installation_key(), b"g", 1, 10, sha256(b"x"));
        assert!(
            record
                .signing_text_as(true)
                .starts_with("xmtp-mesh-seq-attest-v1:")
        );

        let c = ctx(&s, &[&s], &[]);
        let mut flipped = signed_row(&s, G, 1, b"a");
        flipped.seq_attested = true;
        let v = check_rows(&c, G, vec![flipped], &mut Stored::default()).unwrap();
        assert_eq!(reason(&v), SeqReject::BadSignature);
        let mut flipped = attested_row(&s, G, 1, b"a");
        flipped.seq_attested = false;
        let v = check_rows(&c, G, vec![flipped], &mut Stored::default()).unwrap();
        assert_eq!(reason(&v), SeqReject::BadSignature);
    }

    #[test]
    fn an_id_repeated_within_a_frame_is_a_duplicate_or_equivocation() {
        let s = KeySigner::new();
        let c = ctx(&s, &[&s], &[]);
        let first = signed_row(&s, G, 1, b"a");
        let v = check_rows(
            &c,
            G,
            vec![first.clone(), first.clone()],
            &mut Stored::default(),
        )
        .unwrap();
        assert_eq!(
            v,
            Verdict::Accept {
                held: vec![first.clone()],
                new_rows: vec![first.clone()],
                gap: None
            }
        );
        let other = signed_row(&s, G, 1, b"b");
        let v = check_rows(
            &c,
            G,
            vec![first.clone(), other.clone()],
            &mut Stored::default(),
        )
        .unwrap();
        match v {
            Verdict::Reject {
                reason: SeqReject::Equivocation,
                equivocation: Some(e),
            } => {
                assert_eq!(e.signature_a, first.seq_signature.unwrap());
                assert_eq!(e.signature_b, other.seq_signature.unwrap());
            }
            other => panic!("{other:?}"),
        }
    }

    /// Rules 1–2 cover the whole frame before rules 3–4: a bad signature
    /// later in the frame is the reason, not an earlier equivocation.
    #[test]
    fn rules_one_and_two_run_over_the_whole_frame_first() {
        let s = KeySigner::new();
        let c = ctx(&s, &[&s], &[]);
        let mut bad = signed_row(&s, G, 2, b"c");
        bad.data = b"changed".to_vec();
        let rows = vec![signed_row(&s, G, 1, b"b"), bad];
        let v = check_rows(&c, G, rows, &mut Stored(vec![signed_row(&s, G, 1, b"a")])).unwrap();
        assert_eq!(reason(&v), SeqReject::BadSignature);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "no stored row at id 1")]
    fn a_hole_below_the_max_id_is_a_bug() {
        let s = KeySigner::new();
        let c = ctx(&s, &[&s], &[]);
        let _ = check_rows(
            &c,
            G,
            vec![signed_row(&s, G, 1, b"a")],
            &mut Stored(vec![signed_row(&s, G, 2, b"b")]),
        );
    }

    /// Rule 4: rows already held are duplicates, whoever signed them; only
    /// the same signer with a different record is equivocation.
    #[test]
    fn held_rows_are_duplicates_whoever_signed_them() {
        let (seq, attester) = (KeySigner::new(), KeySigner::new());
        let c = ctx(&seq, &[&seq, &attester], &[]);
        let same = signed_row(&seq, G, 1, b"a");
        let v = check_rows(&c, G, vec![same.clone()], &mut Stored(vec![same.clone()])).unwrap();
        assert_eq!(
            v,
            Verdict::Accept {
                held: vec![same.clone()],
                new_rows: vec![],
                gap: None
            }
        );
        let attested = attested_row(&attester, G, 1, b"a");
        let v = check_rows(
            &c,
            G,
            vec![same.clone()],
            &mut Stored(vec![attested.clone()]),
        )
        .unwrap();
        assert!(matches!(v, Verdict::Accept { ref held, .. } if held.len() == 1));
        let reused = signed_row(&seq, G, 1, b"another message, same id");
        let v = check_rows(&c, G, vec![reused], &mut Stored(vec![attested])).unwrap();
        assert!(
            matches!(v, Verdict::Accept { ref held, .. } if held.len() == 1),
            "§C4.7 id reuse: a different signer's row at a held id is left as it is"
        );
    }

    #[test]
    fn one_signer_two_records_at_one_id_is_equivocation() {
        let s = KeySigner::new();
        let stored = signed_row(&s, G, 1, b"a");
        let other = signed_row(&s, G, 1, b"b");
        let v = check_rows(
            &ctx(&s, &[&s], &[]),
            G,
            vec![other.clone()],
            &mut Stored(vec![stored.clone()]),
        )
        .unwrap();
        let record = |r: &StoredGroupMessage| {
            SeqRecord::new(&s.installation_key(), G, 1, 10, sha256(&r.data)).encode_to_vec()
        };
        assert_eq!(
            v,
            Verdict::Reject {
                reason: SeqReject::Equivocation,
                equivocation: Some(Equivocation {
                    group_id: G.to_vec(),
                    id: 1,
                    signer: s.installation_key(),
                    record_a: record(&stored),
                    signature_a: stored.seq_signature.clone().unwrap(),
                    attested_a: false,
                    record_b: record(&other),
                    signature_b: other.seq_signature.clone().unwrap(),
                    attested_b: false,
                }),
            }
        );
    }

    #[test]
    fn rows_after_a_gap_wait_for_the_retry() {
        let s = KeySigner::new();
        let c = ctx(&s, &[&s], &[]);
        let rows = vec![signed_row(&s, G, 2, b"b"), signed_row(&s, G, 4, b"d")];
        let v = check_rows(&c, G, rows, &mut Stored(vec![signed_row(&s, G, 1, b"a")])).unwrap();
        match v {
            Verdict::Accept { new_rows, gap, .. } => {
                assert_eq!(new_rows.iter().map(|r| r.id).collect::<Vec<_>>(), vec![2]);
                assert_eq!(gap, Some(2));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_bad_row_after_a_gap_still_rejects_the_frame() {
        let (s, stranger) = (KeySigner::new(), KeySigner::new());
        let rows = vec![
            signed_row(&s, G, 3, b"c"),
            signed_row(&stranger, G, 4, b"d"),
        ];
        let v = check_rows(&ctx(&s, &[&s], &[]), G, rows, &mut Stored::default()).unwrap();
        assert_eq!(reason(&v), SeqReject::WrongSigner);
    }

    /// DESIGN.md §B13 "Cost": measures the wire overhead one proof adds,
    /// from actual encoded sizes rather than a guess, so the doc's
    /// approximate figures can be kept honest. A direct row's proof names
    /// its signer explicitly (`Sequenced.proofs`, tag 4); a relay `Ref`
    /// row's proof travels with an empty signer, meaning the envelope's
    /// (`RelayRow.proof`, tag 3, §R4.6).
    #[test]
    fn proof_overhead_is_about_100_bytes_direct_and_about_70_relay() {
        use xmtp_proto::mls_v1::{GroupMessage, group_message};

        use crate::relay::inner::{RelayRow, RowRef, relay_row::Row};
        use crate::sync::frames::Sequenced;

        let message = GroupMessage {
            version: Some(group_message::Version::V1(group_message::V1 {
                id: 1,
                created_ns: 1,
                group_id: vec![1; 32],
                data: vec![0; 200],
                sender_hmac: vec![0; 32],
                should_push: true,
                is_commit: false,
            })),
        };
        let bare = Sequenced {
            group_id: vec![1; 32],
            messages: vec![message],
            sender_is_sequencer: true,
            proofs: vec![],
        };
        let direct_proof = SeqProof {
            signer: vec![9; 32],
            signature: vec![9; 64],
            attested: false,
        };
        let with_proof = Sequenced {
            proofs: vec![direct_proof],
            ..bare.clone()
        };
        let direct_overhead = with_proof.encoded_len() - bare.encoded_len();
        // Named explicitly per doc so a change here is a deliberate edit,
        // not silent drift; DESIGN.md §B13 states these as approximate.
        assert_eq!(direct_overhead, 102, "direct proof overhead moved");

        let bare_ref = RelayRow {
            row: Some(Row::Reference(RowRef {
                id: 1,
                created_ns: 1,
                data_hash: vec![9; 32],
            })),
            proof: None,
        };
        let relay_proof = SeqProof {
            signer: vec![], // the envelope's signer, not repeated (§R4.6)
            signature: vec![9; 64],
            attested: false,
        };
        let with_ref_proof = RelayRow {
            proof: Some(relay_proof),
            ..bare_ref.clone()
        };
        let relay_overhead = with_ref_proof.encoded_len() - bare_ref.encoded_len();
        assert_eq!(relay_overhead, 68, "relay proof overhead moved");
    }
}
