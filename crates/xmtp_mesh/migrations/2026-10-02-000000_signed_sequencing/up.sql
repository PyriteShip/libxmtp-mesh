-- §B13: the ordering installation's proof for every sequenced row. Nullable
-- only until the node's first start_sync signs rows stored before it.
ALTER TABLE group_messages ADD COLUMN seq_signer BLOB;
ALTER TABLE group_messages ADD COLUMN seq_signature BLOB;
-- The signature is an upgrade attestation, not a sequencing signature.
ALTER TABLE group_messages ADD COLUMN seq_attested BOOLEAN NOT NULL DEFAULT 0;
-- Stored before signed sequencing: start_sync attests these rather than
-- signing them as their sequencer.
ALTER TABLE group_messages ADD COLUMN seq_legacy BOOLEAN NOT NULL DEFAULT 0;
UPDATE group_messages SET seq_legacy = 1;
-- Two different records one signer signed under one (group_id, id), kept
-- as proof. At most 1024 rows; the oldest are dropped.
CREATE TABLE equivocations (
    group_id BLOB NOT NULL,
    id BIGINT NOT NULL,
    signer BLOB NOT NULL,
    record_a BLOB NOT NULL,
    signature_a BLOB NOT NULL,
    record_b BLOB NOT NULL,
    signature_b BLOB NOT NULL,
    seen_ns BIGINT NOT NULL,
    PRIMARY KEY (group_id, id, signer)
);
