DROP TABLE equivocations;
ALTER TABLE group_messages DROP COLUMN seq_legacy;
ALTER TABLE group_messages DROP COLUMN seq_attested;
ALTER TABLE group_messages DROP COLUMN seq_signature;
ALTER TABLE group_messages DROP COLUMN seq_signer;
