CREATE TABLE relay_spool (
    hash BLOB PRIMARY KEY NOT NULL,
    sealed BLOB NOT NULL,
    ttl INTEGER NOT NULL,
    drop_at BIGINT NOT NULL,
    from_installation BLOB NOT NULL
);
CREATE INDEX relay_spool_drop_at ON relay_spool (drop_at);
-- SpoolWant lookups by the 8-byte digest id.
CREATE INDEX relay_spool_short ON relay_spool (substr(hash, 1, 8));
-- Per-neighbour share count and soonest-drop eviction.
CREATE INDEX relay_spool_from ON relay_spool (from_installation, drop_at);
CREATE TABLE relay_seen (
    hash BLOB PRIMARY KEY NOT NULL,
    forget_at BIGINT NOT NULL
);
-- Digest lookups by the 8-byte id; purge and cap eviction by forget_at.
CREATE INDEX relay_seen_short ON relay_seen (substr(hash, 1, 8));
CREATE INDEX relay_seen_forget_at ON relay_seen (forget_at);
CREATE TABLE relay_keys (
    group_id BLOB PRIMARY KEY NOT NULL,
    relay_key BLOB NOT NULL,
    confirmed BOOLEAN NOT NULL,
    -- The installation whose ack (sequencer) or offer (joiner) confirmed
    -- the key; empty while unconfirmed.
    confirmed_by BLOB NOT NULL DEFAULT x''
);
CREATE TABLE relay_dm (
    group_id BLOB PRIMARY KEY NOT NULL,
    peer_acked_high BIGINT NOT NULL
);
ALTER TABLE group_messages ADD COLUMN from_peer BOOLEAN NOT NULL DEFAULT 0;
