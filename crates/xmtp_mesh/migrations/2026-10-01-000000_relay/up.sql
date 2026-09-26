CREATE TABLE relay_spool (
    hash BLOB PRIMARY KEY NOT NULL,
    sealed BLOB NOT NULL,
    ttl INTEGER NOT NULL,
    drop_at BIGINT NOT NULL,
    from_installation BLOB NOT NULL
);
CREATE INDEX relay_spool_drop_at ON relay_spool (drop_at);
CREATE TABLE relay_seen (
    hash BLOB PRIMARY KEY NOT NULL,
    forget_at BIGINT NOT NULL
);
CREATE TABLE relay_keys (
    group_id BLOB PRIMARY KEY NOT NULL,
    relay_key BLOB NOT NULL,
    confirmed BOOLEAN NOT NULL
);
CREATE TABLE relay_dm (
    group_id BLOB PRIMARY KEY NOT NULL,
    peer_acked_high BIGINT NOT NULL
);
ALTER TABLE group_messages ADD COLUMN from_peer BOOLEAN NOT NULL DEFAULT 0;
