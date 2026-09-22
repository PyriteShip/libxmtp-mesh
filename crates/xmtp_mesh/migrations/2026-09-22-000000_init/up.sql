CREATE TABLE node_meta (
    key TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL
);
CREATE TABLE identity_updates (
    inbox_id TEXT NOT NULL,
    sequence_id BIGINT NOT NULL,
    server_timestamp_ns BIGINT NOT NULL,
    update_bytes BLOB NOT NULL,
    PRIMARY KEY (inbox_id, sequence_id)
);
CREATE TABLE inbox_identifiers (
    identifier TEXT NOT NULL,
    identifier_kind INTEGER NOT NULL,
    inbox_id TEXT NOT NULL,
    PRIMARY KEY (identifier, identifier_kind)
);
CREATE TABLE key_packages (
    installation_key BLOB PRIMARY KEY NOT NULL,
    key_package BLOB NOT NULL
);
CREATE TABLE groups (
    group_id BLOB PRIMARY KEY NOT NULL,
    sequencer BLOB
);
CREATE TABLE group_messages (
    group_id BLOB NOT NULL,
    id BIGINT NOT NULL,
    created_ns BIGINT NOT NULL,
    data BLOB NOT NULL,
    sender_hmac BLOB NOT NULL,
    should_push BOOLEAN NOT NULL,
    is_commit BOOLEAN NOT NULL,
    data_hash BLOB NOT NULL,
    PRIMARY KEY (group_id, id),
    UNIQUE (group_id, data_hash)
);
CREATE TABLE pending_group_messages (
    group_id BLOB NOT NULL,
    data_hash BLOB NOT NULL,
    data BLOB NOT NULL,
    sender_hmac BLOB NOT NULL,
    should_push BOOLEAN NOT NULL,
    is_commit BOOLEAN NOT NULL,
    created_ns BIGINT NOT NULL,
    PRIMARY KEY (group_id, data_hash)
);
CREATE TABLE welcomes (
    installation_key BLOB NOT NULL,
    id BIGINT NOT NULL,
    created_ns BIGINT NOT NULL,
    envelope_hash BLOB NOT NULL,
    input BLOB NOT NULL,
    PRIMARY KEY (installation_key, id),
    UNIQUE (installation_key, envelope_hash)
);
CREATE TABLE outbound_welcomes (
    envelope_hash BLOB PRIMARY KEY NOT NULL,
    installation_key BLOB NOT NULL,
    input BLOB NOT NULL
);
