-- Private discovery (DESIGN.md §B14.4): one row per contact. A row with
-- removed_ns set is a removed contact, kept so its static key is refused.
CREATE TABLE contacts (
    inbox_id TEXT PRIMARY KEY NOT NULL,
    noise_static_pub BLOB NOT NULL,
    discovery_key BLOB NOT NULL,
    generation INTEGER NOT NULL,
    updated_ns BIGINT NOT NULL,
    removed_ns BIGINT
);
CREATE INDEX contacts_static ON contacts (noise_static_pub);
