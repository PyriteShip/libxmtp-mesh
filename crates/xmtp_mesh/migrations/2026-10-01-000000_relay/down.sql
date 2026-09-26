ALTER TABLE group_messages DROP COLUMN from_peer;
DROP TABLE relay_dm;
DROP TABLE relay_keys;
DROP TABLE relay_seen;
DROP INDEX relay_spool_drop_at;
DROP TABLE relay_spool;
