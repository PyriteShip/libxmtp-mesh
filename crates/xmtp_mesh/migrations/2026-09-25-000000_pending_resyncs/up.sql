-- Restore convergence, final review I2: a replaced identity log whose local
-- libxmtp client has not resynced yet. Written in the replace's own
-- transaction and deleted once the client resynced, so a crash or stop in
-- between is replayed at the next start_sync. `generation` counts replaces,
-- so a resync of an older replace never clears a newer one's marker.
CREATE TABLE IF NOT EXISTS pending_resyncs (
    inbox_id TEXT PRIMARY KEY NOT NULL,
    generation BIGINT NOT NULL
);
