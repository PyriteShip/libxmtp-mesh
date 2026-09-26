use std::time::Duration;

/// Relay limits and timings (spec §5, §6.1, §8). `Default` is the spec;
/// tests shorten the timings.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// Longest an envelope stays in the spool (phase 1: 10 min).
    pub hold: Duration,
    pub max_entries: usize,
    pub max_bytes: usize,
    /// Most `relay_seen` entries kept; beyond it the soonest to be forgotten
    /// go first (spec §5.1). Default 16 × `max_entries`.
    pub max_seen: usize,
    /// Per neighbour phone (verified installation), shared by all its links (D18).
    pub neighbour_envelopes_per_min: u32,
    pub neighbour_bytes_per_min: u32,
    pub global_envelopes_per_min: u32,
    pub global_bytes_per_min: u32,
    /// Random wait before pushing a new envelope on, for timing privacy.
    pub push_delay_ms: (u64, u64),
    /// Random wait before a DM answer that a delivery triggered (an ack, or
    /// a sync answering a pending), so a phone next to the recipient cannot
    /// pair an envelope going in with a fresh one coming out (spec §9).
    /// Answers to local new content are not delayed.
    pub answer_delay_ms: (u64, u64),
    /// Re-sends after the first send, each a fresh seal (spec §6.1).
    pub retry_after: Vec<Duration>,
    /// How often an unacked relay-key offer is repeated on a live link.
    pub key_reoffer: Duration,
    /// Engine housekeeping period (purge, retries, offers, quarantine).
    pub tick: Duration,
    /// Starting TTL range at origin (inclusive).
    pub origin_ttl: (u32, u32),
    pub quarantine_max: usize,
    pub quarantine_for: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            hold: Duration::from_secs(600),
            max_entries: 4096,
            max_bytes: 8 * 1024 * 1024,
            max_seen: 16 * 4096,
            neighbour_envelopes_per_min: 200,
            neighbour_bytes_per_min: 256 * 1024,
            global_envelopes_per_min: 2000,
            global_bytes_per_min: 2560 * 1024,
            push_delay_ms: (100, 500),
            answer_delay_ms: (2_000, 10_000),
            retry_after: [2, 5, 15, 60]
                .into_iter()
                .map(|m| Duration::from_secs(m * 60))
                .collect(),
            key_reoffer: Duration::from_secs(5),
            tick: Duration::from_secs(1),
            origin_ttl: (3, 5),
            quarantine_max: 32,
            quarantine_for: Duration::from_secs(600),
        }
    }
}

impl RelayConfig {
    /// Most spool entries one neighbour may occupy (25%, spec §5.4); also
    /// its token-bucket burst.
    pub fn share_cap(&self) -> usize {
        self.max_entries / 4
    }

    pub fn share_cap_bytes(&self) -> usize {
        self.max_bytes / 4
    }
}
