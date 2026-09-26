//! Spool admission (spec §5.1, §5.4, §8): validate, dedup, cap one
//! neighbour's share, evict soonest-drop when full. Rate limits are the engine's
//! (in-memory [`TokenBucket`]s), checked before this runs.
use tokio::time::Instant;

use super::RelayConfig;
use super::envelope::{self, EXPIRY_BUCKET_SECS, MAX_TTL};
use crate::MeshError;
use crate::store::{MeshStore, SpoolEntry};

/// Grace beyond 24 h for a signed expiry (clock drift, spec §8).
const MAX_AHEAD_SECS: i64 = 25 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DropReason {
    Invalid,
    Expired,
    Share,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Accept {
    New { hash: [u8; 32] },
    Duplicate,
    Dropped(DropReason),
}

pub(crate) fn accept(
    store: &mut MeshStore,
    cfg: &RelayConfig,
    ttl: u32,
    sealed: &[u8],
    from: &[u8],
    now_secs: i64,
) -> Result<Accept, MeshError> {
    let Some(header) = envelope::header(sealed) else {
        return Ok(Accept::Dropped(DropReason::Invalid));
    };
    if ttl > MAX_TTL || header.expires_at % EXPIRY_BUCKET_SECS != 0 {
        return Ok(Accept::Dropped(DropReason::Invalid));
    }
    let expires_at = header.expires_at.min(i64::MAX as u64) as i64;
    if expires_at <= now_secs {
        return Ok(Accept::Dropped(DropReason::Expired));
    }
    if expires_at > now_secs + MAX_AHEAD_SECS {
        return Ok(Accept::Dropped(DropReason::Invalid));
    }
    let hash = envelope::hash(sealed);
    store.transaction(|s| {
        if s.relay_is_seen(&hash)? {
            return Ok(Accept::Duplicate);
        }
        s.relay_purge(now_secs)?;
        if !from.is_empty() && s.spool_count_from(from)? >= cfg.share_cap() as i64 {
            return Ok(Accept::Dropped(DropReason::Share));
        }
        loop {
            let (n, bytes) = s.spool_totals()?;
            if (n as usize) < cfg.max_entries && bytes as usize + sealed.len() <= cfg.max_bytes {
                break;
            }
            if !s.spool_evict_soonest()? {
                break;
            }
        }
        let stored_ttl = if from.is_empty() {
            ttl
        } else {
            ttl.saturating_sub(1)
        };
        s.spool_insert(&SpoolEntry {
            hash: hash.to_vec(),
            sealed: sealed.to_vec(),
            ttl: stored_ttl as i32,
            drop_at: expires_at.min(now_secs + cfg.hold.as_secs() as i64),
            from_installation: from.to_vec(),
        })?;
        s.relay_mark_seen(&hash, expires_at)?;
        Ok(Accept::New { hash })
    })
}

/// Classic token bucket: `capacity` burst, refilled at `per_minute`.
pub(crate) struct TokenBucket {
    capacity: f64,
    tokens: f64,
    per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    pub(crate) fn new(capacity: f64, per_minute: f64, now: Instant) -> Self {
        Self {
            capacity,
            tokens: capacity,
            per_sec: per_minute / 60.0,
            last: now,
        }
    }

    /// Refill to `now`, then say whether `n` tokens are available.
    pub(crate) fn allows(&mut self, n: f64, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.per_sec).min(self.capacity);
        self.last = now;
        self.tokens >= n
    }

    pub(crate) fn take(&mut self, n: f64) {
        self.tokens -= n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::envelope;

    const NOW: i64 = 1_000_200; // a multiple of 600

    fn sealed(len_body: usize, expires_at: u64) -> Vec<u8> {
        envelope::seal(&rand::random(), expires_at, &vec![0; len_body]).unwrap()
    }

    /// Expiries in these tests are multiples of 600 past NOW (NOW itself is one).
    const M: i64 = 600;

    fn small() -> RelayConfig {
        RelayConfig {
            max_entries: 8,
            max_bytes: 8 * 512,
            ..RelayConfig::default()
        }
    }

    #[test]
    fn new_then_duplicate_and_ttl_decrements_from_links() {
        let mut s = MeshStore::open_in_memory().unwrap();
        let e = sealed(10, (NOW + M) as u64);
        let Accept::New { hash } = accept(&mut s, &small(), 4, &e, b"p", NOW).unwrap() else {
            panic!("new")
        };
        assert_eq!(s.spool_get(&hash).unwrap().unwrap().ttl, 3);
        assert_eq!(
            accept(&mut s, &small(), 4, &e, b"q", NOW).unwrap(),
            Accept::Duplicate
        );
        let o = sealed(10, (NOW + M) as u64);
        let Accept::New { hash } = accept(&mut s, &small(), 4, &o, b"", NOW).unwrap() else {
            panic!("new")
        };
        assert_eq!(
            s.spool_get(&hash).unwrap().unwrap().ttl,
            4,
            "own origin keeps its ttl"
        );
    }

    #[test]
    fn invalid_and_expired_are_dropped() {
        let mut s = MeshStore::open_in_memory().unwrap();
        let cfg = small();
        let ok = sealed(10, (NOW + M) as u64);
        let mut bad_len = ok.clone();
        bad_len.push(0);
        assert_eq!(
            accept(&mut s, &cfg, 3, &bad_len, b"p", NOW).unwrap(),
            Accept::Dropped(DropReason::Invalid)
        );
        assert_eq!(
            accept(&mut s, &cfg, 8, &ok, b"p", NOW).unwrap(),
            Accept::Dropped(DropReason::Invalid)
        );
        let odd = sealed(10, (NOW + M + 1) as u64);
        assert_eq!(
            accept(&mut s, &cfg, 3, &odd, b"p", NOW).unwrap(),
            Accept::Dropped(DropReason::Invalid),
            "expiry must be coarse"
        );
        let old = sealed(10, (NOW - M) as u64);
        assert_eq!(
            accept(&mut s, &cfg, 3, &old, b"p", NOW).unwrap(),
            Accept::Dropped(DropReason::Expired)
        );
        let far = sealed(10, (NOW + 25 * 3600 + M) as u64);
        assert_eq!(
            accept(&mut s, &cfg, 3, &far, b"p", NOW).unwrap(),
            Accept::Dropped(DropReason::Invalid)
        );
        let edge = sealed(10, (NOW + 25 * 3600) as u64);
        assert!(matches!(
            accept(&mut s, &cfg, 3, &edge, b"p", NOW).unwrap(),
            Accept::New { .. }
        ));
    }

    #[test]
    fn one_neighbour_holds_at_most_a_quarter() {
        let mut s = MeshStore::open_in_memory().unwrap();
        let cfg = small(); // share cap 2
        for _ in 0..2 {
            assert!(matches!(
                accept(&mut s, &cfg, 3, &sealed(1, (NOW + M) as u64), b"spam", NOW).unwrap(),
                Accept::New { .. }
            ));
        }
        assert_eq!(
            accept(&mut s, &cfg, 3, &sealed(1, (NOW + M) as u64), b"spam", NOW).unwrap(),
            Accept::Dropped(DropReason::Share)
        );
        assert!(matches!(
            accept(
                &mut s,
                &cfg,
                3,
                &sealed(1, (NOW + M) as u64),
                b"honest",
                NOW
            )
            .unwrap(),
            Accept::New { .. }
        ));
    }

    #[test]
    fn full_spool_evicts_soonest_drop() {
        let mut s = MeshStore::open_in_memory().unwrap();
        let cfg = small();
        let first = sealed(1, (NOW + M) as u64);
        let Accept::New { hash: first_hash } = accept(&mut s, &cfg, 3, &first, b"", NOW).unwrap()
        else {
            panic!()
        };
        for _ in 0..8 {
            accept(&mut s, &cfg, 3, &sealed(1, (NOW + 2 * M) as u64), b"", NOW).unwrap();
        }
        assert_eq!(s.spool_totals().unwrap().0, 8);
        assert!(
            s.spool_get(&first_hash).unwrap().is_none(),
            "soonest drop evicted"
        );
    }

    #[test]
    fn drop_at_is_capped_by_hold() {
        let mut s = MeshStore::open_in_memory().unwrap();
        let cfg = small(); // hold 10 min
        let e = sealed(1, (NOW + 24 * 3600) as u64);
        let Accept::New { hash } = accept(&mut s, &cfg, 3, &e, b"p", NOW).unwrap() else {
            panic!()
        };
        assert_eq!(s.spool_get(&hash).unwrap().unwrap().drop_at, NOW + 600);
    }

    #[test]
    fn token_bucket_bursts_then_refills() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(3.0, 60.0, t0); // 1 per second
        for _ in 0..3 {
            assert!(b.allows(1.0, t0));
            b.take(1.0);
        }
        assert!(!b.allows(1.0, t0));
        assert!(b.allows(1.0, t0 + std::time::Duration::from_millis(1100)));
    }

    #[test]
    fn defaults_are_the_spec_values() {
        let c = RelayConfig::default();
        assert_eq!(c.hold, std::time::Duration::from_secs(600));
        assert_eq!((c.max_entries, c.max_bytes), (4096, 8 * 1024 * 1024));
        assert_eq!(
            (c.neighbour_envelopes_per_min, c.neighbour_bytes_per_min),
            (200, 256 * 1024)
        );
        assert_eq!(
            (c.global_envelopes_per_min, c.global_bytes_per_min),
            (2000, 2560 * 1024)
        );
        assert_eq!(c.push_delay_ms, (100, 500));
        assert_eq!(c.origin_ttl, (3, 5));
        assert_eq!(
            (c.share_cap(), c.share_cap_bytes()),
            (1024, 2 * 1024 * 1024)
        );
        assert_eq!(c.key_reoffer, std::time::Duration::from_secs(5));
        assert_eq!(
            (c.quarantine_max, c.quarantine_for),
            (32, std::time::Duration::from_secs(600))
        );
        let mins: Vec<u64> = c.retry_after.iter().map(|d| d.as_secs() / 60).collect();
        assert_eq!(mins, vec![2, 5, 15, 60]);
    }
}
