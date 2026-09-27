//! Spool admission (§R5.1, §R5.4, §R8): validate, dedup, cap one
//! neighbour's share (newest wins: a full share evicts its own soonest-drop
//! entry), cap all strangers together the same way, evict soonest-drop
//! when full (a stranger's envelope only ever displaces strangers' entries).
//! Rate limits are the engine's
//! (in-memory [`TokenBucket`]s), checked before this runs.
use tokio::time::Instant;

use super::RelayConfig;
use super::envelope::{self, EXPIRY_BUCKET_SECS, MAX_TTL};
use crate::MeshError;
use crate::store::{MeshStore, SpoolEntry};

/// Grace beyond 24 h for a signed expiry (clock drift, §R8).
const MAX_AHEAD_SECS: i64 = 25 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DropReason {
    Invalid,
    Expired,
    /// A stranger's envelope with no room left once only strangers'
    /// entries may go (§R5.4): contacts' entries are never displaced.
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Accept {
    /// `share_evicted`: how many of the sender's soonest-drop entries were
    /// pushed out of its full share to make room.
    New {
        hash: [u8; 32],
        share_evicted: u32,
    },
    Duplicate,
    Dropped(DropReason),
}

/// The envelope's signed expiry if its header is well formed and it is live
/// now (not expired, not implausibly far ahead).
pub(crate) fn live_expiry(sealed: &[u8], now_secs: i64) -> Result<i64, DropReason> {
    let header = envelope::header(sealed).ok_or(DropReason::Invalid)?;
    if header.expires_at % EXPIRY_BUCKET_SECS != 0 {
        return Err(DropReason::Invalid);
    }
    let expires_at = header.expires_at.min(i64::MAX as u64) as i64;
    if expires_at <= now_secs {
        return Err(DropReason::Expired);
    }
    if expires_at > now_secs + MAX_AHEAD_SECS {
        return Err(DropReason::Invalid);
    }
    Ok(expires_at)
}

pub(crate) fn accept(
    store: &mut MeshStore,
    cfg: &RelayConfig,
    ttl: u32,
    sealed: &[u8],
    from: &[u8],
    now_secs: i64,
) -> Result<Accept, MeshError> {
    if ttl > MAX_TTL {
        return Ok(Accept::Dropped(DropReason::Invalid));
    }
    let expires_at = match live_expiry(sealed, now_secs) {
        Ok(at) => at,
        Err(reason) => return Ok(Accept::Dropped(reason)),
    };
    let hash = envelope::hash(sealed);
    store.transaction(|s| {
        // The spool row too: a capped seen-set may have forgotten an
        // envelope that is still held.
        if s.relay_is_seen(&hash)? || s.spool_get(&hash)?.is_some() {
            return Ok(Accept::Duplicate);
        }
        s.relay_purge(now_secs)?;
        let mut share_evicted = 0;
        if !from.is_empty() {
            while s.spool_count_from(from)? >= cfg.share_cap() as i64
                && s.spool_evict_soonest_from(from)?
            {
                share_evicted += 1;
            }
        }
        // All strangers together hold at most their joint share, in
        // entries and bytes (§R5.4). A stranger's envelope makes room only
        // by displacing strangers' entries: if contacts' entries alone
        // leave no room, it is refused.
        let stranger = crate::relay::is_stranger(from);
        if stranger {
            let (n, bytes) = s.spool_totals()?;
            let (sn, sbytes) = s.spool_stranger_totals()?;
            let len = sealed.len() as i64;
            if n - sn >= cfg.max_entries as i64
                || bytes - sbytes + len > cfg.max_bytes as i64
                || len > cfg.stranger_share_bytes() as i64
                || cfg.stranger_share_cap() == 0
            {
                return Ok(Accept::Dropped(DropReason::Full));
            }
            loop {
                let (sn, sbytes) = s.spool_stranger_totals()?;
                if (sn as usize) < cfg.stranger_share_cap()
                    && sbytes as usize + sealed.len() <= cfg.stranger_share_bytes()
                {
                    break;
                }
                if !s.spool_evict_soonest_stranger()? {
                    break;
                }
                share_evicted += 1;
            }
        }
        loop {
            let (n, bytes) = s.spool_totals()?;
            if (n as usize) < cfg.max_entries && bytes as usize + sealed.len() <= cfg.max_bytes {
                break;
            }
            let evicted = if stranger {
                s.spool_evict_soonest_stranger()?
            } else {
                s.spool_evict_soonest()?
            };
            if !evicted {
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
        s.relay_mark_seen(&hash, expires_at, cfg.max_seen)?;
        Ok(Accept::New {
            hash,
            share_evicted,
        })
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

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.per_sec).min(self.capacity);
        self.last = now;
    }

    /// Refill to `now`, then say whether `n` tokens are available.
    pub(crate) fn allows(&mut self, n: f64, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= n
    }

    /// Refill to `now`; the tokens available.
    pub(crate) fn level(&mut self, now: Instant) -> f64 {
        self.refill(now);
        self.tokens
    }

    /// Refill to `now`; whether it is back at capacity (as good as new).
    pub(crate) fn is_full(&mut self, now: Instant) -> bool {
        self.level(now) >= self.capacity
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
        let Accept::New { hash, .. } = accept(&mut s, &small(), 4, &e, b"p", NOW).unwrap() else {
            panic!("new")
        };
        assert_eq!(s.spool_get(&hash).unwrap().unwrap().ttl, 3);
        assert_eq!(
            accept(&mut s, &small(), 4, &e, b"q", NOW).unwrap(),
            Accept::Duplicate
        );
        let o = sealed(10, (NOW + M) as u64);
        let Accept::New { hash, .. } = accept(&mut s, &small(), 4, &o, b"", NOW).unwrap() else {
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
        // Share cap 2; a long hold so drop_at follows the expiry.
        let cfg = RelayConfig {
            hold: std::time::Duration::from_secs(10 * M as u64),
            ..small()
        };
        let mut held = Vec::new();
        for i in 0..2 {
            let Accept::New {
                hash,
                share_evicted: 0,
            } = accept(
                &mut s,
                &cfg,
                3,
                &sealed(1, (NOW + (i + 1) * M) as u64),
                b"spam",
                NOW,
            )
            .unwrap()
            else {
                panic!("first two fit the share")
            };
            held.push(hash);
        }
        // Full share: the newcomer wins; the neighbour's soonest-drop entry
        // (the first, expiring at NOW + M) goes.
        let Accept::New {
            hash: newest,
            share_evicted: 1,
        } = accept(
            &mut s,
            &cfg,
            3,
            &sealed(1, (NOW + 3 * M) as u64),
            b"spam",
            NOW,
        )
        .unwrap()
        else {
            panic!("newcomer accepted by evicting within the share")
        };
        assert_eq!(s.spool_count_from(b"spam").unwrap(), 2);
        assert!(s.spool_get(&held[0]).unwrap().is_none());
        assert!(s.spool_get(&held[1]).unwrap().is_some());
        assert!(s.spool_get(&newest).unwrap().is_some());
        // Another neighbour's share is untouched by it.
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
            Accept::New {
                share_evicted: 0,
                ..
            }
        ));
        assert_eq!(s.spool_count_from(b"spam").unwrap(), 2);
    }

    #[test]
    fn a_share_already_over_the_cap_is_trimmed_below_it() {
        let mut s = MeshStore::open_in_memory().unwrap();
        let cfg = small(); // share cap 2
        for i in 0..3u8 {
            s.spool_insert(&SpoolEntry {
                hash: vec![i; 32],
                sealed: vec![0; 512],
                ttl: 3,
                drop_at: NOW + 60 + i64::from(i),
                from_installation: b"p".to_vec(),
            })
            .unwrap();
        }
        let Accept::New { share_evicted, .. } =
            accept(&mut s, &cfg, 3, &sealed(1, (NOW + M) as u64), b"p", NOW).unwrap()
        else {
            panic!("accepted")
        };
        assert_eq!(share_evicted, 2);
        assert_eq!(s.spool_count_from(b"p").unwrap(), 2);
        assert!(s.spool_get(&[2; 32]).unwrap().is_some(), "latest-drop kept");
    }

    #[test]
    fn live_expiry_refuses_expired_and_malformed() {
        assert_eq!(live_expiry(&sealed(1, (NOW + M) as u64), NOW), Ok(NOW + M));
        assert_eq!(
            live_expiry(&sealed(1, NOW as u64), NOW),
            Err(DropReason::Expired)
        );
        assert_eq!(
            live_expiry(&sealed(1, (NOW + M + 1) as u64), NOW),
            Err(DropReason::Invalid)
        );
        assert_eq!(live_expiry(&[0; 17], NOW), Err(DropReason::Invalid));
    }

    #[test]
    fn full_spool_evicts_soonest_drop() {
        let mut s = MeshStore::open_in_memory().unwrap();
        let cfg = small();
        let first = sealed(1, (NOW + M) as u64);
        let Accept::New {
            hash: first_hash, ..
        } = accept(&mut s, &cfg, 3, &first, b"", NOW).unwrap()
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
        let Accept::New { hash, .. } = accept(&mut s, &cfg, 3, &e, b"p", NOW).unwrap() else {
            panic!()
        };
        assert_eq!(s.spool_get(&hash).unwrap().unwrap().drop_at, NOW + 600);
    }

    /// Accept keeps the seen-set within
    /// `max_seen`; an envelope still in the spool whose seen entry was
    /// forgotten is still a duplicate.
    #[test]
    fn accept_caps_the_seen_set() {
        let mut s = MeshStore::open_in_memory().unwrap();
        let cfg = RelayConfig {
            max_seen: 2,
            ..small()
        };
        let first = sealed(10, (NOW + M) as u64);
        for i in 0..4 {
            let e = if i == 0 {
                first.clone()
            } else {
                sealed(10, (NOW + 2 * M) as u64)
            };
            assert!(matches!(
                accept(&mut s, &cfg, 3, &e, &[i + 1], NOW).unwrap(),
                Accept::New { .. }
            ));
        }
        assert_eq!(s.relay_seen_count().unwrap(), 2);
        assert!(!s.relay_is_seen(&envelope::hash(&first)).unwrap());
        assert_eq!(
            accept(&mut s, &cfg, 3, &first, b"q", NOW).unwrap(),
            Accept::Duplicate,
            "still spooled"
        );
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
        assert_eq!(c.answer_delay_ms, (2_000, 10_000));
        assert_eq!(c.max_seen, 16 * c.max_entries);
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

    /// §R5.4: stranger links share one spool cap between them; a contact's
    /// share is its own.
    #[test]
    fn strangers_together_keep_to_their_spool_cap() {
        let cfg = RelayConfig {
            max_entries: 16,
            max_bytes: 16 * 512,
            stranger_window_factor: 2,
            ..RelayConfig::default()
        };
        assert_eq!(cfg.stranger_share_cap(), 8);
        let mut s = MeshStore::open_in_memory().unwrap();
        let sources: Vec<Vec<u8>> = (0..3).map(|_| crate::relay::stranger_source()).collect();
        for src in &sources {
            for _ in 0..4 {
                accept(&mut s, &cfg, 3, &sealed(10, (NOW + M) as u64), src, NOW).unwrap();
            }
        }
        assert_eq!(s.spool_count_strangers().unwrap(), 8);
        let contact = vec![9u8; 32];
        for _ in 0..4 {
            accept(
                &mut s,
                &cfg,
                3,
                &sealed(10, (NOW + M) as u64),
                &contact,
                NOW,
            )
            .unwrap();
        }
        assert_eq!(s.spool_count_from(&contact).unwrap(), 4);
        assert_eq!(s.spool_count_strangers().unwrap(), 8);
    }

    /// §R5.4: strangers filling the spool's bytes never push out a
    /// contact's entry, even one that would drop sooner than theirs.
    #[test]
    fn strangers_filling_bytes_never_displace_a_contacts_entry() {
        let big = |exp| sealed(1000, exp);
        let big_len = big((NOW + 2 * M) as u64).len();
        let cfg = RelayConfig {
            max_entries: 64,
            max_bytes: 8 * big_len,
            ..RelayConfig::default()
        };
        let mut s = MeshStore::open_in_memory().unwrap();
        let contact = vec![9u8; 32];
        let Accept::New { hash, .. } = accept(
            &mut s,
            &cfg,
            3,
            &sealed(10, (NOW + M) as u64),
            &contact,
            NOW,
        )
        .unwrap() else {
            panic!("new")
        };
        for _ in 0..3 {
            let src = crate::relay::stranger_source();
            for _ in 0..5 {
                accept(&mut s, &cfg, 3, &big((NOW + 2 * M) as u64), &src, NOW).unwrap();
            }
        }
        assert!(
            s.spool_get(&hash).unwrap().is_some(),
            "the contact's entry stays"
        );
        let (n, bytes) = s.spool_totals().unwrap();
        assert!(bytes as usize <= cfg.max_bytes);
        assert_eq!(s.spool_count_strangers().unwrap(), n - 1);
    }

    /// §R5.4: strangers together keep to a byte cap too, and a stranger's
    /// envelope is refused when only contacts' entries could make room.
    #[test]
    fn strangers_keep_to_a_byte_cap_and_are_refused_by_a_spool_full_of_contacts() {
        let cfg = RelayConfig {
            max_entries: 8,
            max_bytes: 8 * 2048,
            stranger_window_factor: 1,
            ..RelayConfig::default()
        };
        let mut s = MeshStore::open_in_memory().unwrap();
        let src = crate::relay::stranger_source();
        for _ in 0..3 {
            accept(&mut s, &cfg, 3, &sealed(1500, (NOW + M) as u64), &src, NOW).unwrap();
        }
        let (_, bytes) = s.spool_stranger_totals().unwrap();
        assert!(bytes as usize <= cfg.stranger_share_bytes(), "{bytes}");

        let mut s = MeshStore::open_in_memory().unwrap();
        for c in 0..4u8 {
            for _ in 0..2 {
                accept(
                    &mut s,
                    &cfg,
                    3,
                    &sealed(10, (NOW + M) as u64),
                    &[c; 32],
                    NOW,
                )
                .unwrap();
            }
        }
        assert_eq!(
            accept(
                &mut s,
                &cfg,
                3,
                &sealed(10, (NOW + 2 * M) as u64),
                &src,
                NOW
            )
            .unwrap(),
            Accept::Dropped(DropReason::Full)
        );
        assert_eq!(s.spool_totals().unwrap().0, 8);
        assert_eq!(s.spool_count_strangers().unwrap(), 0);
    }
}
