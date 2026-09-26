//! Relay tables (spec §5.1, §4.5, §6.3). Times are unix seconds.
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Binary, Bool, Integer};

use super::{GROUP_COLUMNS, I64Row, MeshStore, NewGroupMessage, PendingRow, StoredGroupMessage};
use crate::MeshError;

/// One envelope held for others.
#[derive(Debug, Clone, PartialEq, QueryableByName)]
pub struct SpoolEntry {
    #[diesel(sql_type = Binary)]
    pub hash: Vec<u8>,
    #[diesel(sql_type = Binary)]
    pub sealed: Vec<u8>,
    /// Hops left to push it on (0: carried, not pushed).
    #[diesel(sql_type = Integer)]
    pub ttl: i32,
    /// Local time after which it is dropped: min(signed expiry, now + hold).
    #[diesel(sql_type = BigInt)]
    pub drop_at: i64,
    /// Verified installation key of the neighbour it arrived from; empty
    /// when this node originated it (D18: limits are per phone, not per link).
    #[diesel(sql_type = Binary)]
    pub from_installation: Vec<u8>,
}

#[derive(QueryableByName)]
struct KeyRow {
    #[diesel(sql_type = Binary)]
    group_id: Vec<u8>,
    #[diesel(sql_type = Binary)]
    relay_key: Vec<u8>,
    #[diesel(sql_type = Bool)]
    confirmed: bool,
}

// The embedded field is named `msg`, not `row`: the generated
// `QueryableByName::build` binds its `&impl NamedRow` parameter as `row`,
// and an embedded field named `row` would shadow it before later fields
// are deserialized (E0308: "expected `&_`, found `StoredGroupMessage`").
#[derive(QueryableByName)]
struct OriginRow {
    #[diesel(embed)]
    msg: StoredGroupMessage,
    #[diesel(sql_type = Bool)]
    from_peer: bool,
}

#[derive(QueryableByName)]
struct TotalsRow {
    #[diesel(sql_type = BigInt)]
    n: i64,
    #[diesel(sql_type = BigInt)]
    bytes: i64,
}

const SPOOL_COLUMNS: &str = "hash, sealed, ttl, drop_at, from_installation";

fn key32(v: Vec<u8>) -> Result<[u8; 32], MeshError> {
    v.try_into()
        .map_err(|_| MeshError::Relay("stored relay key is not 32 bytes".into()))
}

impl MeshStore {
    pub fn relay_is_seen(&mut self, hash: &[u8]) -> Result<bool, MeshError> {
        let rows: Vec<I64Row> = sql_query("SELECT COUNT(*) AS v FROM relay_seen WHERE hash = ?")
            .bind::<Binary, _>(hash)
            .load(&mut self.conn)?;
        Ok(rows[0].v > 0)
    }

    pub fn relay_is_seen_short(&mut self, short: &[u8]) -> Result<bool, MeshError> {
        let rows: Vec<I64Row> =
            sql_query("SELECT COUNT(*) AS v FROM relay_seen WHERE substr(hash, 1, 8) = ?")
                .bind::<Binary, _>(short)
                .load(&mut self.conn)?;
        Ok(rows[0].v > 0)
    }

    pub fn relay_mark_seen(&mut self, hash: &[u8], forget_at: i64) -> Result<(), MeshError> {
        sql_query(
            "INSERT INTO relay_seen (hash, forget_at) VALUES (?, ?) \
             ON CONFLICT(hash) DO UPDATE SET forget_at = MAX(forget_at, excluded.forget_at)",
        )
        .bind::<Binary, _>(hash)
        .bind::<BigInt, _>(forget_at)
        .execute(&mut self.conn)?;
        Ok(())
    }

    pub fn spool_insert(&mut self, e: &SpoolEntry) -> Result<(), MeshError> {
        sql_query(format!(
            "INSERT OR IGNORE INTO relay_spool ({SPOOL_COLUMNS}) VALUES (?, ?, ?, ?, ?)"
        ))
        .bind::<Binary, _>(&e.hash)
        .bind::<Binary, _>(&e.sealed)
        .bind::<Integer, _>(e.ttl)
        .bind::<BigInt, _>(e.drop_at)
        .bind::<Binary, _>(&e.from_installation)
        .execute(&mut self.conn)?;
        Ok(())
    }

    pub fn spool_get(&mut self, hash: &[u8]) -> Result<Option<SpoolEntry>, MeshError> {
        let rows: Vec<SpoolEntry> = sql_query(format!(
            "SELECT {SPOOL_COLUMNS} FROM relay_spool WHERE hash = ?"
        ))
        .bind::<Binary, _>(hash)
        .load(&mut self.conn)?;
        Ok(rows.into_iter().next())
    }

    pub fn spool_by_short(&mut self, short: &[u8]) -> Result<Option<SpoolEntry>, MeshError> {
        let rows: Vec<SpoolEntry> = sql_query(format!(
            "SELECT {SPOOL_COLUMNS} FROM relay_spool WHERE substr(hash, 1, 8) = ? LIMIT 1"
        ))
        .bind::<Binary, _>(short)
        .load(&mut self.conn)?;
        Ok(rows.into_iter().next())
    }

    pub fn spool_pushable(&mut self) -> Result<Vec<SpoolEntry>, MeshError> {
        Ok(sql_query(format!(
            "SELECT {SPOOL_COLUMNS} FROM relay_spool WHERE ttl > 0 ORDER BY drop_at DESC"
        ))
        .load(&mut self.conn)?)
    }

    pub fn spool_totals(&mut self) -> Result<(i64, i64), MeshError> {
        let rows: Vec<TotalsRow> = sql_query(
            "SELECT COUNT(*) AS n, COALESCE(SUM(length(sealed)), 0) AS bytes FROM relay_spool",
        )
        .load(&mut self.conn)?;
        Ok((rows[0].n, rows[0].bytes))
    }

    pub fn spool_count_from(&mut self, installation: &[u8]) -> Result<i64, MeshError> {
        let rows: Vec<I64Row> =
            sql_query("SELECT COUNT(*) AS v FROM relay_spool WHERE from_installation = ?")
                .bind::<Binary, _>(installation)
                .load(&mut self.conn)?;
        Ok(rows[0].v)
    }

    pub fn spool_evict_soonest(&mut self) -> Result<bool, MeshError> {
        let n = sql_query(
            "DELETE FROM relay_spool WHERE hash = \
             (SELECT hash FROM relay_spool ORDER BY drop_at ASC LIMIT 1)",
        )
        .execute(&mut self.conn)?;
        Ok(n > 0)
    }

    pub fn relay_purge(&mut self, now_secs: i64) -> Result<(), MeshError> {
        sql_query("DELETE FROM relay_spool WHERE drop_at <= ?")
            .bind::<BigInt, _>(now_secs)
            .execute(&mut self.conn)?;
        sql_query("DELETE FROM relay_seen WHERE forget_at <= ?")
            .bind::<BigInt, _>(now_secs)
            .execute(&mut self.conn)?;
        Ok(())
    }

    pub fn relay_key(&mut self, group_id: &[u8]) -> Result<Option<([u8; 32], bool)>, MeshError> {
        let rows: Vec<KeyRow> =
            sql_query("SELECT group_id, relay_key, confirmed FROM relay_keys WHERE group_id = ?")
                .bind::<Binary, _>(group_id)
                .load(&mut self.conn)?;
        rows.into_iter()
            .next()
            .map(|r| Ok((key32(r.relay_key)?, r.confirmed)))
            .transpose()
    }

    pub fn set_relay_key(
        &mut self,
        group_id: &[u8],
        key: &[u8; 32],
        confirmed: bool,
    ) -> Result<(), MeshError> {
        sql_query(
            "INSERT INTO relay_keys (group_id, relay_key, confirmed) VALUES (?, ?, ?) \
             ON CONFLICT(group_id) DO UPDATE SET relay_key = excluded.relay_key, confirmed = excluded.confirmed",
        )
        .bind::<Binary, _>(group_id)
        .bind::<Binary, _>(key.as_slice())
        .bind::<Bool, _>(confirmed)
        .execute(&mut self.conn)?;
        Ok(())
    }

    /// The stored relay key for `group_id`, first storing `candidate`
    /// (unconfirmed) if there is none. One transaction, so concurrent offers
    /// for one group always agree on one key.
    pub fn relay_key_or_insert(
        &mut self,
        group_id: &[u8],
        candidate: &[u8; 32],
    ) -> Result<([u8; 32], bool), MeshError> {
        self.transaction(|s| {
            sql_query(
                "INSERT OR IGNORE INTO relay_keys (group_id, relay_key, confirmed) VALUES (?, ?, 0)",
            )
            .bind::<Binary, _>(group_id)
            .bind::<Binary, _>(candidate.as_slice())
            .execute(&mut s.conn)?;
            s.relay_key(group_id)?
                .ok_or_else(|| MeshError::Relay("relay key missing after insert".into()))
        })
    }

    pub fn relay_keys(&mut self) -> Result<Vec<(Vec<u8>, [u8; 32], bool)>, MeshError> {
        let rows: Vec<KeyRow> =
            sql_query("SELECT group_id, relay_key, confirmed FROM relay_keys ORDER BY group_id")
                .load(&mut self.conn)?;
        rows.into_iter()
            .map(|r| Ok((r.group_id, key32(r.relay_key)?, r.confirmed)))
            .collect()
    }

    pub fn peer_acked_high(&mut self, group_id: &[u8]) -> Result<i64, MeshError> {
        let rows: Vec<I64Row> = sql_query(
            "SELECT COALESCE(MAX(peer_acked_high), 0) AS v FROM relay_dm WHERE group_id = ?",
        )
        .bind::<Binary, _>(group_id)
        .load(&mut self.conn)?;
        Ok(rows[0].v)
    }

    pub fn note_peer_acked_high(&mut self, group_id: &[u8], high: i64) -> Result<(), MeshError> {
        sql_query(
            "INSERT INTO relay_dm (group_id, peer_acked_high) VALUES (?, ?) \
             ON CONFLICT(group_id) DO UPDATE SET peer_acked_high = MAX(peer_acked_high, excluded.peer_acked_high)",
        )
        .bind::<Binary, _>(group_id)
        .bind::<BigInt, _>(high)
        .execute(&mut self.conn)?;
        Ok(())
    }

    pub fn rows_after_with_origin(
        &mut self,
        group_id: &[u8],
        after: i64,
        limit: i64,
    ) -> Result<Vec<(StoredGroupMessage, bool)>, MeshError> {
        let rows: Vec<OriginRow> = sql_query(format!(
            "SELECT {GROUP_COLUMNS}, from_peer FROM group_messages \
             WHERE group_id = ? AND id > ? ORDER BY id ASC LIMIT ?"
        ))
        .bind::<Binary, _>(group_id)
        .bind::<BigInt, _>(after)
        .bind::<BigInt, _>(limit)
        .load(&mut self.conn)?;
        Ok(rows.into_iter().map(|r| (r.msg, r.from_peer)).collect())
    }

    pub fn pending_by_hash(
        &mut self,
        group_id: &[u8],
        data_hash: &[u8],
    ) -> Result<Option<NewGroupMessage>, MeshError> {
        let rows: Vec<PendingRow> = sql_query(
            "SELECT group_id, data, sender_hmac, should_push, is_commit FROM pending_group_messages \
             WHERE group_id = ? AND data_hash = ?",
        )
        .bind::<Binary, _>(group_id)
        .bind::<Binary, _>(data_hash)
        .load(&mut self.conn)?;
        Ok(rows.into_iter().next().map(|r| NewGroupMessage {
            group_id: r.group_id,
            data: r.data,
            sender_hmac: r.sender_hmac,
            should_push: r.should_push,
            is_commit: r.is_commit,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MeshStore, NewGroupMessage};

    fn entry(hash: u8, drop_at: i64, from: &[u8], len: usize) -> SpoolEntry {
        SpoolEntry {
            hash: vec![hash; 32],
            sealed: vec![0; len],
            ttl: 3,
            drop_at,
            from_installation: from.to_vec(),
        }
    }

    fn msg(data: &[u8]) -> NewGroupMessage {
        NewGroupMessage {
            group_id: vec![1],
            data: data.to_vec(),
            sender_hmac: vec![],
            should_push: true,
            is_commit: false,
        }
    }

    #[test]
    fn spool_insert_get_short_and_totals() {
        let mut s = MeshStore::open_in_memory().unwrap();
        s.spool_insert(&entry(1, 100, b"p", 512)).unwrap();
        s.spool_insert(&entry(2, 50, b"q", 1024)).unwrap();
        assert_eq!(
            s.spool_get(&[1; 32]).unwrap().unwrap().from_installation,
            b"p"
        );
        assert_eq!(
            s.spool_by_short(&[2; 8]).unwrap().unwrap().hash,
            vec![2; 32]
        );
        assert_eq!(s.spool_totals().unwrap(), (2, 1536));
        assert_eq!(s.spool_count_from(b"p").unwrap(), 1);
    }

    #[test]
    fn evicts_soonest_drop_first_and_purges_expired() {
        let mut s = MeshStore::open_in_memory().unwrap();
        s.spool_insert(&entry(1, 100, b"p", 512)).unwrap();
        s.spool_insert(&entry(2, 50, b"p", 512)).unwrap();
        assert!(s.spool_evict_soonest().unwrap());
        assert!(s.spool_get(&[2; 32]).unwrap().is_none());
        s.relay_mark_seen(&[9; 32], 10).unwrap();
        s.relay_purge(100).unwrap();
        assert!(
            s.spool_get(&[1; 32]).unwrap().is_none(),
            "drop_at <= now is purged"
        );
        assert!(!s.relay_is_seen(&[9; 32]).unwrap());
        assert!(!s.spool_evict_soonest().unwrap(), "empty spool");
    }

    #[test]
    fn pushable_excludes_ttl_zero() {
        let mut s = MeshStore::open_in_memory().unwrap();
        s.spool_insert(&entry(1, 100, b"p", 512)).unwrap();
        s.spool_insert(&SpoolEntry {
            ttl: 0,
            ..entry(2, 100, b"p", 512)
        })
        .unwrap();
        let hashes: Vec<_> = s
            .spool_pushable()
            .unwrap()
            .into_iter()
            .map(|e| e.hash)
            .collect();
        assert_eq!(hashes, vec![vec![1; 32]]);
    }

    /// Spec §5.1 / issue #8 lesson 2: the seen-set survives a restart.
    #[test]
    fn seen_set_survives_reopen() {
        let path = std::env::temp_dir().join(format!("relay-seen-{}.db", rand::random::<u64>()));
        let path = path.to_str().unwrap();
        {
            let mut s = MeshStore::open(Some(path), None).unwrap();
            s.relay_mark_seen(&[5; 32], i64::MAX).unwrap();
        }
        let mut s = MeshStore::open(Some(path), None).unwrap();
        assert!(s.relay_is_seen(&[5; 32]).unwrap());
        assert!(s.relay_is_seen_short(&[5; 8]).unwrap());
        drop(s);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn relay_key_or_insert_keeps_the_first_key() {
        let mut s = MeshStore::open_in_memory().unwrap();
        assert_eq!(
            s.relay_key_or_insert(&[1], &[3; 32]).unwrap(),
            ([3; 32], false)
        );
        assert_eq!(
            s.relay_key_or_insert(&[1], &[4; 32]).unwrap(),
            ([3; 32], false)
        );
        s.set_relay_key(&[1], &[3; 32], true).unwrap();
        assert_eq!(
            s.relay_key_or_insert(&[1], &[5; 32]).unwrap(),
            ([3; 32], true)
        );
        assert_eq!(s.relay_key(&[1]).unwrap(), Some(([3; 32], true)));
    }

    #[test]
    fn relay_keys_and_acked_high() {
        let mut s = MeshStore::open_in_memory().unwrap();
        assert!(s.relay_key(&[1]).unwrap().is_none());
        s.set_relay_key(&[1], &[3; 32], false).unwrap();
        s.set_relay_key(&[1], &[3; 32], true).unwrap();
        assert_eq!(s.relay_key(&[1]).unwrap(), Some(([3; 32], true)));
        assert_eq!(s.relay_keys().unwrap().len(), 1);
        assert_eq!(s.peer_acked_high(&[1]).unwrap(), 0);
        s.note_peer_acked_high(&[1], 5).unwrap();
        s.note_peer_acked_high(&[1], 3).unwrap();
        assert_eq!(s.peer_acked_high(&[1]).unwrap(), 5, "keeps the max");
    }

    #[test]
    fn from_peer_is_recorded_and_pending_found_by_hash() {
        let mut s = MeshStore::open_in_memory().unwrap();
        s.ensure_group(&[1]).unwrap();
        s.append_sequenced(&msg(b"mine"), 1).unwrap();
        s.append_sequenced_marked(&msg(b"theirs"), 2, true).unwrap();
        let rows = s.rows_after_with_origin(&[1], 0, 10).unwrap();
        assert_eq!(
            rows.iter()
                .map(|(r, p)| (r.data.clone(), *p))
                .collect::<Vec<_>>(),
            vec![(b"mine".to_vec(), false), (b"theirs".to_vec(), true)]
        );
        s.add_pending(&msg(b"queued"), 3).unwrap();
        let hash = crate::store::sha256(b"queued");
        assert_eq!(
            s.pending_by_hash(&[1], &hash).unwrap().unwrap().data,
            b"queued"
        );
        assert!(s.pending_by_hash(&[1], &[0; 32]).unwrap().is_none());
    }
}
