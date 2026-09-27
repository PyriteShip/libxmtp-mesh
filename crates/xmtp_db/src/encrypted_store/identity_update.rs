use std::collections::HashMap;

use crate::StorageError;
use crate::impl_store;

use super::{
    ConnectionExt,
    db_connection::DbConnection,
    schema::identity_updates::{self, dsl},
};
use derive_builder::Builder;
use diesel::{dsl::max, prelude::*};

/// StoredIdentityUpdate holds a serialized IdentityUpdate record
#[derive(Insertable, Identifiable, Queryable, Debug, Clone, PartialEq, Eq, Builder)]
#[diesel(table_name = identity_updates)]
#[diesel(primary_key(inbox_id, sequence_id))]
#[builder(setter(into), build_fn(error = "StorageError"))]
pub struct StoredIdentityUpdate {
    pub inbox_id: String,
    pub sequence_id: i64,
    pub server_timestamp_ns: i64,
    pub payload: Vec<u8>,
    pub originator_id: i32,
}

impl StoredIdentityUpdate {
    pub fn build() -> StoredIdentityUpdateBuilder {
        StoredIdentityUpdateBuilder::default()
    }

    pub fn new(
        inbox_id: String,
        sequence_id: i64,
        server_timestamp_ns: i64,
        payload: Vec<u8>,
        originator_id: i32,
    ) -> Self {
        Self {
            inbox_id,
            sequence_id,
            server_timestamp_ns,
            payload,
            originator_id,
        }
    }
}

impl_store!(StoredIdentityUpdate, identity_updates);

pub trait QueryIdentityUpdates {
    /// Returns all identity updates for the given inbox ID up to the provided sequence_id.
    /// Returns updates greater than `from_sequence_id` and less than _or equal to_ `to_sequence_id`
    fn get_identity_updates<InboxId: AsRef<str>>(
        &self,
        inbox_id: InboxId,
        from_sequence_id: Option<i64>,
        to_sequence_id: Option<i64>,
    ) -> Result<Vec<StoredIdentityUpdate>, crate::ConnectionError>;

    /// Batch insert identity updates, ignoring duplicates.
    fn insert_or_ignore_identity_updates(
        &self,
        updates: &[StoredIdentityUpdate],
    ) -> Result<(), crate::ConnectionError>;

    fn get_latest_sequence_id_for_inbox(
        &self,
        inbox_id: &str,
    ) -> Result<i64, crate::ConnectionError>;

    /// Given a list of inbox_ids return a HashMap of each inbox ID -> highest known sequence ID
    fn get_latest_sequence_id(
        &self,
        inbox_ids: &[&str],
    ) -> Result<HashMap<String, i64>, crate::ConnectionError>;

    /// Returns the count of identity updates for inbox_ids
    fn count_inbox_updates(
        &self,
        inbox_ids: &[&str],
    ) -> Result<HashMap<String, i64>, crate::ConnectionError>;

    /// Atomically replaces `inbox_id`'s stored identity log: in one
    /// transaction, deletes its `identity_updates` and `association_state`
    /// rows, inserts `rows`, and verifies the result starts at sequence 1
    /// with no gaps (an empty `rows` is valid: it leaves the inbox purged).
    /// A gap or a bad start rolls the whole transaction back, so a rejected
    /// replace never leaves the inbox purged with nothing in its place.
    /// Every row in `rows` must belong to `inbox_id`; a mismatched row is
    /// refused before anything is touched.
    ///
    /// xmtp-mesh restore convergence (DESIGN.md §C4.3): callers
    /// (`resync_identity_log`) fetch the winning log from the node BEFORE
    /// calling this, so the purge and its replacement are one call. A
    /// separate purge-then-reload left a window where a concurrent
    /// `load_identity_updates` or `get_association_state` for the same
    /// inbox could observe the inbox purged but not yet reloaded (a
    /// permanent gap) or race the reload itself (a hybrid log).
    fn replace_identity_log(
        &self,
        inbox_id: &str,
        rows: &[StoredIdentityUpdate],
    ) -> Result<(), crate::ConnectionError>;

    /// Caches `state` for `inbox_id` at `sequence_id`, but only if the
    /// stored `identity_updates` row at that sequence id still has
    /// `expected_payload`. The read and the write happen in one write
    /// transaction, so nothing can observe the row between them. Returns
    /// whether the state was written.
    ///
    /// xmtp-mesh restore convergence (DESIGN.md §C4.3, cache-write race):
    /// replaces a separate check-then-write, which `replace_identity_log`
    /// could commit in between -- the check would pass against a
    /// pre-replace row, and the write would then land in the freshly
    /// emptied cache slot the replace's own delete had just cleared.
    /// Because writes serialize, a concurrent `replace_identity_log` for
    /// the same inbox now either commits entirely before this call (the
    /// payload differs or the row is gone, and this call is skipped) or
    /// entirely after it (the replace's own purge then removes whatever
    /// this call just cached).
    fn write_to_cache_if_current(
        &self,
        inbox_id: &str,
        sequence_id: i64,
        expected_payload: &[u8],
        state: Vec<u8>,
    ) -> Result<bool, crate::ConnectionError>;

    /// Inserts `rows` (all of one inbox: `inbox_id`) for a caller that read
    /// its cursor before fetching them from the node, but only if the
    /// stored log is still consistent with what the caller saw at that
    /// cursor:
    /// - `cursor = Some(seq)`: the stored row at `seq` must still have
    ///   `cursor_payload`.
    /// - `cursor = None`: the stored log must still have no row at
    ///   sequence 1, or that row must already equal `rows`'s own sequence
    ///   1 (the same genuine first update, not a different origin).
    ///
    /// The check and the insert happen in one write transaction. Returns
    /// whether the rows were inserted; every row must belong to
    /// `inbox_id`, or this returns an error before touching anything.
    ///
    /// xmtp-mesh restore convergence (DESIGN.md §C4.3, stale
    /// fetch): closes the window where a concurrent `resync_identity_log`
    /// replaces this inbox's log while a `load_identity_updates` fetch
    /// (which read its cursor, then awaited the network) is still in
    /// flight -- without this, the stale fetch's rows land on top of the
    /// winner once it finally inserts, producing a permanent hybrid log
    /// that still verifies (the same wallet signs both forks) and is
    /// undetectable by `replace_identity_log`'s own contiguity check
    /// (the result is still contiguous). A benign concurrent load, with
    /// nothing racing it, always finds its cursor row unchanged, so
    /// non-mesh callers of `load_identity_updates` are unaffected.
    fn insert_identity_updates_if_current(
        &self,
        inbox_id: &str,
        cursor: Option<i64>,
        cursor_payload: Option<&[u8]>,
        rows: &[StoredIdentityUpdate],
    ) -> Result<bool, crate::ConnectionError>;
}

impl<T> QueryIdentityUpdates for &T
where
    T: QueryIdentityUpdates,
{
    fn get_identity_updates<InboxId: AsRef<str>>(
        &self,
        inbox_id: InboxId,
        from_sequence_id: Option<i64>,
        to_sequence_id: Option<i64>,
    ) -> Result<Vec<StoredIdentityUpdate>, crate::ConnectionError> {
        (**self).get_identity_updates(inbox_id, from_sequence_id, to_sequence_id)
    }

    fn insert_or_ignore_identity_updates(
        &self,
        updates: &[StoredIdentityUpdate],
    ) -> Result<(), crate::ConnectionError> {
        (**self).insert_or_ignore_identity_updates(updates)
    }

    fn get_latest_sequence_id_for_inbox(
        &self,
        inbox_id: &str,
    ) -> Result<i64, crate::ConnectionError> {
        (**self).get_latest_sequence_id_for_inbox(inbox_id)
    }

    fn get_latest_sequence_id(
        &self,
        inbox_ids: &[&str],
    ) -> Result<HashMap<String, i64>, crate::ConnectionError> {
        (**self).get_latest_sequence_id(inbox_ids)
    }

    fn count_inbox_updates(
        &self,
        inbox_ids: &[&str],
    ) -> Result<HashMap<String, i64>, crate::ConnectionError> {
        (**self).count_inbox_updates(inbox_ids)
    }

    fn replace_identity_log(
        &self,
        inbox_id: &str,
        rows: &[StoredIdentityUpdate],
    ) -> Result<(), crate::ConnectionError> {
        (**self).replace_identity_log(inbox_id, rows)
    }

    fn write_to_cache_if_current(
        &self,
        inbox_id: &str,
        sequence_id: i64,
        expected_payload: &[u8],
        state: Vec<u8>,
    ) -> Result<bool, crate::ConnectionError> {
        (**self).write_to_cache_if_current(inbox_id, sequence_id, expected_payload, state)
    }

    fn insert_identity_updates_if_current(
        &self,
        inbox_id: &str,
        cursor: Option<i64>,
        cursor_payload: Option<&[u8]>,
        rows: &[StoredIdentityUpdate],
    ) -> Result<bool, crate::ConnectionError> {
        (**self).insert_identity_updates_if_current(inbox_id, cursor, cursor_payload, rows)
    }
}

impl<C: ConnectionExt> QueryIdentityUpdates for DbConnection<C> {
    /// Returns all identity updates for the given inbox ID up to the provided sequence_id.
    /// Returns updates greater than `from_sequence_id` and less than _or equal to_ `to_sequence_id`
    fn get_identity_updates<InboxId: AsRef<str>>(
        &self,
        inbox_id: InboxId,
        from_sequence_id: Option<i64>,
        to_sequence_id: Option<i64>,
    ) -> Result<Vec<StoredIdentityUpdate>, crate::ConnectionError> {
        let mut query = dsl::identity_updates
            .order(dsl::sequence_id.asc())
            .filter(dsl::inbox_id.eq(inbox_id.as_ref()))
            .into_boxed();

        if let Some(sequence_id) = from_sequence_id {
            query = query.filter(dsl::sequence_id.gt(sequence_id));
        }

        if let Some(sequence_id) = to_sequence_id {
            query = query.filter(dsl::sequence_id.le(sequence_id));
        }

        self.raw_query_read(|conn| query.load::<StoredIdentityUpdate>(conn))
    }

    /// Batch insert identity updates, ignoring duplicates.
    #[tracing::instrument(level = "trace", skip(updates))]
    fn insert_or_ignore_identity_updates(
        &self,
        updates: &[StoredIdentityUpdate],
    ) -> Result<(), crate::ConnectionError> {
        self.raw_query_write(|conn| {
            diesel::insert_or_ignore_into(dsl::identity_updates)
                .values(updates)
                .execute(conn)
        })?;
        Ok(())
    }

    fn get_latest_sequence_id_for_inbox(
        &self,
        inbox_id: &str,
    ) -> Result<i64, crate::ConnectionError> {
        let query = dsl::identity_updates
            .select(dsl::sequence_id)
            .order(dsl::sequence_id.desc())
            .limit(1)
            .filter(dsl::inbox_id.eq(inbox_id))
            .into_boxed();

        self.raw_query_read(|conn| query.first::<i64>(conn))
    }

    /// Given a list of inbox_ids return a HashMap of each inbox ID -> highest known sequence ID
    #[tracing::instrument(level = "trace", skip_all)]
    fn get_latest_sequence_id(
        &self,
        inbox_ids: &[&str],
    ) -> Result<HashMap<String, i64>, crate::ConnectionError> {
        // Query IdentityUpdates grouped by inbox_id, getting the max sequence_id
        let query = dsl::identity_updates
            .group_by(dsl::inbox_id)
            .select((dsl::inbox_id, max(dsl::sequence_id)))
            .filter(dsl::inbox_id.eq_any(inbox_ids));

        // Get the results as a Vec of (inbox_id, sequence_id) tuples
        let result_tuples: Vec<(String, i64)> = self
            .raw_query_read(|conn| query.load::<(String, Option<i64>)>(conn))?
            .into_iter()
            // Diesel needs an Option type for aggregations like max(sequence_id), so we
            // unwrap the option here
            .filter_map(|(inbox_id, sequence_id_opt)| {
                sequence_id_opt.map(|sequence_id| (inbox_id, sequence_id))
            })
            .collect();

        // Convert the Vec to a HashMap
        Ok(HashMap::from_iter(result_tuples))
    }

    fn count_inbox_updates(
        &self,
        inbox_ids: &[&str],
    ) -> Result<HashMap<String, i64>, crate::ConnectionError> {
        use diesel::dsl::count_star;
        let query = dsl::identity_updates
            .group_by(dsl::inbox_id)
            .select((dsl::inbox_id, count_star()))
            .filter(dsl::inbox_id.eq_any(inbox_ids));
        self.raw_query_read(|conn| {
            query
                .load_iter::<(String, i64), _>(conn)?
                .collect::<Result<HashMap<_, _>, _>>()
        })
    }

    fn replace_identity_log(
        &self,
        inbox_id: &str,
        rows: &[StoredIdentityUpdate],
    ) -> Result<(), crate::ConnectionError> {
        if let Some(bad) = rows.iter().find(|r| r.inbox_id != inbox_id) {
            return Err(crate::ConnectionError::InvalidQuery(format!(
                "replace_identity_log for {inbox_id}: a row belongs to a different inbox ({})",
                bad.inbox_id
            )));
        }
        use super::schema::association_state::dsl as cache;
        self.raw_query_write(|conn| {
            conn.transaction::<_, diesel::result::Error, _>(|conn| {
                diesel::delete(cache::association_state.filter(cache::inbox_id.eq(inbox_id)))
                    .execute(conn)?;
                diesel::delete(dsl::identity_updates.filter(dsl::inbox_id.eq(inbox_id)))
                    .execute(conn)?;
                if !rows.is_empty() {
                    diesel::insert_into(dsl::identity_updates)
                        .values(rows)
                        .execute(conn)?;
                }

                // Verify inside the same transaction, reading back what was
                // just inserted: the replacement log, in sequence order,
                // starts at 1 with no gaps. Returning an error here makes
                // `transaction` roll the whole thing back -- the deletes
                // above are undone too, so a rejected replace never leaves
                // the inbox purged with nothing in its place.
                let stored: Vec<i64> = dsl::identity_updates
                    .select(dsl::sequence_id)
                    .filter(dsl::inbox_id.eq(inbox_id))
                    .order(dsl::sequence_id.asc())
                    .load(conn)?;
                for (i, seq) in stored.iter().enumerate() {
                    let expected = i as i64 + 1;
                    if *seq != expected {
                        return Err(diesel::result::Error::QueryBuilderError(
                            format!(
                                "replace_identity_log for {inbox_id}: gap or bad start, expected sequence {expected} at position {i}, stored log has {seq}"
                            )
                            .into(),
                        ));
                    }
                }
                Ok(())
            })
        })
    }

    fn write_to_cache_if_current(
        &self,
        inbox_id: &str,
        sequence_id: i64,
        expected_payload: &[u8],
        state: Vec<u8>,
    ) -> Result<bool, crate::ConnectionError> {
        use super::schema::association_state::dsl as cache;
        self.raw_query_write(|conn| {
            conn.transaction::<_, diesel::result::Error, _>(|conn| {
                let stored_payload: Option<Vec<u8>> = dsl::identity_updates
                    .select(dsl::payload)
                    .filter(dsl::inbox_id.eq(inbox_id))
                    .filter(dsl::sequence_id.eq(sequence_id))
                    .first(conn)
                    .optional()?;
                if stored_payload.as_deref() != Some(expected_payload) {
                    return Ok(false);
                }
                diesel::insert_or_ignore_into(cache::association_state)
                    .values((
                        cache::inbox_id.eq(inbox_id),
                        cache::sequence_id.eq(sequence_id),
                        cache::state.eq(state),
                    ))
                    .execute(conn)?;
                Ok(true)
            })
        })
    }

    fn insert_identity_updates_if_current(
        &self,
        inbox_id: &str,
        cursor: Option<i64>,
        cursor_payload: Option<&[u8]>,
        rows: &[StoredIdentityUpdate],
    ) -> Result<bool, crate::ConnectionError> {
        if let Some(bad) = rows.iter().find(|r| r.inbox_id != inbox_id) {
            return Err(crate::ConnectionError::InvalidQuery(format!(
                "insert_identity_updates_if_current for {inbox_id}: a row belongs to a different inbox ({})",
                bad.inbox_id
            )));
        }
        self.raw_query_write(|conn| {
            conn.transaction::<_, diesel::result::Error, _>(|conn| {
                let still_current = match cursor {
                    Some(seq) => {
                        let stored: Option<Vec<u8>> = dsl::identity_updates
                            .select(dsl::payload)
                            .filter(dsl::inbox_id.eq(inbox_id))
                            .filter(dsl::sequence_id.eq(seq))
                            .first(conn)
                            .optional()?;
                        stored.as_deref() == cursor_payload
                    }
                    None => {
                        let stored_seq_1: Option<Vec<u8>> = dsl::identity_updates
                            .select(dsl::payload)
                            .filter(dsl::inbox_id.eq(inbox_id))
                            .filter(dsl::sequence_id.eq(1))
                            .first(conn)
                            .optional()?;
                        match stored_seq_1 {
                            None => true,
                            Some(stored) => rows
                                .iter()
                                .find(|r| r.sequence_id == 1)
                                .is_some_and(|r| r.payload == stored),
                        }
                    }
                };
                if !still_current {
                    return Ok(false);
                }
                if !rows.is_empty() {
                    diesel::insert_or_ignore_into(dsl::identity_updates)
                        .values(rows)
                        .execute(conn)?;
                }
                Ok(true)
            })
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_dedicated_worker);

    use crate::{Store, test_utils::with_connection};
    use xmtp_common::{rand_time, rand_vec};

    use super::*;

    fn build_update(inbox_id: &str, sequence_id: i64) -> StoredIdentityUpdate {
        StoredIdentityUpdate::new(
            inbox_id.to_string(),
            sequence_id,
            rand_time(),
            rand_vec::<24>(),
            1,
        )
    }

    #[xmtp_common::test]
    fn insert_and_read() {
        with_connection(|conn| {
            let inbox_id = "inbox_1";
            let update_1 = build_update(inbox_id, 1);
            let update_1_payload = update_1.payload.clone();
            let update_2 = build_update(inbox_id, 2);
            let update_2_payload = update_2.payload.clone();

            update_1.store(conn).expect("should store without error");
            update_2.store(conn).expect("should store without error");

            let all_updates = conn
                .get_identity_updates(inbox_id, None, None)
                .expect("query should work");

            assert_eq!(all_updates.len(), 2);
            let first_update = all_updates.first().unwrap();
            assert_eq!(first_update.payload, update_1_payload);
            let second_update = all_updates.last().unwrap();
            assert_eq!(second_update.payload, update_2_payload);
        })
    }

    #[xmtp_common::test]
    fn test_filter() {
        with_connection(|conn| {
            let inbox_id = "inbox_1";
            let update_1 = build_update(inbox_id, 1);
            let update_2 = build_update(inbox_id, 2);
            let update_3 = build_update(inbox_id, 3);

            conn.insert_or_ignore_identity_updates(&[update_1, update_2, update_3])
                .expect("insert should succeed");

            let update_1_and_2 = conn
                .get_identity_updates(inbox_id, None, Some(2))
                .expect("query should work");

            assert_eq!(update_1_and_2.len(), 2);

            let all_updates = conn
                .get_identity_updates(inbox_id, None, None)
                .expect("query should work");

            assert_eq!(all_updates.len(), 3);

            let only_update_2 = conn
                .get_identity_updates(inbox_id, Some(1), Some(2))
                .expect("query should work");

            assert_eq!(only_update_2.len(), 1);
            assert_eq!(only_update_2[0].sequence_id, 2);
        })
    }

    #[xmtp_common::test]
    fn test_get_latest_sequence_id() {
        with_connection(|conn| {
            let inbox_1 = "inbox_1";
            let inbox_2 = "inbox_2";
            let update_1 = build_update(inbox_1, 1);
            let update_2 = build_update(inbox_1, 3);
            let update_3 = build_update(inbox_2, 5);
            let update_4 = build_update(inbox_2, 6);

            conn.insert_or_ignore_identity_updates(&[update_1, update_2, update_3, update_4])
                .expect("insert should succeed");

            let latest_sequence_ids = conn
                .get_latest_sequence_id(&[inbox_1, inbox_2])
                .expect("query should work");

            assert_eq!(latest_sequence_ids.get(inbox_1), Some(&3));
            assert_eq!(latest_sequence_ids.get(inbox_2), Some(&6));

            let latest_sequence_ids_with_missing_member = conn
                .get_latest_sequence_id(&[inbox_1, "missing_inbox"])
                .expect("should still succeed");

            assert_eq!(
                latest_sequence_ids_with_missing_member.get(inbox_1),
                Some(&3)
            );
            assert_eq!(
                latest_sequence_ids_with_missing_member.get("missing_inbox"),
                None
            );
        })
    }

    #[xmtp_common::test]
    fn get_single_sequence_id() {
        with_connection(|conn| {
            let inbox_id = "inbox_1";
            let update = build_update(inbox_id, 1);
            let update_2 = build_update(inbox_id, 2);
            update.store(conn).expect("should store without error");
            update_2.store(conn).expect("should store without error");

            let sequence_id = conn
                .get_latest_sequence_id_for_inbox(inbox_id)
                .expect("query should work");
            assert_eq!(sequence_id, 2);
        })
    }

    #[xmtp_common::test]
    fn test_count_inbox_updates() {
        with_connection(|conn| {
            let inbox_1 = "inbox_1";
            let inbox_2 = "inbox_2";
            conn.insert_or_ignore_identity_updates(&[
                build_update(inbox_1, 1),
                build_update(inbox_1, 2),
                build_update(inbox_2, 1),
            ])
            .unwrap();
            let counts = conn
                .count_inbox_updates(&[inbox_1, inbox_2, "missing"])
                .unwrap();
            assert_eq!(counts.get(inbox_1), Some(&2));
            assert_eq!(counts.get(inbox_2), Some(&1));
            assert_eq!(counts.get("missing"), None);
        })
    }

    /// xmtp-mesh restore convergence (DESIGN.md §C4.3): the purge and the
    /// insert of the replacement log are one call, so a caller never
    /// observes the inbox purged with the replacement not yet in place, and
    /// no stale cache entry survives a successful replace.
    #[xmtp_common::test]
    fn replace_identity_log_swaps_the_log_and_cache_atomically() {
        use crate::prelude::QueryAssociationStateCache;
        use xmtp_proto::xmtp::identity::associations::AssociationState as AssociationStateProto;
        with_connection(|conn| {
            // inbox_1 holds a one-update fork, cached at its only sequence.
            build_update("inbox_1", 1).store(conn).unwrap();
            conn.write_to_cache(
                "inbox_1".to_string(),
                1,
                AssociationStateProto {
                    inbox_id: "inbox_1".into(),
                    ..Default::default()
                },
            )
            .unwrap();
            // inbox_2 is untouched by the replace below.
            build_update("inbox_2", 1).store(conn).unwrap();
            conn.write_to_cache(
                "inbox_2".to_string(),
                1,
                AssociationStateProto {
                    inbox_id: "inbox_2".into(),
                    ..Default::default()
                },
            )
            .unwrap();

            let winner = vec![build_update("inbox_1", 1), build_update("inbox_1", 2)];
            conn.replace_identity_log("inbox_1", &winner).unwrap();

            let stored = conn.get_identity_updates("inbox_1", None, None).unwrap();
            assert_eq!(stored.len(), 2);
            assert_eq!(stored[0].payload, winner[0].payload);
            assert_eq!(stored[1].payload, winner[1].payload);
            // The fork's cache entry at sequence 1 is gone, not merely
            // shadowed: a read for it must recompute, never serve stale data.
            assert!(conn.read_from_cache("inbox_1", 1).unwrap().is_none());
            assert!(conn.read_from_cache("inbox_1", 2).unwrap().is_none());

            assert_eq!(
                conn.get_identity_updates("inbox_2", None, None)
                    .unwrap()
                    .len(),
                1
            );
            assert!(conn.read_from_cache("inbox_2", 1).unwrap().is_some());
        })
    }

    /// xmtp-mesh restore convergence (DESIGN.md §C4.3): a gapped replacement
    /// log is refused, and the refusal rolls back the whole transaction --
    /// the original log and its cached state are still there, not purged
    /// with nothing valid in their place.
    #[xmtp_common::test]
    fn replace_identity_log_rolls_back_a_gapped_replacement() {
        use crate::prelude::QueryAssociationStateCache;
        use xmtp_proto::xmtp::identity::associations::AssociationState as AssociationStateProto;
        with_connection(|conn| {
            build_update("inbox_1", 1).store(conn).unwrap();
            conn.write_to_cache(
                "inbox_1".to_string(),
                1,
                AssociationStateProto {
                    inbox_id: "inbox_1".into(),
                    ..Default::default()
                },
            )
            .unwrap();

            // Sequence 2 is missing: 1, 3.
            let gapped = vec![build_update("inbox_1", 1), build_update("inbox_1", 3)];
            let err = conn.replace_identity_log("inbox_1", &gapped).unwrap_err();
            assert!(
                format!("{err}").contains("gap or bad start"),
                "unexpected error: {err}"
            );

            let stored = conn.get_identity_updates("inbox_1", None, None).unwrap();
            assert_eq!(
                stored.len(),
                1,
                "the original log must survive a rejected replace"
            );
            assert_eq!(stored[0].sequence_id, 1);
            assert!(
                conn.read_from_cache("inbox_1", 1).unwrap().is_some(),
                "the original cache entry must survive a rejected replace"
            );
        })
    }

    /// A replacement log that starts above 1 (no sequence 1 at all) is the
    /// same "bad start" case as an internal gap, and is refused the same way.
    #[xmtp_common::test]
    fn replace_identity_log_refuses_a_replacement_that_does_not_start_at_one() {
        with_connection(|conn| {
            let starts_at_two = vec![build_update("inbox_1", 2)];
            let err = conn
                .replace_identity_log("inbox_1", &starts_at_two)
                .unwrap_err();
            assert!(
                format!("{err}").contains("gap or bad start"),
                "unexpected error: {err}"
            );
            assert!(
                conn.get_identity_updates("inbox_1", None, None)
                    .unwrap()
                    .is_empty(),
                "nothing should have been inserted"
            );
        })
    }

    /// An empty replacement is valid: it leaves the inbox purged (used when
    /// the node has nothing for an inbox this client never should have
    /// loaded; xmtp_mesh's own checks normally avoids calling this at all).
    #[xmtp_common::test]
    fn replace_identity_log_with_no_rows_just_purges() {
        with_connection(|conn| {
            build_update("inbox_1", 1).store(conn).unwrap();
            conn.replace_identity_log("inbox_1", &[]).unwrap();
            assert!(
                conn.get_identity_updates("inbox_1", None, None)
                    .unwrap()
                    .is_empty()
            );
        })
    }

    /// Cache-write race: simulates the exact check-then-write
    /// interleaving a separate check and write would leave open. The caller's earlier
    /// "read" captured the fork's payload before a replace won the race and
    /// committed; by the time the corresponding cache write actually runs,
    /// the stored log is the winner's. One atomic call must refuse the
    /// write outright -- there is no separate check step for a commit to
    /// land in between.
    #[xmtp_common::test]
    fn write_to_cache_if_current_refuses_a_write_that_lost_a_race_to_a_replace() {
        use crate::prelude::QueryAssociationStateCache;
        use prost::Message;
        use xmtp_proto::xmtp::identity::associations::AssociationState as AssociationStateProto;
        with_connection(|conn| {
            // The "read" a concurrent get_association_state would have
            // done: capture the fork's payload before anything else happens.
            build_update("inbox_1", 1).store(conn).unwrap();
            let fork_payload = conn
                .get_identity_updates("inbox_1", None, None)
                .unwrap()
                .pop()
                .unwrap()
                .payload;
            let fork_state = AssociationStateProto {
                inbox_id: "fork".into(),
                ..Default::default()
            }
            .encode_to_vec();
            let winner_state = AssociationStateProto {
                inbox_id: "winner".into(),
                ..Default::default()
            }
            .encode_to_vec();

            // The replace wins the race and commits before the write below
            // is attempted.
            let winner = vec![build_update("inbox_1", 1)];
            conn.replace_identity_log("inbox_1", &winner).unwrap();

            // The stale write, keyed on the payload read before the
            // replace, must be refused -- not cached for the winning log.
            let written = conn
                .write_to_cache_if_current("inbox_1", 1, &fork_payload, fork_state)
                .unwrap();
            assert!(!written);
            assert!(conn.read_from_cache("inbox_1", 1).unwrap().is_none());

            // A write keyed on the current (winner's) payload still succeeds.
            let written = conn
                .write_to_cache_if_current("inbox_1", 1, &winner[0].payload, winner_state)
                .unwrap();
            assert!(written);
            let cached = conn.read_from_cache("inbox_1", 1).unwrap().unwrap();
            assert_eq!(cached.inbox_id, "winner");
        })
    }

    /// Stale fetch: a concurrent load read its
    /// cursor and fetched fork rows before a replace won the race and
    /// committed. By the time it inserts, the stored log is the winner's.
    /// The insert must be refused, not appended on top of the winner (which
    /// would otherwise pass `replace_identity_log`'s own contiguity check,
    /// since the result is still contiguous -- just wrong).
    #[xmtp_common::test]
    fn insert_identity_updates_if_current_refuses_fork_rows_appended_after_a_replace() {
        with_connection(|conn| {
            // The fork: inbox_1 has a genuine seq 1, and a load's cursor
            // read it before the replace below.
            build_update("inbox_1", 1).store(conn).unwrap();
            let cursor_payload = conn
                .get_identity_updates("inbox_1", None, None)
                .unwrap()
                .pop()
                .unwrap()
                .payload;

            // The load then fetched the fork's sequence 2 (still using the
            // pre-replace log as ground truth).
            let fork_seq_2 = build_update("inbox_1", 2);

            // The replace wins the race: the node's winning log is also a
            // single update, landing at the same sequence 1 the load's
            // cursor pointed at.
            let winner = vec![build_update("inbox_1", 1)];
            conn.replace_identity_log("inbox_1", &winner).unwrap();

            // The stale load's insert, using the pre-replace cursor and
            // payload, must be refused.
            let inserted = conn
                .insert_identity_updates_if_current(
                    "inbox_1",
                    Some(1),
                    Some(&cursor_payload),
                    &[fork_seq_2],
                )
                .unwrap();
            assert!(!inserted);

            let stored = conn.get_identity_updates("inbox_1", None, None).unwrap();
            assert_eq!(stored.len(), 1, "the log must stay exactly the winner's");
            assert_eq!(stored[0].payload, winner[0].payload);
        })
    }

    /// The `cursor = None` branch of the same fix: a client's first-ever
    /// load of an inbox fetched a genuine seq 1, but a different genuine
    /// seq 1 (the node's actual winner, from a concurrent replace) landed
    /// first. The stale insert must be refused, not treated as "no rows
    /// yet, anything goes."
    #[xmtp_common::test]
    fn insert_identity_updates_if_current_with_no_cursor_refuses_a_different_first_update() {
        with_connection(|conn| {
            let winner = vec![build_update("inbox_1", 1)];
            conn.replace_identity_log("inbox_1", &winner).unwrap();

            let fork_seq_1 = build_update("inbox_1", 1);
            let inserted = conn
                .insert_identity_updates_if_current("inbox_1", None, None, &[fork_seq_1])
                .unwrap();
            assert!(!inserted);

            let stored = conn.get_identity_updates("inbox_1", None, None).unwrap();
            assert_eq!(stored.len(), 1);
            assert_eq!(
                stored[0].payload, winner[0].payload,
                "the winner must be untouched"
            );
        })
    }

    /// `replace_identity_log` must reject
    /// rows that do not belong to the inbox it claims to replace, rather
    /// than silently inserting them outside the purge and the contiguity
    /// check (which only look at `inbox_id`'s own rows).
    #[xmtp_common::test]
    fn replace_identity_log_refuses_rows_for_a_different_inbox() {
        with_connection(|conn| {
            let mismatched = vec![build_update("inbox_2", 1)];
            let err = conn
                .replace_identity_log("inbox_1", &mismatched)
                .unwrap_err();
            assert!(
                format!("{err}").contains("different inbox"),
                "unexpected error: {err}"
            );
            assert!(
                conn.get_identity_updates("inbox_1", None, None)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                conn.get_identity_updates("inbox_2", None, None)
                    .unwrap()
                    .is_empty(),
                "nothing should have been inserted for inbox_2 either"
            );
        })
    }
}
