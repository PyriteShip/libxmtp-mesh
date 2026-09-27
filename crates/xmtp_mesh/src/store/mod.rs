use std::sync::Arc;

use diesel::connection::{SimpleConnection, TransactionManager};
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Binary, Bool, Integer, Nullable, Text};
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
use sha2::{Digest, Sha256};

use crate::MeshError;
use crate::sync::HelloSigner;
use crate::sync::seq::{self, Equivocation, SeqCounters, SeqProof};

mod relay;
#[cfg(test)]
mod tests;
pub use relay::SpoolEntry;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
const META_LOCAL_INSTALLATION: &str = "local_installation";
const META_LOCAL_INBOX: &str = "local_inbox";
/// Most equivocations kept (§B13); the oldest are dropped first.
const MAX_EQUIVOCATIONS: i64 = 1024;

pub fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewGroupMessage {
    pub group_id: Vec<u8>,
    pub data: Vec<u8>,
    pub sender_hmac: Vec<u8>,
    pub should_push: bool,
    pub is_commit: bool,
}

#[derive(Debug, Clone, PartialEq, QueryableByName)]
pub struct StoredGroupMessage {
    #[diesel(sql_type = Binary)]
    pub group_id: Vec<u8>,
    #[diesel(sql_type = BigInt)]
    pub id: i64,
    #[diesel(sql_type = BigInt)]
    pub created_ns: i64,
    #[diesel(sql_type = Binary)]
    pub data: Vec<u8>,
    #[diesel(sql_type = Binary)]
    pub sender_hmac: Vec<u8>,
    #[diesel(sql_type = Bool)]
    pub should_push: bool,
    #[diesel(sql_type = Bool)]
    pub is_commit: bool,
    /// The installation that signed this row's sequencing record (§B13).
    /// `None` only for a row stored before signed sequencing, until
    /// `start_sync` signs it.
    #[diesel(sql_type = Nullable<Binary>)]
    pub seq_signer: Option<Vec<u8>>,
    #[diesel(sql_type = Nullable<Binary>)]
    pub seq_signature: Option<Vec<u8>>,
}

impl StoredGroupMessage {
    /// The row's stored proof, as it travels (§B13). Every row a node
    /// serves has one: `start_sync` signs any row stored without it.
    pub fn proof(&self) -> SeqProof {
        debug_assert!(
            self.seq_signer.is_some() && self.seq_signature.is_some(),
            "sequenced row {} has no proof (§B13)",
            self.id
        );
        SeqProof {
            signer: self.seq_signer.clone().unwrap_or_default(),
            signature: self.seq_signature.clone().unwrap_or_default(),
        }
    }
}

#[derive(QueryableByName)]
struct EquivocationRow {
    #[diesel(sql_type = Binary)]
    group_id: Vec<u8>,
    #[diesel(sql_type = BigInt)]
    id: i64,
    #[diesel(sql_type = Binary)]
    signer: Vec<u8>,
    #[diesel(sql_type = Binary)]
    record_a: Vec<u8>,
    #[diesel(sql_type = Binary)]
    signature_a: Vec<u8>,
    #[diesel(sql_type = Binary)]
    record_b: Vec<u8>,
    #[diesel(sql_type = Binary)]
    signature_b: Vec<u8>,
}

/// A row with no proof yet, for [`MeshStore::sign_unsigned_rows`]. Carries
/// `data_hash` (already `sha256(data)`) rather than the payload itself, so
/// signing every unsigned row need not load each one's full `data` blob.
#[derive(QueryableByName)]
struct UnsignedRow {
    #[diesel(sql_type = Binary)]
    group_id: Vec<u8>,
    #[diesel(sql_type = BigInt)]
    id: i64,
    #[diesel(sql_type = BigInt)]
    created_ns: i64,
    #[diesel(sql_type = Binary)]
    data_hash: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, QueryableByName)]
pub struct StoredWelcome {
    #[diesel(sql_type = Binary)]
    pub installation_key: Vec<u8>,
    #[diesel(sql_type = BigInt)]
    pub id: i64,
    #[diesel(sql_type = BigInt)]
    pub created_ns: i64,
    #[diesel(sql_type = Binary)]
    pub input: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, QueryableByName)]
pub struct IdentityRow {
    #[diesel(sql_type = BigInt)]
    pub sequence_id: i64,
    #[diesel(sql_type = BigInt)]
    pub server_timestamp_ns: i64,
    #[diesel(sql_type = Binary)]
    pub update_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted,
    Duplicate,
    Gap { have: i64 },
}

#[derive(QueryableByName)]
struct I64Row {
    #[diesel(sql_type = BigInt)]
    v: i64,
}

#[derive(QueryableByName)]
struct BlobRow {
    #[diesel(sql_type = Binary)]
    v: Vec<u8>,
}

#[derive(QueryableByName)]
struct OptBlobRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<Binary>)]
    v: Option<Vec<u8>>,
}

#[derive(QueryableByName)]
struct TextRow {
    #[diesel(sql_type = Text)]
    v: String,
}

#[derive(QueryableByName)]
struct PendingResyncRow {
    #[diesel(sql_type = Text)]
    inbox_id: String,
    #[diesel(sql_type = BigInt)]
    generation: i64,
}

#[derive(QueryableByName)]
struct PendingRow {
    #[diesel(sql_type = Binary)]
    group_id: Vec<u8>,
    #[diesel(sql_type = Binary)]
    data: Vec<u8>,
    #[diesel(sql_type = Binary)]
    sender_hmac: Vec<u8>,
    #[diesel(sql_type = Bool)]
    should_push: bool,
    #[diesel(sql_type = Bool)]
    is_commit: bool,
}

#[derive(QueryableByName)]
struct OutboundRow {
    #[diesel(sql_type = Binary)]
    envelope_hash: Vec<u8>,
    #[diesel(sql_type = Binary)]
    input: Vec<u8>,
}

const GROUP_COLUMNS: &str = "group_id, id, created_ns, data, sender_hmac, should_push, is_commit, seq_signer, seq_signature";

/// (envelope_hash, input) pairs for outbound welcomes awaiting delivery.
type OutboundWelcomePairs = Vec<(Vec<u8>, Vec<u8>)>;

pub struct MeshStore {
    conn: SqliteConnection,
    /// Signs each row as it is sequenced here (§B13). Set by
    /// `MeshNode::start_sync`; kept after `stop_sync`.
    seq_signer: Option<Arc<dyn HelloSigner>>,
    seq: Arc<SeqCounters>,
}

impl MeshStore {
    /// `path: None` opens a private in-memory database. `key` enables SQLCipher.
    pub fn open(path: Option<&str>, key: Option<[u8; 32]>) -> Result<Self, MeshError> {
        let mut conn = SqliteConnection::establish(path.unwrap_or(":memory:"))?;
        if let Some(key) = key {
            conn.batch_execute(&format!("PRAGMA key = \"x'{}'\";", hex::encode(key)))?;
        }
        conn.batch_execute("PRAGMA foreign_keys = ON;")?;
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| MeshError::Migration(e.to_string()))?;
        Ok(Self {
            conn,
            seq_signer: None,
            seq: Arc::default(),
        })
    }

    pub fn open_in_memory() -> Result<Self, MeshError> {
        Self::open(None, None)
    }

    /// Run `f` atomically: every statement commits together, or none does
    /// when `f` fails or panics (the panic then continues). Nests (inner
    /// calls become savepoints).
    pub fn transaction<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, MeshError>,
    ) -> Result<T, MeshError> {
        type Tm = <SqliteConnection as Connection>::TransactionManager;
        Tm::begin_transaction(&mut self.conn)?;
        // The store sits behind a non-poisoning mutex, so a panic must not
        // leave this transaction open for the next caller.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self)));
        match outcome {
            Ok(Ok(value)) => {
                Tm::commit_transaction(&mut self.conn)?;
                Ok(value)
            }
            Ok(Err(e)) => {
                self.rollback();
                Err(e)
            }
            Err(panic) => {
                self.rollback();
                std::panic::resume_unwind(panic)
            }
        }
    }

    fn rollback(&mut self) {
        type Tm = <SqliteConnection as Connection>::TransactionManager;
        if let Err(rollback) = Tm::rollback_transaction(&mut self.conn) {
            tracing::error!(error = %rollback, "mesh store rollback failed");
        }
    }

    // ---- meta ----

    fn meta(&mut self, key: &str) -> Result<Option<Vec<u8>>, MeshError> {
        let rows: Vec<BlobRow> = sql_query("SELECT value AS v FROM node_meta WHERE key = ?")
            .bind::<Text, _>(key)
            .load(&mut self.conn)?;
        Ok(rows.into_iter().next().map(|r| r.v))
    }

    fn set_meta(&mut self, key: &str, value: &[u8]) -> Result<(), MeshError> {
        sql_query("INSERT INTO node_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
            .bind::<Text, _>(key)
            .bind::<Binary, _>(value)
            .execute(&mut self.conn)?;
        Ok(())
    }

    pub fn local_installation(&mut self) -> Result<Option<Vec<u8>>, MeshError> {
        self.meta(META_LOCAL_INSTALLATION)
    }

    pub fn set_local_installation(&mut self, installation: &[u8]) -> Result<(), MeshError> {
        self.set_meta(META_LOCAL_INSTALLATION, installation)
    }

    pub fn local_inbox(&mut self) -> Result<Option<String>, MeshError> {
        Ok(self
            .meta(META_LOCAL_INBOX)?
            .map(|v| String::from_utf8_lossy(&v).into_owned()))
    }

    pub fn set_local_inbox(&mut self, inbox_id: &str) -> Result<(), MeshError> {
        self.set_meta(META_LOCAL_INBOX, inbox_id.as_bytes())
    }

    // ---- identity ----

    pub fn identity_rows(
        &mut self,
        inbox_id: &str,
        after: i64,
    ) -> Result<Vec<IdentityRow>, MeshError> {
        Ok(sql_query(
            "SELECT sequence_id, server_timestamp_ns, update_bytes FROM identity_updates \
             WHERE inbox_id = ? AND sequence_id > ? ORDER BY sequence_id ASC",
        )
        .bind::<Text, _>(inbox_id)
        .bind::<BigInt, _>(after)
        .load(&mut self.conn)?)
    }

    pub fn identity_len(&mut self, inbox_id: &str) -> Result<i64, MeshError> {
        let rows: Vec<I64Row> = sql_query(
            "SELECT COALESCE(MAX(sequence_id), 0) AS v FROM identity_updates WHERE inbox_id = ?",
        )
        .bind::<Text, _>(inbox_id)
        .load(&mut self.conn)?;
        Ok(rows[0].v)
    }

    pub fn append_identity(
        &mut self,
        inbox_id: &str,
        sequence_id: i64,
        server_timestamp_ns: i64,
        update_bytes: &[u8],
    ) -> Result<(), MeshError> {
        self.transaction(|s| {
            let expected = s.identity_len(inbox_id)? + 1;
            if sequence_id != expected {
                return Err(MeshError::IdentityConflict {
                    inbox_id: inbox_id.to_string(),
                    expected,
                    got: sequence_id,
                });
            }
            sql_query("INSERT INTO identity_updates (inbox_id, sequence_id, server_timestamp_ns, update_bytes) VALUES (?, ?, ?, ?)")
                .bind::<Text, _>(inbox_id)
                .bind::<BigInt, _>(sequence_id)
                .bind::<BigInt, _>(server_timestamp_ns)
                .bind::<Binary, _>(update_bytes)
                .execute(&mut s.conn)?;
            Ok(())
        })
    }

    /// Replace `inbox_id`'s whole identity log with `rows` (sequence ids
    /// 1..=N, checked by the caller) and its identifier mappings with
    /// `identifiers`, in one transaction (restore convergence §C4.3). The
    /// same transaction records a pending client resync for `inbox_id`
    /// (see [`Self::pending_resyncs`]). Touches no other
    /// table.
    pub fn replace_identity(
        &mut self,
        inbox_id: &str,
        rows: &[IdentityRow],
        identifiers: &[(String, i32)],
    ) -> Result<(), MeshError> {
        self.transaction(|s| {
            sql_query("DELETE FROM identity_updates WHERE inbox_id = ?")
                .bind::<Text, _>(inbox_id)
                .execute(&mut s.conn)?;
            sql_query("DELETE FROM inbox_identifiers WHERE inbox_id = ?")
                .bind::<Text, _>(inbox_id)
                .execute(&mut s.conn)?;
            for row in rows {
                s.append_identity(
                    inbox_id,
                    row.sequence_id,
                    row.server_timestamp_ns,
                    &row.update_bytes,
                )?;
            }
            for (identifier, kind) in identifiers {
                s.set_identifier(identifier, *kind, inbox_id)?;
            }
            sql_query(
                "INSERT INTO pending_resyncs (inbox_id, generation) VALUES (?, 1) \
                 ON CONFLICT(inbox_id) DO UPDATE SET generation = generation + 1",
            )
            .bind::<Text, _>(inbox_id)
            .execute(&mut s.conn)?;
            Ok(())
        })
    }

    /// Inboxes whose log was replaced but whose local client has not
    /// resynced yet, each with the generation of its latest replace.
    /// Survives a restart; the identity task replays them at
    /// start_sync.
    pub fn pending_resyncs(&mut self) -> Result<Vec<(String, i64)>, MeshError> {
        let rows: Vec<PendingResyncRow> =
            sql_query("SELECT inbox_id, generation FROM pending_resyncs ORDER BY inbox_id")
                .load(&mut self.conn)?;
        Ok(rows
            .into_iter()
            .map(|r| (r.inbox_id, r.generation))
            .collect())
    }

    /// The client resynced `inbox_id` after the replace numbered
    /// `generation`: drop its marker, unless a newer replace has landed since.
    pub fn clear_pending_resync(
        &mut self,
        inbox_id: &str,
        generation: i64,
    ) -> Result<(), MeshError> {
        sql_query("DELETE FROM pending_resyncs WHERE inbox_id = ? AND generation = ?")
            .bind::<Text, _>(inbox_id)
            .bind::<BigInt, _>(generation)
            .execute(&mut self.conn)?;
        Ok(())
    }

    pub fn set_identifier(
        &mut self,
        identifier: &str,
        kind: i32,
        inbox_id: &str,
    ) -> Result<(), MeshError> {
        sql_query("INSERT INTO inbox_identifiers (identifier, identifier_kind, inbox_id) VALUES (?, ?, ?) \
                   ON CONFLICT(identifier, identifier_kind) DO UPDATE SET inbox_id = excluded.inbox_id")
            .bind::<Text, _>(identifier)
            .bind::<Integer, _>(kind)
            .bind::<Text, _>(inbox_id)
            .execute(&mut self.conn)?;
        Ok(())
    }

    pub fn inbox_for_identifier(
        &mut self,
        identifier: &str,
        kind: i32,
    ) -> Result<Option<String>, MeshError> {
        let rows: Vec<TextRow> = sql_query(
            "SELECT inbox_id AS v FROM inbox_identifiers WHERE identifier = ? AND identifier_kind = ?",
        )
        .bind::<Text, _>(identifier)
        .bind::<Integer, _>(kind)
        .load(&mut self.conn)?;
        Ok(rows.into_iter().next().map(|r| r.v))
    }

    /// Every inbox this store holds an identity log for, sorted.
    pub fn identity_inboxes(&mut self) -> Result<Vec<String>, MeshError> {
        let rows: Vec<TextRow> =
            sql_query("SELECT DISTINCT inbox_id AS v FROM identity_updates ORDER BY inbox_id")
                .load(&mut self.conn)?;
        Ok(rows.into_iter().map(|r| r.v).collect())
    }

    // ---- key packages ----

    pub fn put_key_package(
        &mut self,
        installation: &[u8],
        key_package: &[u8],
    ) -> Result<(), MeshError> {
        sql_query(
            "INSERT INTO key_packages (installation_key, key_package) VALUES (?, ?) \
                   ON CONFLICT(installation_key) DO UPDATE SET key_package = excluded.key_package",
        )
        .bind::<Binary, _>(installation)
        .bind::<Binary, _>(key_package)
        .execute(&mut self.conn)?;
        Ok(())
    }

    pub fn key_package(&mut self, installation: &[u8]) -> Result<Option<Vec<u8>>, MeshError> {
        let rows: Vec<BlobRow> =
            sql_query("SELECT key_package AS v FROM key_packages WHERE installation_key = ?")
                .bind::<Binary, _>(installation)
                .load(&mut self.conn)?;
        Ok(rows.into_iter().next().map(|r| r.v))
    }

    // ---- groups ----

    /// Returns true when the group was not known before this call.
    pub fn ensure_group(&mut self, group_id: &[u8]) -> Result<bool, MeshError> {
        let n = sql_query("INSERT OR IGNORE INTO groups (group_id, sequencer) VALUES (?, NULL)")
            .bind::<Binary, _>(group_id)
            .execute(&mut self.conn)?;
        Ok(n == 1)
    }

    pub fn is_known_group(&mut self, group_id: &[u8]) -> Result<bool, MeshError> {
        let rows: Vec<I64Row> = sql_query("SELECT COUNT(*) AS v FROM groups WHERE group_id = ?")
            .bind::<Binary, _>(group_id)
            .load(&mut self.conn)?;
        Ok(rows[0].v > 0)
    }

    pub fn sequencer(&mut self, group_id: &[u8]) -> Result<Option<Vec<u8>>, MeshError> {
        let rows: Vec<OptBlobRow> =
            sql_query("SELECT sequencer AS v FROM groups WHERE group_id = ?")
                .bind::<Binary, _>(group_id)
                .load(&mut self.conn)?;
        Ok(rows.into_iter().next().and_then(|r| r.v))
    }

    /// Trust-on-first-use: sets the sequencer only if none is set yet.
    pub fn pin_sequencer(
        &mut self,
        group_id: &[u8],
        installation: &[u8],
    ) -> Result<Vec<u8>, MeshError> {
        self.transaction(|s| {
            s.ensure_group(group_id)?;
            sql_query("UPDATE groups SET sequencer = ? WHERE group_id = ? AND sequencer IS NULL")
                .bind::<Binary, _>(installation)
                .bind::<Binary, _>(group_id)
                .execute(&mut s.conn)?;
            Ok(s.sequencer(group_id)?.expect("sequencer was just pinned"))
        })
    }

    /// Sets the group's sequencer unconditionally: the §C4.7 handover from a
    /// revoked sequencer. Trust-on-first-use pinning stays `pin_sequencer`.
    pub fn repin_sequencer(
        &mut self,
        group_id: &[u8],
        installation: &[u8],
    ) -> Result<(), MeshError> {
        self.transaction(|s| {
            s.ensure_group(group_id)?;
            sql_query("UPDATE groups SET sequencer = ? WHERE group_id = ?")
                .bind::<Binary, _>(installation)
                .bind::<Binary, _>(group_id)
                .execute(&mut s.conn)?;
            // §R4.5: the new sequencer offers the relay key again.
            s.relay_unconfirm_for_repin(group_id)?;
            Ok(())
        })
    }

    /// §C4.7 handover: repin the sequencer and, in the
    /// SAME transaction, sequence our own pending messages for the group
    /// when we are the new sequencer. Doing both under one lock closes the
    /// window where a local publish landing between a separate repin and a
    /// separate drain could jump ahead of older pending messages with a
    /// lower id. Returns the newly sequenced rows (the caller emits events
    /// after the lock is released).
    pub fn repin_sequencer_and_drain_pending(
        &mut self,
        group_id: &[u8],
        installation: &[u8],
        now_ns: i64,
    ) -> Result<Vec<StoredGroupMessage>, MeshError> {
        self.transaction(|s| {
            s.ensure_group(group_id)?;
            sql_query("UPDATE groups SET sequencer = ? WHERE group_id = ?")
                .bind::<Binary, _>(installation)
                .bind::<Binary, _>(group_id)
                .execute(&mut s.conn)?;
            // §R4.5: the new sequencer offers the relay key again.
            s.relay_unconfirm_for_repin(group_id)?;
            let mut rows = Vec::new();
            for message in s.pending_for(group_id)? {
                let (row, inserted) = s.append_sequenced(&message, now_ns)?;
                s.remove_pending(group_id, &sha256(&message.data))?;
                if inserted {
                    rows.push(row);
                }
            }
            Ok(rows)
        })
    }

    pub fn known_groups(&mut self) -> Result<Vec<Vec<u8>>, MeshError> {
        let rows: Vec<BlobRow> =
            sql_query("SELECT group_id AS v FROM groups ORDER BY group_id").load(&mut self.conn)?;
        Ok(rows.into_iter().map(|r| r.v).collect())
    }

    // ---- sequenced group messages ----

    pub fn max_group_id(&mut self, group_id: &[u8]) -> Result<i64, MeshError> {
        let rows: Vec<I64Row> =
            sql_query("SELECT COALESCE(MAX(id), 0) AS v FROM group_messages WHERE group_id = ?")
                .bind::<Binary, _>(group_id)
                .load(&mut self.conn)?;
        Ok(rows[0].v)
    }

    fn sequenced_by_hash(
        &mut self,
        group_id: &[u8],
        hash: &[u8],
    ) -> Result<Option<StoredGroupMessage>, MeshError> {
        let rows: Vec<StoredGroupMessage> = sql_query(format!(
            "SELECT {GROUP_COLUMNS} FROM group_messages WHERE group_id = ? AND data_hash = ?"
        ))
        .bind::<Binary, _>(group_id)
        .bind::<Binary, _>(hash)
        .load(&mut self.conn)?;
        Ok(rows.into_iter().next())
    }

    /// Whether a message with this data hash is already sequenced in the group.
    pub fn is_sequenced(&mut self, group_id: &[u8], hash: &[u8]) -> Result<bool, MeshError> {
        Ok(self.sequenced_by_hash(group_id, hash)?.is_some())
    }

    fn insert_group_row(
        &mut self,
        row: &StoredGroupMessage,
        from_peer: bool,
    ) -> Result<(), MeshError> {
        sql_query(
            "INSERT INTO group_messages (group_id, id, created_ns, data, sender_hmac, should_push, is_commit, data_hash, from_peer, seq_signer, seq_signature) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind::<Binary, _>(&row.group_id)
        .bind::<BigInt, _>(row.id)
        .bind::<BigInt, _>(row.created_ns)
        .bind::<Binary, _>(&row.data)
        .bind::<Binary, _>(&row.sender_hmac)
        .bind::<Bool, _>(row.should_push)
        .bind::<Bool, _>(row.is_commit)
        .bind::<Binary, _>(sha256(&row.data))
        .bind::<Bool, _>(from_peer)
        .bind::<Nullable<Binary>, _>(row.seq_signer.as_deref())
        .bind::<Nullable<Binary>, _>(row.seq_signature.as_deref())
        .execute(&mut self.conn)?;
        Ok(())
    }

    /// Sequence a message here (this node is the group's sequencer).
    /// Returns the stored row and whether it was newly inserted.
    pub fn append_sequenced(
        &mut self,
        msg: &NewGroupMessage,
        now_ns: i64,
    ) -> Result<(StoredGroupMessage, bool), MeshError> {
        self.append_sequenced_marked(msg, now_ns, false)
    }

    /// [`append_sequenced`](Self::append_sequenced), recording whether the
    /// message came from a peer's `Pending` (multi-hop relay sends such rows
    /// back as a `Ref`, §R6.3).
    pub fn append_sequenced_marked(
        &mut self,
        msg: &NewGroupMessage,
        now_ns: i64,
        from_peer: bool,
    ) -> Result<(StoredGroupMessage, bool), MeshError> {
        self.transaction(|s| {
            if let Some(existing) = s.sequenced_by_hash(&msg.group_id, &sha256(&msg.data))? {
                return Ok((existing, false));
            }
            let mut row = StoredGroupMessage {
                group_id: msg.group_id.clone(),
                id: s.max_group_id(&msg.group_id)? + 1,
                created_ns: now_ns,
                data: msg.data.clone(),
                sender_hmac: msg.sender_hmac.clone(),
                should_push: msg.should_push,
                is_commit: msg.is_commit,
                seq_signer: None,
                seq_signature: None,
            };
            s.sign_new_row(&mut row)?;
            s.insert_group_row(&row, from_peer)?;
            Ok((row, true))
        })
    }

    /// Store a message another node sequenced. Ids must arrive contiguously.
    pub fn insert_sequenced(
        &mut self,
        row: &StoredGroupMessage,
    ) -> Result<InsertOutcome, MeshError> {
        self.transaction(|s| {
            let have = s.max_group_id(&row.group_id)?;
            if row.id <= have {
                return Ok(InsertOutcome::Duplicate);
            }
            if row.id != have + 1 {
                return Ok(InsertOutcome::Gap { have });
            }
            s.insert_group_row(row, false)?;
            Ok(InsertOutcome::Inserted)
        })
    }

    /// [`insert_sequenced`](Self::insert_sequenced), and in the same
    /// transaction drop our pending copy of the message if it is now
    /// sequenced (inserted or already held).
    pub fn insert_sequenced_settling_pending(
        &mut self,
        row: &StoredGroupMessage,
    ) -> Result<InsertOutcome, MeshError> {
        self.transaction(|s| {
            let outcome = s.insert_sequenced(row)?;
            if matches!(outcome, InsertOutcome::Inserted | InsertOutcome::Duplicate) {
                s.remove_pending(&row.group_id, &sha256(&row.data))?;
            }
            Ok(outcome)
        })
    }

    /// v3 paging: ascending returns `id > cursor`; descending returns
    /// `id < cursor`, or the newest messages when `cursor == 0`.
    pub fn query_group(
        &mut self,
        group_id: &[u8],
        cursor: i64,
        limit: i64,
        descending: bool,
    ) -> Result<Vec<StoredGroupMessage>, MeshError> {
        let rows = match (descending, cursor) {
            (false, _) => sql_query(format!(
                "SELECT {GROUP_COLUMNS} FROM group_messages WHERE group_id = ? AND id > ? ORDER BY id ASC LIMIT ?"
            ))
            .bind::<Binary, _>(group_id)
            .bind::<BigInt, _>(cursor)
            .bind::<BigInt, _>(limit)
            .load(&mut self.conn)?,
            (true, 0) => sql_query(format!(
                "SELECT {GROUP_COLUMNS} FROM group_messages WHERE group_id = ? ORDER BY id DESC LIMIT ?"
            ))
            .bind::<Binary, _>(group_id)
            .bind::<BigInt, _>(limit)
            .load(&mut self.conn)?,
            (true, _) => sql_query(format!(
                "SELECT {GROUP_COLUMNS} FROM group_messages WHERE group_id = ? AND id < ? ORDER BY id DESC LIMIT ?"
            ))
            .bind::<Binary, _>(group_id)
            .bind::<BigInt, _>(cursor)
            .bind::<BigInt, _>(limit)
            .load(&mut self.conn)?,
        };
        Ok(rows)
    }

    // ---- signed sequencing (§B13) ----

    /// Sign rows sequenced here from now on as `signer`.
    pub fn set_seq_signer(&mut self, signer: Arc<dyn HelloSigner>) {
        self.seq_signer = Some(signer);
    }

    /// Stop signing sequenced rows and drop the held signer. Called by
    /// `stop_sync`: in production the signer is `ClientHelloSigner`, whose
    /// client keeps the node alive through its own API bundle, so a store
    /// that kept the signer past `stop_sync` would keep the node (and its
    /// database) from ever being dropped after logout. Rows sequenced while
    /// no signer is set stay unsigned until the next `start_sync`'s
    /// [`Self::sign_unsigned_rows`] backfill.
    pub fn clear_seq_signer(&mut self) {
        self.seq_signer = None;
    }

    pub(crate) fn seq_counters(&self) -> Arc<SeqCounters> {
        self.seq.clone()
    }

    /// Sign `row` if a signer is set (a row sequenced before one is set is
    /// signed later by [`Self::sign_unsigned_rows`]).
    fn sign_new_row(&self, row: &mut StoredGroupMessage) -> Result<(), MeshError> {
        let Some(signer) = self.seq_signer.as_ref() else {
            return Ok(());
        };
        let proof = seq::sign_row(
            signer.as_ref(),
            &row.group_id,
            row.id as u64,
            row.created_ns as u64,
            &row.data,
        )?;
        row.seq_signer = Some(proof.signer);
        row.seq_signature = Some(proof.signature);
        self.seq.count_signed(1);
        Ok(())
    }

    /// Sign, in one transaction, every stored row that has no proof yet:
    /// rows sequenced while no signer was set, and rows stored before
    /// signed sequencing (on a joiner these are attestations). Returns how
    /// many were signed; 0 without a signer.
    pub fn sign_unsigned_rows(&mut self) -> Result<u64, MeshError> {
        let Some(signer) = self.seq_signer.clone() else {
            return Ok(0);
        };
        let key = signer.installation_key();
        self.transaction(|s| {
            // `data_hash` is already `sha256(data)` (see `insert_group_row`),
            // so signing every unsigned row need not load each one's full
            // payload under the store mutex.
            let rows: Vec<UnsignedRow> = sql_query(
                "SELECT group_id, id, created_ns, data_hash FROM group_messages \
                 WHERE seq_signer IS NULL OR seq_signature IS NULL ORDER BY group_id, id",
            )
            .load(&mut s.conn)?;
            for row in &rows {
                let record = seq::SeqRecord::new(
                    &key,
                    &row.group_id,
                    row.id as u64,
                    row.created_ns as u64,
                    row.data_hash.clone(),
                );
                let signature = signer.sign(&record.signing_text())?;
                sql_query(
                    "UPDATE group_messages SET seq_signer = ?, seq_signature = ? \
                     WHERE group_id = ? AND id = ?",
                )
                .bind::<Binary, _>(&key)
                .bind::<Binary, _>(&signature)
                .bind::<Binary, _>(&row.group_id)
                .bind::<BigInt, _>(row.id)
                .execute(&mut s.conn)?;
            }
            s.seq.count_signed(rows.len() as u64);
            Ok(rows.len() as u64)
        })
    }

    /// The stored row `(group_id, id)`, if any.
    pub fn sequenced_at(
        &mut self,
        group_id: &[u8],
        id: i64,
    ) -> Result<Option<StoredGroupMessage>, MeshError> {
        let rows: Vec<StoredGroupMessage> = sql_query(format!(
            "SELECT {GROUP_COLUMNS} FROM group_messages WHERE group_id = ? AND id = ?"
        ))
        .bind::<Binary, _>(group_id)
        .bind::<BigInt, _>(id)
        .load(&mut self.conn)?;
        Ok(rows.into_iter().next())
    }

    /// Every stored row's signer in the group, by ascending id.
    pub fn seq_signers(&mut self, group_id: &[u8]) -> Result<Vec<Option<Vec<u8>>>, MeshError> {
        let rows: Vec<OptBlobRow> = sql_query(
            "SELECT seq_signer AS v FROM group_messages WHERE group_id = ? ORDER BY id ASC",
        )
        .bind::<Binary, _>(group_id)
        .load(&mut self.conn)?;
        Ok(rows.into_iter().map(|r| r.v).collect())
    }

    /// Keep `e` as proof (the first one seen per `(group_id, id, signer)`),
    /// then drop the oldest beyond [`MAX_EQUIVOCATIONS`].
    pub fn record_equivocation(&mut self, e: &Equivocation, now_ns: i64) -> Result<(), MeshError> {
        self.transaction(|s| {
            sql_query(
                "INSERT OR IGNORE INTO equivocations \
                 (group_id, id, signer, record_a, signature_a, record_b, signature_b, seen_ns) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<Binary, _>(&e.group_id)
            .bind::<BigInt, _>(e.id)
            .bind::<Binary, _>(&e.signer)
            .bind::<Binary, _>(&e.record_a)
            .bind::<Binary, _>(&e.signature_a)
            .bind::<Binary, _>(&e.record_b)
            .bind::<Binary, _>(&e.signature_b)
            .bind::<BigInt, _>(now_ns)
            .execute(&mut s.conn)?;
            sql_query(
                "DELETE FROM equivocations WHERE rowid IN \
                 (SELECT rowid FROM equivocations ORDER BY seen_ns DESC, rowid DESC LIMIT -1 OFFSET ?)",
            )
            .bind::<BigInt, _>(MAX_EQUIVOCATIONS)
            .execute(&mut s.conn)?;
            Ok(())
        })
    }

    /// The group's kept equivocations, by ascending id.
    pub fn equivocations(&mut self, group_id: &[u8]) -> Result<Vec<Equivocation>, MeshError> {
        let rows: Vec<EquivocationRow> = sql_query(
            "SELECT group_id, id, signer, record_a, signature_a, record_b, signature_b \
             FROM equivocations WHERE group_id = ? ORDER BY id ASC, signer ASC",
        )
        .bind::<Binary, _>(group_id)
        .load(&mut self.conn)?;
        Ok(rows
            .into_iter()
            .map(|r| Equivocation {
                group_id: r.group_id,
                id: r.id,
                signer: r.signer,
                record_a: r.record_a,
                signature_a: r.signature_a,
                record_b: r.record_b,
                signature_b: r.signature_b,
            })
            .collect())
    }

    // ---- pending (awaiting the sequencer) ----

    pub fn add_pending(&mut self, msg: &NewGroupMessage, now_ns: i64) -> Result<(), MeshError> {
        sql_query(
            "INSERT OR IGNORE INTO pending_group_messages (group_id, data_hash, data, sender_hmac, should_push, is_commit, created_ns) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind::<Binary, _>(&msg.group_id)
        .bind::<Binary, _>(sha256(&msg.data))
        .bind::<Binary, _>(&msg.data)
        .bind::<Binary, _>(&msg.sender_hmac)
        .bind::<Bool, _>(msg.should_push)
        .bind::<Bool, _>(msg.is_commit)
        .bind::<BigInt, _>(now_ns)
        .execute(&mut self.conn)?;
        Ok(())
    }

    pub fn pending_for(&mut self, group_id: &[u8]) -> Result<Vec<NewGroupMessage>, MeshError> {
        let rows: Vec<PendingRow> = sql_query(
            "SELECT group_id, data, sender_hmac, should_push, is_commit FROM pending_group_messages \
             WHERE group_id = ? ORDER BY created_ns ASC, rowid ASC",
        )
        .bind::<Binary, _>(group_id)
        .load(&mut self.conn)?;
        Ok(rows
            .into_iter()
            .map(|r| NewGroupMessage {
                group_id: r.group_id,
                data: r.data,
                sender_hmac: r.sender_hmac,
                should_push: r.should_push,
                is_commit: r.is_commit,
            })
            .collect())
    }

    pub fn remove_pending(&mut self, group_id: &[u8], data_hash: &[u8]) -> Result<(), MeshError> {
        sql_query("DELETE FROM pending_group_messages WHERE group_id = ? AND data_hash = ?")
            .bind::<Binary, _>(group_id)
            .bind::<Binary, _>(data_hash)
            .execute(&mut self.conn)?;
        Ok(())
    }

    // ---- welcomes ----

    /// Store a welcome addressed to `installation`. The receiving node assigns ids.
    pub fn append_welcome(
        &mut self,
        installation: &[u8],
        envelope_hash: &[u8],
        input: &[u8],
        now_ns: i64,
    ) -> Result<Option<StoredWelcome>, MeshError> {
        self.transaction(|s| s.append_welcome_inner(installation, envelope_hash, input, now_ns))
    }

    fn append_welcome_inner(
        &mut self,
        installation: &[u8],
        envelope_hash: &[u8],
        input: &[u8],
        now_ns: i64,
    ) -> Result<Option<StoredWelcome>, MeshError> {
        let dup: Vec<I64Row> = sql_query(
            "SELECT COUNT(*) AS v FROM welcomes WHERE installation_key = ? AND envelope_hash = ?",
        )
        .bind::<Binary, _>(installation)
        .bind::<Binary, _>(envelope_hash)
        .load(&mut self.conn)?;
        if dup[0].v > 0 {
            return Ok(None);
        }
        let max: Vec<I64Row> =
            sql_query("SELECT COALESCE(MAX(id), 0) AS v FROM welcomes WHERE installation_key = ?")
                .bind::<Binary, _>(installation)
                .load(&mut self.conn)?;
        let row = StoredWelcome {
            installation_key: installation.to_vec(),
            id: max[0].v + 1,
            created_ns: now_ns,
            input: input.to_vec(),
        };
        sql_query("INSERT INTO welcomes (installation_key, id, created_ns, envelope_hash, input) VALUES (?, ?, ?, ?, ?)")
            .bind::<Binary, _>(&row.installation_key)
            .bind::<BigInt, _>(row.id)
            .bind::<BigInt, _>(row.created_ns)
            .bind::<Binary, _>(envelope_hash)
            .bind::<Binary, _>(&row.input)
            .execute(&mut self.conn)?;
        Ok(Some(row))
    }

    pub fn query_welcomes(
        &mut self,
        installation: &[u8],
        cursor: i64,
        limit: i64,
    ) -> Result<Vec<StoredWelcome>, MeshError> {
        Ok(sql_query(
            "SELECT installation_key, id, created_ns, input FROM welcomes \
             WHERE installation_key = ? AND id > ? ORDER BY id ASC LIMIT ?",
        )
        .bind::<Binary, _>(installation)
        .bind::<BigInt, _>(cursor)
        .bind::<BigInt, _>(limit)
        .load(&mut self.conn)?)
    }

    pub fn add_outbound_welcome(
        &mut self,
        envelope_hash: &[u8],
        installation: &[u8],
        input: &[u8],
    ) -> Result<(), MeshError> {
        sql_query("INSERT OR IGNORE INTO outbound_welcomes (envelope_hash, installation_key, input) VALUES (?, ?, ?)")
            .bind::<Binary, _>(envelope_hash)
            .bind::<Binary, _>(installation)
            .bind::<Binary, _>(input)
            .execute(&mut self.conn)?;
        Ok(())
    }

    pub fn outbound_welcomes_for(
        &mut self,
        installation: &[u8],
    ) -> Result<OutboundWelcomePairs, MeshError> {
        let rows: Vec<OutboundRow> = sql_query(
            "SELECT envelope_hash, input FROM outbound_welcomes WHERE installation_key = ? ORDER BY rowid ASC",
        )
        .bind::<Binary, _>(installation)
        .load(&mut self.conn)?;
        Ok(rows
            .into_iter()
            .map(|r| (r.envelope_hash, r.input))
            .collect())
    }

    /// Remove the outbound welcome `envelope_hash` if it is queued for
    /// `installation`. Returns whether one was removed.
    pub fn remove_outbound_welcome_for(
        &mut self,
        installation: &[u8],
        envelope_hash: &[u8],
    ) -> Result<bool, MeshError> {
        let n = sql_query(
            "DELETE FROM outbound_welcomes WHERE envelope_hash = ? AND installation_key = ?",
        )
        .bind::<Binary, _>(envelope_hash)
        .bind::<Binary, _>(installation)
        .execute(&mut self.conn)?;
        Ok(n > 0)
    }
}
