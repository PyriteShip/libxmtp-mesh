//! Contacts: the phones this one recognises and dials as contacts, its
//! own discovery generation, and the restore window (DESIGN.md §B14.1,
//! §B14.4, §B14.7).
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Binary, Nullable, Text};

use super::MeshStore;
use crate::MeshError;
use crate::sync::frames::ContactCard;

const META_DISCOVERY_GENERATION: &str = "discovery_generation";
/// The random salt of the current generation's key (§B14.1).
const META_DISCOVERY_SALT: &str = "discovery_reset_salt";
/// Unix second the restore window ends (§B14.7).
const META_RESTORE_UNTIL: &str = "restore_window_until";
/// The latest wall clock (unix seconds) seen while the window was open: a
/// clock set back never makes the window longer.
const META_RESTORE_SEEN: &str = "restore_window_seen";
const CONTACT_COLUMNS: &str = "inbox_id, noise_static_pub, discovery_key, generation, updated_ns, \
     removed_ns, auto_added_ns";

/// A stored contact. `Debug` omits the discovery key: it is a secret shared
/// with that contact.
#[derive(Clone, PartialEq, Eq)]
pub struct Contact {
    pub inbox_id: String,
    pub noise_static_pub: [u8; 32],
    pub discovery_key: [u8; 32],
    pub generation: u32,
    pub updated_ns: i64,
    /// A removed contact: kept so its static key is refused (§B14.4).
    pub removed: bool,
    /// Added by the phone itself during a restore window, and not yet
    /// confirmed by the user: it does not get our card (§B14.7).
    pub auto_added: bool,
}

/// The persisted restore window (§B14.7): it ends at `until`; `seen` is the
/// latest wall clock observed while it was open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreWindow {
    pub until: u64,
    pub seen: u64,
}

/// The contacts the node's allowed-dialer set is built from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContactStatics {
    pub live: Vec<[u8; 32]>,
    pub removed: Vec<[u8; 32]>,
}

impl std::fmt::Debug for Contact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Contact")
            .field("inbox_id", &self.inbox_id)
            .field("noise_static_pub", &hex::encode(self.noise_static_pub))
            .field("discovery_key", &"<redacted>")
            .field("generation", &self.generation)
            .field("updated_ns", &self.updated_ns)
            .field("removed", &self.removed)
            .field("auto_added", &self.auto_added)
            .finish()
    }
}

/// What `upsert_contact` did with a card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactUpdate {
    Inserted,
    Updated,
    /// The same card again.
    Unchanged,
    /// An older generation, or another static key for the inbox: ignored
    /// (only a confirmed pairing replaces those).
    Stale,
    /// The inbox is a removed contact: ignored.
    Removed,
    /// The card's static key is on file under another inbox (a live or a
    /// removed contact): refused, forced or not, so no card can take over
    /// another contact's key (§B14.4).
    StaticTaken,
}

#[derive(QueryableByName)]
struct ContactRow {
    #[diesel(sql_type = Text)]
    inbox_id: String,
    #[diesel(sql_type = Binary)]
    noise_static_pub: Vec<u8>,
    #[diesel(sql_type = Binary)]
    discovery_key: Vec<u8>,
    #[diesel(sql_type = BigInt)]
    generation: i64,
    #[diesel(sql_type = BigInt)]
    updated_ns: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    removed_ns: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    auto_added_ns: Option<i64>,
}

impl TryFrom<ContactRow> for Contact {
    type Error = MeshError;

    fn try_from(r: ContactRow) -> Result<Self, MeshError> {
        let key = |v: Vec<u8>| {
            <[u8; 32]>::try_from(v)
                .map_err(|_| MeshError::InvalidRequest("stored contact key is not 32 bytes".into()))
        };
        Ok(Contact {
            inbox_id: r.inbox_id,
            noise_static_pub: key(r.noise_static_pub)?,
            discovery_key: key(r.discovery_key)?,
            generation: u32::try_from(r.generation)
                .map_err(|_| MeshError::InvalidRequest("stored contact generation".into()))?,
            updated_ns: r.updated_ns,
            removed: r.removed_ns.is_some(),
            auto_added: r.auto_added_ns.is_some(),
        })
    }
}

fn check_card(card: &ContactCard) -> Result<(), MeshError> {
    if card.inbox_id.is_empty()
        || card.noise_static_pub.len() != 32
        || card.discovery_key.len() != 32
    {
        return Err(MeshError::InvalidRequest("malformed contact card".into()));
    }
    Ok(())
}

impl MeshStore {
    pub fn contact(&mut self, inbox_id: &str) -> Result<Option<Contact>, MeshError> {
        let rows: Vec<ContactRow> = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts WHERE inbox_id = ?"
        ))
        .bind::<Text, _>(inbox_id)
        .load(&mut self.conn)?;
        rows.into_iter().next().map(Contact::try_from).transpose()
    }

    /// The contact (live or removed) whose Noise static key this is.
    pub fn contact_by_static(
        &mut self,
        noise_static_pub: &[u8],
    ) -> Result<Option<Contact>, MeshError> {
        let rows: Vec<ContactRow> = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts WHERE noise_static_pub = ? \
             ORDER BY updated_ns DESC LIMIT 1"
        ))
        .bind::<Binary, _>(noise_static_pub)
        .load(&mut self.conn)?;
        rows.into_iter().next().map(Contact::try_from).transpose()
    }

    /// Live contacts, by inbox id.
    pub fn contacts(&mut self) -> Result<Vec<Contact>, MeshError> {
        let rows: Vec<ContactRow> = sql_query(format!(
            "SELECT {CONTACT_COLUMNS} FROM contacts WHERE removed_ns IS NULL ORDER BY inbox_id"
        ))
        .load(&mut self.conn)?;
        rows.into_iter().map(Contact::try_from).collect()
    }

    /// The live and the removed contacts' static keys.
    pub fn contact_statics(&mut self) -> Result<ContactStatics, MeshError> {
        let rows: Vec<ContactRow> =
            sql_query(format!("SELECT {CONTACT_COLUMNS} FROM contacts")).load(&mut self.conn)?;
        let mut statics = ContactStatics::default();
        for row in rows {
            let contact = Contact::try_from(row)?;
            if contact.removed {
                statics.removed.push(contact.noise_static_pub);
            } else {
                statics.live.push(contact.noise_static_pub);
            }
        }
        Ok(statics)
    }

    /// Store `card`. Without `force` a card never replaces a newer
    /// generation, another static key, or a removed contact; `force` (a
    /// confirmed pairing) always stores it and clears a removal.
    pub fn upsert_contact(
        &mut self,
        card: &ContactCard,
        now_ns: i64,
        force: bool,
    ) -> Result<ContactUpdate, MeshError> {
        self.upsert_contact_with(card, now_ns, force, false)
    }

    /// [`Self::upsert_contact`]; a card `Inserted` with `auto_added` is
    /// flagged as added by the phone itself during a restore window
    /// (§B14.7). A forced store (a confirmed pairing) clears the flag;
    /// other updates keep it.
    pub fn upsert_contact_with(
        &mut self,
        card: &ContactCard,
        now_ns: i64,
        force: bool,
        auto_added: bool,
    ) -> Result<ContactUpdate, MeshError> {
        check_card(card)?;
        self.transaction(|s| {
            if s.contact_by_static(&card.noise_static_pub)?
                .is_some_and(|owner| owner.inbox_id != card.inbox_id)
            {
                return Ok(ContactUpdate::StaticTaken);
            }
            let outcome = match s.contact(&card.inbox_id)? {
                None => ContactUpdate::Inserted,
                Some(_) if force => ContactUpdate::Updated,
                Some(c) if c.removed => return Ok(ContactUpdate::Removed),
                Some(c)
                    if c.noise_static_pub.as_slice() != card.noise_static_pub.as_slice()
                        || card.generation < c.generation =>
                {
                    return Ok(ContactUpdate::Stale);
                }
                Some(c)
                    if card.generation == c.generation
                        && c.discovery_key.as_slice() == card.discovery_key.as_slice() =>
                {
                    return Ok(ContactUpdate::Unchanged);
                }
                Some(_) => ContactUpdate::Updated,
            };
            sql_query(
                "INSERT INTO contacts (inbox_id, noise_static_pub, discovery_key, generation, updated_ns, \
                 removed_ns, auto_added_ns) VALUES (?, ?, ?, ?, ?, NULL, ?) \
                 ON CONFLICT(inbox_id) DO UPDATE SET noise_static_pub = excluded.noise_static_pub, \
                 discovery_key = excluded.discovery_key, generation = excluded.generation, \
                 updated_ns = excluded.updated_ns, removed_ns = NULL, \
                 auto_added_ns = CASE WHEN ? THEN NULL ELSE contacts.auto_added_ns END",
            )
            .bind::<Text, _>(&card.inbox_id)
            .bind::<Binary, _>(&card.noise_static_pub)
            .bind::<Binary, _>(&card.discovery_key)
            .bind::<BigInt, _>(i64::from(card.generation))
            .bind::<BigInt, _>(now_ns)
            .bind::<Nullable<BigInt>, _>(auto_added.then_some(now_ns))
            .bind::<diesel::sql_types::Bool, _>(force)
            .execute(&mut s.conn)?;
            Ok(outcome)
        })
    }

    /// Mark `inbox_id` removed. Returns whether a live contact was removed.
    pub fn remove_contact(&mut self, inbox_id: &str, now_ns: i64) -> Result<bool, MeshError> {
        let n = sql_query(
            "UPDATE contacts SET removed_ns = ? WHERE inbox_id = ? AND removed_ns IS NULL",
        )
        .bind::<BigInt, _>(now_ns)
        .bind::<Text, _>(inbox_id)
        .execute(&mut self.conn)?;
        Ok(n > 0)
    }

    /// Drop `inbox_id`'s row, live or removed, tombstone included. Returns
    /// whether a row was dropped.
    pub fn forget_contact(&mut self, inbox_id: &str) -> Result<bool, MeshError> {
        let n = sql_query("DELETE FROM contacts WHERE inbox_id = ?")
            .bind::<Text, _>(inbox_id)
            .execute(&mut self.conn)?;
        Ok(n > 0)
    }

    /// The user confirmed a contact the phone added by itself during a
    /// restore window (§B14.7). Returns whether such a live contact was
    /// flagged.
    pub fn confirm_contact(&mut self, inbox_id: &str) -> Result<bool, MeshError> {
        let n = sql_query(
            "UPDATE contacts SET auto_added_ns = NULL \
             WHERE inbox_id = ? AND removed_ns IS NULL AND auto_added_ns IS NOT NULL",
        )
        .bind::<Text, _>(inbox_id)
        .execute(&mut self.conn)?;
        Ok(n > 0)
    }

    /// The persisted restore window, if one was begun and not ended
    /// (it may have run out: see `MeshNode::restore_window_until`).
    pub fn restore_window(&mut self) -> Result<Option<RestoreWindow>, MeshError> {
        let read = |v: Option<Vec<u8>>| -> Result<Option<u64>, MeshError> {
            match v {
                None => Ok(None),
                Some(v) if v.is_empty() => Ok(None),
                Some(v) => Ok(Some(u64::from_be_bytes(v.as_slice().try_into().map_err(
                    |_| MeshError::InvalidRequest("stored restore window".into()),
                )?))),
            }
        };
        let until = read(self.meta(META_RESTORE_UNTIL)?)?;
        let seen = read(self.meta(META_RESTORE_SEEN)?)?;
        Ok(until.map(|until| RestoreWindow {
            until,
            seen: seen.unwrap_or(0),
        }))
    }

    pub fn set_restore_window(&mut self, window: RestoreWindow) -> Result<(), MeshError> {
        self.transaction(|s| {
            s.set_meta(META_RESTORE_UNTIL, &window.until.to_be_bytes())?;
            s.set_meta(META_RESTORE_SEEN, &window.seen.to_be_bytes())
        })
    }

    /// End the restore window (an empty value means none).
    pub fn clear_restore_window(&mut self) -> Result<(), MeshError> {
        self.transaction(|s| {
            s.set_meta(META_RESTORE_UNTIL, &[])?;
            s.set_meta(META_RESTORE_SEEN, &[])
        })
    }

    pub fn discovery_generation(&mut self) -> Result<u32, MeshError> {
        match self.meta(META_DISCOVERY_GENERATION)? {
            None => Ok(0),
            Some(v) => Ok(u32::from_be_bytes(v.as_slice().try_into().map_err(
                |_| MeshError::InvalidRequest("stored discovery generation".into()),
            )?)),
        }
    }

    /// The random salt the reset to the current generation mixed in
    /// (§B14.1); `None` at generation 0.
    pub fn discovery_reset_salt(&mut self) -> Result<Option<[u8; 32]>, MeshError> {
        match self.meta(META_DISCOVERY_SALT)? {
            None => Ok(None),
            Some(v) if v.is_empty() => Ok(None),
            Some(v) => Ok(Some(v.as_slice().try_into().map_err(|_| {
                MeshError::InvalidRequest("stored discovery reset salt".into())
            })?)),
        }
    }

    /// Store the discovery generation and the salt its reset mixed in.
    pub fn set_discovery_generation(
        &mut self,
        generation: u32,
        reset_salt: Option<&[u8; 32]>,
    ) -> Result<(), MeshError> {
        self.transaction(|s| {
            s.set_meta(META_DISCOVERY_GENERATION, &generation.to_be_bytes())?;
            s.set_meta(
                META_DISCOVERY_SALT,
                reset_salt.map(|salt| salt.as_slice()).unwrap_or(&[]),
            )
        })
    }
}
