//! Contacts: the phones this one recognises and dials as contacts, and
//! its own discovery generation (DESIGN.md §B14.1, §B14.4).
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Binary, Nullable, Text};

use super::MeshStore;
use crate::MeshError;
use crate::sync::frames::ContactCard;

const META_DISCOVERY_GENERATION: &str = "discovery_generation";
const CONTACT_COLUMNS: &str =
    "inbox_id, noise_static_pub, discovery_key, generation, updated_ns, removed_ns";

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

    /// Store `card`. Without `force` a card never replaces a newer
    /// generation, another static key, or a removed contact; `force` (a
    /// confirmed pairing) always stores it and clears a removal.
    pub fn upsert_contact(
        &mut self,
        card: &ContactCard,
        now_ns: i64,
        force: bool,
    ) -> Result<ContactUpdate, MeshError> {
        check_card(card)?;
        self.transaction(|s| {
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
                "INSERT INTO contacts (inbox_id, noise_static_pub, discovery_key, generation, updated_ns, removed_ns) \
                 VALUES (?, ?, ?, ?, ?, NULL) \
                 ON CONFLICT(inbox_id) DO UPDATE SET noise_static_pub = excluded.noise_static_pub, \
                 discovery_key = excluded.discovery_key, generation = excluded.generation, \
                 updated_ns = excluded.updated_ns, removed_ns = NULL",
            )
            .bind::<Text, _>(&card.inbox_id)
            .bind::<Binary, _>(&card.noise_static_pub)
            .bind::<Binary, _>(&card.discovery_key)
            .bind::<BigInt, _>(i64::from(card.generation))
            .bind::<BigInt, _>(now_ns)
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

    pub fn discovery_generation(&mut self) -> Result<u32, MeshError> {
        match self.meta(META_DISCOVERY_GENERATION)? {
            None => Ok(0),
            Some(v) => Ok(u32::from_be_bytes(v.as_slice().try_into().map_err(
                |_| MeshError::InvalidRequest("stored discovery generation".into()),
            )?)),
        }
    }

    pub fn set_discovery_generation(&mut self, generation: u32) -> Result<(), MeshError> {
        self.set_meta(META_DISCOVERY_GENERATION, &generation.to_be_bytes())
    }
}
