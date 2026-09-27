//! Private discovery and Noise links (DESIGN.md §B14): keys derived from
//! the account key, rotating advert tokens, Noise handshakes and sealed
//! records.
pub mod keys;
pub(crate) mod noise;
pub(crate) mod records;
pub(crate) mod tx;

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

use parking_lot::{Mutex, RwLock};

pub use keys::{
    ADVERT_LEN, ADVERT_VERSION, FLAG_PAIRING, FLAG_RELAY, TOKEN_LEN, Token, WINDOW_SECS,
    advert_token, parse_service_data, service_data, window_at,
};
pub use noise::short_code;

use crate::sync::frames::frame::Body;
use crate::sync::seq::MeshStats;

/// The kind of an open link (§B14.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// Noise IK between contacts: full sync.
    Contact,
    /// Noise NN with a stranger: relay frames only.
    Relay,
    /// Noise XX in pairing mode: full sync, cards wait for confirmation.
    Pairing,
}

/// How the radio opened a connection (§B14.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkRole {
    /// We dialed; the intent says what we believe the other phone is.
    Dial(DialIntent),
    /// The other phone dialed us.
    Accept,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialIntent {
    /// The other phone advertised a token of this contact.
    Contact { inbox_id: String },
    /// A stranger that offers relay; our relay is on.
    Relay,
    /// Both phones are in pairing mode.
    Pairing,
}

/// Frames a link of `kind` may carry (§B14.3). A relay link carries relay
/// traffic only: nothing that names a phone or a group.
pub(crate) fn allowed_on(kind: LinkKind, body: &Body) -> bool {
    match kind {
        LinkKind::Relay => matches!(
            body,
            Body::Relay(_) | Body::SpoolDigest(_) | Body::SpoolWant(_)
        ),
        LinkKind::Contact | LinkKind::Pairing => true,
    }
}

/// Public facts about the keys `set_account_key` derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkKeyInfo {
    pub noise_static_pub: [u8; 32],
    pub generation: u32,
}

/// What the radio needs for one discovery window (§B14.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvertState {
    pub window: u64,
    /// The service data to advertise: `2 ‖ flags ‖ own_token`.
    pub service_data: [u8; ADVERT_LEN],
    pub own_token: Token,
    /// Every live contact's tokens for windows `window - 1 ..= window + 1`.
    pub contact_tokens: Vec<(Token, String)>,
    /// Unix second at which the next window starts: restart advertising then.
    pub next_window_at: u64,
    /// Changes whenever the token map or our own token changes.
    pub contacts_version: u64,
}

/// What a seen advert is (§B14.2). `dial_first`: our token is the lower
/// one, so we dial now; otherwise we dial only as the §B7.2 fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdvertMatch {
    /// Not a version-2 advert.
    Invalid,
    /// Our own advert.
    Own,
    Contact {
        inbox_id: String,
        dial_first: bool,
    },
    Stranger {
        relay_offered: bool,
        dial_first: bool,
    },
    /// Both phones are in pairing mode.
    Pairing {
        dial_first: bool,
    },
}

#[derive(Debug, Default)]
pub(crate) struct LinkCounters {
    contact: AtomicU64,
    relay: AtomicU64,
    pairing: AtomicU64,
    handshake_failed: AtomicU64,
    frame_rejected: AtomicU64,
    discovery_resets: AtomicU64,
    relay_idle_closed: AtomicU64,
}

impl LinkCounters {
    pub(crate) fn count_link(&self, kind: LinkKind) {
        let counter = match kind {
            LinkKind::Contact => &self.contact,
            LinkKind::Relay => &self.relay,
            LinkKind::Pairing => &self.pairing,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn count_handshake_failed(&self) {
        self.handshake_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn count_frame_rejected(&self) {
        self.frame_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn count_relay_idle_closed(&self) {
        self.relay_idle_closed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn count_discovery_reset(&self) {
        self.discovery_resets.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn fill(&self, stats: &mut MeshStats) {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        stats.links_contact = get(&self.contact);
        stats.links_relay = get(&self.relay);
        stats.links_pairing = get(&self.pairing);
        stats.handshake_failed = get(&self.handshake_failed);
        stats.link_frame_rejected = get(&self.frame_rejected);
        stats.discovery_resets = get(&self.discovery_resets);
        stats.relay_links_idle_closed = get(&self.relay_idle_closed);
    }
}

/// Which IK dialers get a contact link (§B14.2): the live contacts' static
/// keys, or anyone while the phone has no contact at all (not even a
/// removed one: a restored phone). An in-memory copy of the store, so a
/// responder answers without database I/O.
#[derive(Default)]
pub(crate) struct AllowedDialers {
    pub(crate) live: HashSet<[u8; 32]>,
    pub(crate) no_contacts: bool,
}

/// The node's link state (§B14). Keys live in memory only and are zeroized
/// on drop. Lock order: `prk`, then the store, then `keys`, then
/// `dialers`.
#[derive(Default)]
pub(crate) struct LinkState {
    pub(crate) prk: Mutex<Option<keys::AccountPrk>>,
    pub(crate) keys: Mutex<Option<Arc<keys::MeshKeys>>>,
    pub(crate) pairing_mode: AtomicBool,
    pub(crate) counters: LinkCounters,
    contacts_version: AtomicU64,
    /// Test only: seconds added to the wall clock.
    pub(crate) clock_offset_secs: AtomicI64,
    /// The node's one IK replay cache, shared by all its responders.
    pub(crate) replay: noise::ReplayCache,
    pub(crate) dialers: RwLock<AllowedDialers>,
}

impl LinkState {
    pub(crate) fn bump_contacts_version(&self) {
        self.contacts_version.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn contacts_version(&self) -> u64 {
        self.contacts_version.load(Ordering::Relaxed)
    }
}
