//! Link keys, adverts and contacts on the node (DESIGN.md §B14).
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::MeshNode;
use crate::MeshError;
#[cfg(any(test, feature = "test-utils"))]
use crate::link::LinkRole;
use crate::link::keys::{AccountPrk, MeshKeys};
use crate::link::noise::{ReplayCache, ResponderContext};
use crate::link::{
    AdvertMatch, AdvertState, AllowedDialers, ContactLinkEntry, ContactLinkOutcome, FLAG_PAIRING,
    FLAG_RELAY, LinkCounters, LinkKeyInfo, Token, WINDOW_SECS, advert_token, parse_service_data,
    service_data, window_at,
};
use crate::link::{MAX_UNFINISHED_PAIRINGS, PairingEntry, PendingPairing};
use crate::store::{Contact, ContactUpdate};
use crate::sync::MeshTransport;
use crate::sync::frames::ContactCard;
use crate::sync::frames::frame::Body;
use crate::sync::session::Inbound;
#[cfg(any(test, feature = "test-utils"))]
use crate::sync::session::LinkSetup;

/// Most radio peers remembered in back-off; beyond it the soonest to
/// expire goes.
const MAX_RELAY_BACKOFFS: usize = 256;

impl MeshNode {
    /// Derive this phone's link keys from the account key (the secp256k1
    /// key the recovery phrase restores). Call once per process start,
    /// after registration and before `start_sync`. Only the HKDF PRK and
    /// the derived keys are kept, in memory (§B14.1).
    pub fn set_account_key(&self, account_secret: &[u8]) -> Result<LinkKeyInfo, MeshError> {
        let prk = AccountPrk::extract(account_secret)?;
        // Held throughout so a concurrent reset cannot derive from a stale
        // generation.
        let mut prk_slot = self.inner.link.prk.lock();
        let (inbox_id, generation) = {
            let mut store = self.inner.store.lock();
            let inbox_id = store.local_inbox()?.ok_or(MeshError::NotRegistered)?;
            (inbox_id, store.discovery_generation()?)
        };
        let keys = Arc::new(MeshKeys::derive(&prk, &inbox_id, generation));
        let info = LinkKeyInfo {
            noise_static_pub: keys.noise_public,
            generation,
        };
        *prk_slot = Some(prk);
        *self.inner.link.keys.lock() = Some(keys);
        self.inner.link.bump_contacts_version();
        Ok(info)
    }

    pub fn has_account_key(&self) -> bool {
        self.inner.link.keys.lock().is_some()
    }

    pub(crate) fn mesh_keys(&self) -> Option<Arc<MeshKeys>> {
        self.inner.link.keys.lock().clone()
    }

    pub(crate) fn link_counters(&self) -> &LinkCounters {
        &self.inner.link.counters
    }

    pub fn discovery_generation(&self) -> Result<u32, MeshError> {
        self.inner.store.lock().discovery_generation()
    }

    /// Start advertising under a new discovery key (§B14.4): contacts that
    /// have not received the new card stop recognising this phone, which
    /// still recognises them and sends the card on its next contact link.
    pub fn reset_discovery_key(&self) -> Result<u32, MeshError> {
        let prk = self.inner.link.prk.lock();
        let prk = prk.as_ref().ok_or(MeshError::NoAccountKey)?;
        let (inbox_id, generation) = {
            let mut store = self.inner.store.lock();
            let inbox_id = store.local_inbox()?.ok_or(MeshError::NotRegistered)?;
            let generation = store
                .discovery_generation()?
                .checked_add(1)
                .ok_or_else(|| {
                    MeshError::InvalidRequest("discovery generation exhausted".into())
                })?;
            store.set_discovery_generation(generation)?;
            (inbox_id, generation)
        };
        *self.inner.link.keys.lock() = Some(Arc::new(MeshKeys::derive(prk, &inbox_id, generation)));
        self.inner.link.counters.count_discovery_reset();
        self.inner.link.bump_contacts_version();
        Ok(generation)
    }

    /// Unix seconds (plus the test clock offset).
    pub fn unix_now(&self) -> u64 {
        let now = xmtp_common::time::now_ns() / 1_000_000_000;
        now.saturating_add(self.inner.link.clock_offset_secs.load(Ordering::Relaxed))
            .max(0) as u64
    }

    /// Advertise and accept pairing links (§B14.4). Each time it is turned
    /// on, [`MAX_UNFINISHED_PAIRINGS`] unfinished pairings are allowed.
    /// The phone leaves pairing mode by itself after a successful pairing
    /// or at that cap. Turning it off closes every open pairing link the
    /// people have not both confirmed.
    pub fn set_pairing_mode(&self, on: bool) {
        if on {
            self.inner.link.pairing_failures.store(0, Ordering::Relaxed);
            self.inner.link.pairing_mode.store(true, Ordering::Relaxed);
            self.inner.link.bump_contacts_version();
        } else {
            self.leave_pairing_mode();
        }
    }

    /// Stop advertising and accepting pairing links, and close the open
    /// ones not yet confirmed by both people (a handshake still running
    /// is refused when it opens). Returns whether pairing mode was on.
    fn leave_pairing_mode(&self) -> bool {
        let was_on = self.inner.link.pairing_mode.swap(false, Ordering::Relaxed);
        self.inner.link.bump_contacts_version();
        let sessions = self.inner.sessions.lock();
        self.inner.link.pairings.lock().retain(|peer, e| {
            if e.confirmed && e.peer_confirmed {
                return true;
            }
            if let Some(handle) = sessions.get(peer).filter(|h| h.id == e.session_id) {
                let _ = handle.tx.send(Inbound::Pairing { confirm: false });
            }
            false
        });
        was_on
    }

    pub fn pairing_mode(&self) -> bool {
        self.inner.link.pairing_mode.load(Ordering::Relaxed)
    }

    /// Our advert token at `now`, or `None` before `set_account_key`.
    pub fn own_advert_token(&self, now: u64) -> Option<Token> {
        self.mesh_keys().map(|k| k.own_token(window_at(now)))
    }

    /// What the radio advertises and matches during the window of `now`.
    pub fn advert_state(&self, now: u64) -> Result<AdvertState, MeshError> {
        let keys = self.mesh_keys().ok_or(MeshError::NoAccountKey)?;
        let window = window_at(now);
        let own_token = keys.own_token(window);
        let mut flags = 0;
        if self.pairing_mode() {
            flags |= FLAG_PAIRING;
        }
        if self.relay_enabled() {
            flags |= FLAG_RELAY;
        }
        Ok(AdvertState {
            window,
            service_data: service_data(flags, &own_token),
            own_token,
            contact_tokens: self.contact_tokens(window)?,
            next_window_at: (window + 1) * WINDOW_SECS,
            contacts_version: self.inner.link.contacts_version(),
        })
    }

    /// Classify a seen advert's service data (§B14.2).
    pub fn classify_advert(&self, data: &[u8], now: u64) -> Result<AdvertMatch, MeshError> {
        let Some((flags, token)) = parse_service_data(data) else {
            return Ok(AdvertMatch::Invalid);
        };
        let keys = self.mesh_keys().ok_or(MeshError::NoAccountKey)?;
        let window = window_at(now);
        let own = keys.own_token(window);
        // Our own advert (or another installation of our inbox, which
        // shares the keys) from a neighbouring window.
        if [window.saturating_sub(1), window, window + 1]
            .into_iter()
            .any(|w| keys.own_token(w) == token)
        {
            return Ok(AdvertMatch::Own);
        }
        let dial_first = own < token;
        if flags & FLAG_PAIRING != 0 && self.pairing_mode() {
            return Ok(AdvertMatch::Pairing { dial_first });
        }
        if let Some(inbox_id) = self.contact_for_token(&token, window)? {
            return Ok(AdvertMatch::Contact {
                inbox_id,
                dial_first,
            });
        }
        Ok(AdvertMatch::Stranger {
            relay_offered: flags & FLAG_RELAY != 0,
            dial_first,
        })
    }

    fn contact_tokens(&self, window: u64) -> Result<Vec<(Token, String)>, MeshError> {
        let contacts = self.inner.store.lock().contacts()?;
        let mut out = Vec::with_capacity(contacts.len() * 3);
        for c in contacts {
            for w in [window.saturating_sub(1), window, window + 1] {
                out.push((advert_token(&c.discovery_key, w), c.inbox_id.clone()));
            }
        }
        Ok(out)
    }

    /// The live contact whose token for `window - 1 ..= window + 1` this is.
    pub(crate) fn contact_for_token(
        &self,
        token: &Token,
        window: u64,
    ) -> Result<Option<String>, MeshError> {
        Ok(self
            .contact_tokens(window)?
            .into_iter()
            .find(|(t, _)| t == token)
            .map(|(_, inbox_id)| inbox_id))
    }

    pub fn contacts(&self) -> Result<Vec<Contact>, MeshError> {
        self.inner.store.lock().contacts()
    }

    pub fn contact(&self, inbox_id: &str) -> Result<Option<Contact>, MeshError> {
        self.inner.store.lock().contact(inbox_id)
    }

    pub(crate) fn contact_by_static(&self, key: &[u8; 32]) -> Result<Option<Contact>, MeshError> {
        self.inner.store.lock().contact_by_static(key)
    }

    /// Stop recognising and accepting `inbox_id` (§B14.4). Its static key
    /// stays on file, so an IK link from it is refused. Follow with
    /// `reset_discovery_key` so it can no longer recognise this phone.
    pub fn remove_contact(&self, inbox_id: &str) -> Result<bool, MeshError> {
        let mut store = self.inner.store.lock();
        let removed = store.remove_contact(inbox_id, Self::now_ns())?;
        if removed {
            self.refresh_allowed_dialers(&mut store);
            self.inner.link.bump_contacts_version();
        }
        Ok(removed)
    }

    /// Re-read which IK dialers get a contact link (§B14.2) after the
    /// contacts changed. Callers hold the store. On a store error nobody
    /// is allowed (fails closed: dialers get the stranger fallback).
    pub(crate) fn refresh_allowed_dialers(&self, store: &mut crate::store::MeshStore) {
        let dialers = match store.contact_statics() {
            Ok((live, any)) => AllowedDialers {
                live: live.into_iter().collect(),
                no_contacts: !any,
            },
            Err(e) => {
                tracing::warn!(error = %e, "contacts unavailable; no IK dialer allowed");
                AllowedDialers::default()
            }
        };
        *self.inner.link.dialers.write() = dialers;
    }

    /// This phone closed `peer`'s relay link (idle, at the lifetime cap, or
    /// relay off): refuse it as a stranger for the back-off (§B14.3), so
    /// reconnecting cannot hold a radio slot.
    pub(crate) fn back_off_relay_peer(&self, peer: &str) {
        let now = std::time::Instant::now();
        let until = now + *self.inner.relay_backoff.lock();
        let mut backoffs = self.inner.relay_backoffs.lock();
        backoffs.retain(|_, t| *t > now);
        if backoffs.len() >= MAX_RELAY_BACKOFFS
            && !backoffs.contains_key(peer)
            && let Some(soonest) = backoffs
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(p, _)| p.clone())
        {
            backoffs.remove(&soonest);
        }
        backoffs.insert(peer.to_string(), until);
    }

    /// Whether `peer` is refused as a stranger right now; counted when so.
    pub(crate) fn relay_peer_refused(&self, peer: &str) -> bool {
        let refused = self
            .inner
            .relay_backoffs
            .lock()
            .get(peer)
            .is_some_and(|t| *t > std::time::Instant::now());
        if refused {
            self.inner.link.counters.count_relay_backoff_refused();
        }
        refused
    }

    /// A stranger relay link opened on session `session_id` (§B14.5).
    pub(crate) fn relay_stranger_link_up(&self, peer: &str, session_id: u64) {
        self.relay_session_link_up(
            peer,
            session_id,
            crate::relay::stranger_source(),
            String::new(),
        );
    }

    pub(crate) fn store_contact_card(
        &self,
        card: &ContactCard,
        force: bool,
    ) -> Result<ContactUpdate, MeshError> {
        if let Some(keys) = self.mesh_keys()
            && (card.inbox_id == keys.inbox_id
                || card.noise_static_pub.as_slice() == keys.noise_public.as_slice())
        {
            return Err(MeshError::InvalidRequest(
                "a contact card for this phone itself".into(),
            ));
        }
        let mut store = self.inner.store.lock();
        let outcome = store.upsert_contact(card, Self::now_ns(), force)?;
        if matches!(outcome, ContactUpdate::Inserted | ContactUpdate::Updated) {
            self.refresh_allowed_dialers(&mut store);
            self.inner.link.bump_contacts_version();
        }
        Ok(outcome)
    }

    /// Contact link `peer` (session `session_id`) verified `inbox_id` /
    /// `installation`. If another live contact link reaches the same
    /// installation (both phones dialed), both phones keep the one dialed
    /// by the lower static key (§B14.3). Decided, and the kept link
    /// registered verified, under one `sessions` lock, so a closing link
    /// is never left verified.
    pub(crate) fn contact_link_verified(
        &self,
        peer: &str,
        session_id: u64,
        inbox_id: String,
        installation: Vec<u8>,
        dialer_static: [u8; 32],
    ) -> ContactLinkOutcome {
        let sessions = self.inner.sessions.lock();
        let current = |p: &str, id: u64| sessions.get(p).is_some_and(|h| h.id == id);
        if !current(peer, session_id) {
            return ContactLinkOutcome::Kept { close: None };
        }
        let rival = {
            let mut links = self.inner.link.contact_links.lock();
            links.retain(|p, l| current(p, l.session_id));
            let rival = links
                .iter()
                .find(|(p, l)| p.as_str() != peer && l.installation == installation)
                .map(|(p, l)| (p.clone(), l.dialer_static));
            if let Some((_, rival_dialer)) = &rival
                && dialer_static > *rival_dialer
            {
                return ContactLinkOutcome::Superseded;
            }
            links.insert(
                peer.to_string(),
                ContactLinkEntry {
                    session_id,
                    installation: installation.clone(),
                    dialer_static,
                },
            );
            rival
        };
        self.register_verified(peer, inbox_id, installation);
        match rival {
            Some((rival_peer, rival_dialer)) if dialer_static < rival_dialer => {
                // The rival verified first; it is closing now.
                self.forget_peer(&rival_peer);
                ContactLinkOutcome::Kept {
                    close: Some(rival_peer),
                }
            }
            // No rival, or the same phone dialed both: leave it to the
            // radio (§B7.3).
            _ => ContactLinkOutcome::Kept { close: None },
        }
    }

    /// Pairing link `peer` (session `session_id`) opened with `code`.
    pub(crate) fn pairing_opened(&self, peer: &str, session_id: u64, code: String) {
        let sessions = self.inner.sessions.lock();
        if sessions.get(peer).is_some_and(|h| h.id == session_id) {
            self.inner.link.pairings.lock().insert(
                peer.to_string(),
                PairingEntry {
                    session_id,
                    code,
                    confirmed: false,
                    peer_confirmed: false,
                },
            );
        }
    }

    /// The other phone's person confirmed the pairing on `peer`.
    pub(crate) fn pairing_peer_confirmed(&self, peer: &str, session_id: u64) {
        let _sessions = self.inner.sessions.lock();
        if let Some(entry) = self.inner.link.pairings.lock().get_mut(peer)
            && entry.session_id == session_id
        {
            entry.peer_confirmed = true;
        }
    }

    /// The pairing on `peer` stored the other phone's card: it is done.
    /// Its job done, pairing mode ends (§B14.4).
    pub(crate) fn pairing_completed(&self, peer: &str, session_id: u64) {
        {
            let _sessions = self.inner.sessions.lock();
            let mut pairings = self.inner.link.pairings.lock();
            if pairings
                .get(peer)
                .is_some_and(|e| e.session_id == session_id)
            {
                pairings.remove(peer);
            }
        }
        self.leave_pairing_mode();
    }

    /// A pairing handshake or link ended before the other phone's card was
    /// stored. At [`MAX_UNFINISHED_PAIRINGS`] since pairing mode was turned
    /// on, the phone leaves pairing mode (counted).
    pub(crate) fn pairing_unfinished(&self) {
        let failures = self
            .inner
            .link
            .pairing_failures
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if failures >= MAX_UNFINISHED_PAIRINGS && self.leave_pairing_mode() {
            tracing::warn!(
                failures,
                "too many unfinished pairings; leaving pairing mode"
            );
            self.inner.link.counters.count_pairing_exhausted();
        }
    }

    /// Open pairing links waiting for the people to compare codes (or,
    /// both confirmed, for the other phone's card), by peer.
    pub fn pending_pairings(&self) -> Vec<PendingPairing> {
        let mut out: Vec<PendingPairing> = self
            .inner
            .link
            .pairings
            .lock()
            .iter()
            .map(|(peer, e)| PendingPairing {
                peer: peer.clone(),
                code: e.code.clone(),
                confirmed: e.confirmed,
                peer_confirmed: e.peer_confirmed,
            })
            .collect();
        out.sort_by(|a, b| a.peer.cmp(&b.peer));
        out
    }

    /// This phone's person compared the codes and they match. Once the
    /// other phone's person confirmed too, the phones exchange identities
    /// and cards; the other phone's card then replaces any card or removal
    /// stored for its inbox (§B14.4). Watch `contacts()` for it.
    pub fn confirm_pairing(&self, peer: &str) -> Result<(), MeshError> {
        let sessions = self.inner.sessions.lock();
        let mut pairings = self.inner.link.pairings.lock();
        let not_found = || MeshError::NotFound(format!("no pairing on {peer}"));
        let entry = pairings.get_mut(peer).ok_or_else(not_found)?;
        let handle = sessions
            .get(peer)
            .filter(|h| h.id == entry.session_id)
            .ok_or_else(not_found)?;
        entry.confirmed = true;
        let _ = handle.tx.send(Inbound::Pairing { confirm: true });
        Ok(())
    }

    /// The codes differ (or the person declined): forget the pairing and
    /// close its link.
    pub fn reject_pairing(&self, peer: &str) {
        let sessions = self.inner.sessions.lock();
        let Some(entry) = self.inner.link.pairings.lock().remove(peer) else {
            return;
        };
        if let Some(handle) = sessions.get(peer).filter(|h| h.id == entry.session_id) {
            let _ = handle.tx.send(Inbound::Pairing { confirm: false });
        }
    }

    /// This phone's own card, or `None` before `set_account_key`.
    pub(crate) fn own_contact_card(&self) -> Option<ContactCard> {
        let keys = self.mesh_keys()?;
        Some(ContactCard {
            inbox_id: keys.inbox_id.clone(),
            noise_static_pub: keys.noise_public.to_vec(),
            discovery_key: keys.discovery_key.to_vec(),
            generation: keys.generation,
        })
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn own_contact_card_for_test(&self) -> Option<ContactCard> {
        self.own_contact_card()
    }

    /// Store `card` as a confirmed pairing would.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn add_contact_for_test(&self, card: ContactCard) {
        self.store_contact_card(&card, true)
            .expect("contact card stored");
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn set_clock_offset_for_test(&self, secs: i64) {
        self.inner
            .link
            .clock_offset_secs
            .store(secs, Ordering::Relaxed);
        self.inner.link.bump_contacts_version();
    }

    /// Set the stored generation and re-derive (as a restore re-derives 0).
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn set_discovery_generation_for_test(&self, generation: u32) -> Result<(), MeshError> {
        let prk = self.inner.link.prk.lock();
        let prk = prk.as_ref().ok_or(MeshError::NoAccountKey)?;
        let inbox_id = self.local_inbox()?.ok_or(MeshError::NotRegistered)?;
        self.inner
            .store
            .lock()
            .set_discovery_generation(generation)?;
        *self.inner.link.keys.lock() = Some(Arc::new(MeshKeys::derive(prk, &inbox_id, generation)));
        self.inner.link.bump_contacts_version();
        Ok(())
    }

    pub(crate) fn frame_tap(&self) -> Option<Arc<dyn MeshTransport>> {
        self.inner.frame_tap.lock().clone()
    }

    /// Send `body` on `peer`'s link (sealed once the link is open).
    /// Returns whether it went out.
    pub(crate) fn link_send(&self, peer: &str, body: Body) -> bool {
        let link = self.inner.sessions.lock().get(peer).map(|h| h.link.clone());
        match link {
            Some(link) => link.send(body),
            None => {
                // The relay engine's unit tests link peers without sessions.
                #[cfg(test)]
                if let Some(transport) =
                    self.inner.sync.lock().as_ref().map(|c| c.transport.clone())
                {
                    transport.send(&peer.to_string(), crate::sync::frames::encode(body));
                    return true;
                }
                false
            }
        }
    }

    /// Deliver `frame` to `peer`'s session as if it had just been decrypted
    /// there. Before the link opens it waits for the handshake; with no
    /// session, a test-only cleartext session is started for it.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn inject_plain_for_test(&self, peer: &str, frame: Vec<u8>) {
        let tx = {
            let sync = self.inner.sync.lock();
            let Some(config) = sync.as_ref() else { return };
            let mut sessions = self.inner.sessions.lock();
            sessions
                .entry(peer.to_string())
                .or_insert_with(|| {
                    config.spawn_session(
                        self,
                        peer,
                        LinkSetup {
                            role: LinkRole::Accept,
                            plain: true,
                            implicit: false,
                        },
                    )
                })
                .tx
                .clone()
        };
        let _ = tx.send(Inbound::Plain(frame));
    }

    /// Like `on_peer_connected`, but a test-only cleartext link: the
    /// session says Hello at once, as sessions did before Noise.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn connect_plain_for_test(&self, peer: &str) {
        let sync = self.inner.sync.lock();
        let Some(config) = sync.as_ref() else { return };
        let handle = config.spawn_session(
            self,
            peer,
            LinkSetup {
                role: LinkRole::Accept,
                plain: true,
                implicit: false,
            },
        );
        let mut sessions = self.inner.sessions.lock();
        let old = sessions.insert(peer.to_string(), handle);
        self.forget_peer(peer);
        drop(sessions);
        drop(sync);
        drop(old);
    }

    /// Every frame sessions started from now on send also goes to `tap`,
    /// before sealing.
    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn set_frame_tap_for_test(&self, tap: Option<Arc<dyn MeshTransport>>) {
        *self.inner.frame_tap.lock() = tap;
    }

    #[cfg(any(test, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn send_frame_for_test(&self, peer: &str, body: Body) -> bool {
        self.link_send(peer, body)
    }
}

/// The node answers for its accepting handshakes (§B14.2): from memory,
/// without the store, so every dialer is answered alike and quickly.
impl ResponderContext for MeshNode {
    fn window(&self) -> u64 {
        window_at(self.unix_now())
    }

    fn is_allowed_dialer(&self, dialer_static: &[u8; 32]) -> bool {
        let dialers = self.inner.link.dialers.read();
        dialers.no_contacts || dialers.live.contains(dialer_static)
    }

    fn replay_cache(&self) -> &ReplayCache {
        &self.inner.link.replay
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::{FLAG_PAIRING, FLAG_RELAY, service_data};

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    /// Ten seconds into window 1 966 000.
    const NOW: u64 = 1_966_000 * WINDOW_SECS + 10;

    fn keyed(inbox: &str, secret: u8) -> MeshNode {
        let node = MeshNode::in_memory().unwrap();
        node.inner.store.lock().set_local_inbox(inbox).unwrap();
        node.set_account_key(&[secret; 32]).unwrap();
        node
    }

    fn token_of(node: &MeshNode, window: u64) -> Token {
        node.mesh_keys().unwrap().own_token(window)
    }

    #[test]
    fn set_account_key_needs_a_registered_node_and_32_bytes() {
        let node = MeshNode::in_memory().unwrap();
        assert!(matches!(
            node.set_account_key(&[1; 32]),
            Err(MeshError::NotRegistered)
        ));
        node.inner.store.lock().set_local_inbox(A).unwrap();
        assert!(matches!(
            node.set_account_key(&[1; 31]),
            Err(MeshError::InvalidRequest(_))
        ));
        assert!(!node.has_account_key());
        assert!(matches!(
            node.advert_state(NOW),
            Err(MeshError::NoAccountKey)
        ));
        let info = node.set_account_key(&[1; 32]).unwrap();
        assert_eq!(info.generation, 0);
        assert_eq!(
            info.noise_static_pub,
            node.mesh_keys().unwrap().noise_public
        );
        assert!(node.has_account_key());
    }

    /// Our own token from a neighbouring window (skew, or another
    /// installation of our inbox) is ours, not a stranger's.
    #[test]
    fn our_own_token_one_window_either_side_is_own() {
        let a = keyed(A, 1);
        for (offset, own) in [(-2i64, false), (-1, true), (0, true), (1, true), (2, false)] {
            let window = (1_966_000 + offset) as u64;
            let m = a
                .classify_advert(&service_data(0, &token_of(&a, window)), NOW)
                .unwrap();
            assert_eq!(m == AdvertMatch::Own, own, "window offset {offset}: {m:?}");
        }
    }

    /// A card naming our own inbox or our own static key is never stored.
    #[test]
    fn a_card_for_this_phone_itself_is_refused() {
        let (a, b) = (keyed(A, 1), keyed(B, 2));
        let own = a.own_contact_card().unwrap();
        let mut foreign_static = own.clone();
        foreign_static.noise_static_pub = b.own_contact_card().unwrap().noise_static_pub;
        let mut foreign_inbox = own.clone();
        foreign_inbox.inbox_id = C.to_string();
        for card in [own, foreign_static, foreign_inbox] {
            assert!(matches!(
                a.store_contact_card(&card, true),
                Err(MeshError::InvalidRequest(_))
            ));
        }
        assert!(a.contacts().unwrap().is_empty());
    }

    /// §B14.2: a contact matches one window either side (skew up to 15 min),
    /// not two; a stranger never matches.
    #[test]
    fn contact_tokens_match_one_window_either_side() {
        let (a, b) = (keyed(A, 1), keyed(B, 2));
        a.store_contact_card(&b.own_contact_card().unwrap(), false)
            .unwrap();
        for (offset, is_contact) in [(-2i64, false), (-1, true), (0, true), (1, true), (2, false)] {
            let window = (1_966_000 + offset) as u64;
            let seen = service_data(0, &token_of(&b, window));
            let m = a.classify_advert(&seen, NOW).unwrap();
            assert_eq!(
                matches!(m, AdvertMatch::Contact { ref inbox_id, .. } if inbox_id == B),
                is_contact,
                "window offset {offset}: {m:?}"
            );
        }
        let stranger = keyed(C, 3);
        let seen = service_data(FLAG_RELAY, &stranger.own_advert_token(NOW).unwrap());
        assert!(matches!(
            a.classify_advert(&seen, NOW).unwrap(),
            AdvertMatch::Stranger {
                relay_offered: true,
                ..
            }
        ));
        let seen = service_data(0, &stranger.own_advert_token(NOW).unwrap());
        assert!(matches!(
            a.classify_advert(&seen, NOW).unwrap(),
            AdvertMatch::Stranger {
                relay_offered: false,
                ..
            }
        ));
    }

    /// Review focus: a token seen one second before a window boundary still
    /// names the contact one second after it (the radio may classify late);
    /// two windows on it does not.
    #[test]
    fn a_token_seen_before_a_window_boundary_still_matches_after_it() {
        let (a, b) = (keyed(A, 1), keyed(B, 2));
        a.store_contact_card(&b.own_contact_card().unwrap(), false)
            .unwrap();
        let before = 1_966_001 * WINDOW_SECS - 1;
        let seen = service_data(0, &b.own_advert_token(before).unwrap());
        assert!(matches!(
            a.classify_advert(&seen, before + 2).unwrap(),
            AdvertMatch::Contact { .. }
        ));
        assert!(matches!(
            a.classify_advert(&seen, before + 1 + 2 * WINDOW_SECS)
                .unwrap(),
            AdvertMatch::Stranger { .. }
        ));
    }

    #[test]
    fn own_pairing_and_invalid_adverts() {
        let (a, b) = (keyed(A, 1), keyed(B, 2));
        let own = a.advert_state(NOW).unwrap().service_data;
        assert_eq!(a.classify_advert(&own, NOW).unwrap(), AdvertMatch::Own);
        assert_eq!(
            a.classify_advert(&[1; 10], NOW).unwrap(),
            AdvertMatch::Invalid
        );
        let pairing = service_data(FLAG_PAIRING, &b.own_advert_token(NOW).unwrap());
        assert!(
            matches!(
                a.classify_advert(&pairing, NOW).unwrap(),
                AdvertMatch::Stranger { .. }
            ),
            "a pairing advert is a stranger while we are not pairing"
        );
        a.set_pairing_mode(true);
        assert!(matches!(
            a.classify_advert(&pairing, NOW).unwrap(),
            AdvertMatch::Pairing { .. }
        ));
        assert_eq!(a.advert_state(NOW).unwrap().service_data[1], FLAG_PAIRING);
    }

    #[test]
    fn the_lower_token_dials_first() {
        let (a, b) = (keyed(A, 1), keyed(B, 2));
        let (ta, tb) = (
            a.own_advert_token(NOW).unwrap(),
            b.own_advert_token(NOW).unwrap(),
        );
        let a_first = match a.classify_advert(&service_data(0, &tb), NOW).unwrap() {
            AdvertMatch::Stranger { dial_first, .. } => dial_first,
            other => panic!("{other:?}"),
        };
        let b_first = match b.classify_advert(&service_data(0, &ta), NOW).unwrap() {
            AdvertMatch::Stranger { dial_first, .. } => dial_first,
            other => panic!("{other:?}"),
        };
        assert_eq!(a_first, ta < tb);
        assert_ne!(a_first, b_first, "exactly one side dials first");
    }

    /// Spec §10 "discovery reset" (node side): the phone advertises only
    /// the new token; a contact holding the old card no longer recognises
    /// it until it gets the new card.
    #[test]
    fn a_reset_changes_the_advert_but_not_the_static_key() {
        let (a, b) = (keyed(A, 1), keyed(B, 2));
        a.store_contact_card(&b.own_contact_card().unwrap(), false)
            .unwrap();
        let (old_token, old_static) = (
            b.own_advert_token(NOW).unwrap(),
            b.own_contact_card().unwrap().noise_static_pub,
        );
        let version = b.advert_state(NOW).unwrap().contacts_version;
        assert_eq!(b.reset_discovery_key().unwrap(), 1);
        assert_eq!(b.discovery_generation().unwrap(), 1);
        assert_eq!(b.mesh_stats().discovery_resets, 1);
        let state = b.advert_state(NOW).unwrap();
        assert_ne!(
            state.own_token, old_token,
            "the old token is no longer advertised"
        );
        assert_ne!(state.contacts_version, version);
        let card = b.own_contact_card().unwrap();
        assert_eq!(
            (card.generation, card.noise_static_pub.clone()),
            (1, old_static)
        );
        let seen = service_data(0, &state.own_token);
        assert!(matches!(
            a.classify_advert(&seen, NOW).unwrap(),
            AdvertMatch::Stranger { .. }
        ));
        assert_eq!(
            a.store_contact_card(&card, false).unwrap(),
            ContactUpdate::Updated
        );
        assert!(matches!(
            a.classify_advert(&seen, NOW).unwrap(),
            AdvertMatch::Contact { .. }
        ));
    }

    #[test]
    fn advert_state_lists_three_windows_per_live_contact() {
        let (a, b, c) = (keyed(A, 1), keyed(B, 2), keyed(C, 3));
        a.store_contact_card(&b.own_contact_card().unwrap(), false)
            .unwrap();
        a.store_contact_card(&c.own_contact_card().unwrap(), false)
            .unwrap();
        assert!(a.remove_contact(C).unwrap());
        let state = a.advert_state(NOW).unwrap();
        assert_eq!(state.window, 1_966_000);
        assert_eq!(state.next_window_at, 1_966_001 * WINDOW_SECS);
        let b_tokens: Vec<Token> = (1_965_999..=1_966_001).map(|w| token_of(&b, w)).collect();
        assert_eq!(
            state.contact_tokens,
            b_tokens
                .into_iter()
                .map(|t| (t, B.to_string()))
                .collect::<Vec<_>>()
        );
        assert_eq!(a.contacts().unwrap().len(), 1);
    }
}
