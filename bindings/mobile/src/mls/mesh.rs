//! xmtp-mesh: serverless XMTP transport for mobile.
//!
//! Platform-neutral uniffi surface. A radio (BLE on Android today, iOS later)
//! implements `FfiMeshTransport` and feeds bytes into `FfiMeshNode`. All
//! protocol logic lives in the `xmtp_mesh` crate.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Weak};

use bytes::Bytes;
use http::{request, uri::PathAndQuery};
use parking_lot::Mutex;
use tokio::sync::broadcast::error::RecvError;
use xmtp_api_d14n::ClientBundle;
use xmtp_mesh::{
    AdvertMatch, AdvertState, ClientGroupMembership, ClientHelloSigner, ClientRelayExporter,
    Contact, DialIntent, LinkRole, MAX_FRAME_LEN, MeshError, MeshNode, MeshStats, MeshTransport,
    NodeEvent, PeerId, RelayStats, ResyncOutcome, VerifiedPeer,
};
use xmtp_mls::client::ClientError;
use xmtp_mls::identity::IdentityError;
use xmtp_proto::api::{ApiClientError, Client, IsConnectedCheck, ToBoxedClient};
use xmtp_proto::xmtp::identity::api::v1::get_identity_updates_response::IdentityUpdateLog;

use super::{FfiSignatureRequest, FfiXmtpClient, XmtpApiClient};
use crate::FfiError;
use crate::logger::init_logger;

/// A mesh node: the in-process stand-in for XMTP's servers.
#[derive(uniffi::Object)]
pub struct FfiMeshNode {
    node: MeshNode,
    key: Option<[u8; 32]>,
}

// `MeshNode` does not implement `Debug`, so this is written by hand rather
// than derived. Only needed so `Result<Arc<FfiMeshNode>, _>::unwrap_err()`
// type-checks in tests; never prints key material.
impl std::fmt::Debug for FfiMeshNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiMeshNode")
            .field("key", &self.key.map(|_| "<redacted>"))
            .finish()
    }
}

/// One node per database file per process. `connect_to_mesh` (the API client
/// libxmtp talks to) and the radio (`open_mesh_node`) must share it. Keyed by
/// the canonical path (see `canonicalize_db_path`) so that an absolute path,
/// a relative or `..`-containing spelling, and a symlink to the same file all
/// resolve to one entry. Holds only `Weak` references: once every `Arc`
/// returned to a caller is dropped, the node is torn down rather than leaked,
/// and the next `open_mesh_node` for that path opens a fresh one.
static NODES: LazyLock<Mutex<HashMap<String, Weak<FfiMeshNode>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) fn mesh_error(e: MeshError) -> FfiError {
    FfiError::generic(format!("mesh: {e}"))
}

fn parse_key(key: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, FfiError> {
    key.map(|k| {
        <[u8; 32]>::try_from(k.as_slice())
            .map_err(|_| FfiError::generic("mesh encryption key must be 32 bytes"))
    })
    .transpose()
}

/// Resolve `path` to a canonical, absolute string so that different spellings
/// of the same file (relative vs. absolute, a `..` component, a symlink) map
/// to the same registry key. If the file already exists, canonicalize it
/// directly (this also resolves symlinks on the file itself). Otherwise (the
/// common case: `MeshNode::open` creates the sqlite file) canonicalize the
/// parent directory, which must already exist, and join the file name.
fn canonicalize_db_path(path: &str) -> Result<String, FfiError> {
    let p = std::path::Path::new(path);
    let canonical = if p.exists() {
        std::fs::canonicalize(p)
            .map_err(|e| FfiError::generic(format!("mesh: cannot resolve db_path {path:?}: {e}")))?
    } else {
        let file_name = p
            .file_name()
            .ok_or_else(|| FfiError::generic(format!("mesh: db_path {path:?} has no file name")))?;
        let parent = match p.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => std::path::Path::new("."),
        };
        let canonical_parent = std::fs::canonicalize(parent).map_err(|e| {
            FfiError::generic(format!(
                "mesh: cannot resolve db_path {path:?}: parent directory does not exist: {e}"
            ))
        })?;
        canonical_parent.join(file_name)
    };
    Ok(canonical.to_string_lossy().into_owned())
}

/// Open (or return the already-open) mesh node stored at `db_path`.
/// `encryption_key` is the 32-byte SQLCipher key. `None` means an unencrypted store (tests only).
#[uniffi::export]
pub fn open_mesh_node(
    db_path: String,
    encryption_key: Option<Vec<u8>>,
) -> Result<Arc<FfiMeshNode>, FfiError> {
    init_logger();
    let key = parse_key(encryption_key)?;
    let canonical = canonicalize_db_path(&db_path)?;
    let mut nodes = NODES.lock();
    // Opportunistically drop entries whose node no longer has any owner.
    nodes.retain(|_, existing| existing.strong_count() > 0);
    if let Some(existing) = nodes.get(&canonical).and_then(Weak::upgrade) {
        if existing.key != key {
            return Err(FfiError::generic(
                "mesh node already open at this path with a different key",
            ));
        }
        return Ok(existing);
    }
    let node = MeshNode::open(&canonical, key).map_err(mesh_error)?;
    let ffi = Arc::new(FfiMeshNode { node, key });
    nodes.insert(canonical, Arc::downgrade(&ffi));
    Ok(ffi)
}

/// An XMTP API `Client` backed by a mesh node, keeping the node's `Arc`
/// (and therefore its `NODES` registry entry) alive for exactly as long as
/// the API client built from it lives. Without this, `connect_to_mesh`
/// dropping its local `Arc<FfiMeshNode>` on return would let a Weak-backed
/// registry entry die immediately after `connect_to_mesh` returns in the
/// normal client-only flow (no separate `open_mesh_node` caller keeping it
/// alive), so a later `open_mesh_node` call (e.g. by the radio, for
/// `start_sync`) would open a second, unrelated `MeshNode` on the same
/// SQLite file: the client talks to one node, the radio syncs another, and
/// sync silently does nothing.
struct MeshClient(Arc<FfiMeshNode>);

#[xmtp_common::async_trait]
impl Client for MeshClient {
    type Error = <MeshNode as Client>::Error;
    type Stream = <MeshNode as Client>::Stream;

    async fn request(
        &self,
        request: request::Builder,
        path: PathAndQuery,
        body: Bytes,
    ) -> Result<http::Response<Bytes>, ApiClientError<Self::Error>> {
        self.0.node.request(request, path, body).await
    }

    async fn stream(
        &self,
        request: request::Builder,
        path: PathAndQuery,
        body: Bytes,
    ) -> Result<http::Response<Self::Stream>, ApiClientError<Self::Error>> {
        self.0.node.stream(request, path, body).await
    }

    fn fake_stream(&self) -> http::Response<Self::Stream> {
        self.0.node.fake_stream()
    }
}

#[xmtp_common::async_trait]
impl IsConnectedCheck for MeshClient {
    async fn is_connected(&self) -> bool {
        self.0.node.is_connected().await
    }
}

fn api_client_for_node(node: Arc<FfiMeshNode>) -> Arc<XmtpApiClient> {
    Arc::new(XmtpApiClient(ClientBundle::v3(MeshClient(node).arced())))
}

/// The mesh counterpart of `connect_to_backend`: an API client served by the
/// local mesh node at `db_path`. Never opens a network connection.
#[uniffi::export]
pub fn connect_to_mesh(
    db_path: String,
    encryption_key: Option<Vec<u8>>,
) -> Result<Arc<XmtpApiClient>, FfiError> {
    let node = open_mesh_node(db_path, encryption_key)?;
    Ok(api_client_for_node(node))
}

/// Copies `inbox_id`'s identity log from the mesh node at `from_db_path` into
/// the node at `to_db_path` (created if missing), so the next installation of
/// that inbox extends the log its peers already hold instead of re-creating
/// the inbox (reset; DESIGN.md §B10.2). Both nodes use
/// `encryption_key`, the client's database key. The target never becomes
/// bound to an installation by this. Errors, touching nothing, when there is
/// no database at `from_db_path` or it does not open with the key.
///
/// Returns how many identity updates the target now holds for the inbox.
#[uniffi::export(async_runtime = "tokio")]
pub async fn carry_mesh_identity_log(
    from_db_path: String,
    to_db_path: String,
    encryption_key: Option<Vec<u8>>,
    inbox_id: String,
) -> Result<u64, FfiError> {
    init_logger();
    if !std::path::Path::new(&from_db_path).exists() {
        return Err(FfiError::generic(format!(
            "mesh: no node database at {from_db_path:?} to carry from"
        )));
    }
    // Through the registry: the old node may still be open (its client is
    // alive until JS drops it), and a second connection must not be opened.
    let from = open_mesh_node(from_db_path, encryption_key.clone())?;
    let log = from.node.identity_log(&inbox_id).map_err(mesh_error)?;
    drop(from);
    let to = match open_mesh_node(to_db_path.clone(), encryption_key) {
        Ok(to) => to,
        Err(e) => {
            // Two different failures share this `Err`. A bad file (stale or
            // corrupt: `MeshNode::open` creates the file before migrations
            // can fail on it) means nothing else can be using it, so it must
            // not survive. The registry's "already open with a different
            // key" guard (`open_mesh_node`, `:108-111`) means another
            // in-process connection still holds this exact file live; only
            // that guard returns without ever calling `MeshNode::open`, so
            // deleting the file in that case would pull it out from under
            // that live connection instead of fixing anything. Only the
            // former is discarded.
            if !e.to_string().contains("already open") {
                discard_target(&to_db_path);
            }
            return Err(e);
        }
    };
    import_or_discard_target(to, &to_db_path, &inbox_id, log).await
}

/// Removes whatever `carry_mesh_identity_log` may have left at `to_db_path`
/// after a failed attempt: a partial file must not survive to fork again at
/// the next sequence id. Best-effort: a failed delete here is not itself
/// fatal to the carry's own error, and a stray file is replaced (not
/// appended to) the next time this path is opened for writing. Callers must
/// only reach this when the target file itself is the problem, never when
/// it is still open elsewhere in-process (see `carry_mesh_identity_log`).
fn discard_target(to_db_path: &str) {
    let _ = std::fs::remove_file(to_db_path);
}

/// `MeshNode::import_identity_log` does not roll back a partial ingestion
/// on a gap or a fork: it can have already
/// written a prefix of `log` before returning `Err`. A partial log would
/// fork again at the next sequence id, so on `Err` the freshly opened target
/// file is discarded instead: the caller (Android) then falls back to an
/// empty node, as it does when there was nothing to carry at all.
async fn import_or_discard_target(
    to: Arc<FfiMeshNode>,
    to_db_path: &str,
    inbox_id: &str,
    log: Vec<IdentityUpdateLog>,
) -> Result<u64, FfiError> {
    match to.node.import_identity_log(inbox_id, log).await {
        Ok(held) => Ok(held as u64),
        Err(e) => {
            drop(to);
            discard_target(to_db_path);
            Err(mesh_error(e))
        }
    }
}

/// Test-only twin of `connect_to_mesh` that also hands back a `Weak` witness
/// of the node, without itself holding a strong `Arc` (which would keep the
/// node alive on its own and defeat the point of the test). Used to prove
/// that the returned client — not the test — is what keeps the node alive.
#[cfg(test)]
fn connect_to_mesh_for_test(
    db_path: String,
    encryption_key: Option<Vec<u8>>,
) -> Result<(Arc<XmtpApiClient>, Weak<FfiMeshNode>), FfiError> {
    let node = open_mesh_node(db_path, encryption_key)?;
    let weak = Arc::downgrade(&node);
    Ok((api_client_for_node(node), weak))
}

/// Largest whole frame the mesh node sends or accepts. A radio's reassembly
/// limit must equal this (Android: `LinkLimits.MAX_FRAME_BYTES`).
#[uniffi::export]
pub fn mesh_max_frame_len() -> u32 {
    MAX_FRAME_LEN as u32
}

// `mesh_max_frame_len` narrows to u32; fail the build if that ever truncates.
const _: () = assert!(MAX_FRAME_LEN <= u32::MAX as usize);

/// A connected peer whose installation proved membership of its inbox:
/// presence for the UI's "nearby". `peer_id` is connection-scoped (radio-assigned).
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiVerifiedPeer {
    pub peer_id: String,
    pub inbox_id: String,
    pub installation_id: Vec<u8>,
}

impl From<VerifiedPeer> for FfiVerifiedPeer {
    fn from(p: VerifiedPeer) -> Self {
        Self {
            peer_id: p.peer,
            inbox_id: p.inbox_id,
            installation_id: p.installation,
        }
    }
}

/// How the radio opened a connection (DESIGN.md §B14.2).
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum FfiLinkRole {
    /// We dialed a phone whose advert token belongs to this contact.
    DialContact { inbox_id: String },
    /// We dialed a stranger that offers relay (our relay is on).
    DialRelay,
    /// We dialed a phone in pairing mode (ours is on too).
    DialPairing,
    /// The other phone dialed us.
    Accept,
}

impl From<FfiLinkRole> for LinkRole {
    fn from(role: FfiLinkRole) -> Self {
        match role {
            FfiLinkRole::DialContact { inbox_id } => {
                LinkRole::Dial(DialIntent::Contact { inbox_id })
            }
            FfiLinkRole::DialRelay => LinkRole::Dial(DialIntent::Relay),
            FfiLinkRole::DialPairing => LinkRole::Dial(DialIntent::Pairing),
            FfiLinkRole::Accept => LinkRole::Accept,
        }
    }
}

/// An open pairing link (DESIGN.md §B14.4).
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiPendingPairing {
    pub peer_id: String,
    /// The 6 digits both phones show.
    pub code: String,
    /// This phone's person confirmed.
    pub confirmed: bool,
    /// The other phone's person confirmed.
    pub peer_confirmed: bool,
}

impl From<xmtp_mesh::PendingPairing> for FfiPendingPairing {
    fn from(p: xmtp_mesh::PendingPairing) -> Self {
        Self {
            peer_id: p.peer,
            code: p.code,
            confirmed: p.confirmed,
            peer_confirmed: p.peer_confirmed,
        }
    }
}

/// Public facts about the link keys derived from the account key.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiLinkKeyInfo {
    pub noise_static_pub: Vec<u8>,
    pub generation: u32,
}

/// A contact's token for one window around now (DESIGN.md §B14.2).
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiContactToken {
    pub token: Vec<u8>,
    pub inbox_id: String,
}

/// What the radio advertises and matches for one window (DESIGN.md §B14.2).
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiAdvertState {
    pub window: u64,
    /// Advertise exactly this as the service data: `2 ‖ flags ‖ token`.
    pub service_data: Vec<u8>,
    /// Goes in the link-layer Hello in place of the old short id.
    pub own_token: Vec<u8>,
    /// Every contact's tokens for the previous, current and next window.
    pub contact_tokens: Vec<FfiContactToken>,
    /// Unix second of the next window: restart advertising then.
    pub next_window_at: u64,
    /// Changes whenever the tokens change: re-read the state then.
    pub contacts_version: u64,
}

impl From<AdvertState> for FfiAdvertState {
    fn from(s: AdvertState) -> Self {
        Self {
            window: s.window,
            service_data: s.service_data.to_vec(),
            own_token: s.own_token.to_vec(),
            contact_tokens: s
                .contact_tokens
                .into_iter()
                .map(|(token, inbox_id)| FfiContactToken {
                    token: token.to_vec(),
                    inbox_id,
                })
                .collect(),
            next_window_at: s.next_window_at,
            contacts_version: s.contacts_version,
        }
    }
}

/// What a seen advert is. `dial_first`: our token is lower, so dial now;
/// otherwise dial only as the §B7.2 fallback.
#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum FfiAdvertMatch {
    Invalid,
    Own,
    Contact {
        inbox_id: String,
        dial_first: bool,
    },
    Stranger {
        relay_offered: bool,
        dial_first: bool,
    },
    Pairing {
        dial_first: bool,
    },
}

impl From<AdvertMatch> for FfiAdvertMatch {
    fn from(m: AdvertMatch) -> Self {
        match m {
            AdvertMatch::Invalid => Self::Invalid,
            AdvertMatch::Own => Self::Own,
            AdvertMatch::Contact {
                inbox_id,
                dial_first,
            } => Self::Contact {
                inbox_id,
                dial_first,
            },
            AdvertMatch::Stranger {
                relay_offered,
                dial_first,
            } => Self::Stranger {
                relay_offered,
                dial_first,
            },
            AdvertMatch::Pairing { dial_first } => Self::Pairing { dial_first },
        }
    }
}

/// A stored contact (DESIGN.md §B14.1). Never carries the shared discovery
/// key: the radio and the app need only the token map from `advert_state`.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FfiContact {
    pub inbox_id: String,
    pub generation: u32,
    pub updated_ns: i64,
}

impl From<Contact> for FfiContact {
    fn from(c: Contact) -> Self {
        Self {
            inbox_id: c.inbox_id,
            generation: c.generation,
            updated_ns: c.updated_ns,
        }
    }
}

/// Relay counters since the relay engine started (DESIGN.md §R5.4). A snapshot, not a stream.
#[derive(uniffi::Record, Clone, Debug, Default, PartialEq, Eq)]
pub struct FfiRelayStats {
    pub accepted: u64,
    pub duplicate: u64,
    pub dropped_invalid: u64,
    pub dropped_expired: u64,
    pub dropped_share: u64,
    pub dropped_rate: u64,
    /// Stranger envelopes refused because only contacts' entries were left
    /// to displace (DESIGN.md §R5.4).
    pub dropped_full: u64,
    pub pushed: u64,
    pub originated: u64,
    pub delivered: u64,
    pub delivered_unspooled: u64,
    pub refs_sent: u64,
}

impl From<RelayStats> for FfiRelayStats {
    fn from(s: RelayStats) -> Self {
        Self {
            accepted: s.accepted,
            duplicate: s.duplicate,
            dropped_invalid: s.dropped_invalid,
            dropped_expired: s.dropped_expired,
            dropped_share: s.dropped_share,
            dropped_rate: s.dropped_rate,
            dropped_full: s.dropped_full,
            pushed: s.pushed,
            originated: s.originated,
            delivered: s.delivered,
            delivered_unspooled: s.delivered_unspooled,
            refs_sent: s.refs_sent,
        }
    }
}

/// Signed-sequencing counters (DESIGN.md §B13), private-discovery link
/// counters (§B14.3), and peers refused for an older protocol version,
/// since the node was opened. A snapshot.
#[derive(uniffi::Record, Clone, Debug, Default, PartialEq, Eq)]
pub struct FfiMeshStats {
    pub seq_rows_signed: u64,
    pub seq_rows_verified: u64,
    pub seq_rejected_missing_proof: u64,
    pub seq_rejected_bad_signature: u64,
    pub seq_rejected_wrong_signer: u64,
    pub seq_equivocations: u64,
    pub peers_rejected_version: u64,
    /// Links opened, by kind.
    pub links_contact: u64,
    pub links_relay: u64,
    pub links_pairing: u64,
    /// Noise handshakes that failed or timed out.
    pub handshake_failed: u64,
    /// Links closed for a record that failed authentication, a frame not
    /// allowed on the link type, or a card or Hello that does not match it.
    pub link_frame_rejected: u64,
    pub discovery_resets: u64,
    /// Relay links closed after carrying no useful relay traffic for the
    /// idle bound.
    pub relay_links_idle_closed: u64,
    /// Relay links closed while still in use: at the lifetime cap, or when
    /// relay was switched off.
    pub relay_links_force_closed: u64,
    /// Relay links refused or not dialed because this phone closed the same
    /// radio peer's relay link moments ago (the back-off).
    pub relay_links_backoff_refused: u64,
    /// Times the phone left pairing mode after too many unfinished pairing
    /// handshakes.
    pub pairing_attempts_exhausted: u64,
}

impl From<MeshStats> for FfiMeshStats {
    fn from(s: MeshStats) -> Self {
        Self {
            seq_rows_signed: s.seq_rows_signed,
            seq_rows_verified: s.seq_rows_verified,
            seq_rejected_missing_proof: s.seq_rejected_missing_proof,
            seq_rejected_bad_signature: s.seq_rejected_bad_signature,
            seq_rejected_wrong_signer: s.seq_rejected_wrong_signer,
            seq_equivocations: s.seq_equivocations,
            peers_rejected_version: s.peers_rejected_version,
            links_contact: s.links_contact,
            links_relay: s.links_relay,
            links_pairing: s.links_pairing,
            handshake_failed: s.handshake_failed,
            link_frame_rejected: s.link_frame_rejected,
            discovery_resets: s.discovery_resets,
            relay_links_idle_closed: s.relay_links_idle_closed,
            relay_links_force_closed: s.relay_links_force_closed,
            relay_links_backoff_refused: s.relay_links_backoff_refused,
            pairing_attempts_exhausted: s.pairing_attempts_exhausted,
        }
    }
}

/// Error a foreign mesh callback may return (in Kotlin: throw). The mesh
/// logs it and carries on; it never propagates. Any other exception thrown
/// by foreign code arrives here too, via `UnexpectedUniFFICallbackError`,
/// instead of panicking (which aborts release builds).
#[derive(uniffi::Error, Debug, thiserror::Error)]
pub enum FfiMeshCallbackError {
    #[error("mesh callback failed: {err}")]
    Failed { err: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for FfiMeshCallbackError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed { err: e.to_string() }
    }
}

/// Implemented by the platform radio. See the `xmtp_mesh::MeshTransport`
/// contract: every `peer_id` names one connection and is never reused; a
/// `disconnect` of a stale id is a no-op.
///
/// Implementations must not block: post the work to the radio's own thread
/// (for example a `HandlerThread`) and return. They should not throw; if
/// they do, the error is logged and ignored. A failed `send` is treated like
/// a frame lost on the link, and the session's own deadlines and resync recover.
#[uniffi::export(with_foreign)]
pub trait FfiMeshTransport: Send + Sync {
    /// Deliver one whole frame over connection `peer_id`. The radio chunks, acks and reassembles.
    fn send(&self, peer_id: String, frame: Vec<u8>) -> Result<(), FfiMeshCallbackError>;
    /// Drop connection `peer_id` (for example, it failed authentication) and
    /// later report `on_peer_lost` for it.
    fn disconnect(&self, peer_id: String) -> Result<(), FfiMeshCallbackError>;
}

/// Presence events. Called on a tokio worker thread, so implementations must
/// not block (hand off to the UI thread and return). They should not throw;
/// if they do, the error is logged and the stream continues.
#[uniffi::export(with_foreign)]
pub trait FfiMeshPresenceCallback: Send + Sync {
    fn on_peer_verified(&self, peer: FfiVerifiedPeer) -> Result<(), FfiMeshCallbackError>;
    fn on_peer_lost(&self, peer_id: String) -> Result<(), FfiMeshCallbackError>;
}

/// Handle for [`FfiMeshNode::stream_presence`]. Ends the stream on `end()` or
/// drop. Callers should call `end()` (or `close()` in Kotlin) when done rather
/// than rely on garbage collection: until then the stream's task keeps the
/// node's state alive and keeps calling the callback.
#[derive(uniffi::Object)]
pub struct FfiMeshPresenceStream {
    task: tokio::task::AbortHandle,
}

#[uniffi::export]
impl FfiMeshPresenceStream {
    pub fn end(&self) {
        self.task.abort();
    }
}

impl Drop for FfiMeshPresenceStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// What the client did after its mesh node replaced an inbox's identity log
/// (restore convergence DESIGN.md §C4.3–§C4.4).
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum FfiMeshResyncOutcome {
    /// The client reloaded the winning log; nothing to do.
    Reloaded,
    /// The client's own inbox, without this installation: call
    /// `FfiXmtpClient::mesh_rebase_signature_request`, sign it with the
    /// wallet, and apply it.
    RebaseNeeded,
    /// The client's own inbox, whose winning log is full: no re-base. Show
    /// "Too many devices on this identity".
    TooManyInstallations,
}

impl From<ResyncOutcome> for FfiMeshResyncOutcome {
    fn from(outcome: ResyncOutcome) -> Self {
        match outcome {
            ResyncOutcome::Reloaded => Self::Reloaded,
            ResyncOutcome::RebaseNeeded => Self::RebaseNeeded,
            ResyncOutcome::TooManyInstallations => Self::TooManyInstallations,
        }
    }
}

/// Identity resyncs of a syncing node. Called on a tokio worker thread:
/// implementations must not block, and should not throw (a thrown error is
/// logged and the stream continues).
#[uniffi::export(with_foreign)]
pub trait FfiMeshIdentityCallback: Send + Sync {
    fn on_identity_resynced(
        &self,
        inbox_id: String,
        outcome: FfiMeshResyncOutcome,
    ) -> Result<(), FfiMeshCallbackError>;
}

/// Handle for [`FfiMeshNode::stream_identity`]. Ends the stream on `end()` or drop.
#[derive(uniffi::Object)]
pub struct FfiMeshIdentityStream {
    task: tokio::task::AbortHandle,
}

#[uniffi::export]
impl FfiMeshIdentityStream {
    pub fn end(&self) {
        self.task.abort();
    }
}

impl Drop for FfiMeshIdentityStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// In the error `mesh_rebase_signature_request` returns when the winning log
/// is full. The Android library matches it (MeshIdentityEvents.kt).
pub const MESH_TOO_MANY_INSTALLATIONS: &str = "mesh: too many installations";

fn rebase_error(e: ClientError) -> FfiError {
    match e {
        ClientError::Identity(IdentityError::TooManyInstallations { count, max, .. }) => {
            FfiError::generic(format!(
                "{MESH_TOO_MANY_INSTALLATIONS}: the inbox already has {count}/{max}"
            ))
        }
        other => other.into(),
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiXmtpClient {
    /// Restore convergence (DESIGN.md §C4.4): after the mesh node replaced this inbox's
    /// log with one that does not list this installation, a request to add it
    /// (pre-signed with the installation key). Add the wallet's signature and
    /// apply it with `apply_signature_request`, as for
    /// `revoke_all_other_installations_signature_request`. `None` when the
    /// log already lists this installation. When the log is full, an error
    /// containing [`MESH_TOO_MANY_INSTALLATIONS`].
    pub async fn mesh_rebase_signature_request(
        &self,
    ) -> Result<Option<Arc<FfiSignatureRequest>>, FfiError> {
        let request = self
            .inner_client
            .identity_updates()
            .rebase_installation_signature_request()
            .await
            .map_err(rebase_error)?;
        Ok(request.map(|request| {
            Arc::new(FfiSignatureRequest {
                inner: Arc::new(tokio::sync::Mutex::new(request)),
                scw_verifier: self.inner_client.scw_verifier().clone(),
            })
        }))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiMeshNode {
    /// Derive the link keys (DESIGN.md §B14.1) from the account's
    /// secp256k1 private key (32 bytes, the key the recovery phrase
    /// restores). Call after registration and before `start_sync`, once per
    /// process start. The node keeps only derived keys, in memory.
    pub fn set_account_key(&self, account_key: Vec<u8>) -> Result<FfiLinkKeyInfo, FfiError> {
        let info = self
            .node
            .set_account_key(&account_key)
            .map_err(mesh_error)?;
        Ok(FfiLinkKeyInfo {
            noise_static_pub: info.noise_static_pub.to_vec(),
            generation: info.generation,
        })
    }

    /// Accept (and advertise) pairing links (DESIGN.md §B14.4). The node
    /// leaves pairing mode by itself after too many unfinished pairings.
    pub fn set_pairing_mode(&self, on: bool) {
        self.node.set_pairing_mode(on);
    }

    pub fn pairing_mode(&self) -> bool {
        self.node.pairing_mode()
    }

    /// Open pairing links and the code each shows (DESIGN.md §B14.4).
    pub fn pending_pairings(&self) -> Vec<FfiPendingPairing> {
        self.node
            .pending_pairings()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// The person compared the codes and they match. Nothing identifying
    /// crosses until both people confirmed; then the phones exchange
    /// identities, and the other phone appears as a contact.
    pub fn confirm_pairing(&self, peer_id: String) -> Result<(), FfiError> {
        self.node.confirm_pairing(&peer_id).map_err(mesh_error)
    }

    /// The codes differ, or the person declined: close the pairing link.
    pub fn reject_pairing(&self, peer_id: String) {
        self.node.reject_pairing(&peer_id);
    }

    /// Advert and token map for the window of `now_unix_secs` (DESIGN.md
    /// §B14.2). Advertise `service_data`; stop and restart advertising at
    /// `next_window_at`, or sooner if `contacts_version` changes.
    pub fn advert_state(&self, now_unix_secs: u64) -> Result<FfiAdvertState, FfiError> {
        Ok(self
            .node
            .advert_state(now_unix_secs)
            .map_err(mesh_error)?
            .into())
    }

    /// Classify a seen advert's service data (DESIGN.md §B14.2): the dial
    /// decision for one sighting.
    pub fn classify_advert(
        &self,
        service_data: Vec<u8>,
        now_unix_secs: u64,
    ) -> Result<FfiAdvertMatch, FfiError> {
        Ok(self
            .node
            .classify_advert(&service_data, now_unix_secs)
            .map_err(mesh_error)?
            .into())
    }

    /// Advertise under a new discovery key from the next `advert_state`
    /// (DESIGN.md §B14.4): the Settings "Reset discovery key" button.
    /// Returns the new generation.
    pub fn reset_discovery_key(&self) -> Result<u32, FfiError> {
        self.node.reset_discovery_key().map_err(mesh_error)
    }

    /// Live contacts, by inbox id.
    pub fn contacts(&self) -> Result<Vec<FfiContact>, FfiError> {
        Ok(self
            .node
            .contacts()
            .map_err(mesh_error)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Stop recognising and accepting `inbox_id` (DESIGN.md §B14.4). The app
    /// should offer `reset_discovery_key` right after, so the removed
    /// contact stops recognising this phone too.
    pub fn remove_contact(&self, inbox_id: String) -> Result<bool, FfiError> {
        self.node.remove_contact(&inbox_id).map_err(mesh_error)
    }

    /// Start syncing with peers. `client` must be the registered client whose
    /// API is this node: hellos are signed with its installation key
    /// (`ClientHelloSigner`) and group traffic is scoped by its group
    /// membership (`ClientGroupMembership`, DESIGN.md §B5.2 Rule A).
    ///
    /// Async so that it runs inside uniffi's tokio runtime: the node captures
    /// that runtime for all sessions (`MeshError::NoRuntime` otherwise). The
    /// other methods are then callable from any thread.
    ///
    /// Call `set_account_key` first.
    pub async fn start_sync(
        &self,
        client: Arc<FfiXmtpClient>,
        transport: Arc<dyn FfiMeshTransport>,
    ) -> Result<(), FfiError> {
        let rust_client = client.inner_client.as_ref().clone();
        self.node
            .start_sync(
                Arc::new(ClientHelloSigner(rust_client.clone())),
                Arc::new(TransportBridge(transport)),
                Arc::new(ClientGroupMembership(rust_client)),
            )
            .map_err(mesh_error)
    }

    /// Cancel every session and forget the transport; later callbacks are
    /// ignored until the next `start_sync`.
    pub fn stop_sync(&self) {
        self.node.stop_sync();
    }

    /// Start relaying for other phones (DESIGN.md Part R, phase 1). Call after
    /// `start_sync` and before the radio links come up, so every session
    /// advertises relay; calling it later re-links the live sessions that
    /// advertised relay. `client` must be the one passed to `start_sync`.
    pub fn enable_relay(&self, client: Arc<FfiXmtpClient>) -> Result<(), FfiError> {
        let rust_client = client.inner_client.as_ref().clone();
        self.node
            .enable_relay(Arc::new(ClientRelayExporter(rust_client)))
            .map_err(mesh_error)
    }

    /// Stop relaying: no pushes, relay frames ignored, nothing originated. Direct sync is unaffected.
    pub fn disable_relay(&self) {
        self.node.disable_relay();
    }

    pub fn relay_enabled(&self) -> bool {
        self.node.relay_enabled()
    }

    pub fn relay_stats(&self) -> FfiRelayStats {
        self.node.relay_stats().into()
    }

    pub fn mesh_stats(&self) -> FfiMeshStats {
        self.node.mesh_stats().into()
    }

    /// The radio opened a new connection `peer_id` (fresh, never reused) as
    /// `role`. Report the accepting side before the dialer can send.
    pub fn on_peer_connected(&self, peer_id: String, role: FfiLinkRole) {
        self.node.on_peer_connected(&peer_id, role.into());
    }

    /// One whole frame arrived over `peer_id`. Call in arrival order.
    pub fn on_frame(&self, peer_id: String, frame: Vec<u8>) {
        self.node.on_frame(&peer_id, frame);
    }

    /// Connection `peer_id` is gone.
    pub fn on_peer_lost(&self, peer_id: String) {
        self.node.on_peer_lost(&peer_id);
    }

    /// Connections that completed the signed hello, sorted.
    pub fn authenticated_peers(&self) -> Vec<String> {
        self.node.authenticated_peers()
    }

    /// Connections whose installation proved inbox membership, sorted by `peer_id`.
    pub fn verified_peers(&self) -> Vec<FfiVerifiedPeer> {
        self.node
            .verified_peers()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Report the current verified peers, then every change, to `callback`.
    pub async fn stream_presence(
        &self,
        callback: Arc<dyn FfiMeshPresenceCallback>,
    ) -> Arc<FfiMeshPresenceStream> {
        // Subscribe before the first snapshot so no event falls in between.
        let mut events = self.node.subscribe_events();
        let node = self.node.clone();
        let task = tokio::spawn(async move {
            let mut reported = HashSet::new();
            resync_presence(&node, callback.as_ref(), &mut reported);
            loop {
                match events.recv().await {
                    Ok(NodeEvent::PeerVerified {
                        peer,
                        inbox_id,
                        installation,
                    }) => {
                        if reported.insert(peer.clone()) {
                            report_verified(
                                callback.as_ref(),
                                FfiVerifiedPeer {
                                    peer_id: peer,
                                    inbox_id,
                                    installation_id: installation,
                                },
                            );
                        }
                    }
                    Ok(NodeEvent::PeerLost { peer }) => {
                        if reported.remove(&peer) {
                            report_lost(callback.as_ref(), peer);
                        }
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => {
                        resync_presence(&node, callback.as_ref(), &mut reported)
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });
        Arc::new(FfiMeshPresenceStream {
            task: task.abort_handle(),
        })
    }

    /// Report every identity resync of this node (restore convergence) to
    /// `callback`, until the stream ends. Resyncs happen only while syncing:
    /// the node's identity task, started by `start_sync`, drives them.
    pub async fn stream_identity(
        &self,
        callback: Arc<dyn FfiMeshIdentityCallback>,
    ) -> Arc<FfiMeshIdentityStream> {
        let mut events = self.node.subscribe_events();
        let task = tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(NodeEvent::IdentityResynced { inbox_id, outcome }) => {
                        if let Err(e) = callback.on_identity_resynced(inbox_id, outcome.into()) {
                            tracing::warn!(%e, "mesh identity callback failed");
                        }
                    }
                    Ok(_) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => break,
                }
            }
        });
        Arc::new(FfiMeshIdentityStream {
            task: task.abort_handle(),
        })
    }
}

/// Bring `callback` in line with `node.verified_peers()`: report peers that
/// left since the last report, then peers not reported yet.
fn resync_presence(
    node: &MeshNode,
    callback: &dyn FfiMeshPresenceCallback,
    reported: &mut HashSet<PeerId>,
) {
    let now = node.verified_peers();
    let live: HashSet<PeerId> = now.iter().map(|p| p.peer.clone()).collect();
    let gone: Vec<PeerId> = reported.difference(&live).cloned().collect();
    for peer in gone {
        reported.remove(&peer);
        report_lost(callback, peer);
    }
    for peer in now {
        if reported.insert(peer.peer.clone()) {
            report_verified(callback, peer.into());
        }
    }
}

fn report_verified(callback: &dyn FfiMeshPresenceCallback, peer: FfiVerifiedPeer) {
    if let Err(e) = callback.on_peer_verified(peer) {
        tracing::warn!(%e, "mesh presence callback on_peer_verified failed");
    }
}

fn report_lost(callback: &dyn FfiMeshPresenceCallback, peer: PeerId) {
    if let Err(e) = callback.on_peer_lost(peer) {
        tracing::warn!(%e, "mesh presence callback on_peer_lost failed");
    }
}

/// Adapts the foreign radio to the core crate's transport trait.
struct TransportBridge(Arc<dyn FfiMeshTransport>);

impl MeshTransport for TransportBridge {
    // A failed send is treated like a frame lost on the link: the session's
    // deadlines and resync recover, or the radio reports the link lost.
    fn send(&self, peer: &PeerId, frame: Vec<u8>) {
        if let Err(e) = self.0.send(peer.clone(), frame) {
            tracing::warn!(%peer, %e, "mesh transport send failed; frame dropped");
        }
    }

    fn disconnect(&self, peer: &PeerId) {
        if let Err(e) = self.0.disconnect(peer.clone()) {
            tracing::warn!(%peer, %e, "mesh transport disconnect failed");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::mls::is_connected;
    use xmtp_common::tmp_path;

    use crate::identity::FfiIdentifier;
    use crate::inbox_owner::FfiInboxOwner;
    use crate::mls::inbox_owner::FfiWalletInboxOwner;
    use crate::mls::{
        DbOptions, FfiCreateDMOptions, FfiListConversationsOptions, FfiListMessagesOptions,
        FfiXmtpClient, create_client, decode_text,
    };
    use crate::worker::FfiDeviceSyncMode;
    use std::future::Future;
    use std::time::Duration;
    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

    /// Test radio: frames go into a channel that a plain OS thread (not a tokio
    /// worker, like the Android radio's HandlerThread) feeds, in order, into the
    /// other node. `me` is the connection-scoped PeerId under which the other
    /// node knows this one.
    struct ChannelTransport {
        me: String,
        tx: UnboundedSender<(String, Vec<u8>)>,
    }

    impl FfiMeshTransport for ChannelTransport {
        fn send(&self, _peer_id: String, frame: Vec<u8>) -> Result<(), FfiMeshCallbackError> {
            let _ = self.tx.send((self.me.clone(), frame));
            Ok(())
        }
        fn disconnect(&self, _peer_id: String) -> Result<(), FfiMeshCallbackError> {
            Ok(())
        }
    }

    fn pump(target: Arc<FfiMeshNode>, mut rx: UnboundedReceiver<(String, Vec<u8>)>) {
        std::thread::spawn(move || {
            while let Some((from, frame)) = rx.blocking_recv() {
                target.on_frame(from, frame);
            }
        });
    }

    /// Records presence callbacks as "verified <peer> <inbox>" / "lost <peer>".
    #[derive(Default)]
    struct PresenceLog(parking_lot::Mutex<Vec<String>>);

    impl FfiMeshPresenceCallback for PresenceLog {
        fn on_peer_verified(&self, peer: FfiVerifiedPeer) -> Result<(), FfiMeshCallbackError> {
            self.0
                .lock()
                .push(format!("verified {} {}", peer.peer_id, peer.inbox_id));
            Ok(())
        }
        fn on_peer_lost(&self, peer_id: String) -> Result<(), FfiMeshCallbackError> {
            self.0.lock().push(format!("lost {peer_id}"));
            Ok(())
        }
    }

    /// Records identity resyncs as (inbox, outcome).
    #[derive(Default)]
    struct ResyncLog(parking_lot::Mutex<Vec<(String, FfiMeshResyncOutcome)>>);

    impl FfiMeshIdentityCallback for ResyncLog {
        fn on_identity_resynced(
            &self,
            inbox_id: String,
            outcome: FfiMeshResyncOutcome,
        ) -> Result<(), FfiMeshCallbackError> {
            self.0.lock().push((inbox_id, outcome));
            Ok(())
        }
    }

    fn callback_failed() -> FfiMeshCallbackError {
        FfiMeshCallbackError::Failed {
            err: "foreign code threw".into(),
        }
    }

    /// A presence callback that records like `PresenceLog`, then throws.
    #[derive(Default)]
    struct ThrowingPresence(PresenceLog);

    impl FfiMeshPresenceCallback for ThrowingPresence {
        fn on_peer_verified(&self, peer: FfiVerifiedPeer) -> Result<(), FfiMeshCallbackError> {
            self.0.on_peer_verified(peer)?;
            Err(callback_failed())
        }
        fn on_peer_lost(&self, peer_id: String) -> Result<(), FfiMeshCallbackError> {
            self.0.on_peer_lost(peer_id)?;
            Err(callback_failed())
        }
    }

    /// Forwards to `inner`, except that every call for connection `bad`
    /// throws, as a radio whose link just died might.
    struct ThrowingForPeer {
        bad: String,
        inner: ChannelTransport,
    }

    impl FfiMeshTransport for ThrowingForPeer {
        fn send(&self, peer_id: String, frame: Vec<u8>) -> Result<(), FfiMeshCallbackError> {
            if peer_id == self.bad {
                return Err(callback_failed());
            }
            self.inner.send(peer_id, frame)
        }
        fn disconnect(&self, peer_id: String) -> Result<(), FfiMeshCallbackError> {
            if peer_id == self.bad {
                return Err(callback_failed());
            }
            self.inner.disconnect(peer_id)
        }
    }

    async fn eventually<F, Fut>(what: &str, mut check: F)
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while !check().await {
            assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Shared by `unregistered_mesh_client` and `registered_client_at`: a
    /// client for `owner`'s inbox (nonce 1) whose mesh node lives at
    /// `mesh_path` (key 9s), not yet registered.
    async fn client_at(
        mesh_path: &str,
        owner: &FfiWalletInboxOwner,
    ) -> (Arc<FfiXmtpClient>, Arc<FfiMeshNode>) {
        let node = open_mesh_node(mesh_path.to_string(), Some(vec![9u8; 32])).unwrap();
        let api = connect_to_mesh(mesh_path.to_string(), Some(vec![9u8; 32])).unwrap();
        let ident: FfiIdentifier = owner.identifier();
        let inbox_id = ident.inbox_id(1).unwrap();
        let client = create_client(
            api.clone(),
            api,
            DbOptions::new(Some(tmp_path()), None, None, None),
            &inbox_id,
            ident,
            1,
            None,
            Some(FfiDeviceSyncMode::Disabled),
            None,
            None,
        )
        .await
        .unwrap();
        (client, node)
    }

    async fn unregistered_mesh_client()
    -> (Arc<FfiXmtpClient>, Arc<FfiMeshNode>, FfiWalletInboxOwner) {
        let mesh_path = tmp_path();
        let owner = FfiWalletInboxOwner::new();
        let (client, node) = client_at(&mesh_path, &owner).await;
        (client, node, owner)
    }

    /// A registered client for `owner`'s inbox (nonce 1) whose mesh node
    /// lives at `mesh_path` (key 9s), on a fresh libxmtp DB: a new inbox if
    /// that node does not know it, else a new installation of it.
    async fn registered_client_at(
        mesh_path: &str,
        owner: &FfiWalletInboxOwner,
    ) -> (Arc<FfiXmtpClient>, Arc<FfiMeshNode>) {
        let (client, node) = client_at(mesh_path, owner).await;
        let request = client
            .signature_request()
            .expect("a new installation needs the wallet's signature");
        let text = request.signature_text().await.unwrap();
        request
            .add_ecdsa_signature(owner.sign(text).unwrap())
            .await
            .unwrap();
        client.register_identity(request).await.unwrap();
        (client, node)
    }

    async fn registered_mesh_client() -> (Arc<FfiXmtpClient>, Arc<FfiMeshNode>) {
        let mesh_path = tmp_path();
        let owner = FfiWalletInboxOwner::new();
        registered_client_at(&mesh_path, &owner).await
    }

    struct NullTransport;
    impl FfiMeshTransport for NullTransport {
        fn send(&self, _: String, _: Vec<u8>) -> Result<(), FfiMeshCallbackError> {
            Ok(())
        }
        fn disconnect(&self, _: String) -> Result<(), FfiMeshCallbackError> {
            Ok(())
        }
    }

    /// Link keys plus pairing mode: two test nodes with no contact cards can
    /// link over a pairing (Noise XX) link, which syncs like a contact link
    /// once both people confirmed the code ([`confirm_pairings`]).
    fn ready_to_pair(client: &FfiXmtpClient, node: &FfiMeshNode) {
        node.set_account_key(xmtp_mesh::store::sha256(&client.installation_id()))
            .unwrap();
        node.set_pairing_mode(true);
    }

    /// Both phones show the same code for the pairing between `a` (sees
    /// `b_id`) and `b` (sees `a_id`); both people confirm it.
    async fn confirm_pairings(a: &FfiMeshNode, b_id: &str, b: &FfiMeshNode, a_id: &str) {
        let pending = |n: &FfiMeshNode, peer: &str| {
            n.pending_pairings().into_iter().find(|p| p.peer_id == peer)
        };
        eventually("both phones show a code", || async {
            pending(a, b_id).is_some() && pending(b, a_id).is_some()
        })
        .await;
        let (pa, pb) = (pending(a, b_id).unwrap(), pending(b, a_id).unwrap());
        assert_eq!(pa.code, pb.code);
        assert!(!pa.confirmed && !pa.peer_confirmed);
        assert!(
            a.authenticated_peers().is_empty(),
            "nothing before confirmation"
        );
        assert!(a.confirm_pairing("nobody".into()).is_err());
        a.confirm_pairing(b_id.into()).unwrap();
        b.confirm_pairing(a_id.into()).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn start_sync_needs_the_account_key() {
        let (client, node) = registered_mesh_client().await;
        let err = node
            .start_sync(client.clone(), Arc::new(NullTransport))
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains(&xmtp_mesh::MeshError::NoAccountKey.to_string()),
            "{err}"
        );
        let info = node
            .set_account_key(xmtp_mesh::store::sha256(&client.installation_id()))
            .unwrap();
        assert_eq!((info.noise_static_pub.len(), info.generation), (32, 0));
        assert!(node.set_account_key(vec![1; 31]).is_err());
        node.start_sync(client, Arc::new(NullTransport))
            .await
            .unwrap();
        node.stop_sync();
    }

    #[test]
    fn max_frame_len_is_the_core_limit() {
        assert_eq!(mesh_max_frame_len() as usize, xmtp_mesh::MAX_FRAME_LEN);
        // The Kotlin link layer hard-codes this value (LinkLimits.MAX_FRAME_BYTES).
        assert_eq!(mesh_max_frame_len(), 1 << 20);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn start_sync_rejects_unregistered_client() {
        let (client, node, _owner) = unregistered_mesh_client().await;
        assert!(
            node.start_sync(client, Arc::new(NullTransport))
                .await
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn start_sync_rejects_client_of_another_node() {
        let (a, _node_a) = registered_mesh_client().await;
        let (_b, node_b) = registered_mesh_client().await;
        let err = node_b
            .start_sync(a, Arc::new(NullTransport))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("mesh:"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dm_round_trip_over_ffi_transport() {
        let (a, node_a) = registered_mesh_client().await;
        let (b, node_b) = registered_mesh_client().await;
        ready_to_pair(&a, &node_a);
        ready_to_pair(&b, &node_b);
        // Connection-scoped ids, as the radio allocates them: node_a knows b's
        // pipe as "b#1", node_b knows a's as "a#1".
        let (to_b, rx_b) = unbounded_channel();
        let (to_a, rx_a) = unbounded_channel();
        node_a
            .start_sync(
                a.clone(),
                Arc::new(ChannelTransport {
                    me: "a#1".into(),
                    tx: to_b,
                }),
            )
            .await
            .unwrap();
        node_b
            .start_sync(
                b.clone(),
                Arc::new(ChannelTransport {
                    me: "b#1".into(),
                    tx: to_a,
                }),
            )
            .await
            .unwrap();
        let presence_a = Arc::new(PresenceLog::default());
        let stream_a = node_a.stream_presence(presence_a.clone()).await;
        pump(node_b.clone(), rx_b);
        pump(node_a.clone(), rx_a);
        // The radio calls these from its own thread, never from a tokio worker.
        let (na, nb) = (node_a.clone(), node_b.clone());
        std::thread::spawn(move || {
            nb.on_peer_connected("a#1".into(), FfiLinkRole::Accept);
            na.on_peer_connected("b#1".into(), FfiLinkRole::DialPairing);
        })
        .join()
        .unwrap();
        confirm_pairings(&node_a, "b#1", &node_b, "a#1").await;

        eventually("mutual auth", || async {
            node_a.authenticated_peers() == vec!["b#1".to_string()]
                && node_b.authenticated_peers() == vec!["a#1".to_string()]
        })
        .await;
        eventually("presence: b verified at a", || async {
            node_a.verified_peers()
                == vec![FfiVerifiedPeer {
                    peer_id: "b#1".into(),
                    inbox_id: b.inbox_id(),
                    installation_id: b.installation_id(),
                }]
        })
        .await;

        // Creating the DM needs b's identity log and key package in a's node,
        // which the session exchanges right after auth. Retry until they arrive.
        let mut dm = None;
        for _ in 0..100 {
            if let Ok(conv) = a
                .conversations()
                .find_or_create_dm(b.inbox_id(), FfiCreateDMOptions::default())
                .await
            {
                dm = Some(conv);
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let dm = dm.expect("DM creation never succeeded");
        // a created the DM, so a's node is the sequencer and this send returns
        // once sequenced locally.
        dm.send_text("hello over ffi").await.unwrap();

        eventually("b receives the message", || async {
            let _ = b.conversations().sync_all_conversations(None).await;
            let Ok(dms) = b
                .conversations()
                .list_dms(FfiListConversationsOptions::default())
            else {
                return false;
            };
            for item in dms {
                let Ok(messages) = item
                    .conversation
                    .find_messages(FfiListMessagesOptions::default())
                    .await
                else {
                    continue;
                };
                if messages
                    .into_iter()
                    .any(|m| decode_text(m.content).ok().as_deref() == Some("hello over ffi"))
                {
                    return true;
                }
            }
            false
        })
        .await;

        node_a.on_peer_lost("b#1".into());
        eventually("session dropped", || async {
            node_a.authenticated_peers().is_empty() && node_a.verified_peers().is_empty()
        })
        .await;
        eventually("presence stream reported verify then loss", || async {
            *presence_a.0.lock()
                == vec![
                    format!("verified b#1 {}", b.inbox_id()),
                    "lost b#1".to_string(),
                ]
        })
        .await;
        stream_a.end();

        node_b.stop_sync();
        assert!(node_b.authenticated_peers().is_empty());
        assert!(node_b.verified_peers().is_empty());
        // After stop_sync, callbacks are ignored until the next start_sync.
        node_b.on_peer_connected("a#2".into(), FfiLinkRole::Accept);
        node_b.on_frame("a#2".into(), vec![1, 2, 3]);
        assert!(node_b.authenticated_peers().is_empty());
    }

    #[test]
    fn open_is_idempotent_per_path() {
        let path = tmp_path();
        let a = open_mesh_node(path.clone(), Some(vec![1u8; 32])).unwrap();
        let b = open_mesh_node(path.clone(), Some(vec![1u8; 32])).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "same path must share one node");
        let other = open_mesh_node(tmp_path(), Some(vec![1u8; 32])).unwrap();
        assert!(!Arc::ptr_eq(&a, &other));
    }

    #[test]
    fn reopen_with_different_key_is_rejected() {
        let path = tmp_path();
        // Held for the whole test: with a Weak-backed registry, a node with
        // no live `Arc` is torn down, so the first node must stay alive for
        // the second `open_mesh_node` to see it and reject the new key.
        let _first = open_mesh_node(path.clone(), Some(vec![1u8; 32])).unwrap();
        let err = open_mesh_node(path, Some(vec![2u8; 32])).unwrap_err();
        assert!(err.to_string().contains("different key"), "{err}");
    }

    #[test]
    fn key_must_be_32_bytes() {
        let err = open_mesh_node(tmp_path(), Some(vec![1u8; 31])).unwrap_err();
        assert!(err.to_string().contains("32 bytes"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mesh_api_client_reports_connected() {
        let api = connect_to_mesh(tmp_path(), Some(vec![3u8; 32])).unwrap();
        assert!(is_connected(api).await);
    }

    /// A symlinked directory and its real target are different strings but
    /// the same file; the registry must key on the canonical path so both
    /// spellings share one node.
    #[test]
    #[cfg(unix)]
    fn open_resolves_symlinked_path_to_the_same_node() {
        let base = std::env::temp_dir();
        let real_dir = base.join(format!(
            "mesh_test_real_{}",
            xmtp_common::rand_string::<12>()
        ));
        let link_dir = base.join(format!(
            "mesh_test_link_{}",
            xmtp_common::rand_string::<12>()
        ));
        std::fs::create_dir_all(&real_dir).unwrap();
        std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

        let via_real = real_dir.join("node.db3").to_string_lossy().into_owned();
        let via_link = link_dir.join("node.db3").to_string_lossy().into_owned();

        let a = open_mesh_node(via_real, Some(vec![5u8; 32])).unwrap();
        let b = open_mesh_node(via_link, Some(vec![5u8; 32])).unwrap();
        assert!(
            Arc::ptr_eq(&a, &b),
            "a symlinked spelling of the same db file must share one node"
        );

        std::fs::remove_dir_all(&real_dir).ok();
        std::fs::remove_file(&link_dir).ok();
    }

    /// Once every `Arc<FfiMeshNode>` for a path is dropped, the registry must
    /// not keep the node alive forever (a leak across account switch/reset):
    /// the next open creates a fresh node rather than resurrecting the old one.
    #[test]
    fn reopen_after_all_arcs_dropped_creates_a_new_node() {
        let path = tmp_path();
        let key = Some(vec![9u8; 32]);

        let first = open_mesh_node(path.clone(), key.clone()).unwrap();
        let first_ptr = Arc::as_ptr(&first);
        drop(first);

        let second = open_mesh_node(path, key).unwrap();
        assert_ne!(
            Arc::as_ptr(&second),
            first_ptr,
            "a node with no remaining owner must not be reused"
        );
    }

    /// `connect_to_mesh` must keep its node alive on its own: with no other
    /// `Arc<FfiMeshNode>` held, `open_mesh_node` on the same path must still
    /// find the client's node (a live registry entry, same node), not open a
    /// second, unrelated `MeshNode` on the same SQLite file.
    #[test]
    fn connect_to_mesh_keeps_its_node_alive_with_no_other_arc_held() {
        let path = tmp_path();
        let key = Some(vec![11u8; 32]);

        let (client, weak) = connect_to_mesh_for_test(path.clone(), key.clone()).unwrap();
        // No `Arc<FfiMeshNode>` is held here — only `client` and a non-owning `weak`.
        assert!(
            weak.upgrade().is_some(),
            "connect_to_mesh's client must keep its own node alive"
        );

        let reopened = open_mesh_node(path, key).unwrap();
        assert!(
            Arc::ptr_eq(&reopened, &weak.upgrade().unwrap()),
            "open_mesh_node must return the exact node the client is using, not a second one"
        );

        drop(client);
        drop(reopened);
        assert!(
            weak.upgrade().is_none(),
            "dropping the client and every other Arc must tear the node down"
        );
    }

    /// Foreign code that throws from a callback must not take the process
    /// down (uniffi would panic, and release builds abort on panic): the
    /// error is logged and dropped, and the node keeps working.
    #[tokio::test(flavor = "multi_thread")]
    async fn throwing_callbacks_do_not_break_the_node() {
        let (a, node_a) = registered_mesh_client().await;
        let (b, node_b) = registered_mesh_client().await;
        ready_to_pair(&a, &node_a);
        ready_to_pair(&b, &node_b);
        let (to_b, rx_b) = unbounded_channel();
        let (to_a, rx_a) = unbounded_channel();
        node_a
            .start_sync(
                a.clone(),
                Arc::new(ThrowingForPeer {
                    bad: "x#1".into(),
                    inner: ChannelTransport {
                        me: "a#1".into(),
                        tx: to_b,
                    },
                }),
            )
            .await
            .unwrap();
        node_b
            .start_sync(
                b.clone(),
                Arc::new(ChannelTransport {
                    me: "b#1".into(),
                    tx: to_a,
                }),
            )
            .await
            .unwrap();
        let presence_a = Arc::new(ThrowingPresence::default());
        let stream_a = node_a.stream_presence(presence_a.clone()).await;
        pump(node_b.clone(), rx_b);
        pump(node_a.clone(), rx_a);

        // A connection whose every send and disconnect throws.
        let na = node_a.clone();
        std::thread::spawn(move || {
            na.on_peer_connected("x#1".into(), FfiLinkRole::Accept);
            na.on_frame("x#1".into(), vec![0xde, 0xad]);
        })
        .join()
        .unwrap();

        // A good peer still authenticates, and presence keeps flowing even
        // though the callback throws on every event.
        let (na, nb) = (node_a.clone(), node_b.clone());
        std::thread::spawn(move || {
            nb.on_peer_connected("a#1".into(), FfiLinkRole::Accept);
            na.on_peer_connected("b#1".into(), FfiLinkRole::DialPairing);
        })
        .join()
        .unwrap();
        confirm_pairings(&node_a, "b#1", &node_b, "a#1").await;
        eventually("good peer authenticates", || async {
            node_a.authenticated_peers() == vec!["b#1".to_string()]
                && node_b.authenticated_peers() == vec!["a#1".to_string()]
        })
        .await;
        eventually("presence reported b despite throwing", || async {
            *presence_a.0.0.lock() == vec![format!("verified b#1 {}", b.inbox_id())]
        })
        .await;
        node_a.on_peer_lost("b#1".into());
        eventually("presence reported loss despite throwing", || async {
            *presence_a.0.0.lock()
                == vec![
                    format!("verified b#1 {}", b.inbox_id()),
                    "lost b#1".to_string(),
                ]
        })
        .await;
        stream_a.end();
    }

    /// Reset (DESIGN.md §B10.2): the log is carried through both
    /// rotations, and the same wallet's new installation joins its inbox at
    /// seq 2 instead of re-creating it.
    #[tokio::test(flavor = "multi_thread")]
    async fn carried_log_lets_the_same_wallet_join_its_inbox_on_a_fresh_node() {
        let owner = FfiWalletInboxOwner::new();
        let old_path = tmp_path();
        let (old_client, _old_node) = registered_client_at(&old_path, &owner).await;
        let inbox_id = old_client.inbox_id();

        let mid_path = tmp_path();
        let held = carry_mesh_identity_log(
            old_path.clone(),
            mid_path.clone(),
            Some(vec![9u8; 32]),
            inbox_id.clone(),
        )
        .await
        .unwrap();
        assert_eq!(held, 1);
        let new_path = tmp_path();
        let held = carry_mesh_identity_log(
            mid_path,
            new_path.clone(),
            Some(vec![9u8; 32]),
            inbox_id.clone(),
        )
        .await
        .unwrap();
        assert_eq!(held, 1);
        {
            let fresh = open_mesh_node(new_path.clone(), Some(vec![9u8; 32])).unwrap();
            assert_eq!(
                fresh.node.local_installation().unwrap(),
                None,
                "the carry never binds the node"
            );
        }

        let (new_client, new_node) = registered_client_at(&new_path, &owner).await;
        assert_eq!(new_client.inbox_id(), inbox_id);
        assert_ne!(new_client.installation_id(), old_client.installation_id());
        assert_eq!(
            new_node.node.identity_log(&inbox_id).unwrap().len(),
            2,
            "AddAssociation at seq 2, not a second CreateInbox"
        );
    }

    /// A key that does not open the old node fails before
    /// the target file is created, so the rotation falls back to empty.
    /// No client is built on `old_path`: a
    /// registered client's background workers (e.g. `PendingSelfRemove`)
    /// hold the node's Arc indefinitely, so a client/node built via
    /// `registered_client_at` and then dropped does *not* reliably release
    /// the registry entry in any practical test timeout — it would instead
    /// exercise the node registry's "already open with a different key"
    /// guard (`open_mesh_node`, `mesh.rs:108-111`), whose message also
    /// contains "mesh" and so could not be told apart from this test's
    /// intended path by a loose substring check. With no client, dropping
    /// the bare `Arc<FfiMeshNode>` from `open_mesh_node` alone is
    /// synchronous (proven by `reopen_after_all_arcs_dropped_creates_a_new_node`),
    /// so the next `open_mesh_node` call for `old_path` genuinely opens a
    /// closed file and hits SQLCipher's own decryption failure.
    #[tokio::test(flavor = "multi_thread")]
    async fn carry_with_another_key_fails_before_touching_the_target() {
        let old_path = tmp_path();
        drop(open_mesh_node(old_path.clone(), Some(vec![9u8; 32])).unwrap());

        let target = tmp_path();
        let err = carry_mesh_identity_log(
            old_path,
            target.clone(),
            Some(vec![7u8; 32]),
            "ab".repeat(32),
        )
        .await
        .unwrap_err();
        assert!(
            !err.to_string().contains("already open"),
            "must not be the registry's already-open guard: {err}"
        );
        assert!(
            err.to_string().contains("file is not a database"),
            "must be SQLCipher's own decryption failure: {err}"
        );
        assert!(!std::path::Path::new(&target).exists());
    }

    /// Nothing to carry from means an error, never a new
    /// empty database at either path.
    #[tokio::test(flavor = "multi_thread")]
    async fn carry_from_a_missing_node_file_is_an_error_and_creates_nothing() {
        let (from, to) = (tmp_path(), tmp_path());
        let err = carry_mesh_identity_log(
            from.clone(),
            to.clone(),
            Some(vec![9u8; 32]),
            "ab".repeat(32),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("no node database"), "{err}");
        assert!(!std::path::Path::new(&from).exists());
        assert!(!std::path::Path::new(&to).exists());
    }

    /// `import_identity_log` does not roll back,
    /// so a log that fails partway through (here, a gap: sequence 3 is
    /// missing) leaves a prefix already written. `carry_mesh_identity_log`
    /// must discard that partial target file rather than let a truncated
    /// log survive to fork again at the next sequence id.
    ///
    /// The gapped source is built from a real, carried 2-entry log (seq 1
    /// CreateInbox, seq 2 AddAssociation — `MeshStore` never persists a
    /// non-contiguous log on its own, so no legitimate node file can supply
    /// one), plus one duplicated entry re-numbered to seq 4 to skip seq 3.
    /// `import_or_discard_target` is exercised directly (a seen gap,
    /// not a fork) since `carry_mesh_identity_log` always reads a real,
    /// contiguous log from its `from_db_path`.
    #[tokio::test(flavor = "multi_thread")]
    async fn carry_deletes_the_target_after_an_import_error_partway_through() {
        let owner = FfiWalletInboxOwner::new();
        let old_path = tmp_path();
        let (old_client, _old_node) = registered_client_at(&old_path, &owner).await;
        let inbox_id = old_client.inbox_id();

        let mid_path = tmp_path();
        carry_mesh_identity_log(
            old_path,
            mid_path.clone(),
            Some(vec![9u8; 32]),
            inbox_id.clone(),
        )
        .await
        .unwrap();
        // mid_path now knows the inbox; a second installation there appends
        // AddAssociation at seq 2, giving a real 2-entry log.
        let (_mid_client, mid_node) = registered_client_at(&mid_path, &owner).await;
        let log = mid_node.node.identity_log(&inbox_id).unwrap();
        assert_eq!(log.len(), 2);

        let mut gapped = log.clone();
        let mut skip_three = log[1].clone();
        skip_three.sequence_id = 4;
        gapped.push(skip_three);

        let target = tmp_path();
        let to = open_mesh_node(target.clone(), Some(vec![9u8; 32])).unwrap();
        let err = import_or_discard_target(to, &target, &inbox_id, gapped)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("gap"), "{err}");
        assert!(
            !std::path::Path::new(&target).exists(),
            "the prefix written before the gap must not survive"
        );
    }

    /// `open_mesh_node(to_db_path, ...)` itself can fail after
    /// creating the file (`MeshNode::open` creates it, then migrations run);
    /// that must be discarded too, the same as an `import_identity_log`
    /// failure.
    #[tokio::test(flavor = "multi_thread")]
    async fn carry_discards_the_target_if_opening_it_fails() {
        let owner = FfiWalletInboxOwner::new();
        let old_path = tmp_path();
        let (old_client, _old_node) = registered_client_at(&old_path, &owner).await;
        let inbox_id = old_client.inbox_id();

        let target = tmp_path();
        std::fs::write(&target, b"not a database").unwrap();
        let err = carry_mesh_identity_log(old_path, target.clone(), Some(vec![9u8; 32]), inbox_id)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("mesh"), "{err}");
        assert!(!std::path::Path::new(&target).exists());
    }

    /// `to_db_path` can also fail to open because it is
    /// already open in-process under a different key (the registry guard,
    /// `open_mesh_node`, `:108-111`) — a live connection someone else still
    /// holds, not a bad file. Discarding the file in that case would pull it
    /// out from under that connection. The carry must leave it alone: the
    /// registry error propagates, and the file must still exist and still
    /// open with its original key afterward.
    #[tokio::test(flavor = "multi_thread")]
    async fn carry_does_not_discard_a_target_already_open_with_another_key() {
        let owner = FfiWalletInboxOwner::new();
        let old_path = tmp_path();
        let (old_client, _old_node) = registered_client_at(&old_path, &owner).await;
        let inbox_id = old_client.inbox_id();

        // `registered_client_at` always opens `old_path` with key 9s, and
        // `encryption_key` here is used for *both* ends of the carry, so it
        // must be 9s too, or `from`'s own open would hit the registry guard
        // first and `to` would never be reached. Only the target is opened
        // with a different key (1s) ahead of time.
        let target = tmp_path();
        let held_open = open_mesh_node(target.clone(), Some(vec![1u8; 32])).unwrap();

        let err = carry_mesh_identity_log(old_path, target.clone(), Some(vec![9u8; 32]), inbox_id)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("already open"), "{err}");
        assert!(std::path::Path::new(&target).exists());

        drop(held_open);
        // Reopens cleanly with the original key: the file on disk was never
        // touched by the failed carry.
        open_mesh_node(target, Some(vec![1u8; 32])).unwrap();
    }

    /// A registered client whose inbox log already lists it has nothing to re-base.
    #[tokio::test(flavor = "multi_thread")]
    async fn no_rebase_for_an_installation_already_in_its_log() {
        let (client, _node) = registered_mesh_client().await;
        assert!(
            client
                .mesh_rebase_signature_request()
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Restore convergence (DESIGN.md §C4.3–§C4.4) through the FFI, with a test signer:
    /// a2 is the same wallet re-registered on an empty node (a fork). When
    /// its node replaces the log with a's older one, the identity stream
    /// reports RebaseNeeded; the re-base request, signed by the wallet and
    /// applied, adds a2 at seq 2; a second request is None.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_replaced_log_asks_for_a_rebase_that_a_test_signer_completes() {
        let owner = FfiWalletInboxOwner::new();
        let (a, a_node) = registered_client_at(&tmp_path(), &owner).await;
        tokio::time::sleep(Duration::from_millis(2)).await;
        let (a2, a2_node) = registered_client_at(&tmp_path(), &owner).await;
        let inbox = a.inbox_id();
        assert_eq!(a2.inbox_id(), inbox);

        ready_to_pair(&a2, &a2_node);
        a2_node
            .start_sync(a2.clone(), Arc::new(NullTransport))
            .await
            .unwrap();
        let log = Arc::new(ResyncLog::default());
        let _stream = a2_node.stream_identity(log.clone()).await;

        a2_node
            .node
            .replace_identity_log(&inbox, a_node.node.identity_log(&inbox).unwrap())
            .await
            .unwrap();
        eventually("the identity stream reports a re-base", || async {
            log.0.lock().as_slice() == [(inbox.clone(), FfiMeshResyncOutcome::RebaseNeeded)]
        })
        .await;

        let request = a2
            .mesh_rebase_signature_request()
            .await
            .unwrap()
            .expect("a2 is not in the winning log");
        let text = request.signature_text().await.unwrap();
        request
            .add_ecdsa_signature(owner.sign(text).unwrap())
            .await
            .unwrap();
        a2.apply_signature_request(request).await.unwrap();

        assert_eq!(a2_node.node.identity_log(&inbox).unwrap().len(), 2);
        assert!(a2.mesh_rebase_signature_request().await.unwrap().is_none());
        a2_node.stop_sync();
    }

    /// Android maps a full log to "Too many devices on this identity" by this marker.
    #[test]
    fn a_full_log_carries_the_too_many_installations_marker() {
        let err = rebase_error(xmtp_mls::client::ClientError::Identity(
            xmtp_mls::identity::IdentityError::TooManyInstallations {
                inbox_id: "inbox".into(),
                count: 10,
                max: 10,
            },
        ));
        assert!(
            err.to_string().contains(MESH_TOO_MANY_INSTALLATIONS),
            "{err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn enable_relay_before_start_sync_is_a_mesh_error() {
        let (client, node) = registered_mesh_client().await;
        let err = node.enable_relay(client).unwrap_err();
        assert!(err.to_string().contains("mesh:"), "{err}");
        assert!(!node.relay_enabled());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relay_enables_reports_zero_stats_and_disables() {
        let (client, node) = registered_mesh_client().await;
        ready_to_pair(&client, &node);
        node.start_sync(client.clone(), Arc::new(NullTransport))
            .await
            .unwrap();
        assert!(!node.relay_enabled());
        node.enable_relay(client).unwrap();
        assert!(node.relay_enabled());
        assert_eq!(node.relay_stats(), FfiRelayStats::default());
        node.disable_relay();
        assert!(!node.relay_enabled());
        node.stop_sync();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mesh_stats_start_at_zero() {
        let (client, node) = registered_mesh_client().await;
        ready_to_pair(&client, &node);
        node.start_sync(client, Arc::new(NullTransport))
            .await
            .unwrap();
        assert_eq!(node.mesh_stats(), FfiMeshStats::default());
        node.stop_sync();
    }

    /// The radio's and the app's surface (DESIGN.md §B14): pair over FFI,
    /// confirm, classify each other's adverts, reset, remove.
    #[tokio::test(flavor = "multi_thread")]
    async fn contacts_adverts_and_pairing_over_ffi() {
        let (a, node_a) = registered_mesh_client().await;
        let (b, node_b) = registered_mesh_client().await;
        ready_to_pair(&a, &node_a);
        ready_to_pair(&b, &node_b);
        let (to_b, rx_b) = unbounded_channel();
        let (to_a, rx_a) = unbounded_channel();
        node_a
            .start_sync(
                a.clone(),
                Arc::new(ChannelTransport {
                    me: "a#1".into(),
                    tx: to_b,
                }),
            )
            .await
            .unwrap();
        node_b
            .start_sync(
                b.clone(),
                Arc::new(ChannelTransport {
                    me: "b#1".into(),
                    tx: to_a,
                }),
            )
            .await
            .unwrap();
        pump(node_b.clone(), rx_b);
        pump(node_a.clone(), rx_a);
        let (na, nb) = (node_a.clone(), node_b.clone());
        std::thread::spawn(move || {
            nb.on_peer_connected("a#1".into(), FfiLinkRole::Accept);
            na.on_peer_connected("b#1".into(), FfiLinkRole::DialPairing);
        })
        .join()
        .unwrap();
        confirm_pairings(&node_a, "b#1", &node_b, "a#1").await;

        eventually("both hold the other's card", || async {
            node_a
                .contacts()
                .unwrap()
                .iter()
                .any(|c| c.inbox_id == b.inbox_id())
                && node_b
                    .contacts()
                    .unwrap()
                    .iter()
                    .any(|c| c.inbox_id == a.inbox_id())
        })
        .await;
        assert_eq!(
            node_a
                .contacts()
                .unwrap()
                .into_iter()
                .map(|c| c.inbox_id)
                .collect::<Vec<_>>(),
            vec![b.inbox_id()]
        );
        // A successful pairing leaves pairing mode by itself.
        assert!(!node_a.pairing_mode());
        assert!(!node_b.pairing_mode());

        let now = 1_769_400_010;
        let advert = node_b.advert_state(now).unwrap();
        assert_eq!((advert.service_data.len(), advert.service_data[0]), (10, 2));
        assert_eq!(advert.service_data[1] & 0x01, 0x00, "b left pairing mode");
        assert_eq!(advert.next_window_at, 1_769_400_900);
        assert!(
            advert
                .contact_tokens
                .iter()
                .any(|t| t.inbox_id == a.inbox_id())
        );
        assert!(matches!(
            node_a.classify_advert(advert.service_data.clone(), now).unwrap(),
            FfiAdvertMatch::Contact { inbox_id, .. } if inbox_id == b.inbox_id()
        ));
        assert_eq!(node_b.reset_discovery_key().unwrap(), 1);
        let reset = node_b.advert_state(now).unwrap();
        assert_ne!(reset.own_token, advert.own_token);
        assert!(matches!(
            node_a.classify_advert(reset.service_data, now).unwrap(),
            FfiAdvertMatch::Stranger { .. }
        ));
        assert!(node_a.remove_contact(b.inbox_id()).unwrap());
        assert!(node_a.contacts().unwrap().is_empty());
        assert_eq!(node_a.mesh_stats().links_pairing, 1);
        assert_eq!(node_b.mesh_stats().discovery_resets, 1);

        node_a.stop_sync();
        node_b.stop_sync();
    }
}
