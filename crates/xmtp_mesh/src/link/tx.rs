//! The sending half of one link (§B14.3). Its session and the relay
//! engine share it, so every frame, relayed ones included, is sealed and
//! handed to the radio in one order.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use parking_lot::Mutex;

use super::records::Records;
use super::{LinkKind, allowed_on};
use crate::sync::frames::{self, MAX_FRAME_LEN, frame::Body};
use crate::sync::{MeshTransport, PeerId};

enum TxState {
    /// The Noise handshake is running: frames are refused.
    Pending,
    /// The link is open: frames it may carry are sealed into records.
    Open(Arc<Records>, LinkKind),
    /// Test-only cleartext link: frames go out as they are.
    Plain,
}

/// `LinkTx::kind` values.
const KIND_NONE: u8 = 0;
const KIND_CONTACT: u8 = 1;
const KIND_RELAY: u8 = 2;
const KIND_PAIRING: u8 = 3;

pub(crate) struct LinkTx {
    peer: PeerId,
    /// The open link's kind, readable without `state`'s lock: `state` is
    /// held across `MeshTransport::send`, and callers that hold the node's
    /// `sessions` lock (closing relay links, the radio's `link_kind`) must
    /// never wait on it.
    transport: Arc<dyn MeshTransport>,
    /// The session's cancel flag: a replaced session never sends.
    cancelled: Arc<AtomicBool>,
    kind: AtomicU8,
    state: Mutex<TxState>,
    /// Test only: sees every frame this link sends, before sealing.
    tap: Option<Arc<dyn MeshTransport>>,
}

impl LinkTx {
    pub(crate) fn new(
        peer: PeerId,
        transport: Arc<dyn MeshTransport>,
        cancelled: Arc<AtomicBool>,
        plain: bool,
        tap: Option<Arc<dyn MeshTransport>>,
    ) -> Self {
        Self {
            peer,
            transport,
            cancelled,
            kind: AtomicU8::new(KIND_NONE),
            state: Mutex::new(if plain {
                TxState::Plain
            } else {
                TxState::Pending
            }),
            tap,
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// A handshake message, sent as it is.
    pub(crate) fn send_raw(&self, message: Vec<u8>) {
        if self.is_cancelled() {
            return;
        }
        let _order = self.state.lock();
        self.transport.send(&self.peer, message);
    }

    /// The handshake opened a `kind` link: seal from now on.
    pub(crate) fn open(&self, records: Arc<Records>, kind: LinkKind) {
        *self.state.lock() = TxState::Open(records, kind);
        let value = match kind {
            LinkKind::Contact => KIND_CONTACT,
            LinkKind::Relay => KIND_RELAY,
            LinkKind::Pairing => KIND_PAIRING,
        };
        self.kind.store(value, Ordering::Release);
    }

    /// The open link's kind; `None` while the handshake runs (and on a
    /// test cleartext link). Takes no lock.
    pub(crate) fn kind(&self) -> Option<LinkKind> {
        match self.kind.load(Ordering::Acquire) {
            KIND_CONTACT => Some(LinkKind::Contact),
            KIND_RELAY => Some(LinkKind::Relay),
            KIND_PAIRING => Some(LinkKind::Pairing),
            _ => None,
        }
    }

    /// An open relay (stranger) link. Takes no lock.
    pub(crate) fn is_relay_only(&self) -> bool {
        self.kind() == Some(LinkKind::Relay)
    }

    /// Send one frame. Returns whether it went out: not when the session
    /// was replaced, the frame is over [`MAX_FRAME_LEN`], the link is not
    /// open yet, the link kind may not carry it (a relay link carries relay
    /// frames only, §B14.3), or sealing failed.
    pub(crate) fn send(&self, body: Body) -> bool {
        if self.is_cancelled() {
            return false;
        }
        // One lock for the whole send: the tap sees frames under it, so
        // its order is the wire order.
        let state = self.state.lock();
        if let TxState::Open(_, kind) = &*state
            && !allowed_on(*kind, &body)
        {
            tracing::debug!(peer = %self.peer, ?kind, "frame not allowed on this link: dropped");
            return false;
        }
        let frame = frames::encode(body);
        if frame.len() > MAX_FRAME_LEN {
            tracing::error!(peer = %self.peer, len = frame.len(), "refusing to send oversized mesh frame");
            return false;
        }
        match &*state {
            TxState::Pending => {
                tracing::debug!(peer = %self.peer, "frame before the link opened: dropped");
                return false;
            }
            TxState::Open(records, _) => match records.seal(&frame) {
                Ok(sealed) => {
                    for record in sealed {
                        self.transport.send(&self.peer, record);
                    }
                    if let Some(tap) = &self.tap {
                        tap.send(&self.peer, frame);
                    }
                }
                Err(e) => {
                    tracing::warn!(peer = %self.peer, error = %e, "could not seal a frame");
                    return false;
                }
            },
            TxState::Plain => match &self.tap {
                Some(tap) => {
                    self.transport.send(&self.peer, frame.clone());
                    tap.send(&self.peer, frame);
                }
                None => self.transport.send(&self.peer, frame),
            },
        }
        true
    }
}
