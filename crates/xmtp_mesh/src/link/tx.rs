//! The sending half of one link (§B14.3). Its session and the relay
//! engine share it, so every frame, relayed ones included, is sealed and
//! handed to the radio in one order.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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

pub(crate) struct LinkTx {
    peer: PeerId,
    transport: Arc<dyn MeshTransport>,
    /// The session's cancel flag: a replaced session never sends.
    cancelled: Arc<AtomicBool>,
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
    }

    /// Send one frame. Returns whether it went out: not when the session
    /// was replaced, the frame is over [`MAX_FRAME_LEN`], the link is not
    /// open yet, the link kind may not carry it (a relay link carries relay
    /// frames only, §B14.3), or sealing failed.
    pub(crate) fn send(&self, body: Body) -> bool {
        if self.is_cancelled() {
            return false;
        }
        if let TxState::Open(_, kind) = &*self.state.lock()
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
        // The tap sees frames under the same lock, so its order is the
        // wire order.
        let state = self.state.lock();
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
