//! Records (§B14.3): a frame travels over an open Noise link as one or
//! more Noise transport messages, each `flag ‖ chunk` sealed, in order.
//! Both directions rekey every [`REKEY_EVERY`] records, in step.
use parking_lot::Mutex;
use snow::TransportState;
use zeroize::{Zeroize, Zeroizing};

use crate::MeshError;
use crate::sync::frames::MAX_FRAME_LEN;

pub(crate) const MAX_NOISE_MESSAGE: usize = 65_535;
const TAG_LEN: usize = 16;
pub(crate) const MAX_RECORD_PLAINTEXT: usize = MAX_NOISE_MESSAGE - TAG_LEN;
pub(crate) const MAX_RECORD_CHUNK: usize = MAX_RECORD_PLAINTEXT - 1;
const LAST: u8 = 0;
const MORE: u8 = 1;
pub(crate) const REKEY_EVERY: u64 = 1 << 16;

/// Both directions of one link's Noise transport. Shared by the link's
/// sending half (`LinkTx`) and its session; each call locks briefly.
///
/// Fails closed: after any error (a record that does not authenticate, a
/// bad flag, an over-long frame, a failed seal) every later `seal` and
/// `open` fails too, and the partial frame is dropped.
pub(crate) struct Records {
    state: Mutex<State>,
}

struct State {
    noise: TransportState,
    sent: u64,
    received: u64,
    rekey_every: u64,
    partial: Vec<u8>,
    failed: bool,
}

fn rejected(what: &str) -> MeshError {
    MeshError::LinkAuthFailed(format!("link record rejected: {what}"))
}

impl Records {
    pub(crate) fn new(noise: TransportState) -> Self {
        Self::with_rekey_every(noise, REKEY_EVERY)
    }

    pub(crate) fn with_rekey_every(noise: TransportState, rekey_every: u64) -> Self {
        Self {
            state: Mutex::new(State {
                noise,
                sent: 0,
                received: 0,
                rekey_every: rekey_every.max(1),
                partial: Vec::new(),
                failed: false,
            }),
        }
    }

    /// Seal `frame` into records, in the order they must be sent.
    pub(crate) fn seal(&self, frame: &[u8]) -> Result<Vec<Vec<u8>>, MeshError> {
        let mut st = self.state.lock();
        if st.failed {
            return Err(rejected("link already failed"));
        }
        if frame.len() > MAX_FRAME_LEN {
            return Err(MeshError::LinkAuthFailed(
                "sealing a frame over MAX_FRAME_LEN".into(),
            ));
        }
        let result = st.seal_frame(frame);
        if result.is_err() {
            st.fail();
        }
        result
    }

    /// Open one record; the whole frame once its last record arrived.
    pub(crate) fn open(&self, record: &[u8]) -> Result<Option<Vec<u8>>, MeshError> {
        let mut st = self.state.lock();
        if st.failed {
            return Err(rejected("link already failed"));
        }
        let result = st.open_one(record);
        if result.is_err() {
            st.fail();
        }
        result
    }
}

impl State {
    fn fail(&mut self) {
        self.failed = true;
        self.partial.zeroize();
        self.partial = Vec::new();
    }

    fn seal_frame(&mut self, frame: &[u8]) -> Result<Vec<Vec<u8>>, MeshError> {
        if frame.is_empty() {
            return Ok(vec![self.seal_one(LAST, &[])?]);
        }
        let mut out = Vec::with_capacity(frame.len().div_ceil(MAX_RECORD_CHUNK));
        let mut chunks = frame.chunks(MAX_RECORD_CHUNK).peekable();
        while let Some(chunk) = chunks.next() {
            let flag = if chunks.peek().is_some() { MORE } else { LAST };
            out.push(self.seal_one(flag, chunk)?);
        }
        Ok(out)
    }

    fn open_one(&mut self, record: &[u8]) -> Result<Option<Vec<u8>>, MeshError> {
        if record.len() > MAX_NOISE_MESSAGE || record.len() <= TAG_LEN {
            return Err(rejected("length"));
        }
        let mut plain = Zeroizing::new(vec![0u8; record.len()]);
        let n = self
            .noise
            .read_message(record, &mut plain)
            .map_err(|_| rejected("authentication failed"))?;
        self.received += 1;
        if self.received.is_multiple_of(self.rekey_every) {
            self.noise.rekey_incoming();
        }
        let (flag, chunk) = plain[..n].split_first().ok_or_else(|| rejected("empty"))?;
        if self.partial.len() + chunk.len() > MAX_FRAME_LEN {
            return Err(rejected("frame over MAX_FRAME_LEN"));
        }
        self.partial.extend_from_slice(chunk);
        match *flag {
            LAST => Ok(Some(std::mem::take(&mut self.partial))),
            MORE => Ok(None),
            _ => Err(rejected("flag")),
        }
    }

    fn seal_one(&mut self, flag: u8, chunk: &[u8]) -> Result<Vec<u8>, MeshError> {
        let mut plain = Vec::with_capacity(chunk.len() + 1);
        plain.push(flag);
        plain.extend_from_slice(chunk);
        let mut sealed = vec![0u8; plain.len() + TAG_LEN];
        let n = self
            .noise
            .write_message(&plain, &mut sealed)
            .map_err(|e| MeshError::LinkAuthFailed(format!("sealing a record: {e}")))?;
        sealed.truncate(n);
        self.sent += 1;
        if self.sent.is_multiple_of(self.rekey_every) {
            self.noise.rekey_outgoing();
        }
        Ok(sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::noise::test_pair;

    fn pair() -> (Records, Records) {
        let (a, b) = test_pair();
        (Records::new(a), Records::new(b))
    }

    #[test]
    fn a_small_frame_is_one_record() {
        let (a, b) = pair();
        let records = a.seal(b"hello").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].len(), 5 + 1 + 16);
        assert_eq!(b.open(&records[0]).unwrap(), Some(b"hello".to_vec()));
    }

    /// Spec §10 "1 MiB frame".
    #[test]
    fn a_one_mib_frame_is_split_into_records_and_reassembled() {
        let (a, b) = pair();
        let frame: Vec<u8> = (0..MAX_FRAME_LEN).map(|i| i as u8).collect();
        let records = a.seal(&frame).unwrap();
        assert_eq!(records.len(), MAX_FRAME_LEN.div_ceil(MAX_RECORD_CHUNK));
        assert_eq!(records.len(), 17);
        assert!(records.iter().all(|r| r.len() <= MAX_NOISE_MESSAGE));
        let (last, rest) = records.split_last().unwrap();
        for r in rest {
            assert_eq!(b.open(r).unwrap(), None);
        }
        assert_eq!(b.open(last).unwrap(), Some(frame));
    }

    /// Spec §10 "tampered ciphertext / reordered records".
    #[test]
    fn tampered_reordered_or_replayed_records_are_rejected() {
        let (a, b) = pair();
        let mut r = a.seal(b"one").unwrap().remove(0);
        r[3] ^= 1;
        assert!(
            matches!(b.open(&r), Err(MeshError::LinkAuthFailed(_))),
            "tampered"
        );

        let (a, b) = pair();
        let _first = a.seal(b"one").unwrap().remove(0);
        let second = a.seal(b"two").unwrap().remove(0);
        assert!(b.open(&second).is_err(), "out of order");

        let (a, b) = pair();
        let first = a.seal(b"one").unwrap().remove(0);
        assert_eq!(b.open(&first).unwrap(), Some(b"one".to_vec()));
        assert!(b.open(&first).is_err(), "replayed");
    }

    #[test]
    fn reassembly_stops_at_the_frame_limit() {
        let (mut raw, b) = {
            let (a, b) = test_pair();
            (a, Records::new(b))
        };
        let mut failure = None;
        for i in 0..=MAX_FRAME_LEN / MAX_RECORD_CHUNK + 1 {
            let mut plain = vec![MORE];
            plain.extend(std::iter::repeat_n(0u8, MAX_RECORD_CHUNK));
            let mut sealed = vec![0u8; plain.len() + TAG_LEN];
            let n = raw.write_message(&plain, &mut sealed).unwrap();
            if let Err(e) = b.open(&sealed[..n]) {
                failure = Some((i, e));
                break;
            }
        }
        let (i, e) = failure.expect("reassembly is bounded");
        assert_eq!(
            i,
            MAX_FRAME_LEN / MAX_RECORD_CHUNK,
            "16 full records fit, the 17th does not"
        );
        assert!(matches!(e, MeshError::LinkAuthFailed(_)));
    }

    /// Long-lived links: both sides rekey at the same record count, so a
    /// link keeps working past the rekey point; a receiver out of step
    /// fails closed, not open.
    #[test]
    fn both_directions_rekey_in_step() {
        let (a, b) = test_pair();
        let (a, b) = (
            Records::with_rekey_every(a, 3),
            Records::with_rekey_every(b, 3),
        );
        for i in 0..10u8 {
            let there = a.seal(&[i; 10]).unwrap();
            assert_eq!(b.open(&there[0]).unwrap(), Some(vec![i; 10]));
            let back = b.seal(&[i; 5]).unwrap();
            assert_eq!(a.open(&back[0]).unwrap(), Some(vec![i; 5]));
        }
        let (a, b) = test_pair();
        let (a, b) = (
            Records::with_rekey_every(a, 3),
            Records::with_rekey_every(b, 1000),
        );
        for i in 0..3u8 {
            assert!(b.open(&a.seal(&[i]).unwrap()[0]).is_ok());
        }
        assert!(b.open(&a.seal(&[3]).unwrap()[0]).is_err());
        assert_eq!(REKEY_EVERY, 65_536);
    }

    /// Any rejected record is fatal to the link: later records, even
    /// genuine ones, are refused, and so is sealing.
    #[test]
    fn a_rejected_record_fails_the_link_for_good() {
        let (a, b) = pair();
        let good = a.seal(b"one").unwrap().remove(0);
        let mut bad = good.clone();
        bad[0] ^= 1;
        assert!(b.open(&bad).is_err());
        assert!(b.open(&good).is_err(), "a genuine record after a failure");
        assert!(b.seal(b"reply").is_err(), "sealing after a failure");
    }
}
