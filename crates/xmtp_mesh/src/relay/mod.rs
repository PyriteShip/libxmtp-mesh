//! Multi-hop relay (DESIGN.md Part R): a
//! bounded spool of sealed envelopes that phones flood to and carry for
//! each other. Relays see only a per-envelope tag, a coarse expiry and a padded size.
mod config;
pub(crate) mod dm;
pub(crate) mod engine;
pub(crate) mod envelope;
pub(crate) mod inner;
pub(crate) mod keys;
pub(crate) mod spool;

pub use config::RelayConfig;
pub use engine::RelayStats;
pub use keys::{ClientRelayExporter, RelayExporter};

/// Length of a stranger link's source id: never a 32-byte installation key.
pub(crate) const STRANGER_SOURCE_LEN: usize = 33;

/// A fresh id for one stranger relay link: its rate and spool budgets are
/// per link, since a stranger has no stable identity (§R5.4, D31).
pub(crate) fn stranger_source() -> Vec<u8> {
    let mut id = vec![0xff];
    id.extend_from_slice(&rand::random::<[u8; 32]>());
    id
}

pub(crate) fn is_stranger(source: &[u8]) -> bool {
    source.len() == STRANGER_SOURCE_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stranger_source_is_never_an_installation_key() {
        let (a, b) = (stranger_source(), stranger_source());
        assert!(is_stranger(&a) && is_stranger(&b));
        assert_ne!(a, b, "one id per link");
        assert!(!is_stranger(&[7; 32]));
    }
}
