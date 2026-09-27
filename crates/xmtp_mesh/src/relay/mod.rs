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
