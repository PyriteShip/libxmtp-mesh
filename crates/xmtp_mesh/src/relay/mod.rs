//! Multi-hop relay (spec 2026-09-24-mesh-multihop-relay-design.md): a
//! bounded spool of sealed envelopes that phones flood to and carry for
//! each other. Relays see only a per-envelope tag, a coarse expiry and a padded size.
mod config;
pub(crate) mod envelope;
pub(crate) mod inner;
pub(crate) mod spool;

pub use config::RelayConfig;
