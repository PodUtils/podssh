//! The order in which the relay hosts of one run are tried (T-220):
//! `pod-relay` of PodUtils/podcrates (T-684), with podssh's variable.

pub use pod_relay::failover::*;

/// The setting of the mode; `--relay-failover` wins over it.
pub const MODE_ENV: &str = "PODSSH_RELAY_FAILOVER";
