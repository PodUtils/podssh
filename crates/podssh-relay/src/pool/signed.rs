//! The signed lists of relay hosts (T-346): `pod-relay` of PodUtils/podcrates
//! (T-684). The keys of the process are in the settings of podssh's context.

use pod_identity::KeyName;

pub use pod_relay::pool::signed::*;

/// The variable that names more keys to trust, or `none` for no key.
pub const KEYS_ENV: &str = "PODSSH_RELAY_KEYS";

/// Trust `keys` too, for this process: the binary gives the settings file's
/// `RelayKeys` and the relay members of the net that this host holds.
pub fn set_by_settings(keys: Vec<(KeyName, String)>) {
    crate::context::give_keys(keys);
}

/// The keys that this process trusts: the built-in keys, [`KEYS_ENV`], and
/// what [`set_by_settings`] gave.
pub fn of_process() -> Keys {
    Keys::of_settings(&crate::context::settings())
}
