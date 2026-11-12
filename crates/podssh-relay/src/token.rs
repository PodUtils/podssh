//! Relay tokens from the environment, the cache or a fresh mint: `pod-relay`
//! of PodUtils/podcrates (T-684). A mint takes podssh's context
//! (`crate::context`), whose settings hold the token of [`TOKEN_ENV`].

pub use pod_relay::token::*;

/// Environment variable carrying a token to use instead of minting.
pub const TOKEN_ENV: &str = "PODSSH_RELAY_TOKEN";
