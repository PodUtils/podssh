//! QUIC on UDP to podssh's relay role (T-667), raced with the TCP roads to
//! the same host: `pod-relay` of PodUtils/podcrates (T-684), by podssh's
//! variable [`QUIC_ENV`], which the settings of podssh's context hold.

pub use pod_relay::quic_road::*;

/// The variable that says which sessions race QUIC.
pub const QUIC_ENV: &str = "PODSSH_QUIC";

/// The choice of this process's variable; another word is refused, with
/// why.
pub fn from_env() -> Result<Choice, String> {
    Choice::of(&crate::context::process())
}

/// A session over QUIC, and what the process learned of each host's UDP.
#[cfg(feature = "quic")]
pub mod dial {
    pub use pod_relay::quic_road::dial::*;
    use podssh_ws::{ConnectError, RelaySession, WsClientConfig};

    /// What the process learned of the UDP of `host:port`, while it holds.
    pub fn learned(host: &str, port: u16) -> Option<Learned> {
        pod_relay::quic_road::dial::learned(&crate::context::process(), host, port)
    }

    /// The process learned `learned` of the UDP of `host:port`.
    pub fn learn(host: &str, port: u16, learned: Learned) {
        pod_relay::quic_road::dial::learn(&crate::context::process(), host, port, learned)
    }

    /// A session of `config` over QUIC to the UDP port `port`, with `token`.
    pub async fn session(config: &WsClientConfig, token: &str, port: u16) -> Result<RelaySession, ConnectError> {
        let ctx = crate::context::of(&config.proxy);
        pod_relay::quic_road::dial::session(&ctx, &config.pod(), token, port).await
    }
}
