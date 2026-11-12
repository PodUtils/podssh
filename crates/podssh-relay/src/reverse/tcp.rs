//! A node's dial of a TCP target: `pod-relay` of PodUtils/podcrates (T-684),
//! through podssh's dialer of the proxy that the environment names.

use std::sync::Arc;
use std::time::Duration;

use pod_proxy::Dialer;
pub use pod_relay::reverse::tcp::*;
use podssh_ws::ProxyChoice;
use tokio::net::TcpStream;

/// podssh's dialer of a node's targets: the proxy that the environment names,
/// over the process's resolver.
pub fn dialer() -> Arc<Dialer> {
    Arc::new(podssh_ws::dial::dialer(&ProxyChoice::FromEnvironment, false))
}

/// The handler of each session to `host:port`, through [`dialer`], each dial
/// within `timeout`; a standard sshd is checked where `sshd` asks for it.
pub fn handler(host: String, port: u16, timeout: Duration, sshd: bool) -> TcpHandler {
    TcpHandler { host, port, timeout, sshd, dialer: dialer() }
}

/// Dial `host:port` within `timeout` with [`dialer`]; a standard sshd is
/// checked where `sshd` asks for it.
pub async fn dial_target(host: &str, port: u16, timeout: Duration, sshd: bool) -> Result<TcpStream, String> {
    pod_relay::reverse::tcp::dial_target(&dialer(), host, port, timeout, sshd).await
}
