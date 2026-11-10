//! A GET over HTTPS through podssh's way out: pod-proxy's client
//! ([`pod_proxy::Client`]) with podssh's dial, its TLS context, its user
//! agent and its reader of HTTPS records, so that a hello is sealed with ECH
//! where the user asks for it. A failure is a [`ConnectError`], as each
//! caller of podssh reads it.

use std::sync::Arc;
use std::time::Duration;

use super::ConnectError;
use crate::dial::{self, ProxyChoice};
use crate::http;
use crate::tls::{self, Trust};

/// GET over HTTPS, through the same path as everything else (proxy, TLS
/// verification, sealed with ECH where asked, bounded waits): pod-proxy's
/// client ([`getter`]). The body is capped at `max_body` bytes.
pub async fn https_get(
    host: &str,
    port: u16,
    path: &str,
    max_body: usize,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<http::Response, ConnectError> {
    let client = getter(proxy);
    let get = client.https_get(host, port, path, max_body, trust, timeout);
    get.await.map_err(|failure| get_error(failure, timeout, host, port))
}

/// GET over HTTPS as [`https_get`], with `accept` as the answer's type: a
/// resolver's JSON API answers `application/dns-json` (T-339).
#[allow(clippy::too_many_arguments)]
pub async fn https_get_accepting(
    host: &str,
    port: u16,
    path: &str,
    accept: &str,
    max_body: usize,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<http::Response, ConnectError> {
    let client = getter(proxy);
    let get = client.https_get_accepting(host, port, path, accept, max_body, trust, timeout);
    get.await.map_err(|failure| get_error(failure, timeout, host, port))
}

/// pod-proxy's client over the dial of `proxy`, with the process's TLS and
/// podssh's user agent; a name's HTTPS record is read through that proxy.
pub fn getter(proxy: &ProxyChoice) -> pod_proxy::Client {
    pod_proxy::Client::new(tls::context().clone(), Arc::new(dial::dialer(proxy, false)))
        .with_user_agent(dial::user_agent())
        .with_records(Arc::new(crate::ech::Records(proxy.clone())))
}

/// The failure of a GET as podssh's callers read it: the dial's error as
/// it was, the handshake's as a TLS road says it, and a failure of the
/// exchange as the step of the request (`pod_ws::client::request_error`).
fn get_error(failure: pod_core::Failure, limit: Duration, host: &str, port: u16) -> ConnectError {
    pod_ws::client::request_error(failure, limit, host, port)
}
