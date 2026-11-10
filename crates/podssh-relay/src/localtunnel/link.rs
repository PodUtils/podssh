//! A client's link to a node behind a localtunnel server: TLS by name to
//! the tunnel's name on port 443, checked against the host's roots as each
//! name is (the hosted server's names are under its own certificate), then
//! a WebSocket to `/`, which the server passes to one of the node's
//! connections with its head as it came (`lib/Client.js`, `handleUpgrade`).
//! The request carries [`super::HEADER`]: the hosted server puts a page in
//! front of a request whose `User-Agent` is a browser's (its operator,
//! localtunnel/localtunnel#663, 2024-07-30), and answers it 511 (the same);
//! podssh's is not a browser's, and the header keeps the page away should
//! that change. A 511 is named as that page.

use std::time::Duration;

use podssh_ws::client::{self, ConnectError, RelaySession, RelayStream, WRITE_TIMEOUT};
use podssh_ws::{handshake, ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{HEADER, REMINDER};

/// The path of the node's links.
pub const PATH: &str = "/";
/// What podssh says it is: never a browser's words.
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"));

/// The upgrade request to the tunnel's name `host` (`NAME[:PORT]`), with
/// `key`. A host that a request line cannot carry is refused.
pub fn request(host: &str, key: &str) -> Result<Vec<u8>, String> {
    if host.is_empty() || host.contains(|c: char| c.is_control() || c.is_whitespace() || "/?#@".contains(c)) {
        return Err("a tunnel's name is not a host".into());
    }
    let mut text = format!("GET {PATH} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n");
    // Any value that is not false passes the page for browsers.
    text.push_str(&format!("{HEADER}: podssh\r\n"));
    text.push_str("Connection: Upgrade\r\nUpgrade: websocket\r\n");
    text.push_str(&format!("Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"));
    Ok(text.into_bytes())
}

/// The words of a refused upgrade.
pub fn refusal(host: &str, status: u16, body: &str) -> String {
    match status {
        REMINDER => format!(
            "{host} answered {REMINDER}, the localtunnel server's page for browsers: the request's {HEADER} did not \
             pass it"
        ),
        // The hosted server's words for a name that holds no tunnel now.
        404 | 503 => format!("{host} holds no tunnel now ({status}): the node is away, or under another name"),
        _ => format!("{host} refused the upgrade ({status}): {}", podssh_ws::text::one_line(body)),
    }
}

/// The upgrade over `stream`, a stream to the server for `host`.
pub async fn over<S>(stream: S, host: &str, timeout: Duration) -> Result<RelaySession<S>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = handshake::generate_key().map_err(|e| format!("{host}: {e}"))?;
    let request = request(host, &key)?;
    match tokio::time::timeout(timeout, client::upgrade_with(stream, &request, &key)).await {
        Err(_) => Err(format!("{host}: no answer to the WebSocket upgrade within {} s", timeout.as_secs())),
        Ok(Err(ConnectError::Refused { status, body })) => Err(refusal(host, status, &body)),
        Ok(Err(e)) => Err(format!("{host}: {e}")),
        Ok(Ok((stream, pending))) => {
            Ok(RelaySession::new(stream, pending, Some(client::DEFAULT_IDLE_TIMEOUT), WRITE_TIMEOUT))
        }
    }
}

/// A link to the tunnel's name `host` (`NAME[:PORT]`) through `proxy`, its
/// TLS checked with `trust`.
pub async fn open(
    host: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<RelaySession<RelayStream>, String> {
    let (name, port) = crate::pinggy::host_port(host, "the localtunnel road")?;
    let port = port.unwrap_or(super::PORT);
    let tls = client::open_tls(&name, port, &name, trust, proxy, timeout).await.map_err(|e| format!("{host}: {e}"))?;
    over(tls, host, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_upgrade_carries_the_header_that_passes_the_page_and_no_browser_s_words() {
        let asked = String::from_utf8(request("podssh-0011.loca.lt", "dGhlIHNhbXBsZSBub25jZQ==").unwrap()).unwrap();
        assert!(asked.starts_with("GET / HTTP/1.1\r\nHost: podssh-0011.loca.lt\r\n"), "{asked}");
        assert!(asked.contains("\r\nBypass-Tunnel-Reminder: podssh\r\n"), "{asked}");
        assert!(asked.contains("\r\nUser-Agent: podssh/") && !asked.contains("Mozilla"), "{asked}");
        assert!(asked.ends_with("Sec-WebSocket-Version: 13\r\n\r\n"), "{asked}");
        assert!(request("a b", "k").is_err() && request("h/x", "k").is_err() && request("", "k").is_err());
    }

    #[test]
    fn a_refusal_names_the_page_for_browsers_and_a_name_with_no_tunnel() {
        assert!(refusal("n.loca.lt", 511, "").contains("page for browsers"));
        assert!(refusal("n.loca.lt", 503, "503 - Tunnel Unavailable").contains("holds no tunnel now"));
        assert!(refusal("n.loca.lt", 502, "bad\ngateway").contains("bad gateway"));
    }
}
