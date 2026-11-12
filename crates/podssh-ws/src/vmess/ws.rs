//! VMess over a WebSocket (Xray-core's and v2ray's `ws`): the upgrade goes to
//! the link's path with the link's `host`, then each binary message is a piece
//! of VMess's stream, both ways, as VLESS's WebSocket carries its own
//! (`crate::vless::ws`, whose pump this road shares). The sealed header rides
//! the first message that the body's pump writes; no early data goes in a
//! header.

use tokio::io::DuplexStream;

use super::link::Server;
use super::VmessError;
use crate::client::{self, ConnectError};
use crate::session::RelaySession;
use crate::vless::Dial;
use crate::{handshake, url};

/// The largest message taken: Xray's writer sends what each write gave.
const RECEIVE_CAP: usize = 1024 * 1024;

/// The upgrade; the stream is one end of a pipe that the shared pump copies
/// to and from the WebSocket.
pub(super) async fn open(server: &Server, dial: &Dial<'_>) -> Result<DuplexStream, VmessError> {
    let key = handshake::generate_key().map_err(|e| VmessError::Carry(e.to_string()))?;
    let request = request(server, &key);
    let stream = if server.tls {
        let tls = client::open_tls(&server.host, server.port, &server.sni, dial.trust, dial.proxy, dial.timeout)
            .await
            .map_err(|e| failed(e, &server.path))?;
        url::Stream::Tls(Box::new(tls))
    } else {
        let tcp = crate::dial::dial(&server.host, server.port, dial.proxy, dial.timeout).await;
        url::Stream::Plain(Box::new(tcp.map_err(VmessError::Dial)?))
    };
    let upgraded = tokio::time::timeout(dial.timeout, client::upgrade_with(stream, &request, &key))
        .await
        .map_err(|_| VmessError::Carry(format!("no answer to the upgrade within {} s", dial.timeout.as_secs())))?;
    let (stream, pending) = upgraded.map_err(|e| failed(e, &server.path))?;
    let idle = Some(client::DEFAULT_IDLE_TIMEOUT);
    let session = RelaySession::new(stream, pending, idle, client::WRITE_TIMEOUT).naming("the VMess server");
    session.set_receive_cap(RECEIVE_CAP);
    Ok(crate::vless::ws::spawn(session, dial.at_end))
}

/// The upgrade request: the link's path and `Host`, no subprotocol and no
/// `Origin`, as Xray-core's client sends it.
fn request(server: &Server, key: &str) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        server.path,
        server.authority,
        url::USER_AGENT
    )
    .into_bytes()
}

/// A failure of the dial or the upgrade, in this road's words.
fn failed(e: ConnectError, path: &str) -> VmessError {
    let path = path.split('?').next().unwrap_or("/");
    match e {
        ConnectError::Dial(e) => VmessError::Dial(e),
        ConnectError::Refused { status, body } => {
            let said = if body.is_empty() { String::new() } else { format!(" ({body})") };
            let why = format!(
                "the WebSocket upgrade at {path}{said}; a path that it does not serve, or a proxy or a front end \
                 that does not pass the upgrade, answers so"
            );
            VmessError::Refused { status, why }
        }
        ConnectError::Tls(why) => VmessError::Carry(format!("TLS: {why}")),
        ConnectError::Upgrade(why) => VmessError::Carry(format!("the WebSocket upgrade: {why}")),
        other => VmessError::Carry(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn the_upgrade_names_the_link_s_path_and_host_and_no_subprotocol() {
        let json = r#"{"add":"203.0.113.9","port":"443","id":"550e8400-e29b-41d4-a716-446655440000","aid":"0",
            "net":"ws","host":"cdn.example","path":"/vm?ed=2048","tls":"tls"}"#;
        let link = format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(json));
        let server = Server::parse(&link).unwrap();
        let text = String::from_utf8(request(&server, "dGhlIHNhbXBsZSBub25jZQ==")).unwrap();
        assert!(text.starts_with("GET /vm?ed=2048 HTTP/1.1\r\nHost: cdn.example\r\n"), "{text}");
        assert!(!text.to_ascii_lowercase().contains("sec-websocket-protocol"), "{text}");
        let refused = failed(ConnectError::Refused { status: 404, body: String::new() }, "/vm?ed=2048");
        let line = refused.line("vmess://203.0.113.9:443/vm", "h:22");
        assert!(line.contains("refused the WebSocket upgrade at /vm;") && line.ends_with("HTTP 404"), "{line}");
    }
}
