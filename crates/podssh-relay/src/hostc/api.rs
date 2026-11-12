//! The two calls of hostc's API (`packages/client/src/api.ts` and
//! `connection.ts` of `akazwz/hostc` at `c19ff67`), each over a connection of
//! its own through `HTTPS_PROXY`: `POST /api/tunnels` with the header of the
//! version, whose `201` names the tunnel ([`create`]); then the upgrade of
//! `connectUrl` with the tunnel's bearer token ([`connect`]). The answer is
//! checked before it is used: the id is one of the server's (12 of its
//! alphabet), the URL is `https://` and a name under it, and `connectUrl`
//! is on the API's own host, so the token goes nowhere else. The token is
//! the service's own, never podssh's: it travels in its header alone and no
//! line or error quotes it.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::client::{self, ConnectError};
use podssh_ws::{handshake, ProxyChoice, Trust};
use serde_json::Value;

use super::{Service, PROTOCOL_HEADER, PROTOCOL_VERSION};
use crate::opentunnel::dial::BoxIo;

/// The path of the API's tunnels.
pub const TUNNELS: &str = "/api/tunnels";
/// The largest answer read: the server's is a few hundred bytes.
pub const MAX_BODY: usize = 16 * 1024;
/// The bound of each call, its connection and its answer: 15 s, as hostc's
/// client bounds its own, and the connection's 20 s before it.
pub const CALL_LIMIT: Duration = Duration::from_secs(35);
/// The alphabet and the length of a tunnel's id (`constants.ts`).
pub const ID_ALPHABET: &str = "abcdefghijkmnpqrstuvwxyz23456789";
pub const ID_LENGTH: usize = 12;

/// A dial in progress.
pub type Dialing = Pin<Box<dyn Future<Output = Result<BoxIo, String>> + Send>>;
/// How a node reaches a host of the server: `(host, port, tls)`. [`tls`],
/// or a test's pipe.
pub type Dial = Arc<dyn Fn(&str, u16, bool) -> Dialing + Send + Sync>;

/// TLS to each host of the server through `proxy`, verified with `trust`;
/// plain TCP, directly, to a server of the loopback (`tls` false), which
/// [`Service::parse`] allows alone.
pub fn tls(trust: Trust, proxy: ProxyChoice) -> Dial {
    Arc::new(move |host: &str, port: u16, tls: bool| -> Dialing {
        let (host, trust, proxy) = (host.to_string(), trust.clone(), proxy.clone());
        Box::pin(async move {
            let limit = crate::opentunnel::dial::CONNECT_LIMIT;
            if !tls {
                let tcp = podssh_ws::dial::dial(&host, port, &ProxyChoice::Direct, limit).await;
                return tcp.map(|tcp| Box::new(tcp) as BoxIo).map_err(|e| format!("{host}:{port}: {e}"));
            }
            let opened = client::open_tls(&host, port, &host, &trust, &proxy, limit).await;
            opened.map(|tls| Box::new(tls) as BoxIo).map_err(|e| format!("{host}:{port}: {e}"))
        })
    })
}

/// A tunnel that the server gave.
#[derive(Clone, PartialEq, Eq)]
pub struct Tunnel {
    pub id: String,
    /// Its name, which a visitor opens on [`Tunnel::web_port`].
    pub host: String,
    pub web_port: u16,
    /// Where its socket goes: over TLS or not, the host, the port, the path.
    pub connect: (bool, String, u16, String),
    /// The service's bearer token of the socket. Never in a line.
    token: String,
}

impl std::fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunnel").field("id", &self.id).field("host", &self.host).finish_non_exhaustive()
    }
}

impl Tunnel {
    /// The URL that a visitor opens.
    pub fn url(&self) -> String {
        match self.web_port {
            super::PORT => format!("https://{}", self.host),
            port => format!("https://{}", podssh_ws::dial::authority(&self.host, port)),
        }
    }
}

/// Why a call gave no tunnel, or no socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed {
    /// `426`: the server speaks another version of the protocol.
    Version(String),
    /// `401` or `404` of the socket: the tunnel is gone, a new one is asked.
    Gone(String),
    /// Another answer of no to this request, `429` among them.
    Refused(String),
    /// No answer, or one that a later try may change.
    ForNow(String),
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failed::Version(why) | Failed::Gone(why) | Failed::Refused(why) | Failed::ForNow(why) => f.write_str(why),
        }
    }
}

/// The failure of an answer of `status` with `body`, as hostc's client
/// sorts them (`errorFromResponse`).
pub fn failed(service: &Service, status: u16, body: &[u8]) -> Failed {
    let said = message(body);
    match status {
        426 => Failed::Version(super::refused_version(service, &said)),
        401 | 404 => Failed::Gone(format!("{service} answered {status}: {said}")),
        429 => Failed::Refused(format!(
            "{service} answered 429: {said} (at most {} tunnels a minute from one address)",
            super::CREATE_LIMIT
        )),
        400..=499 => Failed::Refused(format!("{service} answered {status}: {said}")),
        _ => Failed::ForNow(format!("{service} answered {status}: {said}")),
    }
}

/// The `error` of an answer's JSON, on one line, else its first words.
fn message(body: &[u8]) -> String {
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    let text = parsed.as_ref().and_then(|v| v.get("error")).and_then(Value::as_str).map(str::to_string);
    let text = text.unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
    podssh_ws::text::one_line(&text).chars().take(200).collect()
}

/// Ask `service` for a tunnel.
pub async fn create(service: &Service, dial: &Dial) -> Result<Tunnel, Failed> {
    let asking = async {
        let mut io = dial(&service.host, service.port, service.tls).await.map_err(Failed::ForNow)?;
        let version = PROTOCOL_VERSION.to_string();
        let headers = [(PROTOCOL_HEADER, version.as_str()), ("Accept", "application/json")];
        // No body: the server takes none as no prefix (`index.ts`).
        let authority = service.authority();
        let exchange = podssh_ws::http::exchange(&mut io, "POST", &authority, TUNNELS, &headers, b"", MAX_BODY);
        exchange.await.map_err(|e| Failed::ForNow(format!("{service}: {e}")))
    };
    let response = tokio::time::timeout(CALL_LIMIT, asking)
        .await
        .map_err(|_| Failed::ForNow(format!("{service}: no tunnel within {} s", CALL_LIMIT.as_secs())))??;
    match response.status {
        201 => parse(service, &response.body).map_err(|why| Failed::ForNow(format!("{service}: {why}"))),
        status => Err(failed(service, status, &response.body)),
    }
}

/// The server's `201`: `{id, url, connectUrl, token}`.
pub fn parse(service: &Service, body: &[u8]) -> Result<Tunnel, String> {
    let value: Value = serde_json::from_slice(body).map_err(|_| "its answer is not JSON".to_string())?;
    let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::trim);
    let id = text("id").filter(|id| is_id(id)).ok_or("its answer names no id of the server's alphabet")?;
    let url = text("url").ok_or("its answer names no URL")?;
    let (scheme, host, mut web_port, _) = split_url(url)?;
    // A server of the loopback, under its local runtime, names http://: its
    // tunnels' names are taken by TLS on 443 in front of it, as the hosted
    // server's are, unless the URL names a port.
    let local = scheme == "http" && !service.tls;
    if local && !url.trim_start_matches("http://").split('/').next().unwrap_or_default().contains(':') {
        web_port = super::PORT;
    }
    // The id leads the name, with or without a prefix of the server's list.
    let label = host.split('.').next().unwrap_or_default();
    if !(scheme == "https" || local) || !(label == id || label.ends_with(&format!("-{id}"))) || !host.contains('.') {
        return Err(format!("its URL {host} is not https:// and a name of the id {id}"));
    }
    let (scheme, connect_host, port, path) = split_url(text("connectUrl").ok_or("its answer names no connectUrl")?)?;
    let tls = match scheme.as_str() {
        "wss" => true,
        "ws" if !service.tls => false,
        _ => return Err("its connectUrl is not wss://, or ws:// of a server of the loopback".into()),
    };
    if !connect_host.eq_ignore_ascii_case(&service.host) {
        return Err(format!("its connectUrl is on {connect_host}, not on the API's host {}", service.host));
    }
    let token = text("token").filter(|t| is_token(t)).ok_or("its answer names no token that a header can carry")?;
    let connect = (tls, connect_host, port, path);
    Ok(Tunnel { id: id.to_string(), host, web_port, connect, token: token.to_string() })
}

/// Whether `id` is one of the server's ids.
pub fn is_id(id: &str) -> bool {
    id.len() == ID_LENGTH && id.chars().all(|c| ID_ALPHABET.contains(c))
}

/// Whether `token` fits a header as one word: base64url of an HMAC.
fn is_token(token: &str) -> bool {
    (16..=256).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.~+/=".contains(&b))
}

/// The scheme, the host, the port and the path of `SCHEME://HOST[:PORT][/PATH]`,
/// with no user, query or fragment.
fn split_url(url: &str) -> Result<(String, String, u16, String), String> {
    let (scheme, rest) = url.split_once("://").ok_or("a URL with no scheme")?;
    let scheme = scheme.to_ascii_lowercase();
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    if path.contains(['?', '#']) || path.bytes().any(|b| !b.is_ascii_graphic()) {
        return Err("a URL with a query, or a path of other than ASCII".into());
    }
    let (host, port) = crate::pinggy::host_port(authority, "the hostc road")?;
    let default = if matches!(scheme.as_str(), "https" | "wss") { super::PORT } else { 80 };
    Ok((scheme, host.to_ascii_lowercase(), port.unwrap_or(default), path.to_string()))
}

/// The upgrade request of the tunnel's socket, with `key`: no extension is
/// offered, as hostc's client turns `perMessageDeflate` off.
pub fn connect_request(tunnel: &Tunnel, key: &str) -> Vec<u8> {
    let (tls, host, port, path) = &tunnel.connect;
    let authority = match *port == if *tls { super::PORT } else { 80 } {
        true => host.clone(),
        false => podssh_ws::dial::authority(host, *port),
    };
    let mut text =
        format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {}\r\n", podssh_ws::dial::user_agent());
    text.push_str(&format!("Authorization: Bearer {}\r\n{PROTOCOL_HEADER}: {PROTOCOL_VERSION}\r\n", tunnel.token));
    text.push_str("Connection: Upgrade\r\nUpgrade: websocket\r\n");
    text.push_str(&format!("Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"));
    text.into_bytes()
}

/// The tunnel's socket: the stream after the 101, and the bytes read past it.
pub async fn connect(service: &Service, tunnel: &Tunnel, dial: &Dial) -> Result<(BoxIo, Vec<u8>), Failed> {
    let (tls, host, port, _) = &tunnel.connect;
    let opening = async {
        let io = dial(host, *port, *tls).await.map_err(Failed::ForNow)?;
        let key = handshake::generate_key().map_err(|e| Failed::ForNow(format!("{service}: {e}")))?;
        match client::upgrade_with(io, &connect_request(tunnel, &key), &key).await {
            Ok(opened) => Ok(opened),
            Err(ConnectError::Refused { status, body }) => Err(failed(service, status, body.as_bytes())),
            Err(e) => Err(Failed::ForNow(format!("{service}: the tunnel's socket: {e}"))),
        }
    };
    tokio::time::timeout(CALL_LIMIT, opening)
        .await
        .map_err(|_| Failed::ForNow(format!("{service}: no socket within {} s", CALL_LIMIT.as_secs())))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Service {
        Service { host: "hostc.example.test".into(), port: 443, tls: true, zone: Some("hostc.app.test".into()) }
    }

    /// An answer as hostc's `createTunnel` writes one (`index.ts`).
    const ANSWER: &[u8] = br#"{"id":"abcdefghijkm","url":"https://abcdefghijkm.hostc.app.test","connectUrl":"wss://hostc.example.test/api/tunnels/abcdefghijkm/connect","token":"Zm9vYmFyYmF6cXV4cXV1eA-_"}"#;

    #[test]
    fn the_answer_of_hostc_s_server_gives_a_tunnel_and_a_bad_one_none() {
        let tunnel = parse(&service(), ANSWER).unwrap();
        assert_eq!(tunnel.url(), "https://abcdefghijkm.hostc.app.test");
        assert_eq!(
            tunnel.connect,
            (true, "hostc.example.test".into(), 443, "/api/tunnels/abcdefghijkm/connect".into())
        );
        assert!(!format!("{tunnel:?}").contains("Zm9v"), "the token is in no line");
        let other_host = String::from_utf8_lossy(ANSWER).replace("wss://hostc.example.test", "wss://elsewhere.test");
        assert!(parse(&service(), other_host.as_bytes()).unwrap_err().contains("not on the API's host"));
        let plain = String::from_utf8_lossy(ANSWER).replace("wss://", "ws://");
        assert!(parse(&service(), plain.as_bytes()).is_err(), "ws:// of a server over TLS");
        for (from, to) in [("abcdefghijkm\",\"url", "ABC\",\"url"), ("https://abcdefghijkm.", "https://other.")] {
            let bad = String::from_utf8_lossy(ANSWER).replace(from, to);
            assert!(parse(&service(), bad.as_bytes()).is_err(), "{bad}");
        }
        let prefixed = String::from_utf8_lossy(ANSWER).replace("https://abcdefghijkm.", "https://codex-abcdefghijkm.");
        assert_eq!(parse(&service(), prefixed.as_bytes()).unwrap().host, "codex-abcdefghijkm.hostc.app.test");
        let http = String::from_utf8_lossy(ANSWER).replace("https://", "http://");
        assert!(parse(&service(), http.as_bytes()).is_err(), "http:// of the hosted server");
    }

    /// The answer of hostc's server under its local runtime (`cf dev`), as
    /// its workflow runs it: `http://` and `ws://` of the loopback.
    #[test]
    fn a_server_of_the_loopback_names_http_and_ws_and_its_names_are_taken_on_443() {
        let local = Service::parse("http://127.0.0.1:8787").unwrap();
        let body = br#"{"id":"abcdefghijkm","url":"http://abcdefghijkm.hostc.test","connectUrl":"ws://127.0.0.1:8787/api/tunnels/abcdefghijkm/connect","token":"Zm9vYmFyYmF6cXV4cXV1eA-_"}"#;
        let tunnel = parse(&local, body).unwrap();
        assert_eq!(
            (tunnel.url(), tunnel.connect.0, tunnel.connect.2),
            ("https://abcdefghijkm.hostc.test".into(), false, 8787)
        );
        let ported = String::from_utf8_lossy(body).replace("hostc.test\"", "localhost:8787\"");
        assert_eq!(parse(&local, ported.as_bytes()).unwrap().web_port, 8787);
    }

    #[test]
    fn the_socket_s_request_carries_the_version_and_the_token_and_offers_no_extension() {
        let tunnel = parse(&service(), ANSWER).unwrap();
        let asked = String::from_utf8(connect_request(&tunnel, "dGhlIHNhbXBsZSBub25jZQ==")).unwrap();
        assert!(asked.starts_with("GET /api/tunnels/abcdefghijkm/connect HTTP/1.1\r\nHost: hostc.example.test\r\n"));
        assert!(asked.contains("\r\nhostc-protocol: 5\r\n") && asked.contains("\r\nAuthorization: Bearer Zm9v"));
        assert!(!asked.to_ascii_lowercase().contains("sec-websocket-extensions"), "{asked}");
    }

    #[test]
    fn each_answer_of_no_is_sorted_as_hostc_s_client_sorts_it() {
        let words = br#"{"error":"This hostc version is not supported by the server."}"#;
        assert!(matches!(failed(&service(), 426, words), Failed::Version(why) if why.contains("version 5")));
        assert!(matches!(failed(&service(), 404, b"{}"), Failed::Gone(_)));
        assert!(matches!(failed(&service(), 401, b""), Failed::Gone(_)));
        assert!(matches!(failed(&service(), 429, b""), Failed::Refused(why) if why.contains("20 tunnels a minute")));
        assert!(matches!(failed(&service(), 503, b"busy"), Failed::ForNow(_)));
    }
}
