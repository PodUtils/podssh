//! A Bare server as a hop of a WebSocket road (T-740): TompHTTP's Bare v3
//! (`tomphttp/specifications:BareServerV3.md`). The client opens a
//! WebSocket to the node's `v3/`, sends one text frame of JSON that names
//! the far `ws:` or `wss:` URL and the headers of the far request, reads
//! the node's `open`, and from then each binary message is the far
//! WebSocket's, both ways, as the specification keeps each message's type.
//! The node dials the far host itself, so a proxy on the way sees the
//! node's name alone; the node sees the far host's name, and its own TLS to
//! the far host ends there: the road's SSH and podssh's end-to-end channel
//! keep the bytes. A node is a `pod-services` kind (`bare-node`), never a
//! host in this repository.

use std::time::Duration;

use crate::client::ConnectError;
use crate::dial::ProxyChoice;
use crate::frame::{OPCODE_BINARY, OPCODE_TEXT};
use crate::session::RelaySession;
use crate::tls::Trust;
use crate::url::{self, Stream, WsUrl, USER_AGENT};

/// The longest `open` that is read.
const OPEN_MOST: usize = 4096;

/// The node's WebSocket of version 3: its base path with `v3/`, as the
/// node's `/` names the path of its versions (`/bare/` gives `/bare/v3/`).
pub fn hop_url(node: &WsUrl) -> WsUrl {
    let base = node.target.split('?').next().unwrap_or("/");
    let base = if base.ends_with('/') { base.to_string() } else { format!("{base}/") };
    WsUrl { target: format!("{base}v3/"), ..node.clone() }
}

/// The far URL as the node dials it: `wss://HOST:PORT/PATH`, an IPv6 host
/// in brackets.
pub fn remote(far: &WsUrl) -> String {
    let scheme = if far.tls { "wss" } else { "ws" };
    let host = if far.host.contains(':') { format!("[{}]", far.host) } else { far.host.clone() };
    format!("{scheme}://{host}:{}{}", far.port, far.target)
}

/// The first text frame: `connect`, with the far URL and the headers that
/// the node sends to it: `Host` as the far end expects it and podssh's own
/// `User-Agent`, no `Origin`, as a program sends none.
pub fn connect_message(far: &WsUrl) -> String {
    let default_port = if far.tls { 443 } else { 80 };
    let bracketed = if far.host.contains(':') { format!("[{}]", far.host) } else { far.host.clone() };
    let host = if far.port == default_port { bracketed } else { format!("{bracketed}:{}", far.port) };
    serde_json::json!({
        "type": "connect",
        "remote": remote(far),
        "protocols": [],
        "headers": { "Host": host, "User-Agent": USER_AGENT },
        "forwardHeaders": [],
    })
    .to_string()
}

/// Whether the node's first frame is its `open`: a text frame of JSON whose
/// `type` is `open`. Else why not, in the node's own words where it gave
/// some.
pub fn read_open(opcode: u8, payload: &[u8]) -> Result<(), String> {
    if opcode == OPCODE_BINARY {
        return Err("the Bare node answered with a binary message before its open".into());
    }
    if opcode != OPCODE_TEXT {
        return Err(format!("the Bare node answered with a frame of opcode {opcode} before its open"));
    }
    let text = String::from_utf8_lossy(&payload[..payload.len().min(OPEN_MOST)]);
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| "the Bare node's first message is not JSON".to_string())?;
    match value.get("type").and_then(|t| t.as_str()) {
        Some("open") => Ok(()),
        Some(other) => {
            let why = value.get("message").and_then(|m| m.as_str()).unwrap_or_default();
            Err(format!("the Bare node said {other:?} in place of open: {}", crate::text::one_line(why)))
        }
        None => Err("the Bare node's first message names no type".into()),
    }
}

/// `far` through the Bare node `node`: the node's WebSocket, the `connect`,
/// the `open` within `timeout`; then the session's binary messages are the
/// far WebSocket's. A refusal of the node, before or in place of `open`, is
/// an upgrade's failure, so that the road names it as the far end's.
pub async fn dial(
    node: &WsUrl,
    far: &WsUrl,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
    idle: Option<Duration>,
) -> Result<RelaySession<Stream>, ConnectError> {
    let hop = hop_url(node);
    let session = url::dial(&hop, trust, proxy, timeout, idle).await?;
    let refused = |why: String| ConnectError::Upgrade(format!("through the Bare node {}: {why}", node.shown()));
    session.send_text(&connect_message(far)).await.map_err(|e| refused(format!("the connect: {e}")))?;
    let first = tokio::time::timeout(timeout, session.read_frame())
        .await
        .map_err(|_| refused(format!("no open within {} s", timeout.as_secs())))?
        .map_err(|e| refused(format!("the node ended before its open: {e}")))?;
    read_open(first.opcode, &first.payload).map_err(refused)?;
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> WsUrl {
        WsUrl::parse(text).unwrap()
    }

    #[test]
    fn the_hop_is_the_node_s_path_with_v3() {
        assert_eq!(hop_url(&url("wss://openbare.example/bare/")).target, "/bare/v3/");
        assert_eq!(hop_url(&url("wss://node.example/bare")).target, "/bare/v3/");
        assert_eq!(hop_url(&url("wss://node.example/")).target, "/v3/");
        assert_eq!(hop_url(&url("wss://node.example/b/?x=1")).target, "/b/v3/", "no query");
    }

    #[test]
    fn the_connect_names_the_far_url_and_its_host_and_no_origin() {
        let message = connect_message(&url("wss://relay.example/ssh?x=1"));
        let value: serde_json::Value = serde_json::from_str(&message).unwrap();
        assert_eq!(value["type"], "connect");
        assert_eq!(value["remote"], "wss://relay.example:443/ssh?x=1");
        assert_eq!(value["headers"]["Host"], "relay.example");
        assert!(value["headers"].get("Origin").is_none(), "{message}");
        let other = connect_message(&url("ws://[2001:db8::1]:8080/"));
        let value: serde_json::Value = serde_json::from_str(&other).unwrap();
        assert_eq!(value["remote"], "ws://[2001:db8::1]:8080/");
        assert_eq!(value["headers"]["Host"], "[2001:db8::1]:8080");
    }

    #[test]
    fn only_a_text_open_opens() {
        assert_eq!(read_open(OPCODE_TEXT, br#"{"type":"open","protocol":"","setCookies":[]}"#), Ok(()));
        assert!(read_open(OPCODE_BINARY, br#"{"type":"open"}"#).unwrap_err().contains("binary"));
        let refused = read_open(OPCODE_TEXT, br#"{"type":"error","message":"forbidden\nhost"}"#).unwrap_err();
        assert!(refused.contains("\"error\"") && refused.contains("forbidden") && !refused.contains('\n'), "{refused}");
        assert!(read_open(OPCODE_TEXT, b"not json").unwrap_err().contains("not JSON"));
    }
}
