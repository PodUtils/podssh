//! DERP at `/derp` (T-106): the relay role as a DERP server, as Tailscale's
//! derper serves it with `--verify-clients`, for the node keys that its
//! owner lists (`podssh relay serve --derp-keys FILE`). A node of `podssh ts
//! --ts-mode relay --ts-relay HOST:PORT` pins this role then, in the place
//! of the operator's Tailscale relay, whose allowlist only its operator
//! holds (Q63: no entry waits for him). It takes both of derper's forms of
//! the connection: a WebSocket of the subprotocol `derp`, which the fork
//! dials in `relay` mode, and the HTTP upgrade `Upgrade: DERP`, which
//! tailscaled and the fork's `tcp` mode dial. The handshake and the frames
//! are derper's (tailscale/tailscale:derp at v1.104.4, as
//! `crate::derp::frame` reads them): the server's key, the client's info
//! sealed to it, the server's info sealed back; then each packet goes to the
//! key that it names (`derp_hub.rs`). A key that is not in the file is
//! closed with 1008 "not authorized", the close of the operator's relay,
//! which `podssh ts` reads as a refusal of the node key (exit 77). The file
//! is read again at each login, so its owner adds a key with no restart.
//! The packets are WireGuard's, sealed end to end: the role sees keys,
//! sizes and times, never a byte of a session.

use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use podssh_ws::frame as ws;
use podssh_ws::http::request::{self, Request};
use podssh_ws::server;
use podssh_ws::session::RelaySession;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use super::{answer, Config};
use crate::derp::frame::{HEADER, KEY, MAX_FRAME};
use crate::derp::{Key, Secret};

#[path = "derp_hub.rs"]
mod hub;
pub use hub::Hub;

/// The path of the connection, as the fork, tailscaled and derper name it.
pub const PATH: &str = "/derp";
/// derper's probes of latency, each an empty 200, which a client may ask
/// before it picks its home.
const PROBES: [&str; 2] = ["/derp/probe", "/derp/latency-check"];
/// The close of a key that the file does not list: the operator's relay's.
pub const REFUSED_CODE: u16 = 1008;
pub const REFUSED_REASON: &str = "not authorized";
/// The bound of each write of the HTTP upgrade's form, as a WebSocket's
/// session bounds its own: a reader that takes nothing ends its link.
const WRITE_WAIT: Duration = Duration::from_secs(30);

/// The DERP server of this process: one role serves it, so it lives beside
/// the role's `Config`, which each route of the role and each of its tests
/// builds, and which DERP needs not touch.
static HUB: OnceLock<Arc<Hub>> = OnceLock::new();

/// Serve DERP at `/derp` for the node keys of `keys`, from now on. The file
/// is read once here, so that a file that cannot be read or holds a line
/// that is not a key is said at the start; `Ok` holds the number of keys.
/// A second call keeps the first file.
pub fn enable(keys: &Path) -> Result<usize, String> {
    let listed = read_keys(keys)?;
    let _ = HUB.set(Arc::new(Hub::new(Secret::from_bytes(rand::random()), keys.to_path_buf())));
    Ok(listed.len())
}

/// Whether `path` is DERP's, once [`enable`] was called.
pub fn serves(path: &str) -> bool {
    HUB.get().is_some() && (path == PATH || PROBES.contains(&path))
}

/// The keys of a file of node keys: one a line, `nodekey:HEX` as `tailscale
/// status`, the fork and this role's refusals write one, or the 64 hex
/// digits alone; a blank line and a line that starts with `#` are none. A
/// line that is no key is an error that names it, so that a typing slip
/// admits nobody silently.
pub fn parse_keys(text: &str) -> Result<Vec<Key>, String> {
    let mut keys = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let hex = line.strip_prefix("nodekey:").unwrap_or(line);
        keys.push(key_of(hex).ok_or_else(|| format!("line {}: not a node key (nodekey: and 64 hex digits)", n + 1))?);
    }
    Ok(keys)
}

fn key_of(hex: &str) -> Option<Key> {
    if hex.len() != 2 * KEY || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut raw = [0u8; KEY];
    for (i, byte) in raw.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(Key(raw))
}

/// The keys of the file at `path`, read now.
pub(crate) fn read_keys(path: &Path) -> Result<Vec<Key>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_keys(&text).map_err(|why| format!("{}: {why}", path.display()))
}

/// A DERP frame: its kind, the length of its body, the body.
pub fn framed(t: u8, body: &[u8]) -> Vec<u8> {
    [&[t][..], &(body.len() as u32).to_be_bytes()[..], body].concat()
}

/// Serve one request of DERP's: a probe, or the connection of a node in
/// either form.
pub async fn request<S>(mut stream: S, head: Request, pending: Vec<u8>, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(hub) = HUB.get().cloned() else {
        return answer(&mut stream, request::refusal(404, "/derp: this relay serves no DERP", &[])).await;
    };
    let path = head.target.split('?').next().unwrap_or_default();
    if path != PATH {
        return answer(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec())
            .await;
    }
    // derper's own upgrade, which tailscaled dials: raw frames after the 101.
    if head.method == "GET" && head.has_token("upgrade", "derp") {
        // A client of "fast start" reads no 101, and sends its frames at once.
        let fast = head.header("derp-fast-start") == Some("1");
        if !fast && stream.write_all(&switching_raw(&hub.public())).await.is_err() {
            return;
        }
        let (reader, writer) = tokio::io::split(stream);
        let link = Link::Raw { reader: Mutex::new(reader), writer: Mutex::new(writer) };
        return hub.serve(Arc::new(link), pending, &cfg).await;
    }
    // A WebSocket: derper's handler takes the subprotocol `derp` alone.
    let derp = head.header("sec-websocket-protocol").is_some_and(|p| p.split(',').any(|p| p.trim() == "derp"));
    if !derp {
        let why = "/derp: a WebSocket of the subprotocol derp, or Upgrade: DERP";
        return answer(&mut stream, request::refusal(426, why, &[("Sec-WebSocket-Protocol", "derp")])).await;
    }
    let key = match server::check_upgrade(&head) {
        Ok(key) => key,
        Err(refused) => return answer(&mut stream, refused.answer()).await,
    };
    if stream.write_all(&switching(&key)).await.is_err() {
        return;
    }
    let session = server::session(stream, pending, None);
    // A message may hold a whole frame: a packet of 64 KiB and its header.
    session.set_receive_cap(MAX_FRAME + HEADER);
    hub.serve(Arc::new(Link::Ws(Box::new(session))), Vec::new(), &cfg).await;
}

/// The 101 of RFC 6455, with the subprotocol that the client asked for.
fn switching(key: &str) -> Vec<u8> {
    let mut answer = server::switching(key);
    // Before the blank line that ends the head.
    answer.truncate(answer.len() - 2);
    answer.extend_from_slice(b"Sec-WebSocket-Protocol: derp\r\n\r\n");
    answer
}

/// derper's 101 of the HTTP upgrade: its version and its key, which a
/// client may check against the key of the first frame.
fn switching_raw(public: &Key) -> Vec<u8> {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\nDerp-Version: 2\r\n\
         Derp-Public-Key: {}\r\n\r\n",
        public.hex()
    )
    .into_bytes()
}

/// A node's connection, in either of derper's forms: frames that span the
/// messages of a WebSocket, or the bytes of the HTTP upgrade.
pub(crate) enum Link<S> {
    // Boxed: a session is much larger than the halves of the other form.
    Ws(Box<RelaySession<S>>),
    Raw { reader: Mutex<ReadHalf<S>>, writer: Mutex<WriteHalf<S>> },
}

impl<S: AsyncRead + AsyncWrite + Send> Link<S> {
    /// Send one frame; `false` when the link is gone.
    pub(crate) async fn send(&self, frame: &[u8]) -> bool {
        match self {
            Link::Ws(session) => session.send_binary(frame).await.is_ok(),
            Link::Raw { writer, .. } => {
                let mut writer = writer.lock().await;
                let write = async {
                    writer.write_all(frame).await?;
                    writer.flush().await
                };
                matches!(tokio::time::timeout(WRITE_WAIT, write).await, Ok(Ok(())))
            }
        }
    }

    /// More of the client's bytes, at the end of `stream`; `false` at the
    /// end of the link.
    pub(crate) async fn more(&self, stream: &mut Vec<u8>) -> bool {
        match self {
            Link::Ws(session) => loop {
                let Ok(message) = session.read_frame().await else { return false };
                match message.opcode {
                    ws::OPCODE_BINARY => {
                        stream.extend_from_slice(&message.payload);
                        return true;
                    }
                    ws::OPCODE_CLOSE => return false,
                    _ => {}
                }
            },
            Link::Raw { reader, .. } => {
                let mut chunk = vec![0u8; 64 * 1024];
                match reader.lock().await.read(&mut chunk).await {
                    Ok(n) if n > 0 => {
                        stream.extend_from_slice(&chunk[..n]);
                        true
                    }
                    _ => false,
                }
            }
        }
    }

    /// The end of the link, with a WebSocket's close code where it has one;
    /// derper ends the HTTP upgrade's form with no word.
    pub(crate) async fn close(&self, code: u16, reason: &str) {
        match self {
            Link::Ws(session) => {
                let _ = session.send_close(code, reason).await;
            }
            Link::Raw { writer, .. } => {
                let _ = tokio::time::timeout(WRITE_WAIT, writer.lock().await.shutdown()).await;
            }
        }
    }
}

#[cfg(test)]
#[path = "derp_tests.rs"]
mod tests;
