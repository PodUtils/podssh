//! The stand-ins of the file hosts' road (T-738) for the test of the
//! binary (`tests/carrier_filehost.rs`), each on the loopback, so that the
//! binary runs as it ships, with no hook of its own: it names the catalog's
//! hosts and broker, and the test's proxy takes each of those names.
//!
//! - [`Hosts`]: one HTTPS server of the test's CA that answers as each file
//!   host whose form `pod-services` gives (the upload's fields, the answer as
//!   text or JSON, the download under its segment by GET or POST, the delete
//!   by its token form), answers 429 past a count of uploads, and keeps what
//!   each host was asked.
//! - [`Proxy`]: an HTTP proxy of CONNECT alone (the binary's `HTTPS_PROXY`)
//!   that sends each name of a route to its port of the loopback, a
//!   `127.0.0.1` target to itself, and refuses each other name.
//! - [`front`]: TLS of the test's CA in front of a cleartext port, as the
//!   broker's 443 is in front of Mosquitto's `websockets` listener.
//! - [`Mosquitto`]: the broker of `PODSSH_MOSQUITTO_TEST_BIN`, software that
//!   podssh did not write, as `podssh-relay/tests/filehost_board.rs` runs it.

#![allow(dead_code)]

mod http;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::filehost::form::{Answer, Delete, Form};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

pub use http::{parts, Request};

/// A file that a stand-in host keeps.
#[derive(Clone)]
pub struct Kept {
    pub id: String,
    pub bytes: Vec<u8>,
    pub token: Option<String>,
}

// Its size, not its bytes: a failure's message stays readable.
impl std::fmt::Debug for Kept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({} bytes, token {:?})", self.id, self.bytes.len(), self.token.is_some())
    }
}

/// What the hosts were asked, by each host's id.
#[derive(Default, Debug)]
pub struct Record {
    pub uploads: HashMap<String, usize>,
    pub busy: HashMap<String, usize>,
    pub fetches: HashMap<String, usize>,
    pub deletes: HashMap<String, usize>,
    /// Deletes with a token that is not the file's.
    pub bad_deletes: usize,
    /// Downloads of the file's page, not of the file (a segment missed).
    pub pages: usize,
    /// Downloads of no file: one deleted, or never there.
    pub missing: usize,
    /// Requests that no form explains, with why.
    pub strange: Vec<String>,
    /// Each file kept now, by its URL.
    pub kept: HashMap<String, Kept>,
    /// Each file ever uploaded, by its URL, deleted or not.
    pub ever: HashMap<String, Kept>,
}

struct State {
    forms: Vec<Form>,
    /// After this many uploads, a host answers each next one with 429.
    busy_after: HashMap<String, usize>,
    next: u64,
    record: Record,
}

/// The stand-in file hosts, on one port.
pub struct Hosts {
    pub port: u16,
    state: Arc<Mutex<State>>,
}

impl Hosts {
    /// The hosts of `forms`, behind `acceptor`, in the runtime of the caller.
    pub async fn start(acceptor: TlsAcceptor, forms: Vec<Form>, busy_after: &[(&str, usize)]) -> Hosts {
        let busy_after = busy_after.iter().map(|(id, n)| (id.to_string(), *n)).collect();
        let state = Arc::new(Mutex::new(State { forms, busy_after, next: 0, record: Record::default() }));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let serving = state.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, state) = (acceptor.clone(), serving.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                    // One request on each connection, as the road's
                    // `Connection: close` asks.
                    let request = match http::read(&mut tls).await {
                        Ok(Some(request)) => request,
                        Ok(None) => return,
                        Err(why) => {
                            state.lock().unwrap().record.strange.push(format!("a request that does not read: {why}"));
                            let _ = http::write(&mut tls, 400, &[], b"bad request\n").await;
                            return;
                        }
                    };
                    let (status, headers, body) = answer(&mut state.lock().unwrap(), &request);
                    let _ = http::write(&mut tls, status, &headers, &body).await;
                });
            }
        });
        Hosts { port, state }
    }

    /// What the hosts were asked so far, with what they keep.
    pub fn record<T>(&self, read: impl FnOnce(&Record) -> T) -> T {
        read(&self.state.lock().unwrap().record)
    }
}

type Answered = (u16, Vec<(String, String)>, Vec<u8>);

fn plain(status: u16, text: &str) -> Answered {
    (status, Vec::new(), text.as_bytes().to_vec())
}

/// The host's answer to `request`, as its form says.
fn answer(state: &mut State, request: &Request) -> Answered {
    let host = request.host();
    let path = request.path.clone();
    let upload = state.forms.iter().position(|f| f.upload.eq_ignore_ascii_case(&format!("https://{host}{path}")));
    if let (Some(at), "POST") = (upload, request.method.as_str()) {
        return take_upload(state, at, request);
    }
    let Some(form) = state.forms.iter().find(|f| f.serves.iter().any(|s| s.eq_ignore_ascii_case(&host))).cloned()
    else {
        state.record.strange.push(format!("{} {host}{path}: a host of no form", request.method));
        return plain(404, "no such host\n");
    };
    // A delete: a POST of the token form to the file's own URL.
    if let (Delete::TokenForm { token_field, delete_field, .. }, "POST", false) =
        (&form.delete, request.method.as_str(), request.body.is_empty())
    {
        let url = format!("https://{host}{path}");
        let fields = request.boundary().map(|b| parts(&request.body, &b)).unwrap_or_default();
        let field = |name: &str| fields.iter().find(|p| p.0 == name).map(|p| p.2.clone());
        let Some(kept) = state.record.kept.get(&url).cloned() else {
            state.record.missing += 1;
            return plain(404, "no such file\n");
        };
        if field(delete_field).as_deref() != Some(&b""[..]) || field(token_field) != kept.token.map(String::into_bytes)
        {
            state.record.bad_deletes += 1;
            return plain(403, "wrong token\n");
        }
        state.record.kept.remove(&url);
        *state.record.deletes.entry(form.id.clone()).or_default() += 1;
        return plain(200, "");
    }
    let wanted = if form.fetch_post { "POST" } else { "GET" };
    if request.method != wanted {
        state.record.strange.push(format!("{} {host}{path}: {} downloads by {wanted}", request.method, form.id));
        return plain(405, "method not allowed\n");
    }
    // The file under its segment; the bare URL is the file's page.
    let file_path = match &form.fetch_segment {
        Some(segment) => match path.strip_prefix(&format!("/{segment}")) {
            Some(rest) if rest.starts_with('/') => rest.to_string(),
            _ => {
                state.record.pages += 1;
                return (200, vec![("Content-Type".into(), "text/html".into())], b"<html>a page</html>".to_vec());
            }
        },
        None => path.clone(),
    };
    let url = format!("https://{host}{file_path}");
    match state.record.kept.get(&url) {
        Some(kept) => {
            let bytes = kept.bytes.clone();
            *state.record.fetches.entry(form.id.clone()).or_default() += 1;
            (200, vec![("Content-Type".into(), "application/octet-stream".into())], bytes)
        }
        None => {
            state.record.missing += 1;
            plain(404, "no such file\n")
        }
    }
}

/// An upload to the host of `state.forms[at]`: its User-Agent, its fields
/// and its file as the form says; 429 past its count.
fn take_upload(state: &mut State, at: usize, request: &Request) -> Answered {
    let form = state.forms[at].clone();
    let id = form.id.clone();
    // 0x0's operator asks a program to name itself, never a browser.
    let agent = request.header("user-agent").unwrap_or_default();
    if !agent.starts_with("podssh/") || agent.contains("Mozilla") {
        state.record.strange.push(format!("{id}: an upload with the User-Agent {agent:?}"));
        return plain(403, "name your program\n");
    }
    let done = state.record.uploads.get(&id).copied().unwrap_or_default();
    if state.busy_after.get(&id).is_some_and(|most| done >= *most) {
        *state.record.busy.entry(id).or_default() += 1;
        return (429, vec![("Retry-After".into(), "3600".into())], b"too many uploads\n".to_vec());
    }
    let Some(boundary) = request.boundary() else { return plain(400, "not multipart/form-data\n") };
    let fields = parts(&request.body, &boundary);
    for (name, value) in &form.fields {
        if !fields.iter().any(|p| &p.0 == name && p.1.is_none() && p.2 == value.as_bytes()) {
            state.record.strange.push(format!("{id}: an upload with no field {name}={value}"));
            return plain(400, "a field is missing\n");
        }
    }
    let Some(file) = fields.iter().find(|p| p.0 == form.field && p.1.is_some()) else {
        state.record.strange.push(format!("{id}: an upload with no file in {}", form.field));
        return plain(400, "no file\n");
    };
    if file.2.len() > form.most {
        return plain(413, "too large\n");
    }
    state.next += 1;
    let url = format!("https://{}/{}/piece.bin", form.serves[0], state.next);
    let token = matches!(form.delete, Delete::TokenForm { .. }).then(|| format!("stand-in-token-{:08x}", state.next));
    let kept = Kept { id: id.clone(), bytes: file.2.clone(), token: token.clone() };
    state.record.kept.insert(url.clone(), kept.clone());
    state.record.ever.insert(url.clone(), kept);
    *state.record.uploads.entry(id).or_default() += 1;
    let mut headers = Vec::new();
    if let (Delete::TokenForm { header, .. }, Some(token)) = (&form.delete, token) {
        headers.push((header.clone(), token));
    }
    let body = match &form.answer {
        Answer::Text => format!("{url}\n"),
        Answer::Json(keys) => {
            // The URL at the pointer's keys, inside objects, as tmpfiles.org's
            // `{"status": "success", "data": {"url": ...}}`.
            let mut top = keys.iter().rev().fold(serde_json::Value::String(url), |value, key| {
                let mut object = serde_json::Map::new();
                object.insert(key.clone(), value);
                serde_json::Value::Object(object)
            });
            if let Some(object) = top.as_object_mut() {
                object.entry("status").or_insert_with(|| "success".into());
            }
            top.to_string()
        }
    };
    (200, headers, body.into_bytes())
}

/// An HTTP proxy of CONNECT on the loopback.
pub struct Proxy {
    pub port: u16,
    /// Each `HOST:PORT` that a CONNECT asked for, in order.
    pub asked: Arc<Mutex<Vec<String>>>,
    /// Each one that it refused.
    pub refused: Arc<Mutex<Vec<String>>>,
}

/// The names that the proxy was asked for, or refused.
type Seen = Arc<Mutex<Vec<String>>>;

impl Proxy {
    /// The proxy: a name of `routes` on 443 goes to its port of the
    /// loopback, `127.0.0.1:PORT` to itself, and each other is refused 403,
    /// so a road that the test did not stand in for fails at once.
    pub async fn start(routes: HashMap<String, u16>) -> Proxy {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (asked, refused): (Seen, Seen) = Default::default();
        let (a, r, routes) = (asked.clone(), refused.clone(), Arc::new(routes));
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (a, r, routes) = (a.clone(), r.clone(), routes.clone());
                tokio::spawn(async move {
                    let _ = tunnel(tcp, &routes, &a, &r).await;
                });
            }
        });
        Proxy { port, asked, refused }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

async fn tunnel(
    mut tcp: TcpStream,
    routes: &HashMap<String, u16>,
    asked: &Mutex<Vec<String>>,
    refused: &Mutex<Vec<String>>,
) -> std::io::Result<()> {
    let (head, early) = http::head(&mut tcp).await?;
    let mut words = head.split_whitespace();
    let (method, target) = (words.next().unwrap_or_default(), words.next().unwrap_or_default().to_string());
    if method != "CONNECT" {
        refused.lock().unwrap().push(format!("{method} {target}"));
        return tcp.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n").await;
    }
    asked.lock().unwrap().push(target.clone());
    let (host, port) = target.rsplit_once(':').unwrap_or((target.as_str(), "443"));
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    let port: u16 = port.parse().unwrap_or(0);
    let to = match (routes.get(&host), host.as_str()) {
        (Some(local), _) if port == 443 => Some(*local),
        (_, "127.0.0.1") => Some(port),
        _ => None,
    };
    let Some(to) = to else {
        refused.lock().unwrap().push(target);
        return tcp.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
    };
    let Ok(mut upstream) = TcpStream::connect((Ipv4Addr::LOCALHOST, to)).await else {
        return tcp.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
    };
    tcp.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    upstream.write_all(&early).await?;
    tokio::io::copy_bidirectional(&mut tcp, &mut upstream).await.map(|_| ())
}

/// TLS of `acceptor` in front of the cleartext `127.0.0.1:to`: its port.
pub async fn front(acceptor: TlsAcceptor, to: u16) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let Ok(mut plain) = TcpStream::connect((Ipv4Addr::LOCALHOST, to)).await else { return };
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut plain).await;
            });
        }
    });
    port
}

/// Mosquitto with a `websockets` listener on the loopback, stopped when it
/// is dropped.
pub struct Mosquitto {
    child: Child,
    pub port: u16,
    pub log: PathBuf,
}

impl Drop for Mosquitto {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Mosquitto {
    /// The broker, its files in `dir`; `None`, with the line that says why,
    /// with no `PODSSH_MOSQUITTO_TEST_BIN`.
    pub fn start(dir: &Path) -> Option<Mosquitto> {
        let Some(bin) = std::env::var_os("PODSSH_MOSQUITTO_TEST_BIN") else {
            println!("did not run: PODSSH_MOSQUITTO_TEST_BIN names no mosquitto (mqtt-interop.yml sets it)");
            return None;
        };
        // A free port: bound here, let go, then Mosquitto's.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        // Anonymous: the catalog's broker takes a login that is public, and
        // a broker with no password file lets any login in.
        let conf = format!("listener {port} 127.0.0.1\nprotocol websockets\nallow_anonymous true\npersistence false\n");
        std::fs::write(dir.join("mosquitto.conf"), conf).unwrap();
        let log = dir.join("mosquitto.log");
        let out = std::fs::File::create(&log).unwrap();
        let child = Command::new(bin)
            .arg("-c")
            .arg(dir.join("mosquitto.conf"))
            .stdin(Stdio::null())
            .stdout(out.try_clone().unwrap())
            .stderr(out)
            .spawn()
            .expect("mosquitto starts");
        let broker = Mosquitto { child, port, log };
        let until = Instant::now() + Duration::from_secs(20);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < until, "mosquitto did not listen");
            std::thread::sleep(Duration::from_millis(100));
        }
        Some(broker)
    }
}
