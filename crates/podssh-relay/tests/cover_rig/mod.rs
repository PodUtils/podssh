//! A cover role of the loopback, its owner's socket and the requests of the
//! #225 tests. Both test binaries that start a cover share this rig.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use pod_cover::Site;
use podssh_relay::serve::control::Control;
use podssh_relay::serve::cover::{Cover, Issuer};
use podssh_relay::serve::listener::{connection, Door};
use podssh_relay::serve::policy::Policy;
use podssh_relay::serve::{self, tokens, Config, Limits, Mint};
use podssh_ws::tls_server::{acceptor_for, HTTP1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::cover_harness::{Tree, LIMIT};
use crate::publish_harness::{visit, Certs, ROLE};

pub const SERVER: &str = "nginx/1.24.0";

/// The role's one TLS door of a cover, its socket, and what the test asks.
pub struct Rig {
    pub certs: Certs,
    pub door: u16,
    pub cfg: Arc<Config>,
    pub issuer: Issuer,
    pub socket: PathBuf,
    pub _tree: Tree,
}

/// The role of `tag`, whose name is `ROLE`, with the site of `tree`, and an
/// owner's socket in the temporary directory.
pub async fn start(tag: &str, tree: Tree) -> Rig {
    let certs = Certs::new(tag);
    let site = Site::load(tree.path()).unwrap();
    let issuer = Issuer::from_seed([0x11; 32]);
    let cover = Cover::new(site, ROLE, issuer.clone(), Some(SERVER)).unwrap();
    let cfg = Arc::new(Config {
        version: "podssh test".into(),
        mint: Mint::Anyone,
        tokens: tokens::Tokens::new([9; 32]),
        policy: Policy { private: true, ..Default::default() },
        egress: Default::default(),
        limits: Limits::default(),
        pairs: Default::default(),
        resumes: Default::default(),
        answered: Default::default(),
        brake: Default::default(),
        usage: Default::default(),
        cover: Some(cover),
        events: None,
    });
    let served = Certs::served(&certs.role, ROLE, &certs.role_challenge);
    let acceptor = acceptor_for(served, &[HTTP1]).unwrap();
    let door =
        Door { acceptor, cleartext: false, sshd: None, published: Default::default(), proxy: Default::default() };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let served_cfg = cfg.clone();
    tokio::spawn(async move {
        while let Ok((tcp, peer)) = listener.accept().await {
            serve::sockets::bound_unsent(&tcp);
            tokio::spawn(connection(tcp, peer.ip(), door.clone(), served_cfg.clone()));
        }
    });
    let socket = std::env::temp_dir().join(format!("podssh-cover-sock-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let control = Control::bind(socket.to_str().unwrap()).unwrap();
    let served_cfg = cfg.clone();
    tokio::spawn(Box::new(control).serve(served_cfg));
    Rig { certs, door: port, cfg, issuer, socket, _tree: tree }
}

/// One request over TLS to the cover name, its status, its head and its
/// body. `host` is the `Host` header of the request, the name of the cover
/// unless the test asks another.
pub async fn ask(certs: &Certs, port: u16, host: &str, method: &str, path: &str, extra: &str) -> (u16, String, String) {
    ask_at(certs, port, ROLE, host, method, path, extra).await
}

/// [`ask`] with the name of the handshake, `sni`, apart from the `Host`.
pub async fn ask_at(
    certs: &Certs,
    port: u16,
    sni: &str,
    host: &str,
    method: &str,
    path: &str,
    extra: &str,
) -> (u16, String, String) {
    let visit = visit(certs, port, sni, &[HTTP1]).await.expect("the cover's TLS");
    let mut tls = visit.tls;
    let request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra}\r\n");
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(LIMIT, tls.read_to_end(&mut answer)).await;
    let text = String::from_utf8_lossy(&answer).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let status = head.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, head.to_string(), body.to_string())
}

/// The status and head of `tls`, whose request was already written, read to
/// the end of its head.
pub async fn head_of<S>(tls: &mut S) -> (u16, String)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut got = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&got[..at + 4]).into_owned();
            let status = head.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
            return (status, head);
        }
        let n = tokio::time::timeout(LIMIT, tls.read(&mut chunk)).await.expect("an answer in time").unwrap();
        assert!(n > 0, "the role ended with no answer");
        got.extend_from_slice(&chunk[..n]);
    }
}

/// One HTTP request on `tls`, whose answer is read to its end.
pub async fn ask_on<S>(mut tls: S, host: &str, method: &str, path: &str, extra: &str) -> (u16, String, String)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra}\r\n");
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(LIMIT, tls.read_to_end(&mut answer)).await;
    let text = String::from_utf8_lossy(&answer).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let status = head.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, head.to_string(), body.to_string())
}

/// One WebSocket upgrade on `tls` with `token` and `credential`, the
/// credential's header written only when one is given.
pub async fn upgrade_on<S>(mut tls: S, token: &str, credential: Option<&str>, path: &str) -> (u16, String)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {ROLE}\r\nX-Relay-Token: {token}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
    );
    if let Some(credential) = credential {
        request.push_str(&format!("X-Cover-Credential: {credential}\r\n"));
    }
    request.push_str("\r\n");
    tls.write_all(request.as_bytes()).await.unwrap();
    head_of(&mut tls).await
}

/// A credential for `exporter` under `cover`'s name, as one header value.
pub fn credential_for(cover: &Cover, exporter: &[u8; 32], name: &str) -> String {
    let now = i64::try_from(tokens::now_ms() / 1000).unwrap();
    let credential = cover.issue([7; 32], now, exporter, Some(name)).expect("the test's issuer signs");
    podssh_ws::delegated::encode_wire(&credential)
}

/// A listener of the loopback that accepts and holds each target connection
/// of the forward road, so that an upgrade has somewhere to reach.
pub async fn target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut byte = [0u8; 1];
                let _ = tcp.read(&mut byte).await;
            });
        }
    });
    port
}
