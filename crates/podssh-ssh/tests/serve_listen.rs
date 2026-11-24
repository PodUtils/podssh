//! The listener of `podssh serve --listen` (T-124), on real sockets of
//! this host: russh's client logs in over a loopback port that the system
//! chose and over a Unix socket; a key line's `from=` meets the TCP
//! client's address; past `--max-connections`, a client reads serve's
//! version line and a DISCONNECT that names the cap, before any key
//! exchange; a place comes back when its connection ends. The accept loop
//! here is the CLI's in small (`podssh-cli`'s `serve_listen.rs`): the gate
//! before a byte is read, then the server of `--stdio`.

#![cfg(unix)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, client};
use podssh_ssh::server::listen::{self, Entry, Gate, Limits};
use podssh_ssh::server::{self, Authorized, Control, Keys, Settings};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod cleanup;

/// A bound on each wait.
const LIMIT: Duration = Duration::from_secs(30);

fn key() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

fn keys_of(text: &str) -> Keys {
    let mut authorized = Authorized::new();
    let read = authorized.add_text(text);
    assert!(read.bad.is_empty(), "{read:?}");
    Keys::new(authorized)
}

/// One connection placed as the CLI places it: served with its peer, or
/// refused, or closed.
fn admit<S>(stream: S, peer: Option<IpAddr>, gate: &Gate, keys: &Keys, host: &PrivateKey, control: &Control)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match gate.enter() {
        Entry::Admitted(place) => {
            let settings = Arc::new(Settings { peer, ..Settings::default() });
            let (keys, host, control) = (keys.clone(), host.clone(), control.clone());
            tokio::spawn(async move {
                let _ = server::serve_under(stream, host, keys, settings, control).await;
                drop(place);
            });
        }
        Entry::Full(full) => {
            tokio::spawn(listen::refuse(stream, full));
        }
        Entry::Dropped(_) => drop(stream),
    }
}

async fn serve_tcp(listener: tokio::net::TcpListener, gate: Gate, keys: Keys) {
    let (host, control) = (key(), Control::new());
    while let Ok((stream, peer)) = listener.accept().await {
        admit(stream, Some(peer.ip().to_canonical()), &gate, &keys, &host, &control);
    }
}

async fn serve_unix(listener: tokio::net::UnixListener, gate: Gate, keys: Keys) {
    let (host, control) = (key(), Control::new());
    while let Ok((stream, _)) = listener.accept().await {
        admit(stream, None, &gate, &keys, &host, &control);
    }
}

struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// russh's client over `stream`, logged in with `login`: the handle, and
/// whether the login worked.
async fn log_in<S>(stream: S, login: &PrivateKey) -> (client::Handle<Trusting>, bool)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = Arc::new(client::Config::default());
    let mut handle = client::connect_stream(config, stream, Trusting).await.expect("the handshake");
    let login = PrivateKeyWithHashAlg::new(Arc::new(login.clone()), None);
    let result = handle.authenticate_publickey("anyone", login).await.expect("an answer");
    (handle, result.success())
}

async fn loopback(gate: Gate, keys: Keys) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a loopback port");
    let at = listener.local_addr().unwrap();
    tokio::spawn(serve_tcp(listener, gate, keys));
    at
}

/// Wait until `gate` holds `n` connections.
async fn until_open(gate: &Gate, n: usize) {
    tokio::time::timeout(LIMIT, async {
        while gate.open() != n {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the gate holds {} connections, not {n}", gate.open()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_logs_in_over_a_loopback_port_and_from_meets_its_address() {
    let (login, other) = (key(), key());
    let text = format!(
        "from=\"127.0.0.1\" {}\nfrom=\"10.0.0.0/8\" {}\n",
        login.public_key().to_openssh().unwrap(),
        other.public_key().to_openssh().unwrap()
    );
    let at = loopback(Gate::new(Limits::default()), keys_of(&text)).await;
    let stream = tokio::net::TcpStream::connect(at).await.unwrap();
    let (_handle, ok) = tokio::time::timeout(LIMIT, log_in(stream, &login)).await.expect("in time");
    assert!(ok, "from=\"127.0.0.1\" meets a loopback client");
    let stream = tokio::net::TcpStream::connect(at).await.unwrap();
    let (_handle, ok) = tokio::time::timeout(LIMIT, log_in(stream, &other)).await.expect("in time");
    assert!(!ok, "from=\"10.0.0.0/8\" does not");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_logs_in_over_a_unix_socket() {
    let login = key();
    let name = format!("podssh-serve-listen-{}-{:08x}", std::process::id(), rand::random::<u32>());
    let dir = std::env::temp_dir().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    let path = dir.join("s");
    let listener = tokio::net::UnixListener::bind(&path).expect("a socket");
    let keys = keys_of(&login.public_key().to_openssh().unwrap());
    tokio::spawn(serve_unix(listener, Gate::new(Limits::default()), keys));
    let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    let (_handle, ok) = tokio::time::timeout(LIMIT, log_in(stream, &login)).await.expect("in time");
    assert!(ok, "the listed key logs in over the socket");
}

/// The cap of 2: two logins hold their places, the third client reads the
/// version line and a DISCONNECT of reason 12 before any key exchange, and
/// once a login leaves, its place takes a new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn past_the_cap_a_client_reads_too_many_connections() {
    let login = key();
    let gate = Gate::new(Limits { connections: 2 });
    let at = loopback(gate.clone(), keys_of(&login.public_key().to_openssh().unwrap())).await;
    let mut held = Vec::new();
    for _ in 0..2 {
        let stream = tokio::net::TcpStream::connect(at).await.unwrap();
        let (handle, ok) = tokio::time::timeout(LIMIT, log_in(stream, &login)).await.expect("in time");
        assert!(ok);
        held.push(handle);
    }
    until_open(&gate, 2).await;
    let mut third = tokio::net::TcpStream::connect(at).await.unwrap();
    third.write_all(b"SSH-2.0-OpenSSH_9.9\r\n").await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(LIMIT, third.read_to_end(&mut got)).await.expect("in time").unwrap();
    let text = String::from_utf8_lossy(&got).to_string();
    let (line, _) = text.split_once("\r\n").expect("a version line");
    assert!(line.starts_with("SSH-2.0-podssh_"), "{text:?}");
    let packet = &got[line.len() + 2..];
    assert_eq!(packet[5], 1, "SSH_MSG_DISCONNECT, with no KEXINIT before it");
    assert_eq!(u32::from_be_bytes(packet[6..10].try_into().unwrap()), listen::TOO_MANY_CONNECTIONS);
    assert!(text.contains("2 connections at once already (--max-connections)"), "{text:?}");
    let first = held.remove(0);
    let _ = first.disconnect(russh::Disconnect::ByApplication, "bye", "").await;
    drop(first);
    until_open(&gate, 1).await;
    let stream = tokio::net::TcpStream::connect(at).await.unwrap();
    let (_handle, ok) = tokio::time::timeout(LIMIT, log_in(stream, &login)).await.expect("in time");
    assert!(ok, "the place came back");
}
