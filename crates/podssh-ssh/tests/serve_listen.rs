//! The listener of `podssh serve --listen` (T-124), on real sockets of
//! this host: russh's client logs in over a loopback port that the system
//! chose and over a Unix socket; a key line's `from=` meets the TCP
//! client's address; past `--max-connections`, a client reads serve's
//! version line and a DISCONNECT that names the cap, before any key
//! exchange; a place comes back when its connection ends. The deadline
//! from the accept (T-631): a client that says nothing, or a byte now and
//! then, is gone at the limit with the line that names it; a client whose
//! login came in time outlives it; one past `--pending-max` reads the
//! refusal; each place comes back. The accept loop here is the CLI's in
//! small (`podssh-cli`'s `serve_listen.rs`): the gate before a byte is
//! read, then the server of `--stdio`.

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

/// Where the server's end of each connection goes: its line, or none.
type Ends = tokio::sync::mpsc::UnboundedSender<Result<(), String>>;

/// One connection placed as the CLI places it: served with its peer and its
/// deadline, or refused, or closed.
fn admit<S>(stream: S, peer: Option<IpAddr>, gate: &Gate, keys: &Keys, host: &PrivateKey, ends: &Ends)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match gate.enter() {
        Entry::Admitted(place) => {
            let settings = Arc::new(Settings { peer, ..Settings::default() });
            let (keys, host, ends) = (keys.clone(), host.clone(), ends.clone());
            tokio::spawn(async move {
                let ended = server::serve_admitted(stream, host, keys, settings, Control::new(), place).await;
                let _ = ends.send(ended);
            });
        }
        Entry::Full(full) => {
            tokio::spawn(listen::refuse(stream, full));
        }
        Entry::Dropped(_) => drop(stream),
    }
}

async fn serve_tcp(listener: tokio::net::TcpListener, gate: Gate, keys: Keys, ends: Ends) {
    let host = key();
    while let Ok((stream, peer)) = listener.accept().await {
        admit(stream, Some(peer.ip().to_canonical()), &gate, &keys, &host, &ends);
    }
}

async fn serve_unix(listener: tokio::net::UnixListener, gate: Gate, keys: Keys, ends: Ends) {
    let host = key();
    while let Ok((stream, _)) = listener.accept().await {
        admit(stream, None, &gate, &keys, &host, &ends);
    }
}

/// A client that trusts the host key and keeps the words of a disconnect.
#[derive(Clone, Default)]
struct Trusting {
    said: Arc<std::sync::Mutex<Option<String>>>,
}

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn disconnected(&mut self, reason: client::DisconnectReason<Self::Error>) -> Result<(), Self::Error> {
        match reason {
            client::DisconnectReason::ReceivedDisconnect(info) => {
                *self.said.lock().unwrap() = Some(info.message);
                Ok(())
            }
            client::DisconnectReason::Error(e) => Err(e),
        }
    }
}

/// russh's client over `stream`, logged in with `login`: the handle, and
/// whether the login worked.
async fn log_in<S>(stream: S, login: &PrivateKey) -> (client::Handle<Trusting>, bool)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = Arc::new(client::Config::default());
    let mut handle = client::connect_stream(config, stream, Trusting::default()).await.expect("the handshake");
    let login = PrivateKeyWithHashAlg::new(Arc::new(login.clone()), None);
    let result = handle.authenticate_publickey("anyone", login).await.expect("an answer");
    (handle, result.success())
}

async fn loopback(gate: Gate, keys: Keys) -> std::net::SocketAddr {
    loopback_with(gate, keys).await.0
}

/// A listener on a loopback port, and the server's end of each connection.
async fn loopback_with(gate: Gate, keys: Keys) -> (std::net::SocketAddr, Receiver) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a loopback port");
    let at = listener.local_addr().unwrap();
    let (ends, heard) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(serve_tcp(listener, gate, keys, ends));
    (at, heard)
}

type Receiver = tokio::sync::mpsc::UnboundedReceiver<Result<(), String>>;

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
    let (ends, _heard) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(serve_unix(listener, Gate::new(Limits::default()), keys, ends));
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
    let gate = Gate::new(Limits { connections: 2, ..Limits::default() });
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

/// The deadline of these tests, and the margin of a loaded host.
const SHORT: Duration = Duration::from_secs(2);
const MARGIN: Duration = Duration::from_secs(5);

fn short(pending: usize) -> Gate {
    Gate::new(Limits { connections: 8, pending, login: SHORT })
}

/// The server's next end, within the bound.
async fn next_end(heard: &mut Receiver) -> Result<(), String> {
    tokio::time::timeout(LIMIT, heard.recv()).await.expect("an end in time").expect("the server's end")
}

/// A client that says nothing, and one that sends its version line a byte
/// at a time, slower than the limit: each is gone at the deadline, not at
/// a silence, and serve's line names the limit; the places come back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_never_logs_in_is_gone_at_the_deadline() {
    let gate = short(4);
    let (at, mut heard) = loopback_with(gate.clone(), keys_of(&key().public_key().to_openssh().unwrap())).await;
    for trickle in [false, true] {
        let started = tokio::time::Instant::now();
        let mut client = tokio::net::TcpStream::connect(at).await.unwrap();
        let feeding = tokio::spawn(async move {
            if trickle {
                for byte in b"SSH-2.0-a_client_that_takes_its_time_over_each_byte_of_this_line\r\n" {
                    if client.write_all(&[*byte]).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
            let mut got = Vec::new();
            let _ = tokio::time::timeout(LIMIT, client.read_to_end(&mut got)).await;
            got
        });
        let why = next_end(&mut heard).await.expect_err("reaped");
        let took = started.elapsed();
        assert!(took >= SHORT && took < SHORT + MARGIN, "trickle {trickle}: {took:?}");
        assert!(why.contains("within 2 s") && why.contains("--login-timeout"), "{why}");
        let got = tokio::time::timeout(LIMIT, feeding).await.expect("in time").unwrap();
        assert!(got.starts_with(b"SSH-2.0-podssh_"), "the client saw serve's version line alone");
    }
    until_open(&gate, 0).await;
    assert_eq!(gate.pending(), 0);
}

/// A client past its version line that never logs in hears the limit in a
/// disconnect; a login in time outlives the deadline, and its pending
/// place came back at the login.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_deadline_ends_a_handshake_with_no_login_and_spares_a_login() {
    let login = key();
    let gate = short(4);
    let (at, mut heard) = loopback_with(gate.clone(), keys_of(&login.public_key().to_openssh().unwrap())).await;
    let config = Arc::new(client::Config::default());
    let idle = Trusting::default();
    let stream = tokio::net::TcpStream::connect(at).await.unwrap();
    let handle = client::connect_stream(config, stream, idle.clone()).await.expect("the handshake");
    let why = next_end(&mut heard).await.expect_err("reaped");
    assert!(why.contains("no login within 2 s"), "{why}");
    tokio::time::timeout(LIMIT, async {
        while !handle.is_closed() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the client's connection ends");
    let said = idle.said.lock().unwrap().clone().unwrap_or_default();
    assert!(said.contains("no login within 2 s of the connection (--login-timeout)"), "{said:?}");
    let stream = tokio::net::TcpStream::connect(at).await.unwrap();
    let (handle, ok) = tokio::time::timeout(LIMIT, log_in(stream, &login)).await.expect("in time");
    assert!(ok);
    until_open(&gate, 1).await;
    assert_eq!(gate.pending(), 0, "the login gave its pending place back");
    tokio::time::sleep(SHORT + Duration::from_secs(1)).await;
    assert!(!handle.is_closed(), "a login in time outlives the deadline");
    assert!(heard.try_recv().is_err(), "and nothing of it ended");
}

/// Past `--pending-max`, a client reads the refusal before any key
/// exchange, while a silent client holds the one pending place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn past_the_pending_cap_a_client_reads_the_refusal() {
    let gate = Gate::new(Limits { connections: 8, pending: 1, login: LIMIT });
    let at = loopback(gate.clone(), keys_of(&key().public_key().to_openssh().unwrap())).await;
    let _silent = tokio::net::TcpStream::connect(at).await.unwrap();
    until_open(&gate, 1).await;
    let mut second = tokio::net::TcpStream::connect(at).await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(LIMIT, second.read_to_end(&mut got)).await.expect("in time").unwrap();
    let text = String::from_utf8_lossy(&got).to_string();
    assert!(text.starts_with("SSH-2.0-podssh_"), "{text:?}");
    assert!(text.contains("1 connections that have not logged in already (--pending-max)"), "{text:?}");
    assert_eq!(gate.open(), 1, "the refusal took no place of a connection");
}
