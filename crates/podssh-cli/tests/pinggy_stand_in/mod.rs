//! A stand-in of Pinggy's server for the tests of the Pinggy road (T-548),
//! written from Pinggy's documents, apart from podssh's code, so that a
//! defect of one is not the other's: russh's SSH server on one port, raw as
//! `ssh -p 443` reaches it, or inside TLS when the first byte opens a TLS
//! record, as Pinggy takes `openssl s_client` on 443
//! (<https://pinggy.io/docs/client_behind_proxy/>, read 2026-11-09); the
//! certificate of that TLS is the stand-in CA's, which a test gives to the
//! node as `--ca-file`. It lets
//! in each user with no authentication, and keeps the user, as Pinggy reads
//! its keyword `tls` there (<https://pinggy.io/docs/usages/>). Each remote
//! forward makes a tunnel, `tN.DOMAIN`; the session's shell writes its
//! address as `tls://NAME` among a terminal's escapes, and a `direct-tcpip`
//! channel to port 4300 answers `GET /urls` with `{"urls": [...]}`
//! (<https://pinggy.io/docs/api/web_debugger_api/>). A visitor's port reads
//! the SNI of each ClientHello and sends the whole connection, from its
//! first byte, down a `forwarded-tcpip` channel of the tunnel of that name,
//! never ending its TLS, as Pinggy routes a TLS tunnel
//! (<https://pinggy.io/docs/tls_tunnels/>). A name can be given to another
//! tunnel, a stranger at the name.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use podssh_ssh::russh::server::{self, Auth, ChannelOpenHandle, Handle, Msg, Session};
use podssh_ssh::russh::{self, Channel, ChannelId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[path = "../../../podssh-relay/tests/opentunnel_stand_in/keys.rs"]
#[allow(dead_code)]
mod keys;
#[path = "../../../podssh-relay/tests/opentunnel_stand_in/parse.rs"]
#[allow(dead_code)]
mod parse;

/// The server's name, which the stand-in proxy sends to the SSH port.
pub const SERVER: &str = "pinggy.stand-in.test";
/// The domain of each tunnel's name, which the proxy sends to the visitors.
pub const DOMAIN: &str = "a.stand-in.test";

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the stand-in saw, and its tunnels by name.
#[derive(Default)]
pub struct StandIn {
    users: Mutex<Vec<String>>,
    forwards: Mutex<Vec<String>>,
    /// The tunnels made, and the visitors sent down one.
    pub made: AtomicUsize,
    pub visits: AtomicUsize,
    /// Each name's session, to open a visitor's channel on.
    tunnels: Mutex<HashMap<String, Handle>>,
    /// Whether port 4300 answers: else the name is in the shell's text alone.
    pub no_api: std::sync::atomic::AtomicBool,
    /// The SSH connections that came raw, and inside TLS.
    pub raw: AtomicUsize,
    pub tls: AtomicUsize,
}

impl StandIn {
    /// The user of each login, in order.
    pub fn users(&self) -> Vec<String> {
        lock(&self.users).clone()
    }

    /// The address of each remote forward, in order.
    pub fn forwards(&self) -> Vec<String> {
        lock(&self.forwards).clone()
    }

    /// Give the name `from` to the tunnel of `to`: a stranger at the name.
    pub fn hijack(&self, from: &str, to: &str) {
        let mut tunnels = lock(&self.tunnels);
        if let Some(handle) = tunnels.get(to).cloned() {
            tunnels.insert(from.to_string(), handle);
        }
    }

    /// The SSH port, raw or inside TLS of the stand-in CA's certificate, the
    /// visitors' port, and that CA as PEM; served on the runtime that calls
    /// it.
    pub async fn listen(self: &Arc<Self>) -> (u16, u16, String) {
        let mut config = server::Config::default();
        let host_key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
        config.keys.push(host_key);
        config.auth_rejection_time = Duration::from_millis(10);
        config.auth_rejection_time_initial = Some(Duration::ZERO);
        let config = Arc::new(config);
        let ca = keys::Ca::new();
        let (cert, key) = ca.pair(SERVER);
        let acceptor = podssh_ws::tls_server::acceptor(cert.as_bytes(), key.as_bytes(), &[]).expect("the TLS");
        let ssh = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let visitors = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ports = (ssh.local_addr().unwrap().port(), visitors.local_addr().unwrap().port(), ca.pem.clone());
        let me = self.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = ssh.accept().await {
                let (acceptor, config, me) = (acceptor.clone(), config.clone(), me.clone());
                tokio::spawn(async move {
                    // A TLS record's first byte is 22, a handshake; SSH's is 'S'.
                    let mut first = [0u8; 1];
                    if !matches!(tcp.peek(&mut first).await, Ok(1)) {
                        return;
                    }
                    let far = Far { stand_in: me.clone(), tunnel: None };
                    if first[0] == 0x16 {
                        let Ok(tls) = acceptor.accept(tcp).await else { return };
                        me.tls.fetch_add(1, Ordering::SeqCst);
                        if let Ok(session) = server::run_stream(config, tls, far).await {
                            let _ = session.await;
                        }
                    } else {
                        me.raw.fetch_add(1, Ordering::SeqCst);
                        if let Ok(session) = server::run_stream(config, tcp, far).await {
                            let _ = session.await;
                        }
                    }
                });
            }
        });
        let me = self.clone();
        tokio::spawn(async move {
            while let Ok((tcp, peer)) = visitors.accept().await {
                tokio::spawn(me.clone().visit(tcp, peer.port()));
            }
        });
        ports
    }

    /// A visitor: its ClientHello read whole, then the connection down the
    /// tunnel that its SNI names, from the first byte; closed when none.
    async fn visit(self: Arc<Self>, mut tcp: TcpStream, port: u16) {
        let mut hello = Vec::new();
        let mut chunk = [0u8; 4096];
        while parse::record_len(&hello).is_none_or(|len| hello.len() < len) && hello.len() < 64 * 1024 {
            match tcp.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => hello.extend_from_slice(&chunk[..n]),
            }
        }
        let Some(name) = parse::sni(&hello).map(|s| s.to_ascii_lowercase()) else { return };
        let Some(handle) = lock(&self.tunnels).get(&name).cloned() else { return };
        let Ok(channel) = handle.channel_open_forwarded_tcpip("localhost", 0, "127.0.0.1", u32::from(port)).await
        else {
            return;
        };
        self.visits.fetch_add(1, Ordering::SeqCst);
        let mut stream = channel.into_stream();
        if stream.write_all(&hello).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
    }
}

/// One connection of a node, and the name of its tunnel once it has one.
struct Far {
    stand_in: Arc<StandIn>,
    tunnel: Option<String>,
}

impl server::Handler for Far {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        // Pinggy lets in each login: the user is its keyword, not an account.
        lock(&self.stand_in.users).push(user.to_string());
        Ok(Auth::Accept)
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        lock(&self.stand_in.forwards).push(address.to_string());
        let n = self.stand_in.made.fetch_add(1, Ordering::SeqCst) + 1;
        let name = format!("t{n}.{DOMAIN}");
        lock(&self.stand_in.tunnels).insert(name.clone(), session.handle());
        self.tunnel = Some(name);
        *port = 443;
        Ok(true)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        // The address among a terminal's escapes, as Pinggy's interface draws it.
        let name = self.tunnel.clone().unwrap_or_default();
        let text = format!(
            "\u{1b}[2J\u{1b}[1;1HYou can access local server via following URL(s):\r\n\
             \u{1b}[32mtls://{name}\u{1b}[0m\r\nhttps://dashboard.pinggy.io\r\n"
        );
        session.data(channel, text.into_bytes())?;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _originator: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Pinggy lets a client reach port 4300 alone, its web debugger.
        if host != "localhost" || port != 4300 || self.stand_in.no_api.load(Ordering::SeqCst) {
            reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        }
        reply.accept().await;
        let name = self.tunnel.clone().unwrap_or_default();
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") && request.len() < 16 * 1024 {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            if !request.starts_with(b"GET /urls ") {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
                return;
            }
            let body = format!("{{\"urls\":[\"tls://{name}:443\"]}}");
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(body.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
        Ok(())
    }
}
