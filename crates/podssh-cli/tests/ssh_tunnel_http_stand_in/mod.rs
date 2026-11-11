//! A stand-in of localhost.run for the tests of the road of a tunnel of
//! HTTP made by `ssh -R` (T-565), written from localhost.run's documents
//! (<https://localhost.run/docs/>, now at lhr-landing.lovable.app, read
//! 2026-11-10), apart from podssh's code, so that a defect of one is not the
//! other's: russh's SSH server, which lets in each login with no
//! authentication and keeps its user, as `nokey@` is; a remote forward
//! makes a tunnel, `tN.lhr-life.stand-in.test`, and the session's shell writes a
//! welcome whose links name other hosts, then `NAME tunneled with tls
//! termination, https://NAME`, as the landing page's sample does. The edge
//! takes a visitor's HTTPS on one port, its TLS ended with a certificate of
//! the stand-in CA for `*.lhr-life.stand-in.test`, and plain HTTP on another, as
//! "80: unencrypted forwarder on 80 plus a TLS-decrypting forwarder on 443"
//! ("CLI Reference"); it reads the request's head, finds the tunnel by its
//! `Host`, adds `X-Forwarded-For` and `X-Forwarded-Proto` ("HTTP Tunnels"),
//! and sends the plain HTTP down a `forwarded-tcpip` channel of the
//! forward's address and port, then the rest of the connection as it comes
//! (so a WebSocket passes; whether localhost.run's edge passes one is
//! T-565's live run). A tunnel can be given a new name, as a free domain
//! "changes after a few hours", and a name can be given to another tunnel,
//! a stranger at the name. As Sandhole's demo (T-743, `StandIn::sandhole`):
//! a login needs a key, any key, and the shell's one line is `Starting
//! HTTPS on https://NAME for address localhost`, the name under the
//! server's own, which is then the zone itself (`docs/carriers.md`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use podssh_ssh::russh::server::{self, Auth, ChannelOpenHandle, Handle, Msg, Session};
use podssh_ssh::russh::{self, Channel, ChannelId};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

#[path = "../../../podssh-relay/tests/opentunnel_stand_in/keys.rs"]
#[allow(dead_code)]
mod keys;

/// The server's name, which the stand-in proxy sends to the SSH port.
pub const SERVER: &str = "lhr.stand-in.test";
/// The zone of each tunnel's name, which the proxy sends to the edge: apart
/// from the server's own domain, as `lhr.life` is from `localhost.run`, so
/// that a client passes over the hosts of the service's own and keeps these.
pub const ZONE: &str = "lhr-life.stand-in.test";

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A tunnel: its session, the forward that it asked, and its shell.
#[derive(Clone)]
struct Held {
    handle: Handle,
    forward: (String, u32),
    shell: Option<ChannelId>,
}

/// What the stand-in saw, and its tunnels by name.
#[derive(Default)]
pub struct StandIn {
    users: Mutex<Vec<String>>,
    forwards: Mutex<Vec<(String, u32)>>,
    tunnels: Mutex<HashMap<String, Held>>,
    /// The tunnels made, and the visitors sent down one.
    pub made: AtomicUsize,
    pub visits: AtomicUsize,
    /// Sandhole's shape: a key for each login, and its line.
    pub sandhole: AtomicBool,
    /// The fingerprint of each key that logged in.
    keys: Mutex<Vec<String>>,
}

impl StandIn {
    /// The user of each login, in order.
    pub fn users(&self) -> Vec<String> {
        lock(&self.users).clone()
    }

    /// The fingerprint of each key that logged in, in order.
    pub fn keys(&self) -> Vec<String> {
        lock(&self.keys).clone()
    }

    /// Each remote forward that was taken: its address and its port.
    pub fn forwards(&self) -> Vec<(String, u32)> {
        lock(&self.forwards).clone()
    }

    /// Give the name `from` to the tunnel of `to`: a stranger at the name.
    pub fn hijack(&self, from: &str, to: &str) {
        let mut tunnels = lock(&self.tunnels);
        if let Some(held) = tunnels.get(to).cloned() {
            tunnels.insert(from.to_string(), held);
        }
    }

    /// Give the tunnel of `name` a new name, which its shell says; the old
    /// one names nothing then. The new name.
    pub async fn rename(&self, name: &str) -> String {
        let n = self.made.fetch_add(1, Ordering::SeqCst) + 1;
        let new = format!("t{n}.{ZONE}");
        let held = lock(&self.tunnels).remove(name).expect("a tunnel of that name");
        lock(&self.tunnels).insert(new.clone(), held.clone());
        if let Some(shell) = held.shell {
            let line = format!("{new} tunneled with tls termination, https://{new}\r\n");
            let _ = held.handle.data(shell, line.into_bytes()).await;
        }
        new
    }

    /// The SSH port, the edge's HTTPS port and its plain HTTP port, and the
    /// stand-in CA as PEM; served on the runtime that calls it.
    pub async fn listen(self: &Arc<Self>) -> (u16, u16, u16, String) {
        let mut config = server::Config::default();
        let host_key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
        config.keys.push(host_key);
        config.auth_rejection_time = Duration::from_millis(10);
        config.auth_rejection_time_initial = Some(Duration::ZERO);
        let config = Arc::new(config);
        let ca = keys::Ca::new();
        let (cert, key) = ca.pair(&format!("*.{ZONE}"));
        let acceptor = podssh_ws::tls_server::acceptor(cert.as_bytes(), key.as_bytes(), &[]).expect("the TLS");
        let ssh = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let https = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = |l: &TcpListener| l.local_addr().unwrap().port();
        let ports = (port(&ssh), port(&https), port(&http), ca.pem.clone());
        let me = self.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = ssh.accept().await {
                let far = Far { stand_in: me.clone(), tunnel: None };
                let config = config.clone();
                tokio::spawn(async move {
                    if let Ok(session) = server::run_stream(config, tcp, far).await {
                        let _ = session.await;
                    }
                });
            }
        });
        let me = self.clone();
        tokio::spawn(async move {
            while let Ok((tcp, peer)) = https.accept().await {
                let (me, acceptor) = (me.clone(), acceptor.clone());
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        me.visit(tls, peer.port(), "https").await;
                    }
                });
            }
        });
        let me = self.clone();
        tokio::spawn(async move {
            while let Ok((tcp, peer)) = http.accept().await {
                tokio::spawn(me.clone().visit_owned(tcp, peer.port()));
            }
        });
        ports
    }

    async fn visit_owned(self: Arc<Self>, tcp: tokio::net::TcpStream, port: u16) {
        self.visit(tcp, port, "http").await;
    }

    /// A visitor: its request's head read, then the connection down the
    /// tunnel that its `Host` names, as plain HTTP with the edge's headers;
    /// closed when no tunnel has the name.
    async fn visit<S: AsyncRead + AsyncWrite + Unpin>(&self, mut visitor: S, port: u16, proto: &str) {
        let mut head = Vec::new();
        let mut chunk = [0u8; 4096];
        let end = loop {
            if let Some(at) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            match visitor.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) if head.len() + n <= 16 * 1024 => head.extend_from_slice(&chunk[..n]),
                Ok(_) => return,
            }
        };
        let text = String::from_utf8_lossy(&head[..end]).into_owned();
        let host = text.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host").then(|| value.trim().split(':').next().unwrap_or_default().to_lowercase())
        });
        let Some(held) = host.and_then(|host| lock(&self.tunnels).get(&host).cloned()) else { return };
        let (address, forward_port) = held.forward.clone();
        let opened = held.handle.channel_open_forwarded_tcpip(address, forward_port, "127.0.0.1", u32::from(port));
        let Ok(channel) = opened.await else { return };
        self.visits.fetch_add(1, Ordering::SeqCst);
        let line_end = text.find("\r\n").unwrap_or(0) + 2;
        let added = format!("X-Forwarded-For: 127.0.0.1\r\nX-Forwarded-Proto: {proto}\r\n");
        let mut sent = text.as_bytes()[..line_end].to_vec();
        sent.extend_from_slice(added.as_bytes());
        sent.extend_from_slice(&head[line_end..]);
        let mut stream = channel.into_stream();
        if stream.write_all(&sent).await.is_err() {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut visitor, &mut stream).await;
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
        if self.stand_in.sandhole.load(Ordering::SeqCst) {
            // Sandhole: any key, but a key.
            let methods = russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]);
            return Ok(Auth::Reject { proceed_with_methods: Some(methods), partial_success: false });
        }
        // `nokey`: a free tunnel needs no key and no account.
        lock(&self.stand_in.users).push(user.to_string());
        Ok(Auth::Accept)
    }

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::reject())
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _key: server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(if self.stand_in.sandhole.load(Ordering::SeqCst) { Auth::Accept } else { Auth::reject() })
    }

    async fn auth_publickey(&mut self, user: &str, key: server::VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        if !self.stand_in.sandhole.load(Ordering::SeqCst) {
            return Ok(Auth::reject());
        }
        lock(&self.stand_in.users).push(user.to_string());
        lock(&self.stand_in.keys).push(key.public_key.fingerprint(russh::keys::HashAlg::Sha256).to_string());
        Ok(Auth::Accept)
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // "bindport — 80 or 443"; 80 ends TLS at the edge.
        if *port != 80 {
            return Ok(false);
        }
        lock(&self.stand_in.forwards).push((address.to_string(), *port));
        let n = self.stand_in.made.fetch_add(1, Ordering::SeqCst) + 1;
        let name = format!("t{n}.{ZONE}");
        let held = Held { handle: session.handle(), forward: (address.to_string(), *port), shell: None };
        lock(&self.stand_in.tunnels).insert(name.clone(), held);
        self.tunnel = Some(name);
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
        let name = self.tunnel.clone().unwrap_or_default();
        if let Some(held) = lock(&self.stand_in.tunnels).get_mut(&name) {
            held.shell = Some(channel);
        }
        let text = match self.stand_in.sandhole.load(Ordering::SeqCst) {
            true => format!("Starting HTTPS on https://{name} for address localhost\r\n"),
            false => format!(
                "\r\n===============================================\r\nWelcome to localhost.run!\r\n\
             Follow your favourite reverse tunnel at [https://twitter.com/localhost_run].\r\n\
             To set up and manage custom domains go to https://admin.{SERVER}/\r\n\
             ===============================================\r\n\r\n\
             ** your connection id is 7f3a-test, please mention it if you send me any bug reports **\r\n\r\n\
             {name} tunneled with tls termination, https://{name}\r\n"
            ),
        };
        session.data(channel, text.into_bytes())?;
        Ok(())
    }
}
