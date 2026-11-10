//! A stand-in of Serveo's server for the tests of the Serveo road (T-549),
//! written from Serveo's documents (<https://serveo.net/docs/> and
//! <https://serveo.net/articles/remote-access-to-ssh-servers-using-serveo>,
//! read 2026-11-10), apart from podssh's code, so that a defect of one is not
//! the other's. Serveo's alias forward is not OpenSSH's: sshd binds an
//! address, Serveo routes a name. So: russh's SSH server, raw, which lets in
//! each login with no authentication, as an anonymous tunnel needs no key. A
//! remote forward of a host name other than `localhost`, on a port other than
//! 0 and 80, is a private alias, as `ssh -R myalias:22:localhost:22
//! serveo.net` asks it; a forward of an alias that another tunnel holds is
//! refused ("Alias already taken"). A `direct-tcpip` channel to an alias and
//! its port, as `ssh -J serveo.net user@myalias` opens it, goes down a
//! `forwarded-tcpip` channel of the tunnel that holds the alias; one to a
//! name that no tunnel holds is refused. An alias can be held with no tunnel,
//! as Serveo holds a lost tunnel's a while, or given to another tunnel, a
//! stranger at the alias. The tunnel's aliases go with its connection.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use podssh_ssh::russh::server::{self, Auth, ChannelOpenHandle, Handle, Msg, Session};
use podssh_ssh::russh::{self, Channel};
use tokio::net::TcpListener;

/// The server's name, which the stand-in proxy sends to the SSH port.
pub const SERVER: &str = "serveo.stand-in.test";

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Who holds an alias: a tunnel, by its connection's number, or nobody that
/// answers, as a tunnel that went away abruptly leaves it.
#[derive(Clone)]
enum Holder {
    Tunnel(usize, Handle),
    Held,
}

/// What the stand-in saw, and its aliases.
#[derive(Default)]
pub struct StandIn {
    users: Mutex<Vec<String>>,
    /// Each remote forward asked, granted or not: its address and port.
    forwards: Mutex<Vec<(String, u32)>>,
    /// The forwards refused, as another held their alias.
    pub taken: AtomicUsize,
    aliases: Mutex<HashMap<(String, u32), Holder>>,
    /// The channels that went down a tunnel.
    pub jumps: AtomicUsize,
    /// The connections, to number each.
    connections: AtomicUsize,
}

impl StandIn {
    /// The user of each login, in order.
    pub fn users(&self) -> Vec<String> {
        lock(&self.users).clone()
    }

    /// The address and the port of each remote forward, in order.
    pub fn forwards(&self) -> Vec<(String, u32)> {
        lock(&self.forwards).clone()
    }

    /// Hold `alias` on port 22 with no tunnel, as Serveo holds a lost one's.
    pub fn hold(&self, alias: &str) {
        lock(&self.aliases).insert((alias.to_string(), 22), Holder::Held);
    }

    /// Give `alias` to the tunnel of `to`: a stranger at the alias.
    pub fn hijack(&self, alias: &str, to: &str) {
        let mut aliases = lock(&self.aliases);
        if let Some(holder) = aliases.get(&(to.to_string(), 22)).cloned() {
            aliases.insert((alias.to_string(), 22), holder);
        }
    }

    /// The SSH port, raw, served on the runtime that calls it.
    pub async fn listen(self: &Arc<Self>) -> u16 {
        let mut config = server::Config::default();
        let host_key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
        config.keys.push(host_key);
        config.auth_rejection_time = Duration::from_millis(10);
        config.auth_rejection_time_initial = Some(Duration::ZERO);
        let config = Arc::new(config);
        let ssh = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = ssh.local_addr().unwrap().port();
        let me = self.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = ssh.accept().await {
                let id = me.connections.fetch_add(1, Ordering::SeqCst);
                let far = Far { stand_in: me.clone(), id, held: Vec::new() };
                let config = config.clone();
                tokio::spawn(async move {
                    if let Ok(session) = server::run_stream(config, tcp, far).await {
                        let _ = session.await;
                    }
                });
            }
        });
        port
    }
}

/// One connection, a node's or a client's, and the aliases that it holds.
struct Far {
    stand_in: Arc<StandIn>,
    id: usize,
    held: Vec<(String, u32)>,
}

impl Drop for Far {
    /// The connection ended: its aliases are free, unless another took them.
    fn drop(&mut self) {
        let mut aliases = lock(&self.stand_in.aliases);
        for key in &self.held {
            if matches!(aliases.get(key), Some(Holder::Tunnel(id, _)) if *id == self.id) {
                aliases.remove(key);
            }
        }
    }
}

impl server::Handler for Far {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        // An anonymous tunnel: no account and no key.
        lock(&self.stand_in.users).push(user.to_string());
        Ok(Auth::Accept)
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let key = (address.to_ascii_lowercase(), *port);
        lock(&self.stand_in.forwards).push(key.clone());
        // The stand-in serves the private aliases alone: no HTTP tunnel of
        // port 80, no public port of port 0, no forward of localhost.
        if matches!(key.0.as_str(), "" | "localhost" | "0.0.0.0") || matches!(*port, 0 | 80) {
            return Ok(false);
        }
        let mut aliases = lock(&self.stand_in.aliases);
        if aliases.contains_key(&key) {
            self.stand_in.taken.fetch_add(1, Ordering::SeqCst);
            return Ok(false);
        }
        aliases.insert(key.clone(), Holder::Tunnel(self.id, session.handle()));
        self.held.push(key);
        Ok(true)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        originator: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let holder = lock(&self.stand_in.aliases).get(&(host.to_ascii_lowercase(), port)).cloned();
        let Some(Holder::Tunnel(_, handle)) = holder else {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        // The tunnel's channel first: a tunnel that does not answer refuses
        // the jump, as a forward that fails does.
        let Ok(down) = handle.channel_open_forwarded_tcpip(host, port, originator, originator_port).await else {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        reply.accept().await;
        self.stand_in.jumps.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let (mut up, mut down) = (channel.into_stream(), down.into_stream());
            let _ = tokio::io::copy_bidirectional(&mut up, &mut down).await;
        });
        Ok(())
    }
}
