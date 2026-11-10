//! A stand-in of ssh-j.com for the tests of the ssh-j road (T-570), written
//! from its page (<https://ssh-j.com/>, read 2026-11-10) and the server's
//! code (Bitbucket's `ValdikSS/dropbear-sshj`, commit `d622b1e8fe35`), apart
//! from podssh's code, so that a defect of one is not the other's: russh's
//! SSH server, which lets in each login with no authentication and keeps
//! its user; a remote forward keeps (user, address, port) and its session,
//! refuses an address of more than 64 bytes and a second forward of a name
//! that a session holds, and is let go when its session ends; a
//! `direct-tcpip` channel of a user to an address and a port that a forward
//! of the same user holds is accepted, then goes down that forward's session
//! as a `forwarded-tcpip` channel that names the forward's address and port,
//! as the server's table rewrites it; a name that no forward of the user
//! holds is refused. A name can be given to another session's forward, a
//! stranger at the name, and each session can be cut, as the server's
//! restart cuts them.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use podssh_ssh::russh::server::{self, Auth, ChannelOpenHandle, Handle, Msg, Session};
use podssh_ssh::russh::{self, Channel};
use tokio::net::TcpListener;

/// The server's name, which the stand-in proxy sends to its port.
pub const SERVER: &str = "ssh-j.stand-in.test";
/// The longest address that the server keeps (`MAX_HOST_LEN`).
const MOST_ADDRESS: usize = 64;

/// A name at the server: the user, the address and the port of a forward.
pub type Key = (String, String, u32);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the stand-in saw, and its names.
#[derive(Default)]
pub struct StandIn {
    users: Mutex<Vec<String>>,
    forwards: Mutex<Vec<Key>>,
    opens: Mutex<Vec<Key>>,
    /// Each name's session, with the address and port that its forward asked.
    names: Mutex<HashMap<Key, (Handle, String, u32)>>,
    /// The tasks of the sessions, to cut each one.
    tasks: Mutex<Vec<tokio::task::AbortHandle>>,
    /// The forwards made, and the visitors sent down one.
    pub made: AtomicUsize,
    pub visits: AtomicUsize,
}

impl StandIn {
    /// The user of each login, in order.
    pub fn users(&self) -> Vec<String> {
        lock(&self.users).clone()
    }

    /// Each remote forward that was taken, in order.
    pub fn forwards(&self) -> Vec<Key> {
        lock(&self.forwards).clone()
    }

    /// Each `direct-tcpip` channel that a client asked for, in order.
    pub fn opens(&self) -> Vec<Key> {
        lock(&self.opens).clone()
    }

    /// Give the name `from` to the forward of `to`: a stranger at the name.
    pub fn hijack(&self, from: &Key, to: &Key) {
        let mut names = lock(&self.names);
        if let Some(held) = names.get(to).cloned() {
            names.insert(from.clone(), held);
        }
    }

    /// Cut each session, as the server's restart does.
    pub fn cut_all(&self) {
        for task in lock(&self.tasks).drain(..) {
            task.abort();
        }
    }

    /// The SSH port, served on the runtime that calls it.
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
                let (config, me) = (config.clone(), me.clone());
                let far = Far { stand_in: me.clone(), user: None, held: Vec::new() };
                let task = tokio::spawn(async move {
                    if let Ok(session) = server::run_stream(config, tcp, far).await {
                        let _ = session.await;
                    }
                });
                lock(&me.tasks).push(task.abort_handle());
            }
        });
        port
    }
}

/// One session, its user, and the names that its forwards hold.
struct Far {
    stand_in: Arc<StandIn>,
    user: Option<String>,
    held: Vec<Key>,
}

impl Drop for Far {
    /// The server lets a session's names go when it ends (`cleanup_tcp`).
    fn drop(&mut self) {
        let mut names = lock(&self.stand_in.names);
        for key in &self.held {
            names.remove(key);
        }
    }
}

impl server::Handler for Far {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        // Any user: it is a namespace of names, not an account.
        lock(&self.stand_in.users).push(user.to_string());
        self.user = Some(user.to_string());
        Ok(Auth::Accept)
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Some(user) = self.user.clone() else { return Ok(false) };
        if address.len() > MOST_ADDRESS {
            return Ok(false);
        }
        let key: Key = (user, address.to_string(), *port);
        let mut names = lock(&self.stand_in.names);
        // "port is already assigned via pseudodns"
        if names.contains_key(&key) {
            return Ok(false);
        }
        names.insert(key.clone(), (session.handle(), address.to_string(), *port));
        lock(&self.stand_in.forwards).push(key.clone());
        self.held.push(key);
        self.stand_in.made.fetch_add(1, Ordering::SeqCst);
        Ok(true)
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
        let key: Key = (self.user.clone().unwrap_or_default(), host.to_string(), port);
        lock(&self.stand_in.opens).push(key.clone());
        let Some((handle, address, port)) = lock(&self.stand_in.names).get(&key).cloned() else {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        // The server connects to the forward's own socket, which accepts at
        // once; the node's channel opens after.
        reply.accept().await;
        let stand_in = self.stand_in.clone();
        tokio::spawn(async move {
            let n = stand_in.visits.fetch_add(1, Ordering::SeqCst) as u32;
            let Ok(down) = handle.channel_open_forwarded_tcpip(address, port, "127.0.0.1", 40000 + n).await else {
                return;
            };
            let (mut up, mut down) = (channel.into_stream(), down.into_stream());
            let _ = tokio::io::copy_bidirectional(&mut up, &mut down).await;
        });
        Ok(())
    }
}
