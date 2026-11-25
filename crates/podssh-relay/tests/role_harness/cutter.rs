//! A TCP forwarder of the test's between a client and the role (T-627): a
//! cut drops both sockets of each connection that it carries, so the role
//! and the client each see an end with no WebSocket Close, as at a lost
//! link. An abort of the client's own task does not cut: a task that it
//! spawned can keep the socket open and answer the role's pings.

use std::sync::{Arc, Mutex};

use podssh_relay::relay::Relay;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// The forwarder, where it listens, and the connections that it carries.
pub struct Cutter {
    /// The role's relay as a client names it here: the same host, this port.
    pub relay: Relay,
    live: Arc<Mutex<Vec<JoinHandle<()>>>>,
    accept: JoinHandle<()>,
}

impl Cutter {
    /// A forwarder on a free port of the loopback to `role`'s port.
    pub async fn to(role: &Relay) -> Cutter {
        let listener = TcpListener::bind((role.host.as_str(), 0)).await.expect("a port of the forwarder");
        let port = listener.local_addr().expect("the forwarder's address").port();
        let live = Arc::new(Mutex::new(Vec::new()));
        let (held, host, to) = (live.clone(), role.host.clone(), role.port);
        let accept = tokio::spawn(async move {
            while let Ok((mut near, _)) = listener.accept().await {
                // A role that does not answer: the client's own connect
                // then fails on the dropped socket, with its own words.
                let Ok(mut far) = TcpStream::connect((host.as_str(), to)).await else { continue };
                let carry = tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut near, &mut far).await;
                });
                held.lock().unwrap().push(carry);
            }
        });
        Cutter { relay: Relay { host: role.host.clone(), port }, live, accept }
    }

    /// Drop both sockets of each connection carried so far; how many there
    /// were. A connection after the cut is carried as before.
    pub fn cut(&self) -> usize {
        let carried: Vec<_> = self.live.lock().unwrap().drain(..).collect();
        let open = carried.iter().filter(|c| !c.is_finished()).count();
        for carry in carried {
            carry.abort();
        }
        open
    }
}

impl Drop for Cutter {
    fn drop(&mut self) {
        self.accept.abort();
        for carry in self.live.lock().unwrap().drain(..) {
            carry.abort();
        }
    }
}
