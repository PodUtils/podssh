//! `podssh serve --remote-listen` (T-123, step 4): a client's `-R` as a
//! listener on this host's loopback, which serve's user asks for by the
//! flag (exception 1 of rule 2 of `AGENTS.md`), after `PODSSH_LISTEN`
//! (78 at the start where it says no). The bind is the probe: one that
//! fails refuses the forward with its reason, or, with `--publish-remote`
//! too, gives it to the relay's pair instead.
//!
//! The listener takes the port that the client asked for, or one that the
//! system picks for port 0, on 127.0.0.1 whatever address the client named,
//! as OpenSSH's sshd does with `GatewayPorts no`. Each connection it
//! accepts opens a `forwarded-tcpip` channel to the client, which names the
//! connection's own address and port; at most [`MAX_CONNECTIONS`] are open
//! at once for a forward, and a further one is closed at once. The
//! forward's end (a cancel, the connection's end, serve's stop) closes the
//! listener; a connection that it accepted ends with its channel.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::server::remote_forward::{Asked, Opener, Publish, Published, Publisher, Publishing, Stop};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// The connections open at once through one forward.
pub(crate) const MAX_CONNECTIONS: usize = 32;
/// Bound on the open of the client's channel for one connection.
const OPEN_LIMIT: Duration = Duration::from_secs(8);
/// The pause after an accept that failed (out of descriptors, as a rule),
/// so that a loop of failures does not spin.
const ACCEPT_PAUSE: Duration = Duration::from_millis(200);

/// The publisher of `--remote-listen`, with the relay's pair of
/// `--publish-remote` behind it where that is on too.
pub(crate) fn publisher(fallback: Option<Publisher>) -> Publisher {
    Publisher(Arc::new(Listened { fallback: fallback.map(|Publisher(p)| p) }))
}

struct Listened {
    fallback: Option<Arc<dyn Publish>>,
}

impl Publish for Listened {
    fn publish(&self, asked: Asked, opener: Opener) -> Publishing {
        let fallback = self.fallback.clone();
        Box::pin(async move {
            // remote_forward refuses a port past 65535 before any publish.
            let port = u16::try_from(asked.port).map_err(|_| format!("port {} is past 65535", asked.port))?;
            let at = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            let bound = match TcpListener::bind(at).await {
                Ok(listener) => listener,
                Err(e) => {
                    let why = format!("the bind of {at} failed: {e}");
                    return match fallback {
                        Some(relay) => relay.publish(asked, opener).await.map_err(|other| format!("{why}; {other}")),
                        None => Err(why),
                    };
                }
            };
            let port = bound.local_addr().map_err(|e| format!("the listener of {at} has no address: {e}"))?.port();
            let task = tokio::spawn(serve(bound, opener));
            Ok(Published {
                name: format!("127.0.0.1:{port}"),
                port: u32::from(port),
                reach: Some(format!("connect to 127.0.0.1:{port} on serve's host")),
                stop: Stop::new(move || task.abort()),
            })
        })
    }
}

/// Accept each connection, within the cap, and carry it to the client.
async fn serve(listener: TcpListener, opener: Opener) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, from) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(_) => {
                tokio::time::sleep(ACCEPT_PAUSE).await;
                continue;
            }
        };
        // Past the cap the connection closes at once: its peer sees a reset
        // or an end, never a wait that holds a descriptor here.
        let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
        let opener = opener.clone();
        tokio::spawn(async move {
            carry(stream, from, &opener).await;
            drop(slot);
        });
    }
}

/// One connection, through a channel to the client: its end ends both.
async fn carry(mut stream: TcpStream, from: SocketAddr, opener: &Opener) {
    let opened = tokio::time::timeout(OPEN_LIMIT, opener.open(&from.ip().to_string(), u32::from(from.port()))).await;
    let Ok(Ok(mut channel)) = opened else { return };
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut channel).await;
}
