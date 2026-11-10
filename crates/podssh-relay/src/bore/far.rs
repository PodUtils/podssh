//! The node of the bore road: one registration at a time at the server, at
//! the first port of its key that the server gives ([`super::control`]),
//! held until its control connection ends (the server's restart, its 24
//! hours, a lost connection), then made again with the forward opener's
//! jittered backoff, at once after a registration that lived a while. Each
//! visitor is served by the resumable layer's far end with the node's
//! keeper, the far end of the Pinggy road with no TLS, as Serveo's (T-549):
//! a session resumes on the next registration, and reaches its target only
//! after its handshake and the end-to-end channel above it.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::control::{self, Registered};
use super::{ports, Dial, Say, Service};
use crate::session::keep::Keeper;
use crate::session::Settings;

/// The visitors that wait for the layer, for each registration.
const WAITING: usize = 64;
/// A registration that lived this long ended as a server's restart does:
/// the next one is made at once.
const LIVED: Duration = Duration::from_secs(60);

/// A node of the bore road.
pub struct Node {
    pub service: Service,
    /// The ports of the node's key, in order ([`ports::of_fingerprint`]).
    pub ports: Vec<u16>,
    /// The hello of the node's key ([`ports::hello`]).
    pub hello: [u8; ports::HELLO_LEN],
    /// How the node reaches the control port.
    pub dial: Dial,
    pub say: Say,
}

impl Node {
    /// The node of the key whose fingerprint is `fingerprint`, at `service`.
    pub fn of_key(service: Service, fingerprint: &str, dial: Dial, say: Say) -> Node {
        Node { service, ports: ports::of_fingerprint(fingerprint), hello: ports::hello(fingerprint), dial, say }
    }

    /// Register once, as the first registration of a run.
    pub async fn register(&self) -> Result<Registered, String> {
        control::register(&self.dial, &self.service, &self.ports).await
    }

    /// The line of a registration.
    pub fn line(&self, registered: &Registered) -> String {
        let place = match registered.at {
            0 => "the first port of the node's key".to_string(),
            at => format!("port {} of the node's key, as the server refused the ones before it", at + 1),
        };
        let host = &self.service.host;
        format!("bore port {} at {}, {place}", podssh_ws::dial::authority(host, registered.port), self.service)
    }
}

/// Serve the sessions of each visitor of `node`, for ever, under `keeper`,
/// which another road's far end may share; `first` is a registration made
/// already, held first. A new session's target comes from `open`, and the
/// replay buffers of all sessions stay within `budget` bytes. It returns
/// never: the caller ends it.
pub async fn serve_kept<A, O, F>(
    node: Node,
    first: Option<Registered>,
    settings: Settings,
    budget: usize,
    open: O,
    keeper: Arc<Keeper<A>>,
) where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<A, String>> + Send + 'static,
{
    // The sweep ends with the keeper, when the node and its sessions end.
    crate::pinggy::far::sweep(&keeper);
    let (mut next, mut retry) = (first, 0u32);
    loop {
        let registered = match next.take() {
            Some(registered) => registered,
            None => match node.register().await {
                Ok(registered) => {
                    (node.say)(node.line(&registered));
                    registered
                }
                Err(why) => {
                    retry = retry.saturating_add(1);
                    let wait = crate::open::backoff(retry);
                    let (service, ms) = (&node.service, wait.as_millis());
                    (node.say)(format!("no registration at {service}: {why}; again in {ms} ms"));
                    tokio::time::sleep(wait).await;
                    continue;
                }
            },
        };
        let (queue, visitors) = mpsc::channel(WAITING);
        let say = node.say.clone();
        // Each visitor's stream holds no TLS: the end-to-end channel above
        // the layer keeps its bytes from the server.
        // It ends once the registration's queue is gone: the visitors taken
        // already are served on, and new ones come by the next.
        tokio::spawn(crate::pinggy::far::serve(visitors, None, settings, budget, open.clone(), keeper.clone(), say));
        let started = Instant::now();
        let hello = node.hello.to_vec();
        let why = control::hold(registered, node.dial.clone(), node.service.clone(), hello, queue, node.say.clone());
        let why = why.await;
        retry = if started.elapsed() >= LIVED { 0 } else { retry.saturating_add(1) };
        let wait = if retry == 0 { Duration::ZERO } else { crate::open::backoff(retry) };
        let (service, ms) = (&node.service, wait.as_millis());
        (node.say)(format!("the registration at {service} ended ({why}); a new one in {ms} ms"));
        tokio::time::sleep(wait).await;
    }
}
