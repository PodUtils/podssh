//! The client of the bore road: for each link, a connection to a public
//! port of the node's key at the server, through the caller's [`Dial`]
//! (directly, by `HTTPS_PROXY`'s CONNECT, or through the forwarders of the
//! operator's ruling Q56, as the caller makes it), whose first bytes must be
//! the node's hello; else the next port of the series. The port that last
//! gave the hello is tried first. The hello is public: the end-to-end channel
//! above the layer checks the node's key on each link.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use super::{ports, BoxIo, Dial, Say, Service};
use crate::session::client::{self, Outcome};
use crate::session::resume::{self, Next, Note};
use crate::session::{Ask, Ended, OsEntropy, Settings};

/// How long a port may take to give the hello: the server sends the node a
/// `Connection`, which the node takes on a new connection of its own, both
/// maybe through a proxy.
pub const HELLO_WAIT: Duration = Duration::from_secs(8);

/// The links of one client to one node.
pub struct Dialer {
    service: Service,
    ports: Vec<u16>,
    hello: [u8; ports::HELLO_LEN],
    visit: Dial,
    say: Say,
    wait: Duration,
    /// The place in the series of the port that last gave the hello.
    last: AtomicUsize,
}

impl Dialer {
    /// The dialer of the node whose key's fingerprint is `fingerprint`, at
    /// `service`, through `visit`.
    pub fn new(service: Service, fingerprint: &str, visit: Dial, say: Say) -> Dialer {
        let (ports, hello) = (ports::of_fingerprint(fingerprint), ports::hello(fingerprint));
        Dialer { service, ports, hello, visit, say, wait: HELLO_WAIT, last: AtomicUsize::new(0) }
    }

    /// The same, waiting `wait` for each port's hello.
    pub fn with_wait(self, wait: Duration) -> Dialer {
        Dialer { wait, ..self }
    }

    pub fn service(&self) -> &Service {
        &self.service
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    /// One port: its stream once the hello came, else why not.
    async fn port(&self, port: u16) -> Result<BoxIo, String> {
        let shown = podssh_ws::dial::authority(&self.service.host, port);
        let mut stream = (self.visit)(&self.service.host, port).await?;
        let mut heard = [0u8; ports::HELLO_LEN];
        match tokio::time::timeout(self.wait, stream.read_exact(&mut heard)).await {
            Ok(Ok(_)) if heard == self.hello => Ok(stream),
            Ok(Ok(_)) => Err(format!("{shown} is another tunnel's: its first bytes are not the node's hello")),
            Ok(Err(e)) => Err(format!("{shown} ended before the node's hello: {e}")),
            Err(_) => Err(format!("{shown} gave no hello within {} s", self.wait.as_secs())),
        }
    }

    /// A new link to the node, once a port of its key gave its hello; else
    /// why each port gave none.
    pub async fn link(&self) -> Result<BoxIo, String> {
        let start = self.last.load(Ordering::SeqCst);
        let mut missed = Vec::new();
        for step in 0..self.ports.len() {
            let at = (start + step) % self.ports.len();
            match self.port(self.ports[at]).await {
                Ok(stream) => {
                    if at != start {
                        (self.say)(format!("the node answers at the port {} of its key", self.ports[at]));
                    }
                    self.last.store(at, Ordering::SeqCst);
                    return Ok(stream);
                }
                Err(why) => missed.push(why),
            }
        }
        Err(format!(
            "no port of the node's key at {} gave its hello ({}): the node is not there now, or its key is not the \
             one expected",
            self.service,
            missed.join("; ")
        ))
    }
}

/// Carry `app` to the node of `dialer`: the first link and the layer's
/// handshake on it, then a new link after each lost one, until the session
/// ends. `note` hears each step of the session across links.
pub async fn carry<A, N>(dialer: &Dialer, app: A, settings: Settings, note: N) -> Result<Outcome, String>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    let first = dialer.link().await?;
    let client = client::start(first, Ask::New, settings, &mut OsEntropy).await.map_err(|e| e.to_string())?;
    let connect = |_: &Ended| async move {
        match dialer.link().await {
            Ok(link) => Next::Link(link),
            Err(why) => Next::Retry(why),
        }
    };
    // On the heap: the layer's future is larger than a small thread's stack
    // in a debug build.
    Ok(Box::pin(resume::run(client, app, connect, note, &mut OsEntropy)).await)
}
