//! The limits of a listener of `podssh serve --listen` (T-124): a cap on
//! the connections at once, and one on those that have not logged in
//! (T-631), each taken at the accept before a byte is read, and the refusal
//! past them. The listener and its bind are the caller's; each connection
//! let in goes to [`super::serve_admitted`] with its [`Admitted`].
//!
//! A connection let in has a deadline from its accept (T-631): no login by
//! then, and it ends, whether the client said nothing or a byte now and
//! then. The first login cancels it and gives back the place among those
//! not logged in; the waiter ends with the session, so a quick login keeps
//! no timer.
//!
//! A refusal is serve's version line and one DISCONNECT in the clear with
//! the reason `TooManyConnections` (RFC 4253, 11.1; RFC 4250, 4.2.2), as a
//! server may send before the key exchange: OpenSSH's client prints it.
//! Then serve reads what the client sent, so that the close sends no reset
//! ahead of the words, and closes. The refusals under way have a cap of
//! their own; past it a connection is closed with no word, so a flood costs
//! a descriptor for a moment and nothing more.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// The connections at once by default (`--max-connections`).
pub const CONNECTIONS: usize = 64;
/// The connections not yet logged in by default (`--pending-max`).
pub const PENDING: usize = 16;
/// The time from the accept to a login by default (`--login-timeout`):
/// half of OpenSSH's `LoginGraceTime`, as a sandbox's link is short.
pub const LOGIN: Duration = Duration::from_secs(60);
/// The longest `--login-timeout`: past it the limit holds nobody off.
pub const LOGIN_MAX: Duration = Duration::from_secs(3600);
/// The most a cap may be: past it a cap is no bound that a host can hold.
pub const CAP_MAX: usize = 65_536;
/// The refusals under way at once; past it a connection is closed at once.
pub const REFUSING: usize = 16;
/// The whole of one refusal: the words, then the client's bytes read.
pub const REFUSE_LIMIT: Duration = Duration::from_secs(5);
/// The client's bytes that a refusal reads at most before it closes.
const DRAIN_MAX: usize = 64 * 1024;
/// SSH_MSG_DISCONNECT (RFC 4253, 11.1).
const MSG_DISCONNECT: u8 = 1;
/// SSH_DISCONNECT_TOO_MANY_CONNECTIONS (RFC 4250, 4.2.2); russh's
/// `Disconnect::TooManyConnections`, which a test holds it to.
pub const TOO_MANY_CONNECTIONS: u32 = 12;
/// The cipher block of a packet in the clear (RFC 4253, 6).
const CLEAR_BLOCK: usize = 8;

/// The caps of one listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The connections at once, logged in or not.
    pub connections: usize,
    /// The connections at once that have not logged in.
    pub pending: usize,
    /// The time from the accept to the first login.
    pub login: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { connections: CONNECTIONS, pending: PENDING, login: LOGIN }
    }
}

/// Why a connection was not let in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The cap of `--max-connections` was reached.
    Connections(usize),
    /// The cap of `--pending-max` was reached.
    Pending(usize),
}

impl Why {
    /// Why, in words for serve's log.
    pub fn words(&self) -> String {
        match self {
            Why::Connections(n) => format!("{n} connections at once already (--max-connections); try again later"),
            Why::Pending(n) => {
                format!("{n} connections that have not logged in already (--pending-max); try again later")
            }
        }
    }

    /// What the client is told: the words, after whose they are.
    pub fn told(&self) -> String {
        format!("podssh serve: {}", self.words())
    }
}

/// A connection let in: the place that it holds under the caps, given back
/// when it drops with the connection, and its deadline.
#[derive(Debug)]
pub struct Admitted {
    pub(super) all: OwnedSemaphorePermit,
    pub(super) login: Login,
}

/// The deadline of one connection from its accept, and its place among the
/// connections not logged in.
#[derive(Debug)]
pub(super) struct Login {
    pub(super) at: Instant,
    limit: Duration,
    pending: Option<OwnedSemaphorePermit>,
}

impl Login {
    /// What the client and the log are told when the deadline passes.
    pub(super) fn told(&self) -> String {
        format!("podssh serve: no login within {} s of the connection (--login-timeout)", self.limit.as_secs())
    }

    /// The same, before the client's version line came.
    pub(super) fn silent(&self) -> String {
        format!("no SSH version line within {} s of the connection (--login-timeout): closed", self.limit.as_secs())
    }
}

/// Wait for the deadline of `login`: the words of its end when it passes
/// first; never when the first login comes first, whose place among the
/// connections not logged in then comes back. No deadline: never.
pub(super) async fn reaped(login: Option<Login>, mut logged_in: watch::Receiver<bool>) -> String {
    let Some(mut login) = login else { return std::future::pending().await };
    let passed = tokio::select! {
        // The guard of `wait_for` goes inside its block: a guard held on
        // would make the connection's future not Send. A sender gone is a
        // connection gone, which no deadline need end.
        _ = async { logged_in.wait_for(|in_| *in_).await.is_ok() } => false,
        () = tokio::time::sleep_until(login.at) => true,
    };
    if passed {
        return login.told();
    }
    drop(login.pending.take());
    std::future::pending().await
}

/// A connection over a cap, with its place among the refusals.
#[derive(Debug)]
pub struct Full {
    pub why: Why,
    _refusing: OwnedSemaphorePermit,
}

/// What [`Gate::enter`] made of a connection just accepted.
#[derive(Debug)]
pub enum Entry {
    /// In: hold it for the connection's life.
    Admitted(Admitted),
    /// Over a cap: [`refuse`] it.
    Full(Full),
    /// Over a cap, with [`REFUSING`] refusals under way: close it now.
    Dropped(Why),
}

/// The caps of one server's listeners, shared by each of them.
#[derive(Debug, Clone)]
pub struct Gate {
    limits: Limits,
    all: Arc<Semaphore>,
    pending: Arc<Semaphore>,
    refusing: Arc<Semaphore>,
}

impl Gate {
    /// The caps of `limits`; each is 1 at least, and [`CAP_MAX`] at most;
    /// the deadline 1 s at least, and [`LOGIN_MAX`] at most.
    pub fn new(limits: Limits) -> Gate {
        let connections = limits.connections.clamp(1, CAP_MAX);
        let pending = limits.pending.clamp(1, CAP_MAX);
        let login = limits.login.clamp(Duration::from_secs(1), LOGIN_MAX);
        Gate {
            limits: Limits { connections, pending, login },
            all: Arc::new(Semaphore::new(connections)),
            pending: Arc::new(Semaphore::new(pending)),
            refusing: Arc::new(Semaphore::new(REFUSING)),
        }
    }

    /// The caps in force.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Place a connection just accepted, before a byte of it is read: its
    /// deadline starts now.
    pub fn enter(&self) -> Entry {
        let at = Instant::now() + self.limits.login;
        let Ok(all) = self.all.clone().try_acquire_owned() else {
            return self.full(Why::Connections(self.limits.connections));
        };
        let Ok(pending) = self.pending.clone().try_acquire_owned() else {
            return self.full(Why::Pending(self.limits.pending));
        };
        let login = Login { at, limit: self.limits.login, pending: Some(pending) };
        Entry::Admitted(Admitted { all, login })
    }

    fn full(&self, why: Why) -> Entry {
        match self.refusing.clone().try_acquire_owned() {
            Ok(refusing) => Entry::Full(Full { why, _refusing: refusing }),
            Err(_) => Entry::Dropped(why),
        }
    }

    /// The connections let in that are still open.
    pub fn open(&self) -> usize {
        self.limits.connections - self.all.available_permits()
    }

    /// The connections let in that have not logged in.
    pub fn pending(&self) -> usize {
        self.limits.pending - self.pending.available_permits()
    }
}

/// Refuse a connection over a cap: serve's version line and a DISCONNECT
/// that says why, then the client's bytes read until its end, all within
/// [`REFUSE_LIMIT`]. Each failure ends the refusal quietly: the client was
/// refused either way.
pub async fn refuse<S>(mut stream: S, full: Full)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bytes = refusal(&full.why.told());
    let said = async {
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        stream.shutdown().await?;
        let mut buffer = [0u8; 4096];
        let mut read = 0;
        while read < DRAIN_MAX {
            match stream.read(&mut buffer).await? {
                0 => break,
                n => read += n,
            }
        }
        Ok::<(), io::Error>(())
    };
    let _ = tokio::time::timeout(REFUSE_LIMIT, said).await;
    drop(full);
}

/// The bytes of a refusal: the version line, then one packet in the clear
/// that holds a DISCONNECT with `reason`.
pub fn refusal(reason: &str) -> Vec<u8> {
    let mut out = format!("{}\r\n", super::server_id()).into_bytes();
    out.extend(disconnect_packet(TOO_MANY_CONNECTIONS, reason));
    out
}

/// A binary packet in the clear (RFC 4253, 6): its length, the padding's
/// length, the payload, and 4 to 11 bytes of padding that round it to the
/// block. No MAC goes in the clear.
fn disconnect_packet(code: u32, reason: &str) -> Vec<u8> {
    let mut payload = vec![MSG_DISCONNECT];
    payload.extend(code.to_be_bytes());
    put_string(&mut payload, reason.as_bytes());
    put_string(&mut payload, b"");
    let mut padding = CLEAR_BLOCK - (4 + 1 + payload.len()) % CLEAR_BLOCK;
    if padding < 4 {
        padding += CLEAR_BLOCK;
    }
    // The payload is a short reason of serve's own, far below u32::MAX.
    let length = u32::try_from(1 + payload.len() + padding).unwrap_or(u32::MAX);
    let mut packet = length.to_be_bytes().to_vec();
    packet.push(padding as u8);
    packet.extend(payload);
    packet.extend(std::iter::repeat_n(0u8, padding));
    packet
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend(bytes);
}

#[cfg(test)]
#[path = "listen_tests.rs"]
mod tests;
