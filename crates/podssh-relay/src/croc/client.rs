//! The client of croc's relay road: for each link, a connection through the
//! bridge to the relay of the pair's rooms, which tries the rooms in order
//! until one holds the node that waits there. A taken room sends it to the
//! next; a room with no one in it, the next too, once a short wait passed,
//! as the node waits in the first room that no link of its own holds. A
//! meeting with another client of the pair starts the rooms again, once.
//! The meeting proves the pair only: the node's identity is the end-to-end
//! channel's to check, above the layer.

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};
use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use super::far::dial;
use super::meet::{meet, Missed};
use super::rooms::{Rooms, SLOTS};
use super::{Bridge, Say};
use crate::session::client::{self, Outcome};
use crate::session::resume::{self, Next, Note};
use crate::session::{Ask, Ended, OsEntropy, Settings};
use crate::transit::{Link, Part};

/// How long a link may take: a node that waits answers at once, so this is
/// a few rooms' handshakes through the bridge.
pub const MEET_LIMIT: Duration = Duration::from_secs(20);
/// How long a client stays in a room where no peer is: the node's hello
/// comes at once from a room where it waits.
pub const ALONE: Duration = Duration::from_secs(3);
/// The name of the far side of a link, in its failures.
pub const WHO: &str = "croc's relay";

/// The links of one client to the node of one pair.
pub struct Dialer {
    bridge: Bridge,
    rooms: Rooms,
    trust: Trust,
    proxy: ProxyChoice,
    say: Say,
    wait: Duration,
    alone: Duration,
}

impl Dialer {
    /// The dialer of the pair whose words are `rooms`, through `bridge`.
    pub fn new(bridge: Bridge, rooms: Rooms, trust: Trust, proxy: ProxyChoice, say: Say) -> Dialer {
        Dialer { bridge, rooms, trust, proxy, say, wait: MEET_LIMIT, alone: ALONE }
    }

    /// The same, waiting `wait` in all and `alone` in an empty room.
    pub fn with_waits(self, wait: Duration, alone: Duration) -> Dialer {
        Dialer { wait, alone, ..self }
    }

    /// The bridge.
    pub fn bridge(&self) -> &Bridge {
        &self.bridge
    }

    /// The URL of the pair's relay through the bridge.
    pub fn url(&self) -> WsUrl {
        self.bridge.url(&self.rooms)
    }

    /// A new link to the node, which met this client and proved the pair;
    /// else why there is none.
    pub async fn link(&self) -> Result<Link, String> {
        let (url, until) = (self.url(), Instant::now() + self.wait);
        let shown = self.bridge.shown(&self.rooms);
        let (mut full, mut empty, mut others) = (0usize, 0usize, 0u32);
        let mut slot = 0;
        while slot < SLOTS {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let session = dial(&url, &self.trust, &self.proxy).await?;
            let password = self.bridge.password.as_str();
            let alone = Some(self.alone.min(left));
            let met = meet(&session, password, &self.rooms, slot, Part::Client, alone, &mut OsEntropy).await;
            match met {
                Ok(first) => return Ok(Link::start_by(session, first, WHO)),
                Err(Missed::Full) => full += 1,
                Err(Missed::Alone(_)) => empty += 1,
                // Two clients of the pair met in a room that the node had
                // left: each tries the rooms again, once, apart; after that,
                // the next room.
                Err(Missed::SamePart) => {
                    others += 1;
                    (self.say)(format!("another client of the pair met this one at {shown}"));
                    if others == 1 {
                        let _ = session.send_close(1000, "").await;
                        let jitter = rand::rng().random_range(100..600);
                        tokio::time::sleep(Duration::from_millis(jitter)).await;
                        slot = 0;
                        continue;
                    }
                }
                // A room that the relay dropped: the next.
                Err(Missed::Dropped(why)) => (self.say)(format!("{shown}: {why}; the next room")),
                Err(missed) => return Err(format!("{shown}: {missed}")),
            }
            let _ = session.send_close(1000, "").await;
            slot += 1;
        }
        Err(self.missed(&shown, full, empty, others))
    }

    fn missed(&self, shown: &str, full: usize, empty: usize, others: u32) -> String {
        let mut why = format!("no node met this client at {shown} within {} s", self.wait.as_secs());
        if full == SLOTS {
            why = format!("each of the pair's {SLOTS} rooms at {shown} is taken");
        } else if full + empty > 0 {
            why.push_str(&format!(" ({full} of its rooms taken, {empty} with no one)"));
        }
        if others > 0 {
            why.push_str(" (another client of the pair met it)");
        }
        why
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

/// Where a line goes, for a test that hears none.
pub fn quiet() -> Say {
    Arc::new(|_line: String| {})
}
