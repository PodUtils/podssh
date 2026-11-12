//! The client of the road: a link to the node of a pair, by a hello at the
//! node's door. smee.io answers each POST with `200` whether anyone reads
//! the channel or not, and gives a stream nothing that came before it, so
//! the client opens its own way's stream first, then posts the hello again
//! each few seconds until the node's mark comes on that stream, or the
//! node is not there within [`DOOR_LIMIT`]. A node opens a link's id once,
//! however often its hello comes. A stream with no event, as through a
//! proxy that holds an answer until its end, ends the road for this run.
//! The end-to-end channel above the layer checks the node's identity, as the
//! channels prove only the pair's secret.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};

use super::frame::{self, FRAME_MAX};
use super::http::Http;
use super::link::{self, Link, Opening};
use super::names::{Ends, LinkId, Secret};
use super::Say;
use crate::session::client::{self, Outcome};
use crate::session::resume::{self, Next, Note};
use crate::session::{Ask, Ended, OsEntropy, Settings};

/// How long a hello waits for the node at its door.
pub const DOOR_LIMIT: Duration = Duration::from_secs(20);
/// How often the hello is posted again while no mark came: the node's
/// stream of its door may have been between two requests when it came.
pub const KNOCK_EVERY: Duration = Duration::from_secs(3);

/// The links of one client to the node of one pair.
pub struct Dialer {
    secret: Arc<Secret>,
    http: Arc<Http>,
    /// The most bytes of a frame, halved by a refusal of a POST as too large.
    size: Arc<AtomicUsize>,
    /// Why the road is no road through this way out, once a stream gave no
    /// event: no link is tried again in this run.
    held: Mutex<Option<String>>,
    /// Whether a link was made, so that a later miss is the node's, not the
    /// way's.
    met: AtomicBool,
    say: Say,
}

impl Dialer {
    pub fn new(secret: Secret, http: Http, say: Say) -> Dialer {
        Dialer {
            secret: Arc::new(secret),
            http: Arc::new(http),
            size: Arc::new(AtomicUsize::new(FRAME_MAX)),
            held: Mutex::new(None),
            met: AtomicBool::new(false),
            say,
        }
    }

    /// The server of the road.
    pub fn server(&self) -> &crate::piping::Server {
        self.http.server()
    }

    /// The most bytes of a frame now.
    pub fn frame_size(&self) -> usize {
        self.size.load(Ordering::SeqCst)
    }

    /// A new link to the node, whose mark came; else why none.
    pub async fn link(&self) -> Result<Link, String> {
        if let Some(why) = self.held.lock().ok().and_then(|held| held.clone()) {
            return Err(format!("not tried again: {why}"));
        }
        let id = LinkId::random(&mut OsEntropy).map_err(|e| e.to_string())?;
        let ends = Ends::client(&self.secret, &id);
        let mut events = match link::open_stream(&self.http, &ends.recv).await {
            Ok(events) => events,
            Err(Opening::Held(why)) => {
                (self.say)(format!("{why}; the smee.io road is not tried again in this run"));
                if let Ok(mut held) = self.held.lock() {
                    *held = Some(why.clone());
                }
                return Err(why);
            }
            Err(Opening::Failed(why)) => return Err(format!("{}: {why}", self.http.server())),
        };
        self.knock(&id, &ends, &mut events).await?;
        link::send_mark(&self.http, &ends).await.map_err(|o| o.to_string())?;
        self.met.store(true, Ordering::SeqCst);
        Ok(link::carry(self.http.clone(), &ends, events, self.size.clone()))
    }

    /// The hello of link `id` at the node's door, posted again each
    /// [`KNOCK_EVERY`] until the node's mark comes on `events`.
    async fn knock(&self, id: &LinkId, ends: &Ends, events: &mut super::http::Events) -> Result<(), String> {
        let (door, hello) = (self.secret.door(), frame::hello(&self.secret.hello(id)));
        let started = Instant::now();
        loop {
            if let Err(failed) = self.http.post(&door, &hello, link::POST_LIMIT).await {
                // A channel that smee.io's operator closed answers 403.
                return Err(format!("the hello at {}: {failed}", self.http.server()));
            }
            let left = DOOR_LIMIT.saturating_sub(started.elapsed());
            match link::read_mark(events, ends, KNOCK_EVERY.min(left)).await {
                Ok(()) => return Ok(()),
                Err(Opening::Failed(why)) if !why.starts_with("no mark") => return Err(why),
                Err(_) if started.elapsed() >= DOOR_LIMIT => {
                    let was = if self.met.load(Ordering::SeqCst) { ", where it was before" } else { "" };
                    return Err(format!(
                        "no node took the hello at {} within {} s{was}: the node is offline, or serves no smee.io \
                         road",
                        self.http.server(),
                        DOOR_LIMIT.as_secs()
                    ));
                }
                Err(_) => {}
            }
        }
    }

    /// End the kept connection of the POSTs.
    pub async fn close(&self) {
        self.http.close().await;
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
