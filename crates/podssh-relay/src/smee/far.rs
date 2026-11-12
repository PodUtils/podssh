//! The node of the road: a stream of its door's channel for as long as it
//! runs, opened again after each hello, after each lost stream with the
//! forward opener's jittered backoff, and each few minutes, so that no proxy
//! holds a quiet answer for ever; and each link that a hello asks for,
//! served by the resumable layer's far end, with the sessions kept by one
//! keeper across links, as on the other roads. A new session reaches its
//! target only after the layer's handshake, and the channel above it.
//!
//! Each way of a link holds a connection (the stream of the far end's way,
//! and the kept connection of this end's POSTs), so the door is closed
//! while a link runs, and the node holds two connections at most, as the
//! operator's ruling Q44 allows a road that a refused upgrade chose (the
//! Piping Server road's node does the same over HTTP/1.1); a second client
//! knocks until the first link ends. A hello is opened once: a client posts
//! it again until the node's mark comes.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;

use super::frame::{self, Message, FRAME_MAX};
use super::http::Http;
use super::link::{self, Opening, IDLE_LIMIT, MARK_LIMIT};
use super::names::{Ends, LinkId, Secret};
use super::Say;
use crate::session::far as layer;
use crate::session::keep::Keeper;
use crate::session::record::Role;
use crate::session::Settings;

/// How often the sessions whose links are lost are checked for their
/// deadline.
const SWEEP_EVERY: Duration = Duration::from_secs(10);
/// How long the door's stream is read before it is opened again.
pub const DOOR_REFRESH: Duration = Duration::from_secs(240);
/// A stream of the door that ended after this long met a proxy's bound of a
/// quiet answer, not a fault: it is opened again at once.
const QUIET: Duration = Duration::from_secs(20);
/// How long a link's id is kept, so that its hello again opens nothing.
const SEEN_FOR: Duration = Duration::from_secs(120);

/// A node of the road.
pub struct Node {
    /// The pair's key, which names the door and the links.
    pub secret: Arc<Secret>,
    pub http: Arc<Http>,
    pub say: Say,
}

/// What one stream of the door gave.
enum Door {
    /// A hello of this pair's, for a link not seen.
    Hello(LinkId),
    /// The refresh, or a quiet end that a proxy made.
    Again,
    Failed(String),
}

/// Serve the sessions of each link of `node`, for ever, with `keeper`, which
/// another road's far end may share, so that a session resumes on either
/// road; a new session's target comes from `open`, and the replay buffers of
/// all sessions stay within `budget` bytes.
pub async fn serve_kept<A, O, F>(node: Node, settings: Settings, budget: usize, open: O, keeper: Arc<Keeper<A>>)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<A, String>> + Send + 'static,
{
    // The sweep ends with the keeper, when the node and its sessions end.
    {
        let keeper = Arc::downgrade(&keeper);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_EVERY).await;
                let Some(keeper) = keeper.upgrade() else { return };
                keeper.expire().await;
            }
        });
    }
    (node.say)(format!("waiting for clients at smee.io's server {}", node.http.server()));
    let size = Arc::new(AtomicUsize::new(FRAME_MAX));
    let one_link = Arc::new(Semaphore::new(1));
    let mut seen: VecDeque<(Instant, LinkId)> = VecDeque::new();
    let mut failed: u32 = 0;
    loop {
        // The door waits while a link runs: two connections at most (Q44).
        let Ok(permit) = one_link.clone().acquire_owned().await else { return };
        seen.retain(|(at, _)| at.elapsed() < SEEN_FOR);
        match door(&node, &seen).await {
            Door::Hello(id) => {
                failed = 0;
                seen.push_back((Instant::now(), id));
                let (http, secret, say) = (node.http.clone(), node.secret.clone(), node.say.clone());
                let size = size.clone();
                let (keeper, open) = (keeper.clone(), open.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    let ends = Ends::node(&secret, &id);
                    match open_link(&http, &ends).await {
                        Ok(events) => {
                            let link = link::carry(http.clone(), &ends, events, size);
                            layer::serve(link, Role::NODE, settings, &keeper, budget, open).await;
                        }
                        Err(why) => say(format!("link {} did not open: {why}", id.short())),
                    }
                    // The POSTs' connection goes with the link: the door's
                    // stream is the one connection while none runs.
                    http.close().await;
                });
            }
            Door::Again => failed = 0,
            Door::Failed(why) => {
                failed = failed.saturating_add(1);
                let wait = crate::open::backoff(failed);
                let server = node.http.server();
                (node.say)(format!("the door at {server}: {why}; asking again in {} ms", wait.as_millis()));
                tokio::time::sleep(wait).await;
            }
        }
    }
}

/// One stream of the door, read until a hello of this pair's for a link not
/// in `seen`, the refresh, or its end.
async fn door(node: &Node, seen: &VecDeque<(Instant, LinkId)>) -> Door {
    let opened = Instant::now();
    let mut events = match link::open_stream(&node.http, &node.secret.door()).await {
        Ok(events) => events,
        Err(Opening::Held(why) | Opening::Failed(why)) => return Door::Failed(why),
    };
    let reading = async {
        loop {
            let event = match events.next(IDLE_LIMIT).await {
                Ok(Some(event)) => event,
                Ok(None) if opened.elapsed() >= QUIET => return Door::Again,
                Ok(None) => return Door::Failed("the stream of the door ended".into()),
                Err(why) => return Door::Failed(why),
            };
            let Ok(Message::Hello(line)) = frame::read(&event.data) else { continue };
            match node.secret.read_hello(&line) {
                Ok(id) if seen.iter().any(|(_, known)| *known == id) => continue,
                Ok(id) => return Door::Hello(id),
                // Anyone may post to a channel whose name they know.
                Err(why) => (node.say)(format!("a hello at the door that is not this pair's: {why}")),
            }
        }
    };
    tokio::time::timeout(DOOR_REFRESH, reading).await.unwrap_or(Door::Again)
}

/// The link of a hello: the stream of the client's way, this end's mark on
/// its own, and the client's mark read back.
async fn open_link(http: &Http, ends: &Ends) -> Result<super::http::Events, Opening> {
    let mut events = link::open_stream(http, &ends.recv).await?;
    link::send_mark(http, ends).await?;
    link::read_mark(&mut events, ends, MARK_LIMIT).await?;
    Ok(events)
}
