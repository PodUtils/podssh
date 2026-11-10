//! The node of croc's relay road: one connection at a time that waits in a
//! room of the pair at croc's relay, through the bridge, for an operator of
//! the pair; the room is the first that no link of the node's own holds, so
//! a client that tries the rooms in order finds it. At each meeting the
//! next wait opens at once, and the link is served by the resumable layer's
//! far end with the node's keeper, which the pair's road shares, so that a
//! session resumes on either. A new session reaches its target only after
//! its handshake, and the end-to-end channel above it. A room that is taken
//! sends the wait to the next; a connection that fails is made again with
//! the forward opener's jittered backoff, and so is a peer that did not
//! prove the pair, so that a stranger who knows the rooms cannot keep the
//! node busy. The relay drops a waiting room at its 3 h, or when its 128
//! waiting rooms are full: the next wait opens at once.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::url::{self, WsUrl};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use super::client::WHO;
use super::meet::{meet, Missed};
use super::rooms::{Rooms, SLOTS};
use super::{Bridge, Say};
use crate::session::keep::Keeper;
use crate::session::record::Role;
use crate::session::{far, OsEntropy, Settings};
use crate::transit::{Link, Part};

/// How often the sessions whose links are lost are checked for their
/// deadline.
const SWEEP_EVERY: Duration = Duration::from_secs(10);
/// A wait that the relay ended after this long, with no meeting, is the
/// relay's own end of a waiting room: the next one starts at once.
const LONG_WAIT: Duration = Duration::from_secs(60);
/// How long a node whose rooms are each held by its own links waits before
/// it looks again.
const ALL_HELD: Duration = Duration::from_secs(5);

/// The pair's words now, read before each wait: a node goes on with a later
/// pair at an expiry, and its rooms are that pair's.
pub type RoomsNow = Arc<dyn Fn() -> Rooms + Send + Sync>;

/// A node of croc's relay road.
pub struct Node {
    pub bridge: Bridge,
    pub rooms: RoomsNow,
    pub trust: Trust,
    pub proxy: ProxyChoice,
    pub say: Say,
}

/// A connection through the bridge, before its handshake.
pub async fn dial(
    url: &WsUrl,
    trust: &Trust,
    proxy: &ProxyChoice,
) -> Result<podssh_ws::RelaySession<url::Stream>, String> {
    let (timeout, idle) = (crate::open::CONNECT_TIMEOUT, Some(podssh_ws::DEFAULT_IDLE_TIMEOUT));
    url::dial(url, trust, proxy, timeout, idle).await.map_err(|e| url::failure(url, &e))
}

/// The rooms that the node's own links hold.
#[derive(Clone, Default)]
struct Held(Arc<Mutex<[bool; SLOTS]>>);

impl Held {
    fn set(&self, slot: usize, held: bool) {
        let mut slots = self.0.lock().unwrap_or_else(|e| e.into_inner());
        slots[slot] = held;
    }

    /// The first room that no link holds and that was not found taken.
    fn first_free(&self, taken: &[bool; SLOTS]) -> Option<usize> {
        let slots = self.0.lock().unwrap_or_else(|e| e.into_inner());
        (0..SLOTS).find(|&slot| !slots[slot] && !taken[slot])
    }
}

/// Serve the sessions of each link of `node`, for ever, under `keeper`,
/// which another road's far end may share, so that a session resumes on
/// either; a new session's target comes from `open`, and the replay buffers
/// of all sessions stay within `budget` bytes. It returns never: the caller
/// ends it.
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
    let held = Held::default();
    let (mut retry, mut waiting, mut taken) = (0u32, None::<usize>, [false; SLOTS]);
    loop {
        let rooms = (node.rooms)();
        let (url, shown) = (node.bridge.url(&rooms), node.bridge.shown(&rooms));
        let Some(slot) = held.first_free(&taken) else {
            // Each room is held, by the node's links or by strangers: look
            // again in a while, with the strangers' rooms tried anew.
            if taken.iter().any(|t| *t) {
                (node.say)(format!("each room of the pair at {shown} is taken; trying again"));
            }
            taken = [false; SLOTS];
            tokio::time::sleep(ALL_HELD).await;
            continue;
        };
        let session = match dial(&url, &node.trust, &node.proxy).await {
            Ok(session) => session,
            Err(why) => {
                (node.say)(format!("no connection to croc's relay: {why}"));
                waiting = None;
                retry = retry.saturating_add(1);
                pause(&node, retry).await;
                continue;
            }
        };
        if waiting != Some(slot) {
            (node.say)(format!("waiting at {shown} for the pair's operators (room {slot})"));
            waiting = Some(slot);
        }
        let started = Instant::now();
        let password = node.bridge.password.clone();
        match meet(&session, &password, &rooms, slot, Part::Node, None, &mut OsEntropy).await {
            Ok(first) => {
                (retry, taken) = (0, [false; SLOTS]);
                held.set(slot, true);
                let link = Link::start_by(session, first, WHO);
                let (keeper, open, held) = (keeper.clone(), open.clone(), held.clone());
                tokio::spawn(async move {
                    far::serve(link, Role::NODE, settings, &keeper, budget, open).await;
                    held.set(slot, false);
                });
            }
            Err(Missed::Full) => {
                taken[slot] = true;
                waiting = None;
            }
            // The relay's own end of a waiting room: the next wait, at once.
            Err(Missed::Dropped(_)) if started.elapsed() >= LONG_WAIT => retry = 0,
            Err(missed) => {
                (node.say)(format!("a meeting at {shown} failed: {missed}"));
                waiting = None;
                retry = retry.saturating_add(1);
                pause(&node, retry).await;
            }
        }
    }
}

/// The jittered backoff of the `retry`th failure in a row, said.
async fn pause(node: &Node, retry: u32) {
    let wait = crate::open::backoff(retry);
    (node.say)(format!("waiting at croc's relay again in {} ms", wait.as_millis()));
    tokio::time::sleep(wait).await;
}
