//! Shells that outlive their client (T-159): a login shell on a pty that
//! `podssh serve` keeps after its channel leaves, when the client asked
//! (`~d` of T-158, or `keep@podssh` before the shell), for a lease, so that a
//! later login of the same key joins it again by its name.
//!
//! One object holds the shell, and no channel owns it: the pty's input and
//! size, the child's process group, a ring of the recent output, and the one
//! channel attached now, if any. The output goes to that channel and into
//! the ring; with no channel, into the ring alone, and an attach gets what
//! came since the detach. Each attach is a new generation: input that an
//! older channel queued is dropped, and an older channel's close ends
//! nothing (the rules of trzsz/tsshd that T-159 read).
//!
//! A kept shell is found only by its key and its name (`kept_shelf.rs`).
//! The limits: [`PER_KEY`] for each key, [`TOTAL`] in all, a ring of
//! [`RING`] bytes for each, held in memory alone. A lease that runs out
//! hangs up the shell's process group, and kills it after [`KILL_AFTER`].

// Windows refuses each program (`podssh serve` is a Unix host's), so no
// shell is ever kept there.
#![cfg_attr(not(unix), allow(dead_code))]

use std::pin::Pin;
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Waker;
use std::time::Duration;

use pod_term::grammar::Ring;
use russh::server::{Handle, Msg};
use russh::{ChannelId, ChannelWriteHalf};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;

use super::audit::Tally;
use super::channel::Input;
pub(super) use super::kept_ask::{Asked, Keeper};
use super::kept_replay::{dropped_line, replay_from, since};
use super::kept_shelf::Shelf;
use crate::terminal::Size;

// The input, the output and local echo's reports (T-896).
#[path = "kept_flow.rs"]
mod flow;
#[cfg(unix)]
pub(super) use flow::falls_due;
pub(super) use flow::{reports_for, watch_close};
// The output's writer, for the Unix-only start of a kept shell (`kept_run.rs`).
#[cfg(unix)]
pub(super) use flow::Out;

/// The most kept shells of one key.
pub const PER_KEY: usize = 4;

/// The most kept shells of one server.
pub const TOTAL: usize = 32;

/// The ring of each shell: what an attach can get of the output that came
/// with no client. 32 shells hold 8 MiB at most.
pub const RING: usize = 256 * 1024;

/// After a lease's hangup, how long the group may take to end before it
/// is killed.
pub const KILL_AFTER: Duration = Duration::from_secs(10);

/// A channel's bytes that wait in serve for the pty.
const PASTE: usize = 32 * 1024;

/// How often an attach reads the ring again for the output that came while
/// it sent the last part, before it gives up the rest as dropped.
const CATCH_UP: usize = 8;

/// The channel that a kept shell's output goes to now.
pub(super) struct Attached {
    write: ChannelWriteHalf<Msg>,
    handle: Handle,
    id: ChannelId,
    out: Pin<Box<dyn AsyncWrite + Send>>,
    /// The channel's counts for the audit log (T-116): its output, and
    /// the shell's end if it ends while this channel has it.
    tally: Arc<Tally>,
    /// Local echo's reports, where the channel asked (T-896).
    told: Option<flow::Told>,
}

impl Attached {
    pub(super) fn new(write: ChannelWriteHalf<Msg>, handle: Handle, id: ChannelId, tally: Arc<Tally>) -> Attached {
        let out: Pin<Box<dyn AsyncWrite + Send>> = Box::pin(tally.count(write.make_writer()));
        Attached { write, handle, id, out, tally, told: None }
    }

    /// Its parts, for the end of the program (`child::Running`).
    pub(super) fn into_parts(self) -> (ChannelWriteHalf<Msg>, Handle, ChannelId, Arc<Tally>) {
        (self.write, self.handle, self.id, self.tally)
    }

    /// `why` on its stderr, then its end with no status: the client says
    /// that the far end ended it (255).
    pub(super) fn told(self, why: String) {
        tokio::spawn(async move {
            let _ = self.handle.extended_data(self.id, 1, why.into_bytes()).await;
            self.end(None).await;
        });
    }

    /// Its end with `status`, where the shell ended while it joined.
    async fn end(self, status: Option<u32>) {
        if let Some(code) = status {
            let _ = self.write.exit_status(code).await;
        }
        let _ = self.write.eof().await;
        let _ = self.write.close().await;
    }
}

/// A channel's hold on a kept shell: the shell, and its generation then.
#[derive(Clone)]
pub(super) struct Held {
    pub(super) shell: Arc<Shell>,
    pub(super) generation: u64,
}

/// A join: the channel's hold, where its replay starts, and the channel
/// that had the shell, which the caller tells and ends.
pub(super) struct Joined {
    pub(super) held: Held,
    pub(super) from: u64,
    /// The replay is the ring from its first boundary, not from an offset.
    pub(super) reset: bool,
    pub(super) old: Option<Attached>,
}

/// What one turn of an attach's catch-up does.
enum Turn {
    Send(Vec<u8>, u64),
    Joined(u64),
    Ended(Option<u32>),
}

struct State {
    name: Option<String>,
    lease: Duration,
    attached: Option<Attached>,
    generation: u64,
    /// An attach sends what came while no client had the shell.
    joining: bool,
    ring: Ring,
    /// The end of the ring when the last client left.
    detached_at: u64,
    /// The pump's, while the attached channel holds it back.
    waker: Option<Waker>,
    timer: Option<tokio::task::AbortHandle>,
    ended: bool,
    /// The program's exit status, once it ended.
    status: Option<u32>,
}

/// One shell that may be kept.
pub(super) struct Shell {
    /// `PODSSH_SHELL_ID` in its environment.
    pub(super) id: String,
    pub(super) owner: String,
    input: tokio::sync::Mutex<Input>,
    resize: Box<dyn Fn(Size) + Send + Sync>,
    /// Its child's process group, which a stop of serve also hangs up.
    pub(super) group: Arc<AtomicI32>,
    cap: Duration,
    state: Mutex<State>,
    /// True once it must end: a lease ran out, or a client left a shell
    /// that was never kept.
    gone: watch::Sender<bool>,
    shelf: Shelf,
    tells: flow::Tells,
}

impl Shell {
    /// A shell whose pty takes `input` and is sized by `resize`.
    pub(super) fn new(
        keeper: &Keeper,
        id: String,
        input: Input,
        resize: Box<dyn Fn(Size) + Send + Sync>,
        group: Arc<AtomicI32>,
    ) -> Arc<Shell> {
        let (gone, _) = watch::channel(false);
        let state = State {
            name: None,
            lease: keeper.lease,
            attached: None,
            generation: 0,
            joining: false,
            ring: Ring::new(RING),
            detached_at: 0,
            waker: None,
            timer: None,
            ended: false,
            status: None,
        };
        let input = tokio::sync::Mutex::new(input);
        let (owner, shelf, cap) = (keeper.owner.clone(), keeper.shelf.clone(), keeper.cap);
        let (state, tells) = (Mutex::new(state), flow::Tells::default());
        Arc::new(Shell { id, owner, input, resize, group, cap, state, gone, shelf, tells })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(super) fn name(&self) -> Option<String> {
        self.state().name.clone()
    }

    /// Named by the shelf, under its lock.
    pub(super) fn set_name(&self, name: &str) {
        self.state().name = Some(name.to_string());
    }

    /// Its line's words in `shells@podssh` (T-833): `attached` and where
    /// the output stands, or `detached` and the offset at the detach, where
    /// an attach with no count starts.
    pub(super) fn listed(&self) -> (&'static str, u64) {
        let state = self.state();
        if state.attached.is_some() || state.joining {
            ("attached", state.ring.end())
        } else {
            ("detached", state.detached_at)
        }
    }

    pub(super) fn ended(&self) -> bool {
        self.state().ended
    }

    pub(super) fn gone(&self) -> watch::Receiver<bool> {
        self.gone.subscribe()
    }

    pub(super) fn resize(&self, size: Size) {
        (self.resize)(size);
    }

    /// The channel whose shell request started it.
    pub(super) fn first(self: &Arc<Self>, attached: Attached) -> Held {
        let mut state = self.state();
        state.attached = Some(attached);
        state.generation = 1;
        Held { shell: self.clone(), generation: 1 }
    }

    /// Where the input of the channel of `generation` goes: to the pty
    /// while that channel has the shell, then nowhere; `count` counts each
    /// write that the pty took, for local echo's reports.
    pub(super) fn writer(self: &Arc<Self>, generation: u64, count: Option<flow::Count>) -> Input {
        let (near, far) = tokio::io::duplex(PASTE);
        tokio::spawn(flow::feed(self.clone(), generation, far, count));
        Box::new(near)
    }

    fn current(&self, generation: u64) -> bool {
        let state = self.state();
        !state.ended && state.generation == generation
    }

    /// `~d` on the channel of `generation`: keep the shell as `name`, with
    /// no client, for its lease. Err: why not, for the channel's stderr.
    pub(super) fn detach(self: &Arc<Self>, generation: u64, name: &str) -> Result<(), String> {
        if !self.current(generation) {
            return Err("this channel no longer has the shell".into());
        }
        self.shelf.put(self, name)?;
        let mut state = self.state();
        if state.ended || state.generation != generation {
            return Err("this channel no longer has the shell".into());
        }
        state.attached = None;
        let_go(&mut state);
        self.start_lease(&mut state);
        Ok(())
    }

    /// The channel of `generation` closed, or its connection ended: a kept
    /// shell waits for its lease; one never kept is hung up, as before.
    pub(super) fn left(self: &Arc<Self>, generation: u64) {
        let mut state = self.state();
        if state.ended || state.generation != generation {
            return;
        }
        state.attached = None;
        let_go(&mut state);
        if state.name.is_some() {
            self.start_lease(&mut state);
            return;
        }
        drop(state);
        self.gone.send_replace(true);
    }

    /// A new client joins with its `asked`: it takes the shell from one
    /// that has it with `take@podssh`, asks for a shorter lease, and gives
    /// the offset that it has, or asks for a reset (T-833).
    pub(super) fn join(self: &Arc<Self>, asked: &Asked) -> Result<Joined, String> {
        let mut state = self.state();
        let name = state.name.clone().unwrap_or_default();
        if state.ended {
            return Err(format!("the kept shell {name} ended"));
        }
        if state.joining {
            return Err(format!("another client is attaching the shell {name}; try again"));
        }
        if state.attached.is_some() && !asked.take {
            return Err(format!("the shell {name} has a client; --take takes it"));
        }
        let old = state.attached.take();
        // A client that had the shell saw its output: the new one starts now.
        let base = if old.is_some() { state.ring.end() } else { state.detached_at };
        let (from, reset) = replay_from(&state.ring, base, asked.count, asked.reset);
        let_go(&mut state);
        if let Some(timer) = state.timer.take() {
            timer.abort();
        }
        if let Some(lease) = asked.lease {
            state.lease = lease.min(self.cap);
        }
        state.joining = true;
        let held = Held { shell: self.clone(), generation: state.generation };
        Ok(Joined { held, from, reset, old })
    }

    /// Send the joined channel what came since `from`, then make it the
    /// shell's. The output that comes meanwhile goes into the ring and out
    /// in the next turn, so its order holds; past [`CATCH_UP`] turns, the
    /// rest is dropped and said.
    pub(super) async fn catch_up(self: Arc<Self>, joined: Joined, attached: Attached) {
        let (generation, mut from) = (joined.held.generation, joined.from);
        let (handle, id) = (attached.handle.clone(), attached.id);
        if joined.reset {
            let line = super::kept_replay::reset_line(&self.name().unwrap_or_default(), from);
            let _ = handle.extended_data(id, 1, line.into_bytes()).await;
        }
        let mut slot = Some(attached);
        for turn in 1..=CATCH_UP {
            match self.turn(generation, &mut from, turn == CATCH_UP, &mut slot) {
                Turn::Send(bytes, lost) => {
                    if lost > 0 {
                        let _ = handle.extended_data(id, 1, dropped_line(lost).into_bytes()).await;
                    }
                    let Some(attached) = slot.as_mut() else { return };
                    if attached.out.write_all(&bytes).await.is_err() {
                        // The channel is gone: its close lets the shell go.
                        self.state().joining = false;
                        return;
                    }
                }
                Turn::Joined(dropped) => {
                    if dropped > 0 {
                        let _ = handle.extended_data(id, 1, dropped_line(dropped).into_bytes()).await;
                    }
                    return;
                }
                Turn::Ended(status) => {
                    if let Some(attached) = slot.take() {
                        attached.end(status).await;
                    }
                    return;
                }
            }
        }
    }

    /// One turn of [`Shell::catch_up`], under the lock: the bytes to send,
    /// or the channel made the shell's (on the `last` turn, with the bytes
    /// that it did not get), or the end of a shell that ended meanwhile.
    fn turn(&self, generation: u64, from: &mut u64, last: bool, slot: &mut Option<Attached>) -> Turn {
        let mut state = self.state();
        if state.ended || state.generation != generation {
            let ended = state.ended;
            return Turn::Ended(state.status.filter(|_| ended));
        }
        let (bytes, lost) = since(&state.ring, *from);
        let caught = bytes.is_empty() && lost == 0;
        if caught || last {
            let dropped = if caught { 0 } else { state.ring.end().saturating_sub(*from) };
            state.attached = slot.take();
            state.joining = false;
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
            // The pump waits on the new channel's reports from now on.
            self.tells.attached.notify_one();
            return Turn::Joined(dropped);
        }
        *from = state.ring.end();
        Turn::Send(bytes, lost)
    }

    /// The program ended with `status`: no client joins it from now on, it
    /// leaves the shelf, and the attached channel is returned for the status.
    pub(super) fn ended_with(&self, status: Option<u32>) -> Option<Attached> {
        let mut state = self.state();
        state.ended = true;
        state.status = status;
        if let Some(timer) = state.timer.take() {
            timer.abort();
        }
        let attached = state.attached.take();
        drop(state);
        self.shelf.remove(self);
        attached
    }

    fn start_lease(self: &Arc<Self>, state: &mut State) {
        if let Some(timer) = state.timer.take() {
            timer.abort();
        }
        let (shell, lease, generation) = (Arc::downgrade(self), state.lease, state.generation);
        let timer = tokio::spawn(async move {
            tokio::time::sleep(lease).await;
            if let Some(shell) = shell.upgrade() {
                shell.lease_ran_out(generation);
            }
        });
        state.timer = Some(timer.abort_handle());
    }

    fn lease_ran_out(&self, generation: u64) {
        let state = self.state();
        let idle = !state.ended && state.generation == generation && state.attached.is_none() && !state.joining;
        drop(state);
        if idle {
            self.gone.send_replace(true);
        }
    }
}

/// No client from now on: a new generation, the output into the ring alone.
fn let_go(state: &mut State) {
    state.generation += 1;
    state.joining = false;
    state.detached_at = state.ring.end();
    if let Some(waker) = state.waker.take() {
        waker.wake();
    }
}

#[cfg(test)]
#[path = "kept_tests.rs"]
mod tests;
