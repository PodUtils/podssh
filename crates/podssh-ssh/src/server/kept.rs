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

use std::io;
use std::pin::Pin;
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use pod_term::grammar::Ring;
use russh::server::{Handle, Msg};
use russh::{ChannelId, ChannelWriteHalf};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::watch;

use super::channel::Input;
use super::kept_shelf::Shelf;
pub(super) use super::kept_ask::{Asked, Keeper};
use crate::terminal::Size;

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
}

impl Attached {
    pub(super) fn new(write: ChannelWriteHalf<Msg>, handle: Handle, id: ChannelId) -> Attached {
        let out: Pin<Box<dyn AsyncWrite + Send>> = Box::pin(write.make_writer());
        Attached { write, handle, id, out }
    }

    /// Its parts, for the end of the program (`child::Running`).
    pub(super) fn into_parts(self) -> (ChannelWriteHalf<Msg>, Handle, ChannelId) {
        (self.write, self.handle, self.id)
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
        Arc::new(Shell { id, owner, input, resize, group, cap, state: Mutex::new(state), gone, shelf })
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

    /// Whether a client has it, or joins it now.
    pub(super) fn has_client(&self) -> bool {
        let state = self.state();
        state.attached.is_some() || state.joining
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
    /// while that channel has the shell, then nowhere.
    pub(super) fn writer(self: &Arc<Self>, generation: u64) -> Input {
        let (near, far) = tokio::io::duplex(PASTE);
        tokio::spawn(feed(self.clone(), generation, far));
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

    /// A new client joins, taking the shell from one that has it when
    /// `take`; `lease` is its ask of a shorter lease for later.
    pub(super) fn join(self: &Arc<Self>, take: bool, lease: Option<Duration>) -> Result<Joined, String> {
        let mut state = self.state();
        let name = state.name.clone().unwrap_or_default();
        if state.ended {
            return Err(format!("the kept shell {name} ended"));
        }
        if state.joining {
            return Err(format!("another client is attaching the shell {name}; try again"));
        }
        if state.attached.is_some() && !take {
            return Err(format!("the shell {name} has a client; --take takes it"));
        }
        let old = state.attached.take();
        // A client that had the shell saw its output: the new one starts now.
        let from = if old.is_some() { state.ring.end() } else { state.detached_at };
        let_go(&mut state);
        if let Some(timer) = state.timer.take() {
            timer.abort();
        }
        if let Some(lease) = lease {
            state.lease = lease.min(self.cap);
        }
        state.joining = true;
        Ok(Joined { held: Held { shell: self.clone(), generation: state.generation }, from, old })
    }

    /// Send the joined channel what came since `from`, then make it the
    /// shell's. The output that comes meanwhile goes into the ring and out
    /// in the next turn, so its order holds; past [`CATCH_UP`] turns, the
    /// rest is dropped and said.
    pub(super) async fn catch_up(self: Arc<Self>, generation: u64, attached: Attached, mut from: u64) {
        let (handle, id) = (attached.handle.clone(), attached.id);
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

fn dropped_line(bytes: u64) -> String {
    format!("podssh serve: {bytes} bytes of this shell's output were dropped while no client had it\r\n")
}

/// The bytes of `ring` from the offset `from` on, and how many before them
/// are lost: a ring that dropped past `from` gives its bytes from its first
/// boundary instead (T-221), so that no part of a sequence shows as text.
pub(super) fn since(ring: &Ring, from: u64) -> (Vec<u8>, u64) {
    let end = ring.end();
    if from >= end {
        return (Vec::new(), 0);
    }
    match ring.start() {
        Some(start) if start <= from => {
            let kept = ring.kept();
            let skip = usize::try_from(from - start).unwrap_or(usize::MAX).min(kept.len());
            (kept[skip..].to_vec(), 0)
        }
        Some(start) => (ring.kept(), start - from),
        None => (Vec::new(), end - from),
    }
}

/// Copy a channel's input to the pty while its generation is the shell's;
/// then the dropped pipe tells the channel's feeder, which drops the rest.
async fn feed(shell: Arc<Shell>, generation: u64, mut from: DuplexStream) {
    let mut buf = vec![0u8; PASTE];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if !shell.current(generation) {
            return;
        }
        let mut input = shell.input.lock().await;
        if input.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

/// When the channel of `held` closes, the shell lets it go.
pub(super) fn watch_close(held: &Held, mut closed: watch::Receiver<bool>) {
    let (shell, generation) = (held.shell.clone(), held.generation);
    tokio::spawn(async move {
        // The guard of `wait_for` is dropped in its statement: the task stays Send.
        let _ = closed.wait_for(|closed| *closed).await;
        shell.left(generation);
    });
}

/// The shell's output: to the attached channel, and into the ring. It
/// never fails, so the pump reads the pty to its end with no client too.
pub(super) struct Out(pub(super) Arc<Shell>);

impl AsyncWrite for Out {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut guard = self.0.state();
        let state = &mut *guard;
        if let Some(attached) = state.attached.as_mut() {
            match attached.out.as_mut().poll_write(cx, buf) {
                Poll::Ready(Ok(n)) if n > 0 => {
                    state.ring.push(&buf[..n], Instant::now());
                    return Poll::Ready(Ok(n));
                }
                // The client's window holds the shell back, as without T-159.
                Poll::Pending => {
                    state.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                // The channel is gone: its close follows, and the ring
                // keeps the output until then.
                _ => state.attached = None,
            }
        }
        state.ring.push(buf, Instant::now());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// The channel's end is the program's status, sent at its end.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
#[path = "kept_tests.rs"]
mod tests;
