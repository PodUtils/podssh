//! An attach's catch-up (T-159, T-833, T-161), a part of `kept.rs` in a
//! file of its own so that each stays short: what came since the replay's
//! start, then the channel made the shell's; for a client whose terminal is
//! new, the modes before the replay and a redraw after it
//! (`kept_screen.rs`).

use std::sync::Arc;

use tokio::io::AsyncWriteExt;

use super::super::kept_replay::{dropped_line, reset_line, since};
use super::super::kept_screen::{modes_before, nudged, REDRAW_PAUSE};
use super::{Attached, Joined, Shell};

/// How often an attach reads the ring again for the output that came while
/// it sent the last part, before it gives up the rest as dropped.
const CATCH_UP: usize = 8;

/// What one turn of an attach's catch-up does.
enum Turn {
    Send(Vec<u8>, u64),
    Joined(u64),
    Ended(Option<u32>),
}

impl Shell {
    /// Send the joined channel what came since `from`, then make it the
    /// shell's. The output that comes meanwhile goes into the ring and out
    /// in the next turn, so its order holds; past [`CATCH_UP`] turns, the
    /// rest is dropped and said. A fresh attach gets the modes first and a
    /// redraw last (T-161).
    pub(in crate::server) async fn catch_up(self: Arc<Self>, joined: Joined, attached: Attached) {
        let (generation, mut from, fresh) = (joined.held.generation, joined.from, joined.fresh);
        let (handle, id) = (attached.handle.clone(), attached.id);
        if joined.reset {
            let line = reset_line(&self.name().unwrap_or_default());
            let _ = handle.extended_data(id, 1, line.into_bytes()).await;
        }
        let mut slot = Some(attached);
        let mut modes = fresh;
        for turn in 1..=CATCH_UP {
            match self.turn(generation, &mut from, &mut modes, turn == CATCH_UP, &mut slot) {
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
                    if fresh {
                        self.redraw(generation).await;
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

    /// One turn of [`Shell::catch_up`], under the lock: the bytes to send
    /// (after the modes where `modes` is still owed), or the channel made
    /// the shell's (on the `last` turn, with the bytes that it did not get),
    /// or the end of a shell that ended meanwhile.
    fn turn(&self, generation: u64, from: &mut u64, modes: &mut bool, last: bool, slot: &mut Option<Attached>) -> Turn {
        let mut state = self.state();
        if state.ended || state.generation != generation {
            let ended = state.ended;
            return Turn::Ended(state.status.filter(|_| ended));
        }
        let (mut bytes, lost) = since(&state.ring, *from);
        // The modes in effect where the bytes given start: after the lost
        // ones, under the same lock as the bytes, so no cut moves it between.
        if std::mem::take(modes) {
            let mut first = modes_before(&state.ring, from.saturating_add(lost));
            first.append(&mut bytes);
            bytes = first;
        }
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

    /// A change of the pty's size and its return, so that the program on
    /// it draws its screen again for the client that joined as
    /// `generation`. Nothing where serve never knew a size, or where the
    /// shell ended or another client took it first; the size always comes
    /// back, so the pty is never left nudged.
    async fn redraw(&self, generation: u64) {
        let size = {
            let state = self.state();
            if state.ended || state.generation != generation {
                return;
            }
            state.size
        };
        let Some(size) = size else { return };
        (self.resize)(nudged(size));
        tokio::time::sleep(REDRAW_PAUSE).await;
        // A window change meanwhile set the size that holds now.
        let size = self.state().size.unwrap_or(size);
        (self.resize)(size);
    }
}
