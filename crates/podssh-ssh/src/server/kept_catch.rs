//! An attach's catch-up (T-159, T-833, T-161), a part of `kept.rs` in a
//! file of its own so that each stays short: what came since the replay's
//! start, then the channel made the shell's; for a client whose terminal
//! may be new, the modes before the replay and a redraw after it
//! (`kept_screen.rs`).
//!
//! The order on the channel is the modes (stdout), the reset's line
//! (stderr), a dropped part's line, then the bytes. A client that counts
//! the offsets (T-895) counts nothing before a reset's line, which sets its
//! count, so the modes never move the count; an attach with no count has
//! none to move.

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
    /// The modes owed (none but on a fresh attach's first turn), the bytes
    /// since the last turn, and how many before them the ring lost.
    Send {
        modes: Vec<u8>,
        bytes: Vec<u8>,
        lost: u64,
    },
    /// The channel has the shell, with this many bytes that it did not get.
    Joined(u64),
    Ended(Option<u32>),
}

/// What the first turn still owes: the modes, and the reset's line.
struct Owed {
    modes: bool,
    reset: bool,
}

impl Shell {
    /// Send the joined channel what came since `from`, then make it the
    /// shell's. The output that comes meanwhile goes into the ring and out
    /// in the next turn, so its order holds; past [`CATCH_UP`] turns, the
    /// rest is dropped and said. A fresh attach gets the modes first; each
    /// attach gets a redraw last (T-161): the redraw is the shell's own
    /// output, so it moves no count, where the modes would.
    pub(in crate::server) async fn catch_up(self: Arc<Self>, joined: Joined, attached: Attached) {
        let (generation, mut from, fresh) = (joined.held.generation, joined.from, joined.fresh);
        let (handle, id) = (attached.handle.clone(), attached.id);
        let mut owed = Owed { modes: fresh, reset: joined.reset };
        let mut slot = Some(attached);
        for turn in 1..=CATCH_UP {
            match self.turn(generation, &mut from, &mut owed, turn == CATCH_UP, &mut slot) {
                Turn::Send { modes, bytes, lost } => {
                    let Some(attached) = slot.as_mut() else { return };
                    // The reset's line first, awaited: stdout and stderr go
                    // by queues of their own, and a client that counts
                    // (T-895) starts at the line. Its offset makes room for
                    // the modes that follow on stdout, so that the count
                    // after them is the far end's.
                    if std::mem::take(&mut owed.reset) {
                        let at = joined.from.saturating_sub(modes.len() as u64);
                        let line = reset_line(&self.name().unwrap_or_default(), at);
                        let _ = handle.extended_data(id, 1, line.into_bytes()).await;
                    }
                    if !modes.is_empty() && attached.out.write_all(&modes).await.is_err() {
                        // The channel is gone: its close lets the shell go.
                        self.state().joining = false;
                        return;
                    }
                    if lost > 0 {
                        let _ = handle.extended_data(id, 1, dropped_line(lost).into_bytes()).await;
                    }
                    if attached.out.write_all(&bytes).await.is_err() {
                        self.state().joining = false;
                        return;
                    }
                }
                Turn::Joined(dropped) => {
                    if dropped > 0 {
                        let _ = handle.extended_data(id, 1, dropped_line(dropped).into_bytes()).await;
                    }
                    self.redraw(generation).await;
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
    /// (with the modes where they are still owed), or the channel made the
    /// shell's (on the `last` turn, with the bytes that it did not get), or
    /// the end of a shell that ended meanwhile.
    fn turn(&self, generation: u64, from: &mut u64, owed: &mut Owed, last: bool, slot: &mut Option<Attached>) -> Turn {
        let mut state = self.state();
        if state.ended || state.generation != generation {
            let ended = state.ended;
            return Turn::Ended(state.status.filter(|_| ended));
        }
        let (bytes, lost) = since(&state.ring, *from);
        // The modes in effect where the bytes given start: after the lost
        // ones, under the same lock as the bytes, so no cut moves between.
        let modes = if std::mem::take(&mut owed.modes) {
            modes_before(&state.ring, from.saturating_add(lost))
        } else {
            Vec::new()
        };
        // A reset's line goes out before the channel has the shell, so that
        // no live output comes before it.
        let caught = bytes.is_empty() && lost == 0 && modes.is_empty() && !owed.reset;
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
        Turn::Send { modes, bytes, lost }
    }

    /// A change of the pty's size and its return, so that the program on
    /// it draws its screen again for the client that joined as
    /// `generation`. Nothing where serve never knew a size, or where the
    /// shell ended or another client took it first; the size always comes
    /// back, so the pty is never left nudged.
    pub(super) async fn redraw(&self, generation: u64) {
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
        // The size that holds now, set under the lock as a window change
        // sets it, so that none comes between the read and the set.
        let state = self.state();
        (self.resize)(state.size.unwrap_or(size));
    }
}
