//! A kept shell's screen as frames (T-303 with T-159), a part of `kept.rs`
//! in a file of its own so that each stays short.
//!
//! The model of the screen belongs to the shell, as its ring does: it
//! outlives each client. It is made when a channel with frames first has
//! the shell (the channel that starts it, or one that joins it), and from
//! then on the shell's pump feeds it with each byte of the output, also
//! with no client or with a client of bytes (`kept_flow.rs`, `Out`). Each
//! channel with frames is an epoch of the model's sender
//! (`frames_epoch.rs`): its first frame is the whole screen, then the
//! differences from the state that it acknowledged. A channel of bytes
//! gets the ring, as before.
//!
//! A model made at an attach reads the ring first, as a fresh attach of
//! bytes does; then the program on the pty is asked to draw its screen
//! again (T-161's redraw), which a full-screen program does.

use std::sync::Arc;

use russh::server::{Handle, Msg};
use russh::{ChannelId, ChannelWriteHalf};
use tokio::task::JoinHandle;

use super::super::audit::Tally;
use super::super::frames::Shared;
use super::super::kept_screen::modes_before;
use super::{Attached, Joined, Shell};
use crate::frames::wire::Version;
use crate::terminal::Size;

/// The size of a model made for a shell whose size serve never knew.
const UNSIZED: Size = Size { cols: 80, rows: 24, px_width: 0, px_height: 0 };

impl Attached {
    /// A channel that has the shell with frames: the output's bytes go
    /// nowhere on it, as the frames of the shell's model go by `framing`,
    /// the task that sends them, waited for before the status.
    pub(in crate::server) fn framed(
        write: ChannelWriteHalf<Msg>,
        handle: Handle,
        id: ChannelId,
        tally: Arc<Tally>,
        framing: JoinHandle<()>,
    ) -> Attached {
        let mut attached = Attached::new(write, handle, id, tally);
        attached.out = Box::pin(tokio::io::sink());
        attached.framing = Some(framing);
        attached
    }

    /// The task that sends the frames, to wait for before the status.
    pub(in crate::server) fn take_framing(&mut self) -> Option<JoinHandle<()>> {
        self.framing.take()
    }
}

impl Shell {
    /// The model of the channel that starts the shell with frames: the
    /// shell's from now on, in its first epoch.
    pub(in crate::server) fn keep_frames(&self, frames: Arc<Shared>) {
        self.state().frames = Some(frames);
    }

    /// The shell's model for a channel that joins it with frames of
    /// `version`, made from the ring where the shell has none yet, and a
    /// new epoch for that channel: the model, the epoch, and whether the
    /// model was made now (then the program draws its screen again).
    pub(in crate::server) fn frames_for(&self, version: Version) -> (Arc<Shared>, u64, bool) {
        let mut state = self.state();
        let (frames, made) = match state.frames.clone() {
            Some(frames) => (frames, false),
            None => {
                let frames = Shared::new(state.size.unwrap_or(UNSIZED), version);
                // The modes in effect where the ring starts, then the ring:
                // what a fresh attach of bytes replays.
                if let Some(start) = state.ring.start() {
                    frames.seed(&modes_before(&state.ring, start));
                    frames.seed(&state.ring.kept());
                }
                state.frames = Some(frames.clone());
                (frames, true)
            }
        };
        let epoch = frames.restart(version);
        (frames, epoch, made)
    }

    /// The channel of `joined`, with frames, made the shell's: it gets no
    /// replay, as its first frame is the whole screen of the shell's model.
    /// A model made at this attach gets the program's redraw too. A shell
    /// that ended, or that another client took first, ends the channel.
    pub(in crate::server) async fn attach_framed(self: Arc<Self>, joined: Joined, attached: Attached, made: bool) {
        let generation = joined.held.generation;
        let refused = {
            let mut state = self.state();
            if state.ended || state.generation != generation {
                let ended = state.ended;
                Some((attached, state.status.filter(|_| ended)))
            } else {
                state.attached = Some(attached);
                state.joining = false;
                if let Some(waker) = state.waker.take() {
                    waker.wake();
                }
                // The pump waits on the new channel's reports from now on.
                self.tells.attached.notify_one();
                None
            }
        };
        if let Some((mut attached, status)) = refused {
            // Its frames end with the shell's, or with its epoch.
            if let Some(task) = attached.take_framing() {
                let _ = task.await;
            }
            attached.end(status).await;
            return;
        }
        if made {
            self.redraw(generation).await;
        }
    }
}
