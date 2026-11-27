//! A shell shared by name (T-837) with frames (T-303), a part of `share.rs`
//! in a file of its own so that each stays short.
//!
//! The shell has one model of its screen. It is made when the first seat
//! asks for frames: the owner's, at the shell's start, whose model it
//! takes; or a name's, at its attach, made from the owner's recent output
//! (T-901's ring), as a seat of bytes gets its screen so far. From then on
//! the owner's pump feeds it with each byte, for the shell's life
//! (`Hub::said`), and its size is the pty's, the least of each seat's.
//!
//! Each seat with frames is a view of the model (`frames_epoch.rs`): its
//! own sender, base, acknowledgements and pace, its queue and its task, so
//! that a seat on a slow road holds no other back. A seat of bytes gets
//! the screen so far and the output, as before.
//!
//! Only the owner's view writes the model's answers to the pty (the cursor's
//! place, the device's status), as the owner's terminal would with bytes: a
//! name's view never does, so a question gets one answer from the model,
//! and none where the owner reads bytes, whose terminal answers itself.
//!
//! A seat's local echo (T-896) with frames: its reports ride the shell's
//! broadcast as before, and its task puts each into its view's inbox, which
//! the pump or the view's task places after the frame that holds the echo
//! of the keys that it counts (`Shared::reported_aside`).

// Windows refuses each program (`podssh serve` is a Unix host's), so the
// parts that share one are unused there.
#![cfg_attr(not(unix), allow(dead_code))]

use std::sync::Arc;

use russh::server::Msg;
use russh::ChannelWriteHalf;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;

use super::super::channel::{Input, Open};
use super::super::frames::Shared;
use super::super::kept_screen::modes_before;
use super::super::share_told::{Said, SeatTold};
use super::super::share_view::gone;
use super::{least, Hub, Mode, Pass, Seat};
use crate::frames::wire::Version;
use crate::terminal::Size;

/// The size of a model made for a shell whose seats gave none.
const UNSIZED: Size = Size { cols: 80, rows: 24, px_width: 0, px_height: 0 };

/// Why a seat with frames finds no shell.
const ENDED: &str = "the shared shell ended";

impl Hub {
    /// The owner's model (the channel whose pty it is asked for frames):
    /// the shell's from its start, fed by the owner's pump.
    pub(in crate::server) fn keep_frames(&self, frames: Arc<Shared>) {
        let _ = self.frames.set(frames);
    }

    /// The model of the shell's screen, for a seat that asks for frames of
    /// `version`: made where the shell has none yet, of the least size of
    /// the seats, from the modes before the owner's recent output and that
    /// output. Made under the output's lock, as the pump feeds it, so that
    /// no byte is in the ring and not in the model. None once the shell
    /// ended.
    pub(in crate::server) fn frames_for(&self, version: Version) -> Option<Arc<Shared>> {
        let output = self.output.lock().unwrap_or_else(|p| p.into_inner());
        output.as_ref()?;
        let frames = self.frames.get_or_init(|| {
            let sizes = self.sizes.lock().unwrap_or_else(|p| p.into_inner());
            let frames = Shared::bare(least(sizes.values()).unwrap_or(UNSIZED), version);
            drop(sizes);
            let ring = self.screen.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(start) = ring.start() {
                frames.seed(&modes_before(&ring, start));
                frames.seed(&ring.kept());
            }
            frames
        });
        Some(frames.clone())
    }
}

impl Seat {
    /// This seat has the view `view` of the shell's model `frames`.
    pub(in crate::server) fn set_framed(&self, frames: Arc<Shared>, view: u64) {
        let _ = self.framed.set((frames, view));
    }

    /// This seat's view of the shell's model, where it asked for frames:
    /// where its client's acknowledgements go.
    pub(in crate::server) fn framed(&self) -> Option<(&Arc<Shared>, u64)> {
        self.framed.get().map(|(frames, view)| (frames, *view))
    }

    /// This seat's view leaves the model: its task ends, and no frame is
    /// made for it. Once the seat's channel closes, or the seat goes.
    pub(super) fn unframe(&self) {
        if let Some((frames, view)) = self.framed.get() {
            frames.leave(*view);
        }
    }
}

/// Attach the channel `open`, which asked for frames of `version`, to the
/// shell of `pass`: a view of the shell's model of its own, whose first
/// frame is the whole screen, in place of the screen so far and the output;
/// its input to the pty only where the name may write, as for a seat of
/// bytes (`share_view::attach`, the one place where a right is applied).
pub(in crate::server) fn attach(open: &mut Open, pass: &Pass, version: Version) -> Result<(), String> {
    let Some(frames) = pass.hub.frames_for(version) else { return Err(ENDED.into()) };
    let Some(from) = pass.hub.subscribe() else { return Err(ENDED.into()) };
    let Some(write) = open.write.take() else { return Err(ENDED.into()) };
    // Its view first: the size that the seat gives the pty then reaches
    // the model before the view's first frame.
    let view = frames.join(version);
    let seat = pass.hub.seat(open.asked.take());
    seat.set_framed(frames.clone(), view);
    // Local echo's reports of this seat's own bytes, where it asked; only a
    // writer's ask is taken (T-896). They go in its frames' queue, each
    // after the frame that holds the echo of the keys that it counts.
    let asked = open.predict && pass.mode == Mode::Write;
    let reports = asked.then(|| write.make_writer_ext(Some(crate::predict::EXT)));
    let told = asked.then(|| {
        pass.hub.tells.ask(seat.id());
        SeatTold::to(Box::pin(frames.aside(view)), seat.id())
    });
    let input: Input = match pass.mode {
        Mode::Write => seat.writer(),
        // A watcher's bytes go nowhere: its channel never holds the pty.
        Mode::Read => Box::new(tokio::io::sink()),
    };
    open.give_input(input);
    open.seat = Some(seat.clone());
    let out = write.make_writer_ext(Some(crate::frames::EXT));
    // A name's view writes no answer to the pty: the owner's does.
    let framing = tokio::spawn(frames.run_epoch(view, out, tokio::io::sink(), reports));
    tokio::spawn(follow(from, write, open.closed.clone(), seat, told, framing));
    Ok(())
}

/// A seat with frames: they go by their own task (`framing`); this one
/// reads the shell's broadcast for the seat's reports, each into its view's
/// inbox, and for the shell's end. Then, once the last frame went, a status
/// of 0, EOF and close, as a seat of bytes ends. A channel that closes
/// first ends it, and the seat's view.
async fn follow(
    mut from: broadcast::Receiver<Said>,
    write: ChannelWriteHalf<Msg>,
    mut closed: watch::Receiver<bool>,
    seat: Arc<Seat>,
    mut told: Option<SeatTold>,
    framing: JoinHandle<()>,
) {
    loop {
        let next = tokio::select! {
            next = from.recv() => next,
            () = gone(&mut closed) => {
                seat.unframe();
                return;
            }
        };
        match next {
            Ok(said) => {
                let failed = match told.as_mut() {
                    Some(reports) => reports.tell(&said).await.is_err(),
                    None => false,
                };
                if failed {
                    told = None;
                }
            }
            // The next item holds the counts of now.
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
    // The last frame goes before the status.
    tokio::select! {
        _ = framing => {}
        () = gone(&mut closed) => {
            seat.unframe();
            return;
        }
    }
    drop(seat);
    let _ = write.exit_status(0).await;
    let _ = write.eof().await;
    let _ = write.close().await;
}

#[cfg(test)]
#[path = "share_frames_tests.rs"]
mod tests;
