//! The far end's screen as frames (T-303): `--frames` asks `podssh serve`
//! for the difference of its screen at most each half round trip, in place
//! of each byte of the pty. Under a flood over a slow link, the bytes that
//! wait in the link are then a frame or two, so Ctrl-C shows its prompt
//! within a round trip, where the byte stream first shows each byte that
//! was on its way.
//!
//! The far end keeps a model of its screen ([`screen`]), numbers each
//! state that it sends, and starts each frame from the newest state that
//! the client acknowledged ([`sender`]); the client keeps the states that a
//! frame may start from, draws the newest on its terminal, and acknowledges
//! by number ([`receiver`]). The records are [`wire`]'s. Keys go as bytes,
//! each one, as without frames.
//!
//! Only a far end that has the pty's bytes in clear can send frames:
//! `podssh serve` with a pty, asked with `env frames@podssh v1`. Another
//! server refuses the request, and the session carries each byte.
//!
//! A frame skips output, so the terminal's own scrollback gets none of the
//! session's lines, and what a program writes for the terminal alone (a
//! file of ZMODEM, a copy to the clipboard) does not arrive. A line of
//! podssh's own on the terminal moves the cursor where no state knows it:
//! the next frame then draws the whole screen again.

use std::sync::{Arc, Mutex};

use russh::client::Msg;
use russh::{Channel, ChannelMsg, ChannelWriteHalf};

pub mod receiver;
pub mod screen;
pub mod sender;
pub mod wire;

pub use wire::{ACK, ENV, EXT, VERSION};

/// What gives the terminal back to its user, as the last frame left it:
/// read at the session's end, however it ended.
#[derive(Clone, Default)]
pub struct Leave(Arc<Mutex<Vec<u8>>>);

impl Leave {
    /// The bytes for the terminal now; empty while no frame was drawn.
    pub fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn set(&self, bytes: Vec<u8>) {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = bytes;
    }

    /// Write [`Leave::bytes`] to this process's terminal, at once: the
    /// session's loop has ended, and nothing else writes there.
    pub(crate) fn restore(&self) {
        use std::io::Write as _;
        let bytes = self.bytes();
        if bytes.is_empty() {
            return;
        }
        let mut out = std::io::stdout();
        let _ = out.write_all(&bytes);
        let _ = out.flush();
    }
}

/// The frames of one session, on this process's terminal.
pub struct Frames {
    receiver: receiver::Receiver,
    /// The count of podssh's own writes to the terminal at the last draw.
    own: u64,
    leave: Leave,
}

impl Default for Frames {
    fn default() -> Self {
        Frames { receiver: receiver::Receiver::default(), own: crate::predict::own_writes(), leave: Leave::default() }
    }
}

impl Frames {
    /// The end of this session's frames, for whoever restores the terminal.
    pub fn leave(&self) -> Leave {
        self.leave.clone()
    }

    /// The far end's extended data of [`EXT`]: what the terminal shows of
    /// it. `Err` for bytes that are no frame of this version.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        // A line of podssh's own since the last draw: the cursor moved.
        let own = crate::predict::own_writes();
        if own != self.own {
            self.own = own;
            self.receiver.disturbed();
        }
        let drawn = self.receiver.feed(bytes)?;
        if !drawn.is_empty() {
            self.leave.set(self.receiver.leave());
        }
        Ok(drawn)
    }

    /// The terminal's content moved under the frames: a new size of the
    /// window, or output of the far end that is no frame (its stderr).
    pub fn disturbed(&mut self) {
        self.receiver.disturbed();
    }

    /// The acknowledgement that is due, as the value of [`ACK`].
    pub fn take_ack(&mut self) -> Option<String> {
        self.receiver.take_ack().map(wire::Ack::value)
    }
}

/// Whether a session asks its far end for frames: `--frames`, a shell or a
/// command on a pty, with this process's own terminal on each side, and
/// nothing else that reads the output as bytes or takes the keys.
pub(crate) fn wanted(opts: &crate::options::Options, want_pty: bool, stdin_tty: bool) -> bool {
    use crate::options::Request;
    opts.frames
        && want_pty
        && stdin_tty
        && crate::terminal::stdout_is_terminal()
        && matches!(opts.request, Request::Shell | Request::Exec(_))
        && opts.expect.is_none()
        && opts.elevate.is_none()
        && opts.output.is_none()
        && opts.feed.is_none()
        && opts.keep.ask.is_none()
}

/// Why a session that has `--frames` does not ask for them, in one line;
/// `None` where it asks, or has no `--frames`.
pub(crate) fn not_asked(opts: &crate::options::Options, want_pty: bool, stdin_tty: bool) -> Option<&'static str> {
    if !opts.frames || wanted(opts, want_pty, stdin_tty) {
        return None;
    }
    Some(if opts.keep.ask.is_some() {
        "--frames: no frames with --attach: a kept shell sends each byte"
    } else if !want_pty || !stdin_tty || !crate::terminal::stdout_is_terminal() {
        "--frames: no frames: they need a terminal on each side and a pseudo-terminal at the far end"
    } else {
        "--frames: no frames: this session's output is read as bytes"
    })
}

/// Ask the far end for frames, before the shell or the command; whether
/// the ask went.
pub(crate) async fn ask(channel: &Channel<Msg>) -> bool {
    channel.set_env(true, ENV, VERSION).await.is_ok()
}

/// The far end's answer to [`ask`]: the frames of the session where it
/// sends them, on a terminal that reads the sequences they are drawn with.
/// A refusal says so in one line, and the session carries each byte.
pub(crate) async fn answered(
    channel: &mut Channel<Msg>,
    early: &mut Vec<ChannelMsg>,
    asked: bool,
    log: &crate::log::Log,
) -> Result<Option<Frames>, String> {
    if !asked {
        return Ok(None);
    }
    if crate::session::wait_reply(channel, early).await? {
        return Ok(Some(Frames::default()));
    }
    log.info("--frames: the far end sends no frames (only podssh serve with a pty does); the session shows each byte");
    Ok(None)
}

/// Send the acknowledgement that is due, with no reply asked. One goes for
/// each pass of the session's loop at the most.
pub(crate) async fn acknowledge(frames: Option<&mut Frames>, writer: &ChannelWriteHalf<Msg>) {
    if let Some(value) = frames.and_then(Frames::take_ack) {
        let _ = writer.set_env(false, ACK, value).await;
    }
}
