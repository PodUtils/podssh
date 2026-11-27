//! The `env` requests of the frames (T-303) on a connection of `podssh
//! serve`, apart from the handler so that it stays short: the ask, `env
//! frames@podssh v2` (or `v1`, an older client's), before the program, on a
//! channel whose pty serve opened, once; and each acknowledgement, `env
//! frames-ack@podssh NUMBER`, while the program runs. Each other ask is
//! refused, as by a server that does not know the name, and the client's
//! session carries each byte. A client asks `v2` then `v1` at once: the
//! second is refused where the first was taken. A login under a shared
//! shell's name asks on its seat, whose pty is the shell's (T-837).

use russh::server::Session;
use russh::ChannelId;

use super::super::channel::Open;
use super::Served;
use crate::frames::wire::{Ack, Version, ACK, ENV};

impl Served {
    /// The answer to an `env` request of the frames; None for another
    /// name.
    pub(super) fn frames_env(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Option<Result<(), russh::Error>> {
        match name {
            ENV => {
                let seat = self.viewer.is_some();
                let taken = Version::of(value).is_some_and(|version| {
                    self.channels.get_mut(&channel).is_some_and(|open| take(open, version, seat))
                });
                Some(if taken { session.channel_success(channel) } else { session.channel_failure(channel) })
            }
            ACK => {
                // A value that is no acknowledgement, or a channel with no
                // frames, changes nothing: the request asks for no reply.
                // A seat of a shared shell acknowledges its own view.
                let open = self.channels.get(&channel);
                let seat = open.and_then(|open| open.seat.as_ref()).and_then(|seat| seat.framed());
                match (seat, open.and_then(|open| open.frames.as_ref()), Ack::parse(value)) {
                    (Some((frames, view)), _, Some(ack)) => frames.acked_by(view, ack),
                    (None, Some(frames), Some(ack)) => frames.acked(ack),
                    _ => {}
                }
                Some(session.channel_success(channel))
            }
            _ => None,
        }
    }
}

/// Take the ask of `version` on `open`, before its program, once: on a pty
/// of serve's own, or on a `seat` of a shared shell (T-837) that asked for
/// a pty, whose size is all it has. A channel that joins a kept shell
/// (T-159) gets the frames of the shell's model at its join, in place of
/// this one, and a shell kept with frames keeps its model
/// (`kept_frames.rs`); a seat gets a view of the shared shell's model at
/// its attach, and an owner under `--share` gives the shell this one
/// (`share_frames.rs`). A channel that took local echo's ask (T-160) too
/// gets its reports in the frames' queue.
#[cfg(unix)]
fn take(open: &mut Open, version: Version, seat: bool) -> bool {
    if open.started() || open.frames.is_some() {
        return false;
    }
    let size = if seat { open.asked } else { open.pty.as_ref().map(super::super::pty_child::Granted::size) };
    let Some(size) = size else { return false };
    open.frames = Some(super::super::frames::Shared::new(size, version));
    true
}

/// Serve runs no program on Windows.
#[cfg(not(unix))]
fn take(_: &mut Open, _: Version, _: bool) -> bool {
    false
}
