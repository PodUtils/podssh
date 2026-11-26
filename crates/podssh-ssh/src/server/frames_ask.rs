//! The `env` requests of the frames (T-303) on a connection of `podssh
//! serve`, apart from the handler so that it stays short: the ask, `env
//! frames@podssh v2` (or `v1`, an older client's), before the program, on a
//! channel whose pty serve opened, once; and each acknowledgement, `env
//! frames-ack@podssh NUMBER`, while the program runs. Each other ask is
//! refused, as by a server that does not know the name, and the client's
//! session carries each byte. A client asks `v2` then `v1` at once: the
//! second is refused where the first was taken.

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
                // A login under a shared shell's name has no pty of its
                // own, and the owner's shell under --share is shared.
                let alone = self.viewer.is_none() && !self.settings.share;
                let version = Version::of(value).filter(|_| alone);
                let taken = version
                    .is_some_and(|version| self.channels.get_mut(&channel).is_some_and(|open| take(open, version)));
                Some(if taken { session.channel_success(channel) } else { session.channel_failure(channel) })
            }
            ACK => {
                // A value that is no acknowledgement, or a channel with no
                // frames, changes nothing: the request asks for no reply.
                let frames = self.channels.get(&channel).and_then(|open| open.frames.as_ref());
                if let (Some(frames), Some(ack)) = (frames, Ack::parse(value)) {
                    frames.acked(ack);
                }
                Some(session.channel_success(channel))
            }
            _ => None,
        }
    }
}

/// Take the ask of `version` on `open`, before its program, once: on a pty
/// of serve's own. A channel that joins a kept shell (T-159) gets the
/// frames of the shell's model at its join, in place of this one, and a
/// shell kept with frames keeps its model (`kept_frames.rs`). A channel that
/// took local echo's ask (T-160) too gets its reports in the frames' queue.
#[cfg(unix)]
fn take(open: &mut Open, version: Version) -> bool {
    if open.started() || open.frames.is_some() {
        return false;
    }
    let Some(size) = open.pty.as_ref().map(super::super::pty_child::Granted::size) else { return false };
    open.frames = Some(super::super::frames::Shared::new(size, version));
    true
}

/// Serve runs no program on Windows.
#[cfg(not(unix))]
fn take(_: &mut Open, _: Version) -> bool {
    false
}
