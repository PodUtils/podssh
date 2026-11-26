//! The `env` request of local echo (T-160) on a connection of `podssh
//! serve`, apart from the handler so that it stays short: `env
//! predict@podssh v1`, before the program, on a channel whose pty serve
//! opened, on serve's own tty under `--share`, or on a writing seat of a
//! shell shared by name (T-896). The program's output then carries the
//! reports (`server/predict.rs`, `server/share_told.rs`). Each other ask is
//! refused, as by a server that does not know the name, and the client
//! shows no guess.

use russh::server::Session;
use russh::ChannelId;

use super::super::channel::Open;
use super::super::share::Mode;
use super::Served;
use crate::predict::report::{ENV, VERSION};

impl Served {
    /// The answer to an `env` request of [`ENV`]; None for another name.
    pub(super) fn predict_env(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Option<Result<(), russh::Error>> {
        if name != ENV {
            return None;
        }
        let (seat, share) = (self.viewer.as_ref().map(|pass| pass.mode), self.settings.share);
        let taken = value == VERSION && self.channels.get_mut(&channel).is_some_and(|open| take(open, seat, share));
        Some(if taken { session.channel_success(channel) } else { session.channel_failure(channel) })
    }
}

/// Take the ask on `open`, before its program. A login under a shared
/// shell's name (`seat`) gets reports only where its bytes reach the tty
/// (a writer) and it asked for a pty, whose size is all it has: a
/// watcher's keys go nowhere, and no report could count them. The owner
/// gets them on a pty of serve's own, or on serve's own tty where `--share`
/// may share the shell, whose reports ride its seats' broadcast; a command
/// there is not shared, and sends none. A channel whose screen goes as
/// frames (T-303) gets them too, each after the frame that holds the echo
/// of the keys it counts (`server/frames.rs`).
#[cfg(unix)]
fn take(open: &mut Open, seat: Option<Mode>, share: bool) -> bool {
    if open.started() || open.offer.is_some() {
        return false;
    }
    let reports = match seat {
        Some(mode) => mode == Mode::Write && open.asked.is_some(),
        None => open.pty.is_some() || (share && open.line.is_some()),
    };
    open.predict |= reports;
    reports
}

/// Serve runs no program on Windows.
#[cfg(not(unix))]
fn take(_: &mut Open, _: Option<Mode>, _: bool) -> bool {
    false
}
