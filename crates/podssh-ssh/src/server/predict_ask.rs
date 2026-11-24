//! The `env` request of local echo (T-160) on a connection of `podssh
//! serve`, apart from the handler so that it stays short: `env
//! predict@podssh v1`, before the program, on a channel whose pty serve
//! opened. The program's output then carries the reports
//! (`server/predict.rs`). Each other ask is refused, as by a server that
//! does not know the name, and the client shows no guess.

use russh::server::Session;
use russh::ChannelId;

use super::super::channel::Open;
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
        let taken = value == VERSION && self.channels.get_mut(&channel).is_some_and(take);
        Some(if taken { session.channel_success(channel) } else { session.channel_failure(channel) })
    }
}

/// Take the ask on `open`: before its program, on a pty of serve's own,
/// not a shell shared by name (T-837), whose output goes to each seat.
#[cfg(unix)]
fn take(open: &mut Open) -> bool {
    if open.started() || open.pty.is_none() || open.offer.is_some() {
        return false;
    }
    open.predict = true;
    true
}

/// Serve runs no program on Windows.
#[cfg(not(unix))]
fn take(_: &mut Open) -> bool {
    false
}
