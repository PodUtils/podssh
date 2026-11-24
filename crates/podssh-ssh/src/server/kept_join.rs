//! A channel that joins a kept shell (T-158, T-159): its shell request, after
//! `env attach@podssh NAME`, finds the shell of its key by that name, takes
//! it from the client that has it where `take@podssh` asked, and gets what
//! came while no client had it, then the shell's output. Its own pty, which
//! its `pty-req` made, is closed, and its size goes to the shell's.

// Windows refuses each program (`podssh serve` is a Unix host's), so no
// shell is ever kept there.
#![cfg_attr(not(unix), allow(dead_code))]

use russh::ChannelId;

use super::channel::Open;
use super::kept::{reports_for, watch_close, Attached};
use super::kept_shelf::Shelf;
use crate::terminal::Size;

/// Join the channel `open` (`channel`) to the kept shell that it asked for,
/// as a client of the key `owner`: Ok with the shell's name; Err with the
/// words of the refusal, and the channel unchanged but for its asks.
pub(super) fn join(open: &mut Open, shelf: &Shelf, owner: &str, channel: ChannelId) -> Result<String, String> {
    let asked = std::mem::take(&mut open.keep);
    let Some(name) = asked.attach.clone() else { return Err("no kept shell was named".into()) };
    let shell = shelf.find(owner, &name)?;
    // A shell joined to a client inside it would feed its own output back.
    if asked.from.as_deref() == Some(shell.id.as_str()) {
        return Err(format!("the attach comes from inside the shell {name}"));
    }
    let Some(write) = open.write.take() else { return Err("a program runs on this channel already".into()) };
    let mut joined = match shell.join(&asked) {
        Ok(joined) => joined,
        Err(why) => {
            open.write = Some(write);
            return Err(why);
        }
    };
    if let Some(old) = joined.old.take() {
        old.told(format!("podssh serve: another client took the kept shell {name}\r\n"));
    }
    if let Some(size) = spare_pty(open) {
        shell.resize(size);
    }
    // Local echo's reports, where this channel asked (T-896): its count of
    // its own bytes starts at its attach, as the client's does.
    let (told, count) = reports_for(&shell, open.predict, &write);
    open.give_stdin(shell.writer(joined.held.generation, count));
    watch_close(&joined.held, open.closed.clone());
    open.kept = Some(joined.held.clone());
    let attached = Attached::new(write, open.handle.clone(), channel, open.tally.clone()).with_reports(told);
    tokio::spawn(shell.clone().catch_up(joined, attached));
    Ok(name)
}

/// Close the pty or the line discipline that the channel's `pty-req` got,
/// as the kept shell has its own: the size that it asked for.
#[cfg(unix)]
fn spare_pty(open: &mut Open) -> Option<Size> {
    let line = open.line.take().map(|grant| {
        let now = *grant.size.borrow();
        Size { cols: now.cols.into(), rows: now.rows.into(), px_width: 0, px_height: 0 }
    });
    open.pty.take().map(|granted| granted.size()).or(line)
}

#[cfg(not(unix))]
fn spare_pty(_: &mut Open) -> Option<Size> {
    None
}
