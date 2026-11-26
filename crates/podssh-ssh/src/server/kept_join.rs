//! A channel that joins a kept shell (T-158, T-159): its shell request, after
//! `env attach@podssh NAME`, finds the shell of its key by that name, takes
//! it from the client that has it where `take@podssh` asked, and gets what
//! came while no client had it, then the shell's output. Its own pty, which
//! its `pty-req` made, is closed, and its size goes to the shell's. A
//! channel that asked for frames (T-303) gets the frames of the shell's
//! model in place of the ring and the output (`kept_frames.rs`).

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
    // With frames, the shell's model and a new epoch of its frames for this
    // channel, whose acknowledgements go to it from now on.
    let framed = open.frames.as_ref().map(|asked| shell.frames_for(asked.version()));
    if let Some((frames, _, _)) = framed.as_ref() {
        open.frames = Some(frames.clone());
    }
    // Local echo's reports, where this channel asked (T-896): its count of
    // its own bytes starts at its attach, as the client's does.
    let (told, count) = reports_for(&shell, open.predict, &write, framed.as_ref().map(|f| &f.0));
    let generation = joined.held.generation;
    open.give_stdin(shell.writer(generation, count));
    watch_close(&joined.held, open.closed.clone());
    open.kept = Some(joined.held.clone());
    let (handle, tally) = (open.handle.clone(), open.tally.clone());
    match framed {
        Some((frames, epoch, made)) => {
            let out = tally.count(write.make_writer_ext(Some(crate::frames::EXT)));
            let reports = open.predict.then(|| tally.count(write.make_writer_ext(Some(crate::predict::EXT))));
            // The model's answers go to the pty while this channel has it.
            let answers = shell.writer(generation, None);
            let framing = tokio::spawn(frames.run_epoch(epoch, out, answers, reports));
            let attached = Attached::framed(write, handle, channel, tally, framing).with_reports(told);
            tokio::spawn(shell.clone().attach_framed(joined, attached, made));
        }
        None => {
            let attached = Attached::new(write, handle, channel, tally).with_reports(told);
            tokio::spawn(shell.clone().catch_up(joined, attached));
        }
    }
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
