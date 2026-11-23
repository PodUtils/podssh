//! A send of the session's input, which waits for the channel's window while
//! it reads the channel's messages (T-598), apart from `io.rs` for its length.
//! The messages taken beside an earlier wait go first (T-780). A signal that
//! ends the session ends a send too; a write of ZMODEM's also ends at the
//! keys that stop a transfer, at the transfer's limit, and with its end
//! (T-859).

use std::time::{Duration, Instant};

use russh::client::Msg;
use russh::{ChannelReadHalf, ChannelWriteHalf};
use tokio::time::Interval;

use super::beside::{beside, next};
use super::busy::Busy;
use super::{handle_msg, input, link_ended, sleep_until, transfer, End, Input, Out, Taken, Through};
use crate::log::Log;
use crate::terminal::termination::Termination;
use crate::zmodem::Zmodem;

/// What a send waits for beside its write and the channel's messages.
pub(super) struct Also<'a> {
    /// SIGTERM and SIGHUP: a send that waits never outlives its terminal.
    pub(super) stop: &'a mut Termination,
    /// For a write of ZMODEM's: the local input, and whether it is read. A
    /// question or a transfer takes the keys meanwhile, so that Ctrl-C and
    /// CAN reach it whatever the far end does.
    pub(super) zmodem: Option<(&'a mut Input, bool)>,
}

/// Send `data` on the channel. The send waits for the channel's window,
/// which a connection that ended never opens: the channel's messages are
/// read meanwhile, and its end ends this (`Err`). `Ok(false)`: the channel
/// is closing. A write of ZMODEM's whose transfer ended meanwhile is dropped
/// where it stands (`Ok(true)`): the cancel sequence goes next.
pub(super) async fn send(
    writer: &ChannelWriteHalf<Msg>,
    (reader, aside): (&mut ChannelReadHalf, &mut Taken),
    data: Vec<u8>,
    (status, out, through): (&mut Option<i32>, &mut Out, &mut Through),
    also: Also<'_>,
    busy: &Busy,
    log: &Log,
) -> Result<bool, End> {
    let send = writer.data_bytes(data);
    tokio::pin!(send);
    // A far end that reads nothing leaves the window shut: where the host's
    // buffers take each byte that the window let go, no write of the socket
    // waits, and the stream's own limit never arms (T-598). The window shut
    // for WINDOW_STALL, with bytes to send, ends the session the same way.
    let bounded = through.window_stall;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut shut_since: Option<tokio::time::Instant> = None;
    let Also { stop, zmodem: mut keys } = also;
    let ours = keys.is_some();
    loop {
        let zmodem = through.zmodem.as_ref().filter(|_| ours);
        let reading = zmodem.is_some_and(Zmodem::busy) && keys.as_ref().is_some_and(|(_, open)| *open);
        let due = zmodem.and_then(Zmodem::deadline);
        // Waiting for the window, the pump still takes each message.
        busy.idle();
        tokio::select! {
            sent = &mut send => return Ok(sent.is_ok()),
            msg = busy.polled(next(&mut *reader, &mut *aside)) => match msg {
                Some(m) => {
                    busy.at("the output of the channel, in a send");
                    if let Some(end) = handle_msg(m, status, out, through, log).await {
                        return Err(end);
                    }
                }
                None => return Err(link_ended(*status, out.eof)),
            },
            // The window is read here, never in a branch's body: the write
            // that waits can hold the window's lock while it is not polled
            // (tokio's lock takes its permit, then yields when the task's
            // budget is spent), and a body that awaits that lock waits for
            // ever, with russh's loop behind it on the same lock (T-859).
            shut = window_shut(writer, &mut tick), if bounded => {
                if !shut {
                    shut_since = None;
                } else if shut_since.get_or_insert_with(tokio::time::Instant::now).elapsed() >= WINDOW_STALL {
                    log.error(&format!(
                        "a write made no progress for {} s: the channel's window stayed shut, as the far end reads nothing",
                        WINDOW_STALL.as_secs()
                    ));
                    return Err(End::Lost);
                }
            }
            stopped = stop.next() => {
                busy.at("a signal, in a send");
                // A `signal` request waits for russh's loop as a write does.
                let acted = beside(stop.act(stopped, writer, log), &mut *reader, &mut *aside, &|| busy.mark()).await;
                if let Some(end) = acted {
                    return Err(end);
                }
            }
            got = local_keys(&mut keys), if reading => match got {
                // A question or a transfer takes each key: nothing goes on.
                Some(bytes) => {
                    if let Some(z) = through.zmodem.as_mut() {
                        let _ = z.keys(bytes, Instant::now());
                    }
                }
                None => return Err(transfer::hung_up(through, log)),
            },
            () = sleep_until(due.map(Into::into)), if due.is_some() => {
                if let Some(z) = through.zmodem.as_mut() {
                    z.tick(Instant::now());
                }
            }
        }
        if ours && through.zmodem.as_ref().is_some_and(Zmodem::abandoned) {
            return Ok(true);
        }
    }
}

/// At the next tick: whether the channel's window is shut.
async fn window_shut(writer: &ChannelWriteHalf<Msg>, tick: &mut Interval) -> bool {
    tick.tick().await;
    writer.writable_packet_size().await == 0
}

/// The next keys of the local input, or `None` at its end; never when it is
/// not read.
async fn local_keys(keys: &mut Option<(&mut Input, bool)>) -> Option<Vec<u8>> {
    match keys {
        Some((input, open)) => input::next(input, *open).await,
        None => std::future::pending().await,
    }
}

/// How long the channel's window may stay shut while bytes wait to go: the
/// write limit's 60 s (T-227, T-598).
pub const WINDOW_STALL: Duration = Duration::from_secs(60);

#[cfg(test)]
#[path = "send_tests.rs"]
mod tests;
