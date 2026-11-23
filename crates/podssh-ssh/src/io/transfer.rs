//! ZMODEM's part of the pump (T-148): its words for the terminal and its
//! bytes for the server between the server's messages, each write of them
//! ended by the transfer's limit, its keys and its end (T-859); and the end
//! of the local terminal during a transfer.

use russh::client::Msg;
use russh::{ChannelReadHalf, ChannelWriteHalf};

use super::busy::Busy;
use super::send::{send, Also};
use super::{write_out, End, Out, Taken, Through};
use crate::log::Log;
use crate::zmodem::Zmodem;

/// What ZMODEM has for the terminal and for the server between the
/// server's messages: its words after a key or a wait, and a sender's next
/// bytes. `Err` when the channel or the session ended meanwhile.
pub(super) async fn zmodem_out(
    writer: &ChannelWriteHalf<Msg>,
    (reader, aside): (&mut ChannelReadHalf, &mut Taken),
    (status, out, through): (&mut Option<i32>, &mut Out, &mut Through),
    mut also: Also<'_>,
    busy: &Busy,
    log: &Log,
) -> Result<(), End> {
    // A write that the transfer's end dropped leaves the line of that end
    // and the cancel sequence: they go at once, as nothing else wakes the
    // pump for them.
    loop {
        let Some(taken) = through.zmodem.as_mut().map(|z| z.take(std::time::Instant::now())) else {
            return Ok(());
        };
        if !taken.screen.is_empty() {
            let screen = through.recorded(taken.screen, log);
            let _ = write_out(out.sink.as_ref(), &out.consoles.text(false, screen), false).await;
        }
        if taken.server.is_empty() {
            return Ok(());
        }
        let keys = also.zmodem.as_mut().map(|(input, open)| (&mut **input, *open));
        let again = Also { stop: &mut *also.stop, zmodem: keys };
        let channel = (&mut *reader, &mut *aside);
        let sent = send(writer, channel, taken.server, (status, out, through), again, busy, log).await;
        // Whole, dropped or cut, the write is over: the next one has its own time.
        let dropped = through.zmodem.as_ref().is_some_and(Zmodem::abandoned);
        if let Some(z) = through.zmodem.as_mut() {
            z.written();
        }
        sent?;
        if !dropped {
            return Ok(());
        }
    }
}

/// The local terminal went (the end of stdin) while ZMODEM held its keys:
/// the transfer ends, a file that did not end goes, and so does the session,
/// as nobody is left to answer. The far `sz` or `rz` ends with its pty when
/// the connection closes.
pub(super) fn hung_up(through: &mut Through, log: &Log) -> End {
    if let Some(z) = through.zmodem.as_mut() {
        z.hangup(std::time::Instant::now());
    }
    log.info("the local terminal went during a ZMODEM transfer: the transfer was cancelled, and the session ends");
    End::Terminated
}
