//! A send of the session's input, which waits for the channel's window while
//! it reads the channel's messages (T-598), apart from `io.rs` for its length.

use std::time::Duration;

use russh::client::Msg;
use russh::{ChannelReadHalf, ChannelWriteHalf};

use super::busy::Busy;
use super::{handle_msg, link_ended, End, Out, Through};
use crate::log::Log;

/// Send `data` on the channel. The send waits for the channel's window,
/// which a connection that ended never opens: the channel's messages are
/// read meanwhile, and its end ends this (`Err`). `Ok(false)`: the channel
/// is closing.
pub(super) async fn send(
    writer: &ChannelWriteHalf<Msg>,
    reader: &mut ChannelReadHalf,
    data: Vec<u8>,
    (status, out, through): (&mut Option<i32>, &mut Out, &mut Through),
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
    loop {
        // Waiting for the window, the pump still takes each message.
        busy.idle();
        tokio::select! {
            sent = &mut send => return Ok(sent.is_ok()),
            msg = busy.polled(reader.wait()) => match msg {
                Some(m) => {
                    busy.at("the output of the channel, in a send");
                    if let Some(end) = handle_msg(m, status, out, through, log).await {
                        return Err(end);
                    }
                }
                None => return Err(link_ended(*status, out.eof)),
            },
            _ = tick.tick(), if bounded => {
                if writer.writable_packet_size().await > 0 {
                    shut_since = None;
                } else if shut_since.get_or_insert_with(tokio::time::Instant::now).elapsed() >= WINDOW_STALL {
                    log.error(&format!(
                        "a write made no progress for {} s: the channel's window stayed shut, as the far end reads nothing",
                        WINDOW_STALL.as_secs()
                    ));
                    return Err(End::Lost);
                }
            }
        }
    }
}

/// How long the channel's window may stay shut while bytes wait to go: the
/// write limit's 60 s (T-227, T-598).
pub const WINDOW_STALL: Duration = Duration::from_secs(60);
