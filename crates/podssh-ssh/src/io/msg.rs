//! Each message of the session's channel, on its way to the terminal: the
//! output, the exit status or signal, the close, and the answer to `~d`.

use russh::ChannelMsg;
use tokio::io::AsyncWriteExt;

use super::{end_with, status_code, End, Out, Sink, Through};
use crate::log::Log;
use crate::signals;

pub(super) async fn handle_msg(
    msg: ChannelMsg,
    status: &mut Option<i32>,
    out: &mut Out,
    through: &mut Through,
    log: &Log,
) -> Option<End> {
    // Any message of the channel answers SSH's own question (T-332).
    if let Some(asked) = &through.asked {
        asked.heard();
    }
    match msg {
        ChannelMsg::Data { data } => {
            // The shell's output as the far end counts it, before any filter.
            if let Some(count) = &through.count {
                count.data(data.len());
            }
            let data = out.consoles.text(false, through.out(&data, false, log));
            // Whoever reads our stdout has gone (EPIPE): the data goes
            // nowhere, and the exit status is awaited (T-026).
            if out.gone.is_none() && write_out(out.sink.as_ref(), &data, false).await.is_err() {
                out.gone = Some(tokio::time::Instant::now());
            }
        }
        // A report of local echo's far end, which never shows (T-160).
        ChannelMsg::ExtendedData { data, ext } if ext == crate::predict::EXT && through.predict.is_some() => {
            crate::predict::reported(through.predict.as_mut(), &data).await;
        }
        // A frame of the far end's screen, in place of its bytes (T-303).
        ChannelMsg::ExtendedData { data, ext } if ext == crate::frames::EXT && through.frames.is_some() => {
            return frame(&data, out, through, log).await;
        }
        ChannelMsg::ExtendedData { data, ext } => {
            // serve says a reset, and a part that its ring dropped, here.
            if let (Some(count), 1) = (&through.count, ext) {
                count.stderr(&data);
            }
            // Words beside the frames move the cursor under them (T-303).
            if let Some(frames) = through.frames.as_mut() {
                frames.disturbed();
            }
            let data = out.consoles.text(true, through.out(&data, true, log));
            let _ = write_out(out.sink.as_ref(), &data, true).await;
        }
        ChannelMsg::ExitStatus { exit_status } => {
            crate::outcome::status(exit_status);
            *status = Some(status_code(exit_status));
        }
        ChannelMsg::ExitSignal { signal_name, core_dumped, error_message, .. } => {
            let name = signals::name(&signal_name);
            crate::outcome::signal(&name, core_dumped);
            *status = Some(signals::number(&signal_name).map_or(255, |n| 128 + n));
            let mut note = format!("the remote command was killed by signal {name}");
            if core_dumped {
                note.push_str(" (core dumped)");
            }
            let detail = podssh_ws::text::one_line(&error_message);
            if !detail.is_empty() {
                note.push_str(": ");
                note.push_str(&detail);
            }
            log.info(&note);
        }
        ChannelMsg::Close => {
            // A command that never started: what su said, its refusal.
            if let Some(e) = through.elevated.as_mut().filter(|e| !e.started()) {
                let _ = write_out(out.sink.as_ref(), &out.consoles.text(true, e.finish()), true).await;
            }
            // A sequence that the end cut, for a console (T-294).
            for stderr in [false, true] {
                let tail = out.consoles.finish(stderr);
                if !tail.is_empty() {
                    let _ = write_out(out.sink.as_ref(), &tail, stderr).await;
                }
            }
            return Some(end_with(*status));
        }
        // The answer to `~d`, when one is awaited (T-158).
        reply @ (ChannelMsg::Success | ChannelMsg::Failure) => return through.detaching.answer(&reply, log),
        // The server sends nothing more, but the exit status and the close
        // may still come: a link lost after it cut no output (T-461).
        ChannelMsg::Eof => out.eof = true,
        _ => {}
    }
    None
}

/// The frames that `data` completes, drawn on stdout as the newest state
/// (T-303), and into the recording as drawn. Bytes that are no frame end
/// the session with one line: nothing that follows them can be shown.
async fn frame(data: &[u8], out: &mut Out, through: &mut Through, log: &Log) -> Option<End> {
    let drawn = match through.frames.as_mut()?.feed(data) {
        Ok(drawn) => drawn,
        Err(why) => {
            log.error(&format!("--frames: the far end sent {why}; the session ends, as its screen cannot be shown"));
            return Some(End::NoStatus);
        }
    };
    if drawn.is_empty() {
        return None;
    }
    let drawn = through.recorded(drawn, log);
    // A notice of silence comes off before the far end's next screen, as
    // before its next bytes (T-302).
    let drawn = match through.notice.as_mut().map(|notice| notice.before_output(&drawn, false)) {
        Some(mut first) if !first.is_empty() => {
            first.extend_from_slice(&drawn);
            first
        }
        _ => drawn,
    };
    let drawn = out.consoles.text(false, drawn);
    if out.gone.is_none() && write_out(out.sink.as_ref(), &drawn, false).await.is_err() {
        out.gone = Some(tokio::time::Instant::now());
    }
    None
}

pub(super) async fn write_out(sink: Option<&Sink>, data: &[u8], to_stderr: bool) -> std::io::Result<()> {
    if let Some(sink) = sink {
        sink.send((data.to_vec(), to_stderr))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
    } else if to_stderr {
        let mut err = tokio::io::stderr();
        err.write_all(data).await?;
        err.flush().await?;
    } else {
        let mut out = tokio::io::stdout();
        out.write_all(data).await?;
        out.flush().await?;
    }
    // What `--result-file` counts (T-054).
    crate::outcome::output(data.len(), to_stderr);
    Ok(())
}
