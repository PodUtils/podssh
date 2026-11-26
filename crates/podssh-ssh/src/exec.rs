//! One command on a new session channel with no pty, within limits: its
//! output read in full for a short answer (`capture`: the probes and the
//! digest of `cp`), or its input and output streamed (`send`, `receive`: the
//! copy by exec, T-135), each wait bounded so that a far side that stops
//! reading or writing fails the step and never hangs it.

use std::future::Future;
use std::time::Duration;

use russh::client::{Handle, Msg};
use russh::{Channel, ChannelMsg, ChannelReadHalf};

use crate::handler::Client;
use crate::io::beside::{self, beside, Backlog, Source};
use crate::unopened::Unopened;

/// What a command wrote, and how it ended.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Captured {
    /// The exit status, when the server sent one.
    pub status: Option<u32>,
    /// Standard output, up to the cap.
    pub stdout: Vec<u8>,
    /// Standard error, up to the cap.
    pub stderr: Vec<u8>,
}

/// Why a command did not run to its end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// The server refused the channel or the command (`ForceCommand
    /// internal-sftp` does).
    Refused(String),
    /// No end within the limit.
    Timeout(Duration),
    /// The connection or the channel broke.
    Lost(String),
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::Refused(why) => write!(f, "the server refused the command: {why}"),
            ExecError::Timeout(limit) => write!(f, "the command did not end within {} s", limit.as_secs()),
            ExecError::Lost(why) => write!(f, "the command's channel broke: {why}"),
        }
    }
}

impl std::error::Error for ExecError {}

/// Keep `data` in `into`, `cap` bytes at most: a command that writes more
/// than its answer is not believed past it.
fn keep(into: &mut Vec<u8>, data: &[u8], cap: usize) {
    let room = cap.saturating_sub(into.len());
    into.extend_from_slice(&data[..data.len().min(room)]);
}

/// Run `command` on a new session channel with no pty and no input, and read
/// each output, `cap` bytes at most, until the channel closes, within `limit`.
pub async fn capture(
    handle: &Handle<Client>,
    command: &str,
    limit: Duration,
    cap: usize,
) -> Result<Captured, ExecError> {
    let run = async {
        let mut stdout = Vec::new();
        let mut sink = |data: &[u8]| {
            keep(&mut stdout, data, cap);
            Ok(())
        };
        let mut out = receive(handle, command, limit, cap, &mut sink).await?;
        out.stdout = stdout;
        Ok(out)
    };
    match tokio::time::timeout(limit, run).await {
        Err(_) => Err(ExecError::Timeout(limit)),
        Ok(result) => result,
    }
}

/// A new session channel that runs `command`, each step within `limit`.
async fn open(handle: &Handle<Client>, command: &str, limit: Duration) -> Result<Channel<Msg>, ExecError> {
    let channel = match tokio::time::timeout(limit, handle.channel_open_session()).await {
        Err(_) => return Err(ExecError::Timeout(limit)),
        // A connection that ended is no refusal: a copy or a job reads a
        // refusal as a server that runs no command (T-464).
        Ok(Err(e)) => {
            return Err(match crate::unopened::read(&e, handle).await {
                Unopened::Refused(reason) => ExecError::Refused(format!("no session channel: open failed: {reason}")),
                other => ExecError::Lost(other.words("a session channel", false)),
            });
        }
        Ok(Ok(channel)) => channel,
    };
    match tokio::time::timeout(limit, channel.exec(true, command.as_bytes())).await {
        Err(_) => Err(ExecError::Timeout(limit)),
        Ok(Err(e)) => Err(ExecError::Lost(podssh_ws::text::said(&e))),
        Ok(Ok(())) => Ok(channel),
    }
}

/// A write of the session, `progress` at most, beside the channel's reads:
/// russh's loop puts each message of the command into the channel's bounded
/// queue, inline, and takes a write only after, so a write that reads
/// nothing can wait on a loop that waits on it (T-780). What the wait takes
/// goes into `aside`, which `finish` hands on first (T-923).
async fn write<F: Future<Output = Result<(), russh::Error>>, S: Source<Msg = ChannelMsg>>(
    op: F,
    read: &mut S,
    aside: &mut Backlog<ChannelMsg>,
    progress: Duration,
) -> Result<(), ExecError> {
    match tokio::time::timeout(progress, beside(op, read, aside, &|| {})).await {
        Err(_) => Err(ExecError::Timeout(progress)),
        Ok(Err(e)) => Err(ExecError::Lost(podssh_ws::text::said(&e))),
        Ok(Ok(())) => Ok(()),
    }
}

/// The end of the command's input. A channel that refused it has ended,
/// which `finish` reads; one that took no write within `progress` fails the
/// step.
async fn end_input(
    writer: &russh::ChannelWriteHalf<Msg>,
    read: &mut ChannelReadHalf,
    aside: &mut Backlog<ChannelMsg>,
    progress: Duration,
) -> Result<(), ExecError> {
    match write(writer.eof(), read, aside, progress).await {
        Err(ExecError::Timeout(limit)) => Err(ExecError::Timeout(limit)),
        _ => Ok(()),
    }
}

/// Each message until the channel closes, those that `aside` took first:
/// stdout to `sink`, stderr kept up to `cap`, and the exit status; each wait
/// `progress` at most. A channel that ends with neither its close nor an
/// exit status lost its connection: the command's end was never seen. One
/// that ends after the status and before the output's end (its EOF) lost
/// the output after the cut (T-461).
async fn finish<S: Source<Msg = ChannelMsg>>(
    read: &mut S,
    aside: &mut Backlog<ChannelMsg>,
    progress: Duration,
    cap: usize,
    sink: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
) -> Result<Captured, ExecError> {
    let mut out = Captured::default();
    let (mut closed, mut eof) = (false, false);
    loop {
        match tokio::time::timeout(progress, beside::next(read, aside)).await {
            Err(_) => return Err(ExecError::Timeout(progress)),
            Ok(None) if closed || (eof && out.status.is_some()) => return Ok(out),
            Ok(None) if out.status.is_some() => {
                return Err(ExecError::Lost(
                    "the connection ended after the command's status, before its output".into(),
                ))
            }
            Ok(None) => return Err(ExecError::Lost("the connection ended before the command did".into())),
            Ok(Some(ChannelMsg::Close)) => closed = true,
            Ok(Some(ChannelMsg::Eof)) => eof = true,
            Ok(Some(ChannelMsg::Failure)) => return Err(ExecError::Refused("exec".into())),
            Ok(Some(ChannelMsg::Data { data })) => {
                sink(&data).map_err(|e| ExecError::Lost(format!("the local copy: {}", podssh_ws::text::said(&e))))?;
            }
            Ok(Some(ChannelMsg::ExtendedData { data, ext: 1 })) => keep(&mut out.stderr, &data, cap),
            Ok(Some(ChannelMsg::ExitStatus { exit_status })) => out.status = Some(exit_status),
            Ok(Some(_)) => {}
        }
    }
}

/// Run `command` with no input, and give each piece of its stdout to `sink`,
/// until the channel closes. Each wait for the next message is `progress` at
/// most; the stdout of the result is empty.
pub async fn receive(
    handle: &Handle<Client>,
    command: &str,
    progress: Duration,
    cap: usize,
    sink: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
) -> Result<Captured, ExecError> {
    let channel = open(handle, command, progress).await?;
    let (mut read, writer) = channel.split();
    let mut aside = Backlog::default();
    // The command reads no input: the end of it at once, so a command that
    // reads anyway does not wait.
    end_input(&writer, &mut read, &mut aside, progress).await?;
    finish(&mut read, &mut aside, progress, cap, sink).await
}

/// Run `command` with the pieces that `fill` gives on its stdin (a piece of 0
/// bytes ends the input), then the end of input, and give its stdout to
/// `sink`. Each piece waits `progress` at most for the window: a far side
/// that stops reading fails the step.
pub async fn send(
    handle: &Handle<Client>,
    command: &str,
    progress: Duration,
    cap: usize,
    fill: &mut dyn FnMut(&mut Vec<u8>) -> std::io::Result<()>,
    sink: &mut dyn FnMut(&[u8]) -> std::io::Result<()>,
) -> Result<Captured, ExecError> {
    let channel = open(handle, command, progress).await?;
    let (mut read, writer) = channel.split();
    // What the command says while its input goes, handed on after (T-923).
    let mut aside = Backlog::default();
    let mut piece = Vec::new();
    loop {
        piece.clear();
        fill(&mut piece).map_err(|e| ExecError::Lost(format!("the local source: {}", podssh_ws::text::said(&e))))?;
        if piece.is_empty() {
            break;
        }
        // Behind a key that waits for its echo (T-661), outside the wait for
        // the window.
        crate::pace::turn().await;
        write(writer.data(&piece[..]), &mut read, &mut aside, progress).await?;
    }
    end_input(&writer, &mut read, &mut aside, progress).await?;
    finish(&mut read, &mut aside, progress, cap, sink).await
}

/// Why a command gave no line of the kind asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoLine {
    /// It ended first: its status, and what it wrote, up to the cap.
    Ended(Captured),
    /// It did not run, or did not end, within the limit.
    Failed(ExecError),
}

/// Run `command` with no input, and give the rest of the first line of its
/// stdout that starts with `mark`, within `limit`, and the command's
/// channel. The command goes on: a temporary node runs on after its line
/// (T-167), and the caller keeps its channel open for as long as it needs
/// the command. The lines before are kept, up to `cap`, for a command that
/// ends with no such line.
pub async fn first_line(
    handle: &Handle<Client>,
    command: &str,
    mark: &str,
    limit: Duration,
    cap: usize,
) -> Result<(String, Channel<Msg>), NoLine> {
    let run = async {
        let mut channel = open(handle, command, limit).await.map_err(NoLine::Failed)?;
        let _ = channel.eof().await;
        let (mut out, mut pending) = (Captured::default(), Vec::new());
        loop {
            let message = channel.wait().await;
            match message {
                None => return Err(NoLine::Ended(out)),
                Some(ChannelMsg::Failure) => return Err(NoLine::Failed(ExecError::Refused("exec".into()))),
                Some(ChannelMsg::Data { data }) => {
                    pending.extend_from_slice(&data);
                    while let Some(end) = pending.iter().position(|b| *b == b'\n') {
                        let line: Vec<u8> = pending.drain(..=end).collect();
                        let text = String::from_utf8_lossy(&line);
                        if let Some(rest) = text.trim_end_matches(['\r', '\n']).strip_prefix(mark) {
                            return Ok((rest.to_string(), channel));
                        }
                        keep(&mut out.stdout, &line, cap);
                    }
                    // A line longer than the cap is no line of ours.
                    if pending.len() > cap {
                        keep(&mut out.stdout, &pending, cap);
                        pending.clear();
                    }
                }
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => keep(&mut out.stderr, &data, cap),
                Some(ChannelMsg::ExitStatus { exit_status }) => out.status = Some(exit_status),
                Some(_) => {}
            }
        }
    };
    match tokio::time::timeout(limit, run).await {
        Err(_) => Err(NoLine::Failed(ExecError::Timeout(limit))),
        Ok(result) => result,
    }
}

/// `text` as one word for a POSIX shell, in single quotes. A newline or a
/// NUL has no safe spelling across the shells that a login may run, so such
/// a word has none here.
pub fn shell_word(text: &str) -> Option<String> {
    if text.contains(['\n', '\0']) {
        return None;
    }
    Some(format!("'{}'", text.replace('\'', r"'\''")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_word_is_quoted_whole_and_a_newline_has_no_spelling() {
        assert_eq!(shell_word("/srv/a b").as_deref(), Some("'/srv/a b'"));
        assert_eq!(shell_word("it's").as_deref(), Some(r"'it'\''s'"));
        assert_eq!(shell_word("-n").as_deref(), Some("'-n'"));
        assert_eq!(shell_word("a\nb"), None);
        assert_eq!(shell_word("a\0b"), None);
    }

    /// The command's output while its input goes waits beside the write, and
    /// is handed on after, in order, with its status (T-923). The model's
    /// loop takes the write only once the channel's queue took each message:
    /// awaited alone, the write waits for ever (the control).
    #[tokio::test(start_paused = true)]
    async fn a_write_of_exec_goes_beside_the_command_output() {
        use crate::io::beside::model::model;
        let limit = Duration::from_secs(60);
        let msgs = || {
            let data = (0..8u8).map(|i| ChannelMsg::Data { data: vec![i; 100].into() });
            let end = [ChannelMsg::ExitStatus { exit_status: 0 }, ChannelMsg::Eof, ChannelMsg::Close];
            data.chain(end).collect::<Vec<_>>()
        };
        let (chan, cmd, looping) = model(msgs());
        assert!(tokio::time::timeout(limit, cmd.send("eof")).await.is_err(), "the control");
        looping.abort();
        drop(chan);

        let (mut chan, cmd, looping) = model(msgs());
        let mut aside = Backlog::default();
        let eof = async { cmd.send("eof").await.map_err(|_| russh::Error::SendError) };
        assert_eq!(write(eof, &mut chan, &mut aside, limit).await, Ok(()), "the end went beside");
        assert_eq!(looping.await.expect("the loop ends"), ["data", "eof"]);
        let mut got = Vec::new();
        let mut sink = |data: &[u8]| {
            got.extend_from_slice(data);
            Ok(())
        };
        let out = finish(&mut chan, &mut aside, limit, 1024, &mut sink).await.expect("the command's end");
        assert_eq!(out.status, Some(0));
        assert_eq!(got, (0..8u8).flat_map(|i| vec![i; 100]).collect::<Vec<_>>(), "each piece, in order");
    }

    #[test]
    fn output_past_the_cap_is_dropped() {
        let mut into = Vec::new();
        keep(&mut into, b"abcdef", 4);
        keep(&mut into, b"gh", 4);
        assert_eq!(into, b"abcd");
    }
}
