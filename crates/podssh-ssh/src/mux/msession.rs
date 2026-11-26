//! A session or a stdio forward that a client asked a master for (T-039): a
//! channel of the master's connection, with the client's terminal, command
//! and environment, copied to and from the descriptors that the client
//! passed, until the channel closes. The client hears SESSION_OPENED or a
//! failure, TTY_ALLOC_FAIL when no pty came, and EXIT_MESSAGE with the
//! status, as OpenSSH's master sends them. A client of podssh's that asked
//! for frames gets them drawn on its terminal here ([`super::mframes`]).

use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use russh::client::{Handle, Msg};
use russh::{Channel, ChannelMsg};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;

use super::afd::Passed;
use super::mframes::{self, Framed};
use super::proto::{Message, NewSession, NO_ESCAPE};
use super::wire;
use crate::escape::{Command, Escapes};
use crate::handler::Client;
use crate::io::beside::{self, beside, Backlog};
use crate::log::Log;
use crate::terminal;

/// The size of each read of the client's input.
const CHUNK: usize = 32 * 1024;
/// How long the server may take to open a stdio forward's channel.
const OPEN_LIMIT: Duration = Duration::from_secs(60);
/// How long one side of a stdio forward may still talk once the other ended.
const GRACE: Duration = Duration::from_secs(2);
const HELP: &[u8] = b"\r\nSupported escape sequences:\r\n ~.   - terminate this session\r\n \
~#   - list forwarded connections\r\n ~?   - this message\r\n \
~~   - send the escape character by typing it twice\r\n(Note that escapes are only recognized immediately after newline.)\r\n";
/// The answer to `~Z` in a session through a master (T-148).
const ZMODEM_NOTE: &[u8] = b"\r\npodssh: ZMODEM works in a session of its own, not through a control master\r\n";

async fn failure(stream: &mut UnixStream, rid: u32, reason: String) {
    let _ = wire::write(stream, &Message::Failure { rid, reason }).await;
}

/// Run `asked` with the client's `fds` (stdin, stdout, stderr) and answer
/// on `stream`. `winch` changes at each SIGWINCH of the master, which a
/// client relays to it; `agent` says whether the master may forward its
/// agent.
#[allow(clippy::too_many_arguments)]
pub async fn session(
    handle: &Handle<Client>,
    mut asked: NewSession,
    fds: [OwnedFd; 3],
    sid: u32,
    stream: &mut UnixStream,
    agent: bool,
    winch: watch::Receiver<u64>,
    log: &Arc<Log>,
) {
    let rid = asked.rid;
    // The client's `--frames` (T-303): the master's to read, never a
    // variable of the server's.
    let frames_ask = mframes::Ask::take(&mut asked.env);
    let [stdin, stdout, stderr] = fds;
    let (mut input, mut out, mut err) = match (Passed::new(stdin), Passed::new(stdout), Passed::new(stderr)) {
        (Ok(input), Ok(out), Ok(err)) => (input, out, err),
        _ => return failure(stream, rid, "the master could not use the client's descriptors".into()).await,
    };
    let mut channel = match handle.channel_open_session().await {
        Ok(channel) => channel,
        // OpenSSH's master's words for a refusal; a connection that ended is
        // none (T-464).
        Err(e) => {
            let why = match crate::unopened::read(&e, handle).await {
                crate::unopened::Unopened::Refused(reason) => format!("Session open refused by peer: {reason}"),
                other => other.words("a session", false),
            };
            return failure(stream, rid, why).await;
        }
    };
    for entry in &asked.env {
        if let Some((name, value)) = entry.split_once('=') {
            // No reply asked for: servers refuse unlisted variables silently.
            let _ = channel.set_env(false, name, value).await;
        }
    }
    let mut early = Vec::new();
    let mut pty = false;
    if asked.tty {
        let size = terminal::size_of_fd(input.raw()).unwrap_or_else(terminal::fallback_size);
        let modes = terminal::pty_modes_of(input.raw());
        let sent =
            channel.request_pty(true, &asked.term, size.cols, size.rows, size.px_width, size.px_height, &modes).await;
        if sent.is_ok() {
            pty = crate::session::wait_reply(&mut channel, &mut early).await.unwrap_or(false);
        }
    }
    if asked.agent && agent {
        let _ = crate::agent_forward::request(&mut channel, &mut early, log).await;
    }
    // The frames are asked last before the session's request, as a client
    // of its own asks them; a subsystem is no terminal's session.
    let frames_ask = frames_ask.filter(|_| !asked.subsystem);
    let frames_asked = mframes::ask(&channel, frames_ask, pty, &mut err).await;
    let sent = if asked.subsystem {
        channel.request_subsystem(true, String::from_utf8_lossy(&asked.command)).await
    } else if asked.command.is_empty() {
        channel.request_shell(true).await
    } else {
        channel.exec(true, asked.command.clone()).await
    };
    // The replies come in order: the frames' before the session's.
    let framed = match &sent {
        Ok(()) => {
            let asks = (frames_asked, frames_ask);
            mframes::answered(&mut channel, &mut early, asks, &mut err).await.unwrap_or(None)
        }
        Err(_) => None,
    };
    let started = sent.is_ok() && crate::session::wait_reply(&mut channel, &mut early).await.unwrap_or(false);
    if !started {
        return failure(stream, rid, "the server refused to start the session".into()).await;
    }
    if wire::write(stream, &Message::SessionOpened { rid, sid }).await.is_err() {
        return;
    }
    if asked.tty && !pty {
        let _ = wire::write(stream, &Message::TtyAllocFail { sid }).await;
    }
    let escapes = match (pty, asked.escape) {
        (true, e) if e != NO_ESCAPE => u8::try_from(e).ok().map(Escapes::new),
        _ => None,
    };
    let winch = pty.then_some(winch);
    // What the last frame leaves on the client's terminal, for the end.
    let leave = framed.as_ref().map(Framed::leave);
    let mut term = Term { out: &mut out, err: &mut err, framed };
    let status = pump(channel, early, &mut input, &mut term, escapes, winch).await;
    // The modes of the keys that the last frame set go back, and the
    // cursor shows, however the session ended, before the client hears
    // the status and writes its own line.
    if let Some(bytes) = leave.map(|leave| leave.bytes()).filter(|bytes| !bytes.is_empty()) {
        let _ = out.write_all(&bytes).await;
    }
    let _ = out.flush().await;
    let _ = err.flush().await;
    if let Some(code) = status {
        let _ = wire::write(stream, &Message::ExitMessage { sid, code: code as u32 }).await;
    }
    log.verbose(&format!("a shared session ended ({})", status.map_or("no status".into(), |c| format!("status {c}"))));
}

/// Copy until the channel closes; the status that came, if one did. A link
/// lost after the status and before the output's end (its EOF) gives none:
/// the output after the cut is lost, and the client's run is no success
/// (T-461).
async fn pump(
    channel: Channel<Msg>,
    early: Vec<ChannelMsg>,
    input: &mut Passed,
    term: &mut Term<'_>,
    mut escapes: Option<Escapes>,
    mut winch: Option<watch::Receiver<u64>>,
) -> Option<i32> {
    let (mut reader, writer) = channel.split();
    let (mut status, mut eof) = (None, false);
    // Each write waits for russh's loop, which can wait for this copy to
    // take the channel's next message: the channel drains beside the write
    // (T-780), and what it took goes out first.
    let mut aside = Backlog::default();
    let no_watch = || {};
    for msg in early {
        match take(msg, &mut status, &mut eof, term).await {
            Some(Stop::Closed) => return status,
            Some(Stop::Unframed) => {
                let _ = beside(writer.close(), &mut reader, &mut aside, &no_watch).await;
                return None;
            }
            None => {}
        }
    }
    // A client's keys on a pty hold the master's bulk until their echo (T-661).
    let pty = winch.is_some();
    let mut buf = vec![0u8; CHUNK];
    let mut reading = true;
    let mut last = terminal::size_of_fd(input.raw());
    loop {
        // The frames that came are acknowledged, once for each pass, with
        // no reply asked, as a client of its own does (T-303).
        if let Some(value) = term.framed.as_mut().and_then(Framed::take_ack) {
            let ack = writer.set_env(false, crate::frames::ACK, value);
            let _ = beside(ack, &mut reader, &mut aside, &no_watch).await;
        }
        tokio::select! {
            read = input.read(&mut buf), if reading => match read {
                Ok(0) | Err(_) => {
                    reading = false;
                    let _ = beside(writer.eof(), &mut reader, &mut aside, &no_watch).await;
                }
                Ok(n) => {
                    let (data, commands) = match escapes.as_mut() {
                        Some(e) => e.feed(&buf[..n]),
                        None => (buf[..n].to_vec(), Vec::new()),
                    };
                    if pty && !data.is_empty() {
                        crate::pace::key();
                    }
                    if !data.is_empty() {
                        let sent = beside(writer.data_bytes(data), &mut reader, &mut aside, &no_watch);
                        if sent.await.is_err() {
                            reading = false;
                        }
                    }
                    for command in commands {
                        match command {
                            Command::Disconnect => {
                                let _ = beside(writer.close(), &mut reader, &mut aside, &no_watch).await;
                                return status;
                            }
                            Command::Help => term.note(HELP).await,
                            // The forwards are the master's, as OpenSSH's
                            // ~# lists the master's connections (T-041).
                            Command::List => {
                                let listing = crate::tally::listing().replace('\n', "\r\n");
                                term.note(listing.as_bytes()).await;
                            }
                            // A re-key is the whole connection's: the master's.
                            // A shared session learns no offer of kept shells,
                            // so its escapes never detach (T-158); and it has
                            // no ~C, as a client of OpenSSH's master has none
                            // (T-291).
                            Command::Rekey | Command::Detach | Command::CommandLine => {}
                            // ZMODEM is watched in a session of podssh's own
                            // terminal, not in one that a master carries.
                            Command::Zmodem => term.note(ZMODEM_NOTE).await,
                        }
                    }
                }
            },
            msg = beside::next(&mut reader, &mut aside) => match msg {
                Some(msg) => {
                    // A frame of the screen is a key's echo too (T-303).
                    let frame = matches!(msg, ChannelMsg::ExtendedData { ext: crate::frames::EXT, .. });
                    if pty && (frame || matches!(msg, ChannelMsg::Data { .. })) {
                        crate::pace::echo();
                    }
                    match take(msg, &mut status, &mut eof, term).await {
                        Some(Stop::Closed) => return status,
                        Some(Stop::Unframed) => {
                            let _ = beside(writer.close(), &mut reader, &mut aside, &no_watch).await;
                            return None;
                        }
                        None => {}
                    }
                }
                None => return status.filter(|_| eof),
            },
            changed = changed(&mut winch) => match changed {
                true => {
                    let size = terminal::size_of_fd(input.raw());
                    if let (Some(s), true) = (size, size != last) {
                        // The terminal moved its rows: the next frame draws each.
                        if let Some(framed) = term.framed.as_mut() {
                            framed.disturbed();
                        }
                        let change = writer.window_change(s.cols, s.rows, s.px_width, s.px_height);
                        let _ = beside(change, &mut reader, &mut aside, &no_watch).await;
                        last = size;
                    }
                }
                false => winch = None,
            },
        }
    }
}

/// The client's terminal: its output and its stderr, and the frames drawn
/// on its output where the client asked for them (T-303).
struct Term<'a> {
    out: &'a mut Passed,
    err: &'a mut Passed,
    framed: Option<Framed>,
}

impl Term<'_> {
    /// Words of the master's on the client's stderr: they move the cursor
    /// under the frames, so the next one draws the whole screen.
    async fn note(&mut self, bytes: &[u8]) {
        let _ = self.err.write_all(bytes).await;
        if let Some(framed) = self.framed.as_mut() {
            framed.disturbed();
        }
    }
}

/// Why the copy stops.
enum Stop {
    /// The channel closed.
    Closed,
    /// The far end sent bytes that are no frame: nothing after them can be
    /// shown, so the master closes the channel, and the session has no
    /// status (T-303).
    Unframed,
}

/// The next change of the window, or pending with none to watch.
async fn changed(winch: &mut Option<watch::Receiver<u64>>) -> bool {
    match winch {
        Some(w) => w.changed().await.is_ok(),
        None => std::future::pending().await,
    }
}

/// One message of the channel: `Some` once the copy stops. `eof`: the
/// output ended.
async fn take(msg: ChannelMsg, status: &mut Option<i32>, eof: &mut bool, term: &mut Term<'_>) -> Option<Stop> {
    match msg {
        ChannelMsg::Data { data } => {
            let _ = term.out.write_all(&data).await;
        }
        // A frame of the far end's screen, in place of its bytes (T-303).
        ChannelMsg::ExtendedData { data, ext } if ext == crate::frames::EXT && term.framed.is_some() => {
            let Term { out, err, framed } = term;
            if let Some(framed) = framed.as_mut() {
                if !framed.draw(&data, out, err).await {
                    return Some(Stop::Unframed);
                }
            }
        }
        ChannelMsg::ExtendedData { data, .. } => term.note(&data).await,
        ChannelMsg::ExitStatus { exit_status } => *status = Some(crate::io::status_code(exit_status)),
        ChannelMsg::ExitSignal { signal_name, .. } => {
            *status = Some(crate::signals::number(&signal_name).map_or(255, |n| 128 + n));
        }
        ChannelMsg::Close => return Some(Stop::Closed),
        ChannelMsg::Eof => *eof = true,
        _ => {}
    }
    None
}

/// `-W HOST:PORT` through the master: a direct-tcpip channel and the
/// client's stdin and stdout, or for the port `PORT_STREAMLOCAL` a
/// direct-streamlocal channel to the socket of `host` (T-040). The client
/// hears SESSION_OPENED, and exits 0 when the master closes the control
/// connection, as OpenSSH's does.
#[allow(clippy::too_many_arguments)]
pub async fn stdio(
    handle: &Handle<Client>,
    rid: u32,
    host: &str,
    port: u32,
    fds: [OwnedFd; 2],
    sid: u32,
    stream: &mut UnixStream,
    log: &Arc<Log>,
) {
    let [stdin, stdout] = fds;
    let (input, output) = match (Passed::new(stdin), Passed::new(stdout)) {
        (Ok(input), Ok(output)) => (input, output),
        _ => return failure(stream, rid, "the master could not use the client's descriptors".into()).await,
    };
    let opening = async {
        if port == super::proto::PORT_STREAMLOCAL {
            handle.channel_open_direct_streamlocal(host).await
        } else {
            handle.channel_open_direct_tcpip(host, port, "127.0.0.1", 0).await
        }
    };
    let opened = tokio::time::timeout(OPEN_LIMIT, opening).await;
    let channel = match opened {
        Ok(Ok(channel)) => channel,
        Ok(Err(e)) => {
            let why = format!("stdio forwarding failed: {}", crate::run::describe(&e));
            return failure(stream, rid, why).await;
        }
        Err(_) => return failure(stream, rid, "stdio forwarding failed: no answer from the server".into()).await,
    };
    if wire::write(stream, &Message::SessionOpened { rid, sid }).await.is_err() {
        return;
    }
    let local = tokio::io::join(input, output);
    crate::agent_forward::splice(local, channel.into_stream(), GRACE).await;
    let shown = if port == super::proto::PORT_STREAMLOCAL { host.to_string() } else { format!("{host}:{port}") };
    log.verbose(&format!("a shared stdio forward to {shown} ended"));
}
