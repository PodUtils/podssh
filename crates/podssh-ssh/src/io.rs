//! Copying between the local stdin/stdout/stderr and a session channel, with
//! window-size changes, the escape character and ZMODEM, until the channel
//! closes. The input outlives a session: `--persist` attaches a new one
//! after a lost link, and it reads on where the last one stopped. The
//! forwards that `~C` adds serve beside the session (T-291).

use std::sync::Arc;
use std::time::Duration;

use russh::client::{Handle, Msg};
use russh::{Channel, ChannelMsg, ChannelWriteHalf};
use tokio::io::AsyncWriteExt;

use crate::elevate::Elevated;
use crate::escape::{Command, Escapes};
use crate::escape_run;
use crate::expect::Expect;
use crate::handler::Client;
use crate::log::Log;
use crate::record::Recorder;
use crate::terminal;
use crate::terminal::interrupt::Interrupt;
use crate::terminal::termination::Termination;
use crate::terminal::text::Consoles;
use crate::terminal::watch::Resize;
use crate::zmodem::Zmodem;

pub(crate) mod beside;
mod busy;
mod feed;
mod input;
mod msg;
mod send;
mod transfer;

use beside::beside;
pub use feed::Feed;
pub use input::Input;
use msg::{handle_msg, write_out};
pub use send::WINDOW_STALL;
use send::{send, Also};
use transfer::zmodem_out;

/// How a session ended.
#[derive(Debug)]
pub enum End {
    /// The remote command's exit status (or 128 + a signal).
    Status(i32),
    /// The channel closed without an exit status.
    NoStatus,
    /// The connection went away under the session.
    Lost,
    /// The connection went away after the exit status and before the end of
    /// the output (the channel's EOF or Close): the bytes after the cut are
    /// lost, so the status is no success of the run (GitHub #84).
    Cut(i32),
    /// The user typed an escape that ends the session.
    Escaped(Command),
    /// podssh was told to stop (SIGTERM, SIGHUP).
    Terminated,
    /// `~d`: the far end keeps the shell under this name (T-158).
    Detached(String),
    /// Ctrl-C with no remote pty, and the command did not end by it (T-293).
    Interrupted,
}

/// The messages of a session's channel taken beside a wait on the session.
type Taken = beside::Backlog<ChannelMsg>;

/// What a user types while `--persist` connects again waits for the next
/// session, this much at most.
pub const QUEUE: usize = 64 * 1024;

/// How long the exit status may take once stdout's reader has gone (T-026):
/// the session then ends with it, or with none.
pub const STATUS_WAIT: Duration = Duration::from_secs(5);

/// The exit code of an `exit-status` request. A status above 255 gives 255:
/// OpenSSH passes the value to `exit()`, where 256 would read as a success.
pub fn status_code(exit_status: u32) -> i32 {
    i32::try_from(exit_status).unwrap_or(255).min(255)
}

/// How a session ends once it may: with its status, or with none. A closed
/// stdout and a Close both end so, whether the status came before or after.
pub fn end_with(status: Option<i32>) -> End {
    status.map(End::Status).unwrap_or(End::NoStatus)
}

/// How a session ends when its channel ends with the connection: a status
/// with the output's end (`eof`, before or after it) is the command's end; a
/// status alone is a cut, as a server may send it while the last output
/// still waits for the window (RFC 4254 orders them in no way); none is a
/// loss.
pub fn link_ended(status: Option<i32>, eof: bool) -> End {
    match status {
        Some(code) if eof => End::Status(code),
        Some(code) => End::Cut(code),
        None => End::Lost,
    }
}

/// Where a session's output goes in place of this process's stdout and
/// stderr (T-183): each piece as it came, and whether it is stderr's. One
/// process then runs several sessions, and the receiver says whose each
/// piece is. A receiver that is gone reads as a stdout whose reader went.
pub type Sink = tokio::sync::mpsc::Sender<(Vec<u8>, bool)>;

/// Whether stdout's reader has gone, and since when: the channel's data then
/// goes nowhere, the server hears the end of input, and the status is
/// awaited for a while, never read as a success.
#[derive(Default)]
struct Out {
    gone: Option<tokio::time::Instant>,
    told: bool,
    /// The server's EOF came: its output ended, and a lost link after it
    /// cuts nothing.
    eof: bool,
    /// The text of stdout and of stderr for a Windows console (T-294).
    consoles: Consoles,
    /// The sink in place of the process's streams, when there is one.
    sink: Option<Sink>,
}

/// What a session's output passes through on its way out: the filter of an
/// elevated command (T-032), ZMODEM (T-148), then the recording (T-033).
/// A detach that waits for the far end's answer reads the session's
/// messages too (T-158), and the expect rules read the output (T-191).
#[derive(Default)]
pub struct Through {
    pub elevated: Option<Elevated>,
    pub zmodem: Option<Zmodem>,
    pub record: Option<Recorder>,
    pub detaching: crate::keep::Detaching,
    /// Where the output goes in place of stdout and stderr (T-183).
    pub sink: Option<Sink>,
    /// What `~C` asks of the caller, when the session offers it (T-291).
    pub command_line: Option<crate::escape_command::Commands>,
    pub expect: Option<Expect>,
    /// The notice while the far end is silent (T-302).
    pub notice: Option<crate::notice::Notice>,
    /// SSH's own question, where the road asks none (T-332).
    pub asked: Option<Arc<crate::notice::Asked>>,
    /// Whether a channel's window shut for [`WINDOW_STALL`] ends the session
    /// (T-598): on a road that resumes no link (`--direct`); the resumable
    /// layer's own silence resumes the link, and a stall there is survived.
    pub window_stall: bool,
    /// The count of a kept shell's output that this client has (T-895).
    pub count: Option<crate::keep_count::Counter>,
}

impl Through {
    fn out(&mut self, data: &[u8], stderr: bool, log: &Log) -> Vec<u8> {
        let data = match self.elevated.as_mut() {
            Some(e) => e.feed(data, stderr),
            None => data.to_vec(),
        };
        // The expect rules wait for what the terminal shows.
        if let Some(x) = self.expect.as_mut() {
            x.feed(&data);
        }
        // A transfer takes its bytes off stdout, and adds podssh's words.
        let data = match self.zmodem.as_mut().filter(|_| !stderr) {
            Some(z) => z.output(&data, std::time::Instant::now()),
            None => data,
        };
        let data = self.recorded(data, log);
        // A notice of silence goes before the far end's next bytes (T-302).
        match self.notice.as_mut().map(|notice| notice.before_output(&data, stderr)) {
            Some(mut first) if !first.is_empty() => {
                first.extend_from_slice(&data);
                first
            }
            _ => data,
        }
    }

    /// What the terminal shows, into the recording.
    fn recorded(&mut self, data: Vec<u8>, log: &Log) -> Vec<u8> {
        if let Some(Err(e)) = self.record.as_mut().map(|r| r.output(&data)) {
            log.info(&format!("--record stopped: {e}"));
            self.record = None;
        }
        data
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn pump(
    handle: &Handle<Client>,
    channel: Channel<Msg>,
    early: Vec<ChannelMsg>,
    mut escapes: Option<Escapes>,
    pty: bool,
    input: &mut Input,
    mut through: Through,
    interrupt: Option<Interrupt>,
    log: &Arc<Log>,
) -> End {
    let own = channel.id();
    let (mut reader, writer) = channel.split();
    // The messages taken beside each wait on the session, handed on first:
    // russh's loop can wait on the pump to take one before it takes a write
    // of the pump (T-780).
    let mut aside = beside::Backlog::default();
    // A step that holds the pump 20 s, said at -v (T-780).
    let busy = busy::Busy::default();
    let _watching = busy.watch(log, handle.step(), own);
    let mark = || busy.mark();
    let mut status: Option<i32> = None;
    // A sink takes the bytes unchanged: its receiver knows where they go.
    let sink = through.sink.take();
    let consoles = if sink.is_some() { Consoles::default() } else { Consoles::of_this_process() };
    let mut out = Out { consoles, sink, ..Out::default() };
    // False once this session's input has ended, or its channel takes no more.
    let mut reading = input.open();
    // An elevated command's input waits for it to start (T-032); the
    // session's own input waits for the last expect rule (T-191).
    let mut held = through.elevated.is_some() || through.expect.is_some();
    for msg in early {
        if let Some(end) = handle_msg(msg, &mut status, &mut out, &mut through, log).await {
            return end;
        }
    }
    if let Some(e) = through.elevated.as_mut() {
        busy.at("the elevated command's start");
        beside(e.act(&writer, &mut held, !reading, log), &mut reader, &mut aside, &mark).await;
    }
    if !reading && !held {
        busy.at("the end of the input");
        let _ = beside(writer.eof(), &mut reader, &mut aside, &mark).await;
    }
    let mut resize = Resize::new(pty);
    let mut stop = Termination::new(pty && terminal::raw_active(), interrupt).fed(input.feed());
    // The forwards of `~C` -L and -D, served while the session lasts (T-291).
    let mut added = escape_run::Added::default();
    // The keepalive that asks for a reply, while one waits (T-332).
    let mut ping: Option<Ping<'_>> = None;
    loop {
        busy.at("the pump's turn before its wait");
        beside(expected(&mut through, &writer, &mut held, !reading), &mut reader, &mut aside, &mark).await;
        let also = Also { stop: &mut stop, zmodem: Some((&mut *input, reading && !held)) };
        let channel = (&mut reader, &mut aside);
        let state = (&mut status, &mut out, &mut through);
        let zmodem = zmodem_out(&writer, channel, state, also, &busy, log);
        if let Err(end) = zmodem.await {
            return end;
        }
        let zmodem_at = through.zmodem.as_ref().and_then(Zmodem::deadline);
        let streaming = through.zmodem.as_ref().is_some_and(Zmodem::more);
        busy.idle();
        tokio::select! {
            chunk = input::next(input, reading && !held) => match chunk {
                Some(bytes) => {
                    busy.at("a send of the input");
                    let (data, commands) = match escapes.as_mut() {
                        Some(e) => e.feed(&bytes),
                        None => (bytes, Vec::new()),
                    };
                    // A question or a transfer of ZMODEM takes the keys.
                    let data = match through.zmodem.as_mut() {
                        Some(z) => z.keys(data, std::time::Instant::now()),
                        None => data,
                    };
                    if !data.is_empty() {
                        crate::outcome::stdin(data.len());
                        // A key on a pty holds the bulk until its echo (T-661).
                        if pty {
                            crate::pace::key();
                        }
                        let state = (&mut status, &mut out, &mut through);
                        let also = Also { stop: &mut stop, zmodem: None };
                        match send(&writer, (&mut reader, &mut aside), data, state, also, &busy, log).await {
                            Ok(true) => {}
                            // The channel is closing; keep reading for its status.
                            Ok(false) => reading = false,
                            Err(end) => return end,
                        }
                        // A question that the server answers at once (T-332).
                        if through.asked.as_ref().is_some_and(|a| a.key(ping.is_some())) {
                            ping = Some(Box::pin(handle.send_ping()));
                        }
                    }
                    for command in commands {
                        match command {
                            Command::Disconnect => return End::Escaped(command),
                            // The keys after `~C` in their read start its line.
                            Command::CommandLine => {
                                let first = escapes.as_mut().map(Escapes::take_rest).unwrap_or_default();
                                let caller = through.command_line.clone();
                                let line = escape_run::command_line(handle, input, first, caller, &mut added, log);
                                beside(line, &mut reader, &mut aside, &mark).await;
                            }
                            Command::Rekey => {
                                log.info("rekeying");
                                let _ = beside(handle.rekey_soon(), &mut reader, &mut aside, &mark).await;
                            }
                            Command::Help => {
                                if let Some(e) = &escapes {
                                    log.banner(&e.help());
                                }
                            }
                            Command::List => log.banner(&crate::tally::listing()),
                            Command::Detach => {
                                beside(through.detaching.ask(&writer, log), &mut reader, &mut aside, &mark).await;
                            }
                            Command::Zmodem => match through.zmodem.as_mut() {
                                Some(z) => z.escape(),
                                None => log.info("ZMODEM works in a session with a pty and a local terminal"),
                            },
                        }
                    }
                }
                None => {
                    // The terminal went while ZMODEM held its keys (T-859).
                    if through.zmodem.as_ref().is_some_and(Zmodem::busy) {
                        return transfer::hung_up(&mut through, log);
                    }
                    // The end waits for russh's loop to take it, and the loop
                    // can wait for the pump: the channel drains beside it.
                    busy.at("the end of the input");
                    reading = false;
                    if through.expect.is_some() {
                        let _ = beside(writer.data(&[EOF_KEY][..]), &mut reader, &mut aside, &mark).await;
                    } else {
                        let _ = beside(writer.eof(), &mut reader, &mut aside, &mark).await;
                    }
                }
            },
            msg = busy.polled(beside::next(&mut reader, &mut aside)) => match msg {
                Some(m) => {
                    busy.at("the output of the channel");
                    if pty && matches!(m, ChannelMsg::Data { .. }) {
                        crate::pace::echo();
                    }
                    if let Some(end) = handle_msg(m, &mut status, &mut out, &mut through, log).await {
                        return end;
                    }
                    if let Some(e) = through.elevated.as_mut() {
                        beside(e.act(&writer, &mut held, !reading, log), &mut reader, &mut aside, &mark).await;
                    }
                    // stdout's reader went: the server hears the end of input.
                    if out.gone.is_some() && !out.told {
                        out.told = true;
                        reading = false;
                        let _ = beside(writer.eof(), &mut reader, &mut aside, &mark).await;
                    }
                }
                None => return link_ended(status, out.eof),
            },
            () = sleep_until(out.gone.map(|at| at + STATUS_WAIT)), if out.gone.is_some() => {
                if status.is_none() {
                    log.info(&format!(
                        "stdout was closed, and no exit status came within {} s",
                        STATUS_WAIT.as_secs()
                    ));
                }
                return end_with(status);
            }
            missed = expecting(through.expect.as_ref()) => {
                log.error(&missed);
                return End::NoStatus;
            }
            expired = elevating(&mut through.elevated, &writer, log) => if expired {
                log.error(&through.elevated.as_ref().map(Elevated::expired).unwrap_or_default());
                // The far end closes the session, and its pty hangs up on su.
                let _ = beside(writer.close(), &mut reader, &mut aside, &mark).await;
                return End::NoStatus;
            },
            Some(size) = resize.next() => {
                busy.at("a change of the terminal's size");
                let change = writer.window_change(size.cols, size.rows, size.px_width, size.px_height);
                let _ = beside(change, &mut reader, &mut aside, &mark).await;
                if let Some(r) = through.record.as_mut() {
                    let _ = r.resize(size);
                }
            }
            // A wait of ZMODEM that ran out, and a sender's next bytes,
            // which the top of the loop sends.
            () = sleep_until(zmodem_at.map(Into::into)), if zmodem_at.is_some() => {
                if let Some(z) = through.zmodem.as_mut() {
                    z.tick(std::time::Instant::now());
                }
            }
            () = std::future::ready(()), if streaming => {}
            () = added.next() => {}
            () = answered(&mut ping), if ping.is_some() => {
                ping = None;
                if let Some(asked) = &through.asked {
                    asked.heard();
                }
            }
            // The notice of a silent far end: its title, or its line (T-302).
            action = crate::notice::next(through.notice.as_mut()) => match action {
                crate::notice::Action::Write(bytes) => {
                    busy.at("the notice of a silent far end");
                    let mut stdout = tokio::io::stdout();
                    let _ = stdout.write_all(&bytes).await;
                    let _ = stdout.flush().await;
                }
                crate::notice::Action::Say(line) => log.info(&line),
            },
            stopped = stop.next() => {
                busy.at("a signal");
                if let Some(end) = beside(stop.act(stopped, &writer, log), &mut reader, &mut aside, &mark).await {
                    return end;
                }
            }
        }
    }
}

/// An elevated command's question and time (T-032): true when its time is
/// up; for ever with none.
async fn elevating(elevated: &mut Option<Elevated>, writer: &ChannelWriteHalf<Msg>, log: &Log) -> bool {
    match elevated {
        Some(e) => e.next(writer, log).await,
        None => std::future::pending().await,
    }
}

/// The end of input of a session with expect rules (T-191): the terminal's
/// end of file, Ctrl-D, in the pty's own stream after the keys before it. A
/// channel's EOF there let Dropbear close the pty and hang up the shell
/// before it had read the last rule's keys (exit 129 for `exit 4`).
const EOF_KEY: u8 = 0x04;

/// The keys of each expect rule that matched; then, once the last rule sent
/// its keys, the session's own input, and its end when it has ended (T-191).
async fn expected(through: &mut Through, writer: &ChannelWriteHalf<Msg>, held: &mut bool, ended: bool) {
    let Some(x) = through.expect.as_mut() else { return };
    let keys = x.take();
    if !keys.is_empty() {
        let _ = writer.data(&keys[..]).await;
    }
    if x.done() && *held {
        *held = false;
        if ended {
            let _ = writer.data(&[EOF_KEY][..]).await;
        }
    }
}

/// Until the expect rule that waits runs out of time: the words of its
/// miss; for ever with none (T-191).
async fn expecting(expect: Option<&Expect>) -> String {
    match expect {
        Some(x) => x.missed().await,
        None => std::future::pending().await,
    }
}

/// A keepalive that asks for a reply, as russh sends it (T-332).
type Ping<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), russh::Error>> + Send + 'a>>;

/// Until the server replies to the keepalive; for ever with none. A reply
/// of failure, from a server that knows no such request, is a reply too.
async fn answered(ping: &mut Option<Ping<'_>>) {
    match ping {
        Some(ping) => {
            let _ = ping.as_mut().await;
        }
        None => std::future::pending().await,
    }
}

/// Until `at`, or for ever with none.
async fn sleep_until(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
