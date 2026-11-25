//! The far end of the 7-bit envelope (T-831): `podssh tx send FILE` and
//! `podssh tx receive [DIR]`, typed in the shell of a session whose near end
//! is `podssh ssh`. It paints the trigger, sets its terminal raw with no
//! echo (as lrzsz does), and runs the far role of `pod_term::transfer` on
//! stdin and stdout until the file is kept or the transfer stops. Each byte
//! that it writes is printable ASCII, CR or LF, so a terminal between it and
//! the session's pty (tmux) paints the frames, and the near end reads them
//! back from the paint. It needs no second channel: nothing listens, and
//! nothing connects. A receiver stays after its file is kept while the
//! codec keeps its verdict (`LINGER`, the codec's version 2): the pty can
//! lose `KEPT`, and a `DONE` that comes again gets it again.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Instant;

use pod_term::transfer::{stop, Ended, Event, Transfer, LINGER, WAIT};

use super::files::{self, Incoming};
use super::receive::Offer;
use crate::terminal::{self, RawMode};

/// The narrowest terminal: the trigger's line, 39 bytes, never wraps.
pub const MIN_COLUMNS: u32 = 48;

/// The pause after each part of a frame. tmux, when its client falls
/// behind, skips to a redraw of the screen as it is at the end: the lines
/// that scrolled off before it, a frame's head among them, are never
/// painted (measured through tmux 3.4, T-831). A frame goes in parts of half
/// the pane, each given time to be painted, so a skip over two parts still
/// leaves both on the screen it redraws.
const PACE: std::time::Duration = std::time::Duration::from_millis(40);

/// Why the far end kept no file, in one line each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// No terminal, one too narrow, or a word that is wrong.
    Usage(String),
    /// The file to send, or the directory to receive into, cannot be read.
    NoInput(String),
    /// The file that came cannot be written or kept here.
    CantCreate(String),
    /// The size or the SHA-256 differs, or the other end broke the protocol.
    Data(String),
    /// Refused, skipped, cancelled, or no answer in time.
    Stopped(String),
}

/// `podssh tx send FILE`: the near end receives FILE. The line of the end.
pub fn send(path: &Path) -> Result<String, Failure> {
    let (file, info) = files::open_whole(path).map_err(Failure::NoInput)?;
    let (name, size) = (info.name.clone(), info.size);
    let screen = check_terminal()?;
    let codec = Transfer::far_send(info, rand::random::<u64>().to_be_bytes(), Instant::now());
    let mut far = Far::new(codec, PathBuf::new());
    far.sending = Some((file, name.clone()));
    if far.drive(screen)? {
        Ok(format!("sent {} ({size} bytes, SHA-256 checked by the other end)", shown(&name)))
    } else {
        // The file and its SHA-256 went; `KEPT` did not come back. No failure.
        Ok(format!("sent {} ({size} bytes); the other end did not confirm that it kept it", shown(&name)))
    }
}

/// `podssh tx receive [DIR]`: the near end sends a file of its choice into
/// DIR. A name that DIR has is never replaced. The line of the end.
pub fn receive(dir: &Path) -> Result<String, Failure> {
    if !dir.is_dir() {
        return Err(Failure::NoInput(format!("{} is not a directory", dir.display())));
    }
    let screen = check_terminal()?;
    let codec = Transfer::far_receive(rand::random::<u64>().to_be_bytes(), Instant::now());
    let mut far = Far::new(codec, dir.to_path_buf());
    far.drive(screen)?;
    let (path, size) = far.kept.take().unwrap_or_default();
    Ok(format!("received {} ({size} bytes, SHA-256 checked)", shown(&path.display().to_string())))
}

/// The terminal's columns and rows, when stdin and stdout are a terminal
/// wide enough.
fn check_terminal() -> Result<(u32, u32), Failure> {
    if !terminal::stdin_is_terminal() || !terminal::stdout_is_terminal() {
        return Err(Failure::Usage(
            "stdin and stdout must be a terminal: run it in the shell of a podssh ssh session".to_string(),
        ));
    }
    // A terminal that gives no size is taken as the common 80 by 24.
    let (cols, rows) = terminal::size().map_or((80, 24), |size| (size.cols, size.rows));
    if cols < MIN_COLUMNS {
        return Err(Failure::Usage(format!(
            "the terminal is {cols} columns wide, and the trigger's line needs {MIN_COLUMNS}"
        )));
    }
    Ok((cols, rows))
}

/// One far end, its codec and its file.
struct Far {
    codec: Transfer,
    /// The file that goes, and its name.
    sending: Option<(File, String)>,
    /// Where the file that comes goes.
    dir: PathBuf,
    /// The lines of each part of a frame: half the pane ([`PACE`]).
    pace: usize,
    incoming: Option<Incoming>,
    kept: Option<(PathBuf, u64)>,
    /// A failure of this end, said in place of the reason that went in `STOP`.
    failure: Option<Failure>,
}

impl Far {
    fn new(codec: Transfer, dir: PathBuf) -> Far {
        Far { codec, sending: None, dir, pace: 12, incoming: None, kept: None, failure: None }
    }

    /// The transfer, on a raw terminal, until its end and the end of its
    /// verdict: `true` when the receiver confirmed the file.
    fn drive(&mut self, (width, rows): (u32, u32)) -> Result<bool, Failure> {
        self.codec.set_width(width as usize);
        self.pace = (rows as usize / 2).max(1);
        let raw = RawMode::enter().map_err(|e| Failure::Usage(format!("the terminal cannot be made raw: {e}")))?;
        let input = reader();
        let mut out = std::io::stdout().lock();
        let mut events = Vec::new();
        let ended = loop {
            if let Some(ended) = self.run(std::mem::take(&mut events)) {
                // The last frame (KEPT, SKIP, STOP) goes before the end.
                let _ = put(&mut out, &self.codec.poll_output(Instant::now()), self.pace);
                break ended;
            }
            // A codec with no session would wait for nothing: never loop on it.
            if !self.codec.active() {
                break Ended::Stopped { code: stop::CANCELLED, by_peer: false, reason: "the terminal went".into() };
            }
            if put(&mut out, &self.codec.poll_output(Instant::now()), self.pace).is_err() {
                // The terminal went: nobody reads the frames.
                self.codec.hangup();
                events = self.codec.events();
                continue;
            }
            let now = Instant::now();
            let wait = self.codec.deadline().map_or(WAIT, |due| due.saturating_duration_since(now));
            events = match input.recv_timeout(wait) {
                Ok(Some(bytes)) => self.codec.feed(&bytes, Instant::now()),
                // stdin ended: the session's pty went.
                Ok(None) | Err(RecvTimeoutError::Disconnected) => {
                    self.codec.hangup();
                    self.codec.events()
                }
                Err(RecvTimeoutError::Timeout) => self.codec.tick(Instant::now()),
            };
        };
        if ended == Ended::Done {
            self.linger(&input, &mut out);
        }
        drop(raw);
        match ended {
            Ended::Done => Ok(true),
            Ended::Unconfirmed => Ok(false),
            Ended::Stopped { code, by_peer, reason } => {
                Err(self.failure.take().unwrap_or_else(|| failure(code, by_peer, &reason)))
            }
        }
    }

    /// A receiver keeps its verdict for `LINGER` after `KEPT`, and answers
    /// a `DONE` that comes again with the same `KEPT`: the codec's rule. A
    /// sender keeps none, and goes at once. Ctrl-C or Ctrl-D from the near
    /// end, where its session ended and keys pass again, ends the wait.
    fn linger(&mut self, input: &Receiver<Option<Vec<u8>>>, out: &mut impl Write) {
        while self.codec.lingers() {
            let now = Instant::now();
            let wait = self.codec.deadline().map_or(LINGER, |due| due.saturating_duration_since(now));
            match input.recv_timeout(wait) {
                Ok(Some(bytes)) if bytes.iter().any(|&b| b == 0x03 || b == 0x04) => return,
                Ok(Some(bytes)) => {
                    self.codec.feed(&bytes, Instant::now());
                }
                Ok(None) | Err(RecvTimeoutError::Disconnected) => return,
                Err(RecvTimeoutError::Timeout) => {
                    self.codec.tick(Instant::now());
                }
            }
            if put(out, &self.codec.poll_output(Instant::now()), self.pace).is_err() {
                return;
            }
        }
    }

    /// The events, and those of each act that they cause, until an end.
    fn run(&mut self, events: Vec<Event>) -> Option<Ended> {
        let mut queue: VecDeque<Event> = events.into();
        while let Some(event) = queue.pop_front() {
            match event {
                Event::End { ended, .. } => return Some(ended),
                Event::Offer { name, size, mode, mtime } => self.offered(Offer { name, size: Some(size), mtime, mode }),
                Event::NeedData { offset, max } => self.supply(offset, max),
                Event::Write { bytes, .. } => {
                    if let Err(e) = self.incoming.as_mut().map_or(Ok(()), |file| file.write(&bytes)) {
                        let why = format!("the file could not be written: {e}");
                        self.fail(Failure::CantCreate(why), "the file could not be written there");
                    }
                }
                Event::Verified { size, .. } => self.verified(size),
                // The near end's events, the count and the progress: the
                // terminal shows the frames, and nothing else may go there.
                _ => {}
            }
            queue.extend(self.codec.events());
        }
        None
    }

    /// Stops the transfer for a failure of this end; the other end hears
    /// `peer`, with no path of this host.
    fn fail(&mut self, failure: Failure, peer: &str) {
        self.failure = Some(failure);
        self.codec.stop(stop::LOCAL, peer);
    }

    /// A file that the near end offers: a name that may be written here,
    /// and not taken.
    fn offered(&mut self, offer: Offer) {
        let name = match files::check_name(&offer.name) {
            Ok(name) => name,
            Err(why) => {
                self.failure = Some(Failure::Stopped(format!("skipped a file: {why}")));
                return self.codec.skip("its name cannot be written there");
            }
        };
        let dest = self.dir.join(&name);
        if std::fs::symlink_metadata(&dest).is_ok() {
            self.failure = Some(Failure::Stopped(format!("{} exists, and was not replaced", dest.display())));
            return self.codec.skip(&format!("{name} exists there"));
        }
        match Incoming::create(&self.dir, &name, &offer, false) {
            Ok(file) => {
                self.incoming = Some(file);
                self.codec.take();
            }
            Err(e) => {
                self.failure = Some(Failure::CantCreate(format!("{}: {e}", dest.display())));
                self.codec.skip(&format!("{name} cannot be written there"));
            }
        }
    }

    fn supply(&mut self, offset: u64, max: usize) {
        let Some((file, name)) = self.sending.as_mut() else {
            return self.codec.stop(stop::LOCAL, "no file to send");
        };
        let mut buf = vec![0u8; max];
        match files::read_at(file, offset, &mut buf) {
            Ok(n) => self.codec.supply(&buf[..n]),
            Err(e) => {
                let why = format!("{} could not be read: {e}", shown(name));
                self.fail(Failure::NoInput(why), "the file could not be read there");
            }
        }
    }

    /// The size and SHA-256 held: the copy gets its time, its mode and its
    /// name, and only then does the near end hear `KEPT`.
    fn verified(&mut self, size: u64) {
        let Some(mut file) = self.incoming.take() else { return };
        match file.finish(size) {
            Ok(path) => {
                self.kept = Some((path, size));
                self.codec.kept();
            }
            Err(why) => self.fail(Failure::CantCreate(why), "the file could not be kept there"),
        }
    }
}

/// A `STOP` read or sent, as this end's failure.
fn failure(code: u8, by_peer: bool, reason: &str) -> Failure {
    let line = if by_peer { format!("the other end stopped: {reason}") } else { reason.to_string() };
    match code {
        // A peer of another version of the codec breaks the protocol too.
        stop::DIFFERS | stop::PROTOCOL | stop::UNSUPPORTED => Failure::Data(line),
        _ => Failure::Stopped(line),
    }
}

/// The frames to the terminal, `pace` lines at a time with [`PACE`]
/// between the parts.
fn put(out: &mut impl Write, bytes: &[u8], pace: usize) -> std::io::Result<()> {
    let lines: Vec<&[u8]> = bytes.split_inclusive(|&b| b == b'\n').collect();
    for (i, part) in lines.chunks(pace.max(1)).enumerate() {
        if i > 0 {
            std::thread::sleep(PACE);
        }
        for line in part {
            out.write_all(line)?;
        }
        out.flush()?;
    }
    Ok(())
}

/// stdin, read on a thread of its own so that each wait has its limit: each
/// read, then `None` at its end.
fn reader() -> Receiver<Option<Vec<u8>>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let got = match stdin.read(&mut buf) {
                Ok(0) => None,
                Ok(n) => Some(buf[..n].to_vec()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => None,
            };
            let end = got.is_none();
            if tx.send(got).is_err() || end {
                return;
            }
        }
    });
    rx
}

/// A name or a path, made safe to print.
fn shown(text: &str) -> String {
    podssh_ws::text::one_line(text)
}
