//! [`Zmodem`]: ZMODEM in a session. It watches the server's output for the
//! start of `sz` or `rz` ([`super::detect`]), asks on the terminal, and then
//! runs one side of the protocol. Meanwhile the transfer's bytes stay off
//! the terminal; a question takes the keys, and during a transfer Ctrl-C
//! or five CAN stop it and each other key is dropped. The session's pump
//! gives it the output, the keys and the time, and takes what it has for
//! the terminal and for the server; it says when each write of those bytes
//! ends, so that a write that the server does not take ends the transfer at
//! its limit. The 7-bit envelope (T-831) scans the output first and shares
//! the question, the keys and the write limit (`session/envelope.rs`).

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::ask::{Answer, Question};
use super::detect::{Detector, Start};
use super::files::{self, Incoming};
use super::receive::{Offer, Receiver};
use super::send::Sender;
use super::wire::{self, Header};
use super::{CANCEL, TRIES, WAIT};

mod acts;
mod envelope;

use acts::{shown, yes, Gauge};
use envelope::Envelope;

/// What the session's pump takes: the bytes for the terminal, in order, and
/// those for the server.
#[derive(Debug, Default)]
pub struct Taken {
    pub screen: Vec<u8>,
    pub server: Vec<u8>,
}

struct Receiving {
    proto: Receiver,
    file: Option<Incoming>,
}

struct Sending {
    proto: Sender<File>,
    name: String,
}

/// What ZMODEM does in the session.
enum Mode {
    Idle,
    /// `~Z` chose a file and typed `rz`; its start is awaited until then.
    Armed {
        path: PathBuf,
        until: Instant,
    },
    Receive(Box<Receiving>),
    Send(Box<Sending>),
}

/// What an open question is about.
enum About {
    /// `sz` started: where the files go.
    Directory,
    /// The offered file's name is taken here: replace it?
    Replace(Offer, String),
    /// `rz` started: the file to send.
    Upload(Header),
    /// `~Z`: the file to send, before `rz` is typed.
    Escape,
}

/// ZMODEM in one session with a pty and a local terminal.
pub struct Zmodem {
    detect: Detector,
    mode: Mode,
    question: Option<(Question, About)>,
    screen: Vec<u8>,
    server: Vec<u8>,
    /// Where files come: the current directory, then the last answer.
    dir: PathBuf,
    gauge: Gauge,
    /// Since when the pump's write of [`Zmodem::take`]'s bytes waits.
    writing: Option<Instant>,
    /// The transfer ended, or its write ran out of time, while a write of
    /// its bytes waited: the pump drops the rest of that write.
    abandon: bool,
    /// How long a write may wait before the transfer ends: [`TRIES`] waits
    /// of [`WAIT`], the spec's "40 seconds total".
    limit: Duration,
    /// CAN typed in a row during a transfer: five end it, as five from the
    /// server do (7.2).
    cans: u8,
    /// The 7-bit envelope (T-831), whose scan comes before ZMODEM's.
    envelope: Envelope,
}

impl Default for Zmodem {
    fn default() -> Self {
        Zmodem::new()
    }
}

impl Zmodem {
    /// The watcher of a session: only when it has a pty and a local
    /// terminal, and `PODSSH_ZMODEM` is not `off`. With no terminal nothing
    /// is watched, so nothing is ever received.
    pub fn for_session(terminal: bool) -> Option<Zmodem> {
        let off = std::env::var("PODSSH_ZMODEM").is_ok_and(|v| v.trim().eq_ignore_ascii_case("off"));
        (terminal && !off).then(Zmodem::new)
    }

    /// A watcher, whatever the session: [`Zmodem::for_session`] decides
    /// when there is one.
    pub fn new() -> Zmodem {
        Zmodem {
            detect: Detector::new(),
            mode: Mode::Idle,
            question: None,
            screen: Vec::new(),
            server: Vec::new(),
            dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            gauge: Gauge::default(),
            writing: None,
            abandon: false,
            limit: WAIT * TRIES,
            cans: 0,
            envelope: Envelope::new(),
        }
    }

    /// The limit of a write that the server does not take, in place of 40 s:
    /// a test's far end that stops reading ends the transfer sooner.
    pub fn with_limit(mut self, limit: Duration) -> Zmodem {
        self.limit = limit;
        self
    }

    /// Whether a transfer runs: its keys, its limit and its end then hold
    /// each wait of the pump.
    pub fn transferring(&self) -> bool {
        matches!(self.mode, Mode::Receive(_) | Mode::Send(_)) || self.envelope.transferring()
    }

    /// The pump's write of the bytes of [`Zmodem::take`] ended, whole or
    /// dropped.
    pub fn written(&mut self) {
        self.writing = None;
        self.abandon = false;
    }

    /// Whether the pump drops the rest of the write that waits: the transfer
    /// of its bytes ended, or the write ran out of time.
    pub fn abandoned(&self) -> bool {
        self.abandon
    }

    /// The local terminal went (its input ended): nobody answers a question
    /// or sees a transfer, so each ends, and a file that did not end goes.
    /// The far side's `sz` or `rz` ends with the session's pty.
    pub fn hangup(&mut self, now: Instant) {
        if let Some((_, about)) = self.question.take() {
            // The offered file is skipped; the other questions opened nothing.
            if matches!(about, About::Replace(..)) {
                self.decide(false, now);
            }
        }
        if matches!(self.mode, Mode::Armed { .. }) {
            self.mode = Mode::Idle;
        }
        self.cancel("the local terminal went", now);
    }

    /// Whether a question is open, a transfer runs, or `rz` is awaited.
    pub fn busy(&self) -> bool {
        self.question.is_some() || !matches!(self.mode, Mode::Idle) || self.envelope.busy()
    }

    /// The server's output: what shows on the terminal, in order with
    /// podssh's own words.
    pub fn output(&mut self, data: &[u8], now: Instant) -> Vec<u8> {
        // The envelope reads first while ZMODEM runs nothing (T-831).
        if self.question.is_none() && matches!(self.mode, Mode::Idle | Mode::Armed { .. }) {
            self.enveloped(data, now);
        } else {
            self.zmodem_output(data, now);
        }
        std::mem::take(&mut self.screen)
    }

    /// The server's output for ZMODEM: its transfer's, or its scan's.
    fn zmodem_output(&mut self, data: &[u8], now: Instant) {
        // While a question is open, the far side waits; what it sends again
        // meanwhile (its start, once more) is dropped.
        if self.question.is_some() {
            return;
        }
        let acts = match &mut self.mode {
            Mode::Receive(r) => Some(r.proto.feed(data, now)),
            Mode::Send(s) => Some(s.proto.feed(data, now)),
            Mode::Idle | Mode::Armed { .. } => None,
        };
        match acts {
            Some(acts) => self.run(acts, now),
            None => self.scan(data, now),
        }
    }

    /// Keys: those that go on to the server. A question takes each key; a
    /// transfer drops them, and Ctrl-C stops it.
    pub fn keys(&mut self, keys: Vec<u8>, now: Instant) -> Vec<u8> {
        if let Some((question, _)) = self.question.as_mut() {
            let (echo, answer) = question.keys(&keys);
            self.screen.extend(echo);
            let taken = if answer.is_some() { self.question.take() } else { None };
            if let (Some(answer), Some((_, about))) = (answer, taken) {
                self.answered(about, answer, now);
            }
            return Vec::new();
        }
        if self.envelope.busy() {
            let pieces = self.envelope.keys(&keys, now, &mut self.dir);
            self.pieces(pieces, now);
            return Vec::new();
        }
        if !self.transferring() {
            self.cans = 0;
            return keys;
        }
        if keys.contains(&0x03) {
            self.cancel("cancelled here (Ctrl-C)", now);
            return Vec::new();
        }
        for &key in &keys {
            self.cans = if key == wire::CAN { self.cans + 1 } else { 0 };
            if self.cans >= 5 {
                self.cans = 0;
                self.cancel("cancelled here (CAN)", now);
                break;
            }
        }
        Vec::new()
    }

    /// `~Z`: ask for a file, then type `rz` on the server.
    pub fn escape(&mut self) {
        if self.busy() {
            self.say("a transfer runs already");
            return;
        }
        self.ask(ESCAPE_QUESTION.to_string(), About::Escape);
    }

    /// When [`Zmodem::tick`] is due.
    pub fn deadline(&self) -> Option<Instant> {
        let protocol = match &self.mode {
            _ if self.question.is_some() => None,
            Mode::Receive(r) => r.proto.deadline(),
            Mode::Send(s) => s.proto.deadline(),
            Mode::Armed { until, .. } => Some(*until),
            Mode::Idle => None,
        };
        let write = self.writing.map(|since| since + self.limit);
        [protocol, self.detect.deadline(), write, self.envelope.deadline()].into_iter().flatten().min()
    }

    /// The time: held bytes that were no start show, a wait of the protocol
    /// that ran out acts, and `rz` that did not start is given up.
    pub fn tick(&mut self, now: Instant) {
        let held = self.detect.flush(now);
        self.screen.extend(held);
        let pieces = self.envelope.tick(now, &self.dir);
        self.pieces(pieces, now);
        // A write that the server does not take holds no wait of the
        // protocol: a far end that stops reading sends no answer to time.
        if self.writing.is_some_and(|since| now >= since + self.limit) {
            self.writing = None;
            self.abandon = true;
            let why = format!("the server took nothing that podssh sent for {} s", self.limit.as_secs());
            if self.transferring() {
                self.cancel(&why, now);
            } else {
                self.say(&format!("ZMODEM: {why}; the rest was dropped"));
            }
            return;
        }
        if self.question.is_some() {
            return;
        }
        if matches!(&self.mode, Mode::Armed { until, .. } if now >= *until) {
            self.mode = Mode::Idle;
            self.say(&format!("rz did not start on the server within {} s; nothing was sent", WAIT.as_secs()));
            return;
        }
        let acts = match &mut self.mode {
            Mode::Receive(r) => r.proto.timeout(now),
            Mode::Send(s) => s.proto.timeout(now),
            Mode::Idle | Mode::Armed { .. } => return,
        };
        self.run(acts, now);
    }

    /// Whether a sender has more of its file to send now.
    pub fn more(&self) -> bool {
        self.question.is_none() && matches!(&self.mode, Mode::Send(s) if s.proto.streaming())
    }

    /// What waits for the terminal and for the server. A sender's next bytes
    /// are read here, when nothing else waits for the server. The pump says
    /// when its write of the server's bytes ends ([`Zmodem::written`]).
    pub fn take(&mut self, now: Instant) -> Taken {
        if self.server.is_empty() && self.more() {
            let acts = match &mut self.mode {
                Mode::Send(s) => s.proto.pull(now),
                _ => Vec::new(),
            };
            self.run(acts, now);
        }
        // The envelope's frames, under the same write limit (T-831).
        self.server.extend(self.envelope.poll(now));
        if !self.server.is_empty() {
            self.writing = Some(now);
            self.abandon = false;
        }
        Taken { screen: std::mem::take(&mut self.screen), server: std::mem::take(&mut self.server) }
    }

    fn scan(&mut self, data: &[u8], now: Instant) {
        let scan = self.detect.feed(data, now);
        self.screen.extend(scan.shown);
        if let Some(start) = scan.start {
            self.start(start, scan.rest, now);
        }
    }

    fn start(&mut self, start: Start, rest: Vec<u8>, now: Instant) {
        let armed = match std::mem::replace(&mut self.mode, Mode::Idle) {
            Mode::Armed { path, .. } => Some(path),
            _ => None,
        };
        match (start, armed) {
            // `sz -c` sends a command (ZCOMMAND in ZF0): never run here.
            (Start::Offer(header), _) if header.flags() == wire::ZCOMMAND => {
                self.server.extend_from_slice(CANCEL);
                self.say("the server asked to run a command here (sz -c), which podssh refuses");
            }
            (Start::Offer(_), _) => {
                let question = self.directory_question();
                self.ask(question, About::Directory);
            }
            (Start::Ready(header), Some(path)) => {
                self.upload(&path, &header, now);
                // What came after ZRINIT is the receiver's, for the sender.
                let acts = match &mut self.mode {
                    Mode::Send(s) if !rest.is_empty() => s.proto.feed(&rest, now),
                    _ => Vec::new(),
                };
                self.run(acts, now);
            }
            (Start::Ready(header), None) => self.ask(UPLOAD_QUESTION.to_string(), About::Upload(header)),
        }
    }

    fn directory_question(&self) -> String {
        format!(
            "the server sends by ZMODEM (sz). Receive into {}? Enter takes it, a path changes it, Ctrl-C refuses: ",
            self.dir.display()
        )
    }

    fn ask(&mut self, prompt: String, about: About) {
        let (question, bytes) = Question::new(&format!("podssh: {prompt}"));
        self.screen.extend(bytes);
        self.question = Some((question, about));
    }

    fn say(&mut self, text: &str) {
        self.screen.extend_from_slice(format!("\r\x1b[Kpodssh: {text}\r\n").as_bytes());
    }

    fn answered(&mut self, about: About, answer: Answer, now: Instant) {
        let line = match answer {
            Answer::Line(line) => Some(line),
            Answer::Refused => None,
        };
        match about {
            About::Directory => self.receive_into(line, now),
            About::Replace(offer, name) => {
                if line.is_some_and(|l| yes(&l)) {
                    self.open(offer, name, true, now);
                } else {
                    self.say(&format!("kept {}; the server's file was skipped", shown(&name)));
                    self.decide(false, now);
                }
            }
            About::Upload(header) => match line.filter(|l| !l.is_empty()).map(|l| typed_path(&l)) {
                Some(path) => match files::open(&path) {
                    Ok(_) => self.upload(&path, &header, now),
                    Err(why) => {
                        self.say(&why);
                        self.ask(UPLOAD_QUESTION.to_string(), About::Upload(header));
                    }
                },
                None => {
                    self.server.extend_from_slice(CANCEL);
                    self.say("nothing was sent, and rz on the server was cancelled");
                }
            },
            About::Escape => {
                let Some(path) = line.filter(|l| !l.is_empty()).map(|l| typed_path(&l)) else { return };
                match files::open(&path) {
                    Ok(_) => {
                        // "The sending program may send the string "rz\r" to
                        // invoke the receiving program from a possible command
                        // mode" (8.1).
                        self.server.extend_from_slice(b"rz\r");
                        self.mode = Mode::Armed { path, until: now + WAIT };
                    }
                    Err(why) => {
                        self.say(&why);
                        self.ask(ESCAPE_QUESTION.to_string(), About::Escape);
                    }
                }
            }
        }
    }

    fn receive_into(&mut self, line: Option<String>, now: Instant) {
        let Some(line) = line else {
            self.server.extend_from_slice(CANCEL);
            self.say("refused, and sz on the server was cancelled");
            return;
        };
        let dir = if line.is_empty() { self.dir.clone() } else { typed_path(&line) };
        if !dir.is_dir() {
            self.say(&format!("{} is not a directory", dir.display()));
            let question = self.directory_question();
            self.ask(question, About::Directory);
            return;
        }
        self.dir = dir;
        let (proto, acts) = Receiver::new(now);
        self.mode = Mode::Receive(Box::new(Receiving { proto, file: None }));
        self.run(acts, now);
    }

    fn upload(&mut self, path: &Path, header: &Header, now: Instant) {
        match files::open(path) {
            Ok((file, info)) => {
                let name = info.name.clone();
                self.gauge.start(&name, Some(info.size));
                let (proto, acts) = Sender::new(file, info, header, now);
                self.mode = Mode::Send(Box::new(Sending { proto, name }));
                self.run(acts, now);
            }
            Err(why) => {
                self.server.extend_from_slice(CANCEL);
                self.say(&format!("{why}; rz on the server was cancelled"));
            }
        }
    }
}

/// A path as typed: `~` at its start is the home directory, as a shell
/// reads it.
fn typed_path(line: &str) -> PathBuf {
    let home = || std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from);
    match (line.strip_prefix('~'), home()) {
        (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with(['/', '\\']) => {
            home.join(rest.trim_start_matches(['/', '\\']))
        }
        _ => PathBuf::from(line),
    }
}

const UPLOAD_QUESTION: &str =
    "the server waits for a file by ZMODEM (rz). Send which file? Enter with no name, or Ctrl-C, refuses: ";

const ESCAPE_QUESTION: &str =
    "send which file by ZMODEM? podssh types rz on the server. Enter with no name, or Ctrl-C, sends none: ";
