//! The 7-bit envelope in a session (T-831): the near end of
//! `pod_term::transfer`, for a far `podssh tx` whose path to the pty
//! repaints its output (tmux drops ZMODEM's ZDLE). Its scan of the
//! server's output comes before ZMODEM's: a trigger whose CRC holds starts
//! a question, as `sz` and `rz` start one, and the trigger's line never
//! shows. Then the codec runs the frames; a file that comes goes as T-134
//! writes a copy (a temporary name beside it, then SHA-256 and the size,
//! then the rename), and one that goes is read at each offset that the
//! codec asks. The session's pump gives it nothing of its own: the output,
//! the keys and the time come through [`Zmodem`], and its frames go with
//! [`Zmodem::take`] under the same write limit. The codec's version 2
//! answers alone a frame that comes again while a person answers (`HOLD`),
//! and a `DONE` that comes again after `KEPT` (its verdict, for
//! `transfer::LINGER`); the scan of the output and the ticks go on for it.

use std::collections::VecDeque;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Instant;

use pod_term::transfer::{self, stop, Dir, Ended, Event, Transfer};

use super::super::ask::{Answer, Question};
use super::super::files::{self, Incoming};
use super::super::receive::Offer;
use super::acts::{shown, yes, Gauge};
use super::{typed_path, Zmodem};

/// What the envelope hands the session, in order.
pub(super) enum Piece {
    /// The server's output: ZMODEM's scan reads it, then the terminal.
    Output(Vec<u8>),
    /// podssh's own words, for the terminal.
    Words(Vec<u8>),
    /// A transfer ended; `stopped` when no file ended whole.
    Ended { stopped: bool },
}

/// What an open question is about.
enum About {
    /// The far end sends: where the file goes.
    Download,
    /// The far end receives: the file to send.
    Upload,
    /// The offered file's name is taken here: replace it?
    Replace(Offer, String),
}

/// The file that goes, read at each offset that the codec asks.
struct Sending {
    file: File,
    name: String,
    size: u64,
}

/// The near end of the envelope in one session.
pub(super) struct Envelope {
    codec: Transfer,
    question: Option<(Question, About)>,
    /// The directory of the download's answer.
    into: PathBuf,
    incoming: Option<Incoming>,
    sending: Option<Sending>,
    /// The file that a download kept under its name, and its size.
    kept: Option<(PathBuf, u64)>,
    gauge: Gauge,
    /// Frames that came damaged and went again: a count, not a line each.
    damaged: u64,
    pieces: Vec<Piece>,
}

impl Envelope {
    pub(super) fn new() -> Envelope {
        Envelope {
            codec: Transfer::near(),
            question: None,
            into: PathBuf::new(),
            incoming: None,
            sending: None,
            kept: None,
            gauge: Gauge::default(),
            damaged: 0,
            pieces: Vec::new(),
        }
    }

    /// Whether a question is open or a transfer runs: the keys are its.
    pub(super) fn busy(&self) -> bool {
        self.question.is_some() || self.codec.active()
    }

    /// Whether a transfer that the user accepted runs: its keys, its limit
    /// and its end then hold each wait of the pump.
    pub(super) fn transferring(&self) -> bool {
        self.question.is_none() && self.codec.active()
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        self.codec.deadline()
    }

    /// The frames for the server. The codec times its answer from here.
    pub(super) fn poll(&mut self, now: Instant) -> Vec<u8> {
        self.codec.poll_output(now)
    }

    /// The server's output.
    pub(super) fn output(&mut self, data: &[u8], now: Instant, dir: &Path) -> Vec<Piece> {
        let events = self.codec.feed(data, now);
        self.run(events, now, dir);
        std::mem::take(&mut self.pieces)
    }

    /// Keys while [`Envelope::busy`]: a question takes each; a transfer
    /// drops them, and Ctrl-C or five CAN stop it (the codec's rule).
    pub(super) fn keys(&mut self, keys: &[u8], now: Instant, dir: &mut PathBuf) -> Vec<Piece> {
        if let Some((question, _)) = self.question.as_mut() {
            let (echo, answer) = question.keys(keys);
            self.words(&echo);
            let taken = if answer.is_some() { self.question.take() } else { None };
            if let (Some(answer), Some((_, about))) = (answer, taken) {
                self.answered(about, answer, now, dir);
            }
        } else {
            // Nothing passes once the user accepted: keys would land in the frames.
            let _ = self.codec.keys(keys, now);
        }
        let events = self.codec.events();
        self.run(events, now, dir);
        std::mem::take(&mut self.pieces)
    }

    /// The time: a held trigger shows, a frame goes again, or a wait ends.
    pub(super) fn tick(&mut self, now: Instant, dir: &Path) -> Vec<Piece> {
        let events = self.codec.tick(now);
        self.run(events, now, dir);
        std::mem::take(&mut self.pieces)
    }

    /// The transfer ends here: the write's limit, or the local terminal
    /// went. A question goes with it; `STOP` tells the far end.
    pub(super) fn stop(&mut self, why: &str, now: Instant, dir: &Path) -> Vec<Piece> {
        self.question = None;
        self.codec.stop(stop::CANCELLED, why);
        let events = self.codec.events();
        self.run(events, now, dir);
        std::mem::take(&mut self.pieces)
    }

    /// The events, and those of each act that they cause, in order.
    fn run(&mut self, events: Vec<Event>, now: Instant, dir: &Path) {
        let mut queue: VecDeque<Event> = events.into();
        while let Some(event) = queue.pop_front() {
            self.event(event, now, dir);
            queue.extend(self.codec.events());
        }
    }

    fn event(&mut self, event: Event, now: Instant, dir: &Path) {
        match event {
            Event::Show(bytes) => self.pieces.push(Piece::Output(bytes)),
            Event::Start { dir: Dir::Send, .. } => {
                self.damaged = 0;
                self.ask(download_question(dir), About::Download);
            }
            Event::Start { dir: Dir::Receive, .. } => {
                self.damaged = 0;
                self.ask(UPLOAD_QUESTION.to_string(), About::Upload);
            }
            Event::Unsupported { version } => self.say(&format!(
                "podssh tx on the server speaks version {version} of the envelope, and this podssh version {}; \
                 nothing was sent",
                transfer::VERSION
            )),
            Event::Offer { name, size, mode, mtime } => self.offered(Offer { name, size: Some(size), mtime, mode }),
            Event::NeedData { offset, max } => self.supply(offset, max),
            Event::Write { bytes, .. } => self.write(&bytes),
            Event::Progress { done, .. } => {
                let mut line = Vec::new();
                self.gauge.show(done, now, &mut line);
                self.words(&line);
            }
            Event::Damaged => self.damaged += 1,
            Event::Verified { size, .. } => self.verified(size),
            Event::End { ended, rest } => {
                self.ended(ended);
                if !rest.is_empty() {
                    self.pieces.push(Piece::Output(rest));
                }
            }
        }
    }

    fn ask(&mut self, prompt: String, about: About) {
        let (question, bytes) = Question::new(&format!("podssh: {prompt}"));
        self.words(&bytes);
        self.question = Some((question, about));
    }

    fn say(&mut self, text: &str) {
        self.words(format!("\r\x1b[Kpodssh: {text}\r\n").as_bytes());
    }

    /// podssh's words, joined to the last piece of them.
    fn words(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        match self.pieces.last_mut() {
            Some(Piece::Words(words)) => words.extend_from_slice(bytes),
            _ => self.pieces.push(Piece::Words(bytes.to_vec())),
        }
    }

    fn answered(&mut self, about: About, answer: Answer, now: Instant, dir: &mut PathBuf) {
        let line = match answer {
            Answer::Line(line) => Some(line),
            Answer::Refused => None,
        };
        match about {
            About::Download => {
                let Some(line) = line else {
                    self.codec.refuse("refused here");
                    return;
                };
                let chosen = if line.is_empty() { dir.clone() } else { typed_path(&line) };
                if !chosen.is_dir() {
                    self.say(&format!("{} is not a directory", chosen.display()));
                    self.ask(download_question(dir), About::Download);
                    return;
                }
                dir.clone_from(&chosen);
                self.into = chosen;
                self.codec.accept(now);
            }
            About::Upload => {
                let Some(path) = line.filter(|l| !l.is_empty()).map(|l| typed_path(&l)) else {
                    self.codec.refuse("refused here");
                    return;
                };
                match files::open_whole(&path) {
                    Ok((file, info)) => {
                        self.gauge.start(&info.name, Some(info.size));
                        self.sending = Some(Sending { file, name: info.name.clone(), size: info.size });
                        self.codec.send_file(info, now);
                    }
                    Err(why) => {
                        self.say(&why);
                        self.ask(UPLOAD_QUESTION.to_string(), About::Upload);
                    }
                }
            }
            About::Replace(offer, name) => {
                if line.is_some_and(|l| yes(&l)) {
                    self.open(offer, name, true);
                } else {
                    self.say(&format!("kept {}; the server's file was skipped", shown(&name)));
                    self.codec.skip(&format!("{name} exists here"));
                }
            }
        }
    }

    /// A file that the far end offers: its name is one that may be written
    /// here (the codec checked its component, `check_name` this platform's
    /// rules), and a name that is taken is replaced only after `y`.
    fn offered(&mut self, offer: Offer) {
        let name = match files::check_name(&offer.name) {
            Ok(name) => name,
            Err(why) => {
                self.say(&format!("skipped a file: {why}"));
                self.codec.skip("its name cannot be written here");
                return;
            }
        };
        let dest = self.into.join(&name);
        match std::fs::symlink_metadata(&dest) {
            Ok(meta) if meta.is_dir() => {
                self.say(&format!("skipped {}: {} is a directory", shown(&name), dest.display()));
                self.codec.skip(&format!("{name} is a directory here"));
            }
            Ok(_) => {
                let question = format!("{} exists. Replace it? [y/N] ", shown(&dest.display().to_string()));
                self.ask(question, About::Replace(offer, name));
            }
            Err(_) => self.open(offer, name, false),
        }
    }

    fn open(&mut self, offer: Offer, name: String, replace: bool) {
        match Incoming::create(&self.into, &name, &offer, replace) {
            Ok(file) => {
                self.incoming = Some(file);
                self.gauge.start(&name, offer.size);
                self.codec.take();
            }
            Err(e) => {
                self.say(&format!("skipped {}: {}", shown(&name), files::cannot_create(&self.into, &e)));
                self.codec.skip(&format!("{name} cannot be written here"));
            }
        }
    }

    /// The bytes at `offset`, `max` at most: a short read of the file is no end.
    fn supply(&mut self, offset: u64, max: usize) {
        let Some(sending) = self.sending.as_mut() else {
            return self.codec.stop(stop::LOCAL, "no file to send");
        };
        let mut buf = vec![0u8; max];
        match files::read_at(&mut sending.file, offset, &mut buf) {
            Ok(n) => self.codec.supply(&buf[..n]),
            Err(e) => {
                let why = format!("{} could not be read: {e}", sending.name);
                self.codec.stop(stop::LOCAL, &why);
            }
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        let written = self.incoming.as_mut().map_or(Ok(()), |file| file.write(bytes));
        if let Err(e) = written {
            self.codec.stop(stop::LOCAL, &format!("the file could not be written: {e}"));
        }
    }

    /// The size and SHA-256 held: the copy gets its time, its mode and its
    /// name; only then does the far end hear `KEPT`.
    fn verified(&mut self, size: u64) {
        let Some(mut file) = self.incoming.take() else { return };
        match file.finish(size) {
            Ok(path) => {
                self.kept = Some((path, size));
                self.codec.kept();
            }
            Err(why) => {
                self.say(&shown(&why));
                // The far end hears no path of this host.
                self.codec.stop(stop::LOCAL, "the file could not be kept here");
            }
        }
    }

    fn ended(&mut self, ended: Ended) {
        self.gauge.stop();
        // An end that comes while a question is open answers it.
        self.question = None;
        // A file that did not end is removed with it.
        let unfinished = self.incoming.take().map(|file| shown(&file.name));
        let sending = self.sending.take();
        let damaged = match self.damaged {
            0 => String::new(),
            n => format!("; {n} damaged frames went again"),
        };
        let stopped = matches!(ended, Ended::Stopped { .. });
        match ended {
            Ended::Done => match (self.kept.take(), sending) {
                (Some((path, size)), _) => {
                    let path = shown(&path.display().to_string());
                    self.say(&format!("received {path} ({size} bytes, SHA-256 checked{damaged})"));
                }
                (None, Some(s)) => {
                    let name = shown(&s.name);
                    self.say(&format!("sent {name} ({} bytes, SHA-256 checked by the server{damaged})", s.size));
                }
                (None, None) => {}
            },
            // The file and its SHA-256 went, and `KEPT` did not come: no
            // failure, as the server can have kept it.
            Ended::Unconfirmed => {
                let (name, size) = sending.map_or((String::new(), 0), |s| (shown(&s.name), s.size));
                self.say(&format!("sent {name} ({size} bytes{damaged}); the server did not confirm that it kept it"));
            }
            Ended::Stopped { by_peer, reason, .. } => {
                if let Some(name) = unfinished {
                    self.say(&format!("{name}: the transfer ended before the end of the file, and nothing was kept"));
                }
                let who = if by_peer { "podssh tx on the server: " } else { "" };
                self.say(&format!("tx: {who}{}", shown(&reason)));
            }
        }
        self.kept = None;
        self.pieces.push(Piece::Ended { stopped });
    }
}

impl Zmodem {
    /// The server's output through the envelope first (T-831): what it does
    /// not take goes on to ZMODEM.
    pub(super) fn enveloped(&mut self, data: &[u8], now: Instant) {
        let pieces = self.envelope.output(data, now, &self.dir);
        self.pieces(pieces, now);
    }

    /// The envelope's pieces, in order: output for ZMODEM and the terminal,
    /// podssh's words, and an end that drops a write that waits.
    pub(super) fn pieces(&mut self, pieces: Vec<Piece>, now: Instant) {
        for piece in pieces {
            match piece {
                Piece::Output(bytes) => self.zmodem_output(&bytes, now),
                Piece::Words(bytes) => self.screen.extend(bytes),
                // What still waits to go is no use to the far end: `STOP` goes next.
                Piece::Ended { stopped } => {
                    if stopped && self.writing.is_some() {
                        self.abandon = true;
                    }
                }
            }
        }
    }
}

fn download_question(dir: &Path) -> String {
    format!(
        "the server sends a file through the terminal (podssh tx send). Receive into {}? Enter takes it, a path \
         changes it, Ctrl-C refuses: ",
        dir.display()
    )
}

const UPLOAD_QUESTION: &str = "the server waits for a file through the terminal (podssh tx receive). Send which \
                               file? Enter with no name, or Ctrl-C, refuses: ";
