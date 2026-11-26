//! Local echo for a far end with a high round trip (T-160): `--predict`
//! shows each typed key at once, underlined, where the far end will echo
//! it, and takes the guess off when the far end's own echo comes. Through
//! the relay at 300 ms, a key otherwise shows 300 ms late.
//!
//! The client keeps a model of the far end's screen (`vt100`, the model of
//! the terminal oracle of T-200), which reads each byte of the far end's
//! output and nothing else. The guesses are drawn over the terminal and
//! taken off before each of the far end's bytes ([`draw`]); what they are,
//! and when they show, is [`engine`]'s. Only a far end that tells which
//! keys reached its pty, and whether the pty echoes, can be guessed for:
//! `podssh serve` with a pty, asked with `env predict@podssh v1`
//! ([`report`]). Another server refuses the request, and nothing shows.
//!
//! With the frames of the far end's screen (T-303), the model reads what
//! the frames draw on the terminal in place of the far end's bytes, and the
//! guesses are drawn over that screen, as Mosh's overlay: the far end sends
//! each report after the frame of the output read before it.
//!
//! A line of podssh's own on the terminal (a message, `~?`, ZMODEM's
//! words) moves the terminal's cursor where the model does not know it:
//! local echo then stops for the session, as a guess drawn after it could
//! land anywhere.

use std::num::NonZeroU16;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use russh::client::Msg;
use russh::{Channel, ChannelMsg};
use tokio::io::AsyncWriteExt;

use crate::notice::Boundary;
use crate::terminal::Size;

pub(crate) mod draw;
pub(crate) mod engine;
mod keys;
pub mod report;

pub use engine::{HIDE_BELOW, PASTE, SHOW_FROM};
pub use report::{ECHO_WAIT, ENV, EXT, VERSION};

/// Each write of podssh's own to the terminal, counted: local echo stops
/// when the count moves under it.
static OWN_WRITES: AtomicU64 = AtomicU64::new(0);

/// podssh writes to the terminal itself (a log line, a banner): the
/// model no longer knows where the terminal's cursor is.
pub fn own_write() {
    OWN_WRITES.fetch_add(1, Ordering::Relaxed);
}

/// The count of podssh's own writes to the terminal so far: the frames of
/// the far end's screen draw the whole screen again when it moved (T-303).
pub(crate) fn own_writes() -> u64 {
    OWN_WRITES.load(Ordering::Relaxed)
}

/// Local echo for one session: the model of the far end's screen, the
/// guesses, and what is drawn now.
pub struct Predict {
    model: vt100::Parser,
    boundary: Boundary,
    engine: engine::Engine,
    reports: report::Reports,
    shown: Option<draw::Shown>,
    own: u64,
}

fn dim(n: u32) -> NonZeroU16 {
    NonZeroU16::new(u16::try_from(n).unwrap_or(u16::MAX)).unwrap_or(NonZeroU16::MIN)
}

impl Predict {
    /// For a terminal of `cols` by `rows` whose round trip to the far end
    /// measured `rtt`; the far end's screen is empty at first, as a new
    /// shell's terminal is.
    pub fn new(cols: u32, rows: u32, rtt: Duration) -> Predict {
        Predict {
            model: vt100::Parser::new(dim(rows), dim(cols), 0),
            boundary: Boundary::default(),
            engine: engine::Engine::new(rtt),
            reports: report::Reports::default(),
            shown: None,
            own: OWN_WRITES.load(Ordering::Relaxed),
        }
    }

    /// For this process's terminal.
    pub fn for_terminal(rtt: Duration) -> Predict {
        let size = crate::terminal::size().unwrap_or_else(crate::terminal::fallback_size);
        Predict::new(size.cols, size.rows, rtt)
    }

    /// Whether local echo has stopped for this session.
    pub fn stopped(&self) -> bool {
        self.engine.stopped()
    }

    /// The row of the cursor as the model shows it.
    fn line(&self) -> engine::Line {
        let screen = self.model.screen();
        let (rows, cols) = screen.size();
        let (row, cursor) = screen.cursor_position();
        let cells = (0..cols.get())
            .map(|col| match screen.cell(row.min(rows.get() - 1), col) {
                Some(c) if c.is_wide() || c.is_wide_continuation() => None,
                Some(c) => Some(c.contents().to_string()),
                None => Some(String::new()),
            })
            .collect();
        engine::Line { row, cursor, cols: cols.get(), cells, hidden_cursor: screen.hide_cursor() }
    }

    /// A write of podssh's own came since the last step: stop, and forget
    /// what is drawn, whose place is no longer known. Each step asks first;
    /// after it, nothing is drawn or taken off.
    fn moved_under(&mut self) {
        let now = OWN_WRITES.load(Ordering::Relaxed);
        if now != self.own {
            self.own = now;
            self.shown = None;
            self.engine.stop();
        }
    }

    /// Take off what is drawn.
    fn undo(&mut self) -> Vec<u8> {
        match self.shown.take() {
            Some(shown) => draw::undo(self.model.screen(), &shown),
            None => Vec::new(),
        }
    }

    /// Take off what is drawn, and draw what the guesses are now; never
    /// inside a sequence or a character of the far end that waits for its
    /// next byte.
    fn refresh(&mut self) -> Vec<u8> {
        let mut out = self.undo();
        if !self.boundary.at_ground() {
            return out;
        }
        if let Some((cells, cursor)) = self.engine.shown(&self.line()) {
            let (drawn, shown) = draw::draw(self.model.screen(), &cells, cursor);
            out.extend_from_slice(&drawn);
            self.shown = Some(shown);
        }
        out
    }

    /// `data` went to the far end at `now`: what the terminal shows of it.
    pub fn keys(&mut self, data: &[u8], now: Instant) -> Vec<u8> {
        self.moved_under();
        let line = self.line();
        self.engine.keys(data, &line, now);
        self.refresh()
    }

    /// The far end's output, for the terminal: the guesses off, the bytes,
    /// the guesses that still stand back on.
    pub fn output(&mut self, data: &[u8]) -> Vec<u8> {
        self.moved_under();
        // Stopped, with nothing drawn: the model is read no more.
        if self.engine.stopped() && self.shown.is_none() {
            return data.to_vec();
        }
        let mut out = self.undo();
        out.extend_from_slice(data);
        self.model.process(data);
        self.boundary.feed(data);
        let line = self.line();
        self.engine.output(&line);
        out.extend(self.refresh());
        out
    }

    /// The far end's report bytes at `now`: what changes on the terminal.
    pub fn report(&mut self, bytes: &[u8], now: Instant) -> Vec<u8> {
        self.moved_under();
        match self.reports.feed(bytes) {
            Ok(reports) => {
                for report in reports {
                    let line = self.line();
                    self.engine.report(report, &line, now);
                }
                self.refresh()
            }
            Err(_) => self.stop(),
        }
    }

    /// The terminal has a new size: the guesses go, as the terminal may
    /// have moved its rows.
    pub fn resize(&mut self, cols: u32, rows: u32) -> Vec<u8> {
        self.moved_under();
        let out = self.undo();
        self.model.set_size(dim(rows), dim(cols));
        self.engine.reset();
        out
    }

    /// Stop local echo for this session; what the terminal needs to show
    /// the far end's screen alone.
    pub fn stop(&mut self) -> Vec<u8> {
        self.moved_under();
        let out = self.undo();
        self.engine.stop();
        out
    }
}

/// Whether a session asks its far end for local echo: `--predict`, a shell
/// or a command on a pty, with this process's own terminal on each side,
/// and nothing else that sends keys or takes the output.
pub(crate) fn wanted(opts: &crate::options::Options, want_pty: bool, stdin_tty: bool) -> bool {
    use crate::options::Request;
    opts.predict
        && want_pty
        && stdin_tty
        && crate::terminal::stdout_is_terminal()
        && matches!(opts.request, Request::Shell | Request::Exec(_))
        && opts.expect.is_none()
        && opts.elevate.is_none()
        && opts.output.is_none()
        && opts.feed.is_none()
}

/// Whether this terminal reads the moves that the guesses are drawn with
/// (`CSI C`, `CSI D`, `CSI X`, an underline): a Windows console only in its
/// VT mode, which raw mode asks for and an old console refuses (T-896).
/// Else no guess shows, and -v says why.
pub(crate) fn drawable(log: &crate::log::Log) -> bool {
    if crate::terminal::vt_output() {
        return true;
    }
    log.verbose("--predict: no local echo: this console takes no VT sequences, which the guesses are drawn with");
    false
}

/// Ask the far end for its reports, before the shell or the command; the
/// time of the ask, for the round trip, or `None` when it could not go.
pub(crate) async fn ask(channel: &Channel<Msg>) -> Option<Instant> {
    let at = Instant::now();
    channel.set_env(true, ENV, VERSION).await.ok().map(|()| at)
}

/// The far end's answer to [`ask`], which comes after the pty's: the round
/// trip when it gives reports. A refusal says why at -v.
pub(crate) async fn answered(
    channel: &mut Channel<Msg>,
    early: &mut Vec<ChannelMsg>,
    at: Option<Instant>,
    log: &crate::log::Log,
) -> Result<Option<Duration>, String> {
    let Some(at) = at else { return Ok(None) };
    if crate::session::wait_reply(channel, early).await? {
        return Ok(Some(at.elapsed()));
    }
    log.verbose("--predict: no local echo: the far end gives none (only podssh serve with a pty does)");
    Ok(None)
}

/// Write what local echo shows, at once.
async fn show(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let mut out = tokio::io::stdout();
    let _ = out.write_all(bytes).await;
    let _ = out.flush().await;
}

/// Keys went to the far end: their guesses, on the terminal now.
pub(crate) async fn typed(predict: Option<&mut Predict>, keys: &[u8]) {
    if let Some(p) = predict {
        show(&p.keys(keys, Instant::now())).await;
    }
}

/// A report of the far end, on extended data of [`EXT`].
pub(crate) async fn reported(predict: Option<&mut Predict>, bytes: &[u8]) {
    if let Some(p) = predict {
        show(&p.report(bytes, Instant::now())).await;
    }
}

/// The terminal took a new size.
pub(crate) async fn resized(predict: Option<&mut Predict>, size: Size) {
    if let Some(p) = predict {
        show(&p.resize(size.cols, size.rows)).await;
    }
}

/// podssh is about to write to the terminal itself (an escape's words): the
/// guesses go first, and local echo stops for the session.
pub(crate) async fn halted(predict: Option<&mut Predict>) {
    if let Some(p) = predict {
        show(&p.stop()).await;
    }
}
