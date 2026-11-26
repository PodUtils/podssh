//! `--frames` through a control master (T-303). The master holds the
//! session's channel and writes its output to the terminal that the client
//! passed, so the master asks the far end for the frames and runs their
//! receiver; the client only says that it wants them.
//!
//! OpenSSH's protocol has no field for that, so podssh's two sides use the
//! places that it lets grow: the master names [`OFFER`] among the
//! extensions of its hello, which OpenSSH's client passes over, and a
//! client that read it puts the entry `frames@podssh=v1` (`v2` with
//! `--frames-scroll`) among the session's environment. The master takes
//! that entry out, so no server sees it as a variable. A client never sends
//! it to a master that did not offer: OpenSSH's master would pass it on as
//! a variable, and its channel writes no extended data but stderr's, so a
//! frame that came would show nothing.

use russh::client::Msg;
use russh::{Channel, ChannelMsg};
use tokio::io::AsyncWriteExt;

use super::afd::Passed;
use crate::frames::{Frames, Leave, Version};
use crate::options::{LogLevel, Options};

/// The name of the offer in the master's hello, and of the client's entry
/// in a session's environment: the name of the ask itself.
pub const OFFER: &str = crate::frames::ENV;

/// The line of a client whose master offers no frames: OpenSSH's, or a
/// podssh master before this release.
pub const NOT_OFFERED: &str = "--frames: no frames: the control master does not carry them (only a podssh master \
                               of this release or later does); the session shows each byte";

/// The word after the version in the entry of a client with `-q`.
const QUIET: &str = "quiet";

/// What a client asks of its master.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ask {
    /// `--frames-scroll`: version 2 first, then version 1.
    pub scroll: bool,
    /// The client's level is under INFO (`-q`): the master writes none of
    /// its lines about the frames to the client's terminal.
    pub quiet: bool,
}

impl Ask {
    /// The entry `NAME=VALUE` of the session's environment that carries it.
    pub fn entry(self) -> String {
        let version = if self.scroll { Version::Two } else { Version::One };
        match self.quiet {
            true => format!("{OFFER}={} {QUIET}", version.word()),
            false => format!("{OFFER}={}", version.word()),
        }
    }

    /// The ask of an entry's value; `None` for a value that names no
    /// version of this build, which then asks nothing.
    pub fn read(value: &str) -> Option<Ask> {
        let mut words = value.split(' ');
        let scroll = match Version::of(words.next()?)? {
            Version::Two => true,
            Version::One => false,
        };
        let quiet = words.any(|w| w == QUIET);
        Some(Ask { scroll, quiet })
    }

    /// Take each entry of [`OFFER`] out of a session's environment: the
    /// ask of the first, where it reads. The other entries keep their order.
    pub fn take(env: &mut Vec<String>) -> Option<Ask> {
        let mut ask = None;
        let mut first = true;
        env.retain(|entry| {
            let (name, value) = entry.split_once('=').unwrap_or((entry.as_str(), ""));
            if name != OFFER {
                return true;
            }
            if std::mem::take(&mut first) {
                ask = Ask::read(value);
            }
            false
        });
        ask
    }
}

/// The extension of the master's hello that offers frames.
pub fn offer() -> (String, String) {
    (OFFER.to_string(), Version::Two.word().to_string())
}

/// Whether a master's hello offers frames.
pub fn offered(extensions: &[(String, String)]) -> bool {
    extensions.iter().any(|(name, _)| name == OFFER)
}

/// What a client does with `--frames` through a master, from what it knows:
/// the line of a session that cannot show frames (as without a master),
/// whether it wants them, and whether its master offered them. `Ok(Some)`
/// is the entry to send; `Err` is one line, and the session shows each
/// byte.
pub fn decide(
    not_asked: Option<&'static str>,
    wanted: bool,
    offered: bool,
    ask: Ask,
) -> Result<Option<String>, &'static str> {
    if let Some(line) = not_asked {
        return Err(line);
    }
    if !wanted {
        return Ok(None);
    }
    if !offered {
        return Err(NOT_OFFERED);
    }
    Ok(Some(ask.entry()))
}

/// [`decide`] for a client's options: `tty` is whether it asks the master
/// for a pty, `level` its own level of messages.
pub fn for_client(
    opts: &Options,
    tty: bool,
    stdin_tty: bool,
    offered: bool,
    level: LogLevel,
) -> Result<Option<String>, &'static str> {
    let ask = Ask { scroll: opts.frames_scroll, quiet: level < LogLevel::Info };
    let not_asked = crate::frames::not_asked(opts, tty, stdin_tty);
    decide(not_asked, crate::frames::wanted(opts, tty, stdin_tty), offered, ask)
}

/// One line of the master's on the client's terminal, as the client's own
/// log writes it, unless the client is quiet.
async fn say(err: &mut Passed, ask: Ask, line: &str) {
    if !ask.quiet {
        let _ = err.write_all(crate::log::message_text(line, true, true).as_bytes()).await;
    }
}

/// Ask the far end for the frames of `ask`, before the session's request,
/// on a channel whose pty came: how many asks went. A session with no pty
/// asks none, and the client's terminal gets the line why.
pub(super) async fn ask(channel: &Channel<Msg>, ask: Option<Ask>, pty: bool, err: &mut Passed) -> usize {
    match ask {
        Some(a) if pty => crate::frames::ask(channel, a.scroll).await,
        Some(a) => {
            say(err, a, crate::frames::NO_TERMINAL).await;
            0
        }
        None => 0,
    }
}

/// The far end's replies to the `asked` asks, read before the session's
/// own reply, which comes after them: the frames to draw, or the line of
/// a refusal on the client's terminal. `Err` where the channel ended.
pub(super) async fn answered(
    channel: &mut Channel<Msg>,
    early: &mut Vec<ChannelMsg>,
    (asked, ask): (usize, Option<Ask>),
    err: &mut Passed,
) -> Result<Option<Framed>, String> {
    let Some(ask) = ask.filter(|_| asked > 0) else { return Ok(None) };
    match crate::frames::taken(channel, early, asked, ask.scroll).await? {
        Some(_) => Ok(Some(Framed { frames: Frames::default(), quiet: ask.quiet })),
        None => {
            say(err, ask, crate::frames::REFUSED).await;
            Ok(None)
        }
    }
}

/// The frames of one session through this master, drawn on the terminal
/// that its client passed.
pub(super) struct Framed {
    frames: Frames,
    quiet: bool,
}

impl Framed {
    /// What gives the client's terminal back, as the last frame left it.
    pub(super) fn leave(&self) -> Leave {
        self.frames.leave()
    }

    /// The terminal moved under the frames: a new size, the far end's
    /// stderr, or a line of the master's.
    pub(super) fn disturbed(&mut self) {
        self.frames.disturbed();
    }

    /// The acknowledgement that is due, as the value of `frames::ACK`.
    pub(super) fn take_ack(&mut self) -> Option<String> {
        self.frames.take_ack()
    }

    /// Draw the frames that `data` completes on `out`: false where its
    /// bytes are no frame, after one line on `err`, as nothing that follows
    /// can be shown and the session ends.
    pub(super) async fn draw(&mut self, data: &[u8], out: &mut Passed, err: &mut Passed) -> bool {
        match self.frames.feed(data) {
            Ok(drawn) => {
                if !drawn.is_empty() {
                    let _ = out.write_all(&drawn).await;
                }
                true
            }
            Err(why) => {
                let line = format!("--frames: the far end sent {why}; the session ends, as its screen cannot be shown");
                say(err, Ask { scroll: false, quiet: self.quiet }, &line).await;
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry and its reading are one table: each ask reads back as
    /// itself, and a value that names no version asks nothing.
    #[test]
    fn an_entry_reads_back_as_its_ask() {
        for (scroll, quiet, entry) in [
            (false, false, "frames@podssh=v1"),
            (true, false, "frames@podssh=v2"),
            (false, true, "frames@podssh=v1 quiet"),
            (true, true, "frames@podssh=v2 quiet"),
        ] {
            let ask = Ask { scroll, quiet };
            assert_eq!(ask.entry(), entry);
            let value = entry.split_once('=').map(|(_, v)| v).unwrap_or_default();
            assert_eq!(Ask::read(value), Some(ask), "{entry}");
        }
        for value in ["", "v3", "V1", "quiet", " v1", "v1quiet"] {
            assert_eq!(Ask::read(value), None, "{value:?}");
        }
    }

    /// Each entry of the name leaves the environment, the first one's ask
    /// is read, and the others keep their order: no server sees the name
    /// as a variable.
    #[test]
    fn the_ask_leaves_the_environment() {
        let one = Some(Ask { scroll: false, quiet: false });
        let two_quiet = Some(Ask { scroll: true, quiet: true });
        let rows: [(&[&str], Option<Ask>, &[&str]); 5] = [
            (&["LANG=C", "TERM_X=1"], None, &["LANG=C", "TERM_X=1"]),
            (&["LANG=C", "frames@podssh=v1", "LC_ALL=C"], one, &["LANG=C", "LC_ALL=C"]),
            (&["frames@podssh=v2 quiet", "frames@podssh=v1"], two_quiet, &[]),
            (&["frames@podssh=v9", "A=1"], None, &["A=1"]),
            (&["frames@podssh", "frames@podsshX=v1"], None, &["frames@podsshX=v1"]),
        ];
        for (given, ask, left) in rows {
            let mut env: Vec<String> = given.iter().map(|s| s.to_string()).collect();
            assert_eq!(Ask::take(&mut env), ask, "{given:?}");
            assert_eq!(env, left.iter().map(|s| s.to_string()).collect::<Vec<_>>(), "{given:?}");
        }
    }

    /// The hello offers by name, whatever its value.
    #[test]
    fn a_hello_offers_by_name() {
        let (name, _) = offer();
        assert_eq!(name, OFFER);
        assert!(offered(&[offer()]));
        assert!(offered(&[("info".into(), "0".into()), (OFFER.into(), "v1".into())]));
        assert!(!offered(&[]));
        assert!(!offered(&[("info".into(), "0".into())]));
    }

    /// One rule for a client: a session that cannot show frames says why;
    /// one that does not want them asks nothing; a master that did not
    /// offer gets no entry, and the line says so.
    #[test]
    fn a_client_sends_the_entry_only_to_a_master_that_offered() {
        let ask = Ask { scroll: false, quiet: false };
        let none = crate::frames::NO_TERMINAL;
        for (not_asked, wanted, offered, expected) in [
            (Some(none), false, true, Err(none)),
            (Some(none), false, false, Err(none)),
            (None, false, true, Ok(None)),
            (None, false, false, Ok(None)),
            (None, true, false, Err(NOT_OFFERED)),
            (None, true, true, Ok(Some("frames@podssh=v1".to_string()))),
        ] {
            assert_eq!(decide(not_asked, wanted, offered, ask), expected, "{not_asked:?} {wanted} {offered}");
        }
        assert!(NOT_OFFERED.starts_with("--frames: no frames: ") && NOT_OFFERED.ends_with("each byte"));
    }
}
