//! The owner's word to its shared shell (T-860): the subsystem
//! `share@podssh`, on a new session channel of the connection that owns
//! the shell, deletes or rotates one of the shell's names.
//!
//! The channel's input is one line, `rotate WHICH` or `delete WHICH`, where
//! WHICH is `rw`, `ro` or a whole name. serve answers on the channel's
//! stdout (the new name, or what it deleted) with exit status 0, or with
//! one line on its stderr and exit status 1. Only a connection that holds
//! the owner's seat of that shell may ask: a login under a name runs
//! nothing, and another connection of the owner's key owns no shell here.

// Windows refuses each program (`podssh serve` is a Unix host's), so no
// shell is ever shared there.
#![cfg_attr(not(unix), allow(dead_code))]

use std::sync::Arc;
use std::time::Duration;

use russh::server::{Msg, Session};
use russh::{ChannelId, ChannelWriteHalf};
use tokio::io::{AsyncReadExt, DuplexStream};

use super::channel::Open;
use super::share::{Hub, Mode, Shares};
use super::Settings;

/// The subsystem's name, of podssh's own (RFC 4250, section 4.6.1), as
/// `shells@podssh` is the client's of T-158.
pub(super) const SUBSYSTEM: &str = "share@podssh";

/// The longest line that serve reads: a verb and a name fit in 64.
const LINE_MAX: usize = 256;

/// How long serve waits for the line.
const WAIT: Duration = Duration::from_secs(10);

/// The words of a line that serve does not take.
const USAGE: &str = "say `rotate WHICH` or `delete WHICH`, where WHICH is rw, ro or a whole name";

/// The words for a name that no shell of this connection has: the same
/// for a name of another owner's shell, which this one may not learn of.
const NOT_MINE: &str = "no shared shell of this connection has that name";

/// What the owner asks of a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Verb {
    /// A new name of the same right in its place.
    Rotate,
    /// No new login under it; the seats it opened stay.
    Delete,
}

/// Which name: the one of a right, or a whole name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Which {
    Right(Mode),
    Name(String),
}

/// One line of the owner, read: its verb and its name.
pub(super) fn parse(line: &[u8]) -> Result<(Verb, Which), String> {
    let text = std::str::from_utf8(line).map_err(|_| format!("the line is not UTF-8: {USAGE}"))?;
    let words: Vec<&str> = text.split_whitespace().collect();
    let [verb, which] = words.as_slice() else { return Err(USAGE.into()) };
    let verb = match *verb {
        "rotate" => Verb::Rotate,
        "delete" => Verb::Delete,
        _ => return Err(USAGE.into()),
    };
    let which = match *which {
        "rw" => Which::Right(Mode::Write),
        "ro" => Which::Right(Mode::Read),
        name => Which::Name(name.to_string()),
    };
    Ok((verb, which))
}

/// The shells that this connection owns: the shell of each owner's seat.
/// A connection that logged in under a name never gets here.
pub(super) fn owned<'a>(channels: impl Iterator<Item = &'a Open>) -> Vec<Arc<Hub>> {
    channels.filter_map(|open| open.seat.as_ref().map(|seat| seat.hub.clone())).collect()
}

/// What the subsystem acts with.
pub(super) struct Job {
    pub(super) shares: Shares,
    pub(super) owned: Vec<Arc<Hub>>,
    pub(super) settings: Arc<Settings>,
    /// The fingerprint of the owner's key, for serve's log.
    pub(super) who: String,
}

impl Job {
    /// The one name that `which` means among this connection's shells.
    fn resolve(&self, which: &Which) -> Result<String, String> {
        match which {
            Which::Name(name) => {
                let found = self.shares.find(name);
                let mine = found.is_some_and(|pass| self.owned.iter().any(|hub| Arc::ptr_eq(hub, &pass.hub)));
                if mine {
                    Ok(name.clone())
                } else {
                    Err(NOT_MINE.into())
                }
            }
            Which::Right(mode) => {
                let names = self.owned.iter().flat_map(|hub| self.shares.names_of(hub));
                let names: Vec<String> = names.filter(|(_, m)| m == mode).map(|(name, _)| name).collect();
                match names.as_slice() {
                    [one] => Ok(one.clone()),
                    [] => Err(format!("this connection's shared shell has no name {} now", right(*mode))),
                    more => Err(format!("this connection shares {} shells: name the whole name", more.len())),
                }
            }
        }
    }

    /// Carry out the owner's line: the words for its stdout, or why not.
    pub(super) fn act(&self, verb: Verb, which: &Which) -> Result<String, String> {
        let name = self.resolve(which)?;
        // A shell that ended between the two looks takes its names along.
        let ended = || "the shared shell ended".to_string();
        let said = match verb {
            Verb::Rotate => self.shares.reshare(&name).ok_or_else(ended)?,
            Verb::Delete if self.shares.unshare(&name) => {
                format!("deleted {name}: it lets nobody in now, and the seats it opened stay")
            }
            Verb::Delete => return Err(ended()),
        };
        // The names are credentials: serve's log says what, never which.
        let what = if verb == Verb::Rotate { "rotated" } else { "deleted" };
        self.settings.say(&format!("key {}: {what} a name of its shared shell", self.who));
        Ok(said)
    }
}

/// The word of a right in the owner's line.
fn right(mode: Mode) -> &'static str {
    match mode {
        Mode::Write => "rw",
        Mode::Read => "ro",
    }
}

/// Answer the subsystem request on `channel`: start reading the owner's
/// line, or refuse with one line on the channel's stderr and close it, as
/// a program that did not start. `job` is Err with the words of a refusal.
pub(super) fn answer(
    open: Option<&mut Open>,
    job: Result<Job, String>,
    channel: ChannelId,
    session: &mut Session,
) -> Result<(), russh::Error> {
    let Some(open) = open.filter(|open| !open.started()) else { return session.channel_failure(channel) };
    let job = job.and_then(|job| {
        if job.owned.is_empty() {
            Err("this connection shares no shell: `podssh serve --share` shares the login shell of a tty".into())
        } else {
            Ok(job)
        }
    });
    let (job, write) = match (job, open.write.take()) {
        (Ok(job), Some(write)) => (job, write),
        (refused, _) => {
            let why = refused.err().unwrap_or_else(|| "a program runs on this channel already".into());
            session.extended_data(channel, 1, format!("podssh serve: {why}\n").into_bytes())?;
            session.channel_failure(channel)?;
            session.eof(channel)?;
            return session.close(channel);
        }
    };
    let (near, far) = tokio::io::duplex(LINE_MAX);
    open.give_input(Box::new(near));
    tokio::spawn(run(far, write, job));
    session.channel_success(channel)
}

/// Read the line, act on it, answer, and end the channel.
async fn run(from: DuplexStream, write: ChannelWriteHalf<Msg>, job: Job) {
    let answer = match tokio::time::timeout(WAIT, read_line(from)).await {
        Err(_) => Err(format!("no line came in {} s: {USAGE}", WAIT.as_secs())),
        Ok(Err(why)) => Err(why),
        Ok(Ok(line)) => parse(&line).and_then(|(verb, which)| job.act(verb, &which)),
    };
    let status = match answer {
        Ok(said) => {
            let _ = write.data_bytes(format!("{said}\n")).await;
            0
        }
        Err(why) => {
            let _ = write.extended_data_bytes(1, format!("podssh serve: {why}\n")).await;
            1
        }
    };
    let _ = write.exit_status(status).await;
    let _ = write.eof().await;
    let _ = write.close().await;
}

/// The channel's input up to its first newline, or to its end.
async fn read_line(mut from: DuplexStream) -> Result<Vec<u8>, String> {
    let mut line = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        let n = from.read(&mut buf).await.map_err(|e| format!("the line: {e}"))?;
        if n == 0 {
            return Ok(line);
        }
        line.extend_from_slice(&buf[..n]);
        if let Some(end) = line.iter().position(|&b| b == b'\n') {
            line.truncate(end);
            return Ok(line);
        }
        if line.len() > LINE_MAX {
            return Err(format!("the line is longer than {LINE_MAX} bytes: {USAGE}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_owner_s_line_is_a_verb_and_a_name() {
        let name = || Which::Name("rw-0123456789abcdef0123456789abcdef".into());
        #[rustfmt::skip]
        type Case<'a> = (&'a [u8], Result<(Verb, Which), ()>);
        let cases: &[Case] = &[
            (b"rotate rw", Ok((Verb::Rotate, Which::Right(Mode::Write)))),
            (b"delete ro\r", Ok((Verb::Delete, Which::Right(Mode::Read)))),
            (b"  rotate   ro  ", Ok((Verb::Rotate, Which::Right(Mode::Read)))),
            (b"delete rw-0123456789abcdef0123456789abcdef", Ok((Verb::Delete, name()))),
            (b"", Err(())),
            (b"rotate", Err(())),
            (b"rotate rw ro", Err(())),
            (b"rename rw", Err(())),
            (b"ROTATE rw", Err(())),
            (b"rotate \xff", Err(())),
        ];
        for (line, want) in cases {
            let got = parse(line).map_err(|_| ());
            assert_eq!(&got, want, "{:?}", String::from_utf8_lossy(line));
        }
    }

    /// A shell of `table` with no pty behind it, and its two names.
    fn shell(table: &Shares) -> (Arc<super::super::share::Seat>, String, String) {
        let size = crate::terminal::Size { cols: 80, rows: 24, px_width: 0, px_height: 0 };
        let owner = Hub::open(table, Box::new(tokio::io::sink()), Box::new(|_: crate::terminal::Size| {}), size);
        let names = table.mint(&owner.hub).expect("random bytes");
        (owner, names.write, names.read)
    }

    #[test]
    fn a_right_names_the_one_name_of_this_connection_s_shells() {
        let table = Shares::default();
        let (mine, write, read) = shell(&table);
        let (theirs, their_write, _) = shell(&table);
        let job = |owned: Vec<Arc<Hub>>| {
            let (shares, settings, who) = (table.clone(), Arc::default(), "key".to_string());
            Job { shares, owned, settings, who }
        };
        let one = job(vec![mine.hub.clone()]);
        assert_eq!(one.resolve(&Which::Right(Mode::Write)), Ok(write.clone()));
        assert_eq!(one.resolve(&Which::Right(Mode::Read)), Ok(read.clone()));
        assert_eq!(one.resolve(&Which::Name(read.clone())), Ok(read.clone()));
        // Another owner's name reads as no name at all.
        assert_eq!(one.resolve(&Which::Name(their_write.clone())), Err(NOT_MINE.into()));
        assert_eq!(one.resolve(&Which::Name("rw-".into())), Err(NOT_MINE.into()));
        let both = job(vec![mine.hub.clone(), theirs.hub.clone()]);
        assert!(both.resolve(&Which::Right(Mode::Write)).is_err_and(|why| why.contains("2 shells")));
        assert_eq!(both.resolve(&Which::Name(their_write.clone())), Ok(their_write.clone()));

        // A rotation leaves the other name, and the right finds the new one.
        let fresh = one.act(Verb::Rotate, &Which::Right(Mode::Write)).expect("rotated");
        assert!(fresh.starts_with("rw-") && fresh != write, "{fresh}");
        assert!(table.find(&write).is_none() && table.find(&read).is_some());
        assert_eq!(one.resolve(&Which::Right(Mode::Write)), Ok(fresh));
        assert!(one.act(Verb::Delete, &Which::Right(Mode::Read)).is_ok_and(|said| said.contains(&read)));
        assert!(table.find(&read).is_none());
        assert!(one.resolve(&Which::Right(Mode::Read)).is_err_and(|why| why.contains("no name ro")));
        // A shell that ended has no names left to act on.
        mine.hub.end();
        assert!(one.act(Verb::Rotate, &Which::Right(Mode::Write)).is_err());
    }

    #[tokio::test]
    async fn a_line_ends_at_its_newline_or_its_end_and_a_long_one_is_refused() {
        #[rustfmt::skip]
        type Case<'a> = (&'a [u8], Result<&'a [u8], ()>);
        let cases: &[Case] = &[
            (b"rotate rw\nmore", Ok(b"rotate rw")),
            (b"delete ro", Ok(b"delete ro")),
            (b"", Ok(b"")),
            (&[b'x'; LINE_MAX + 1], Err(())),
        ];
        for (input, want) in cases {
            let (mut near, far) = tokio::io::duplex(4 * LINE_MAX);
            tokio::io::AsyncWriteExt::write_all(&mut near, input).await.unwrap();
            drop(near);
            let got = read_line(far).await.ok();
            let want: Option<Vec<u8>> = want.ok().map(|w| w.to_vec());
            assert_eq!(got, want, "{} bytes", input.len());
        }
    }
}
