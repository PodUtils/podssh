//! The offset of a kept shell's output that this client has (T-895), so
//! that a later `--attach` gives it to the far end (`count@podssh`), which
//! replays what a dead channel never brought.
//!
//! The offsets are the far end's: the bytes of the shell's output from its
//! start (T-833). A session counts from where its output starts: 0 for a
//! new shell; for an attach, the count that it gave, or the list's offset
//! when it had none, or the offset of a reset, which `podssh serve` says on
//! stderr. A part that serve's ring dropped is said there too, with its
//! size. A line that does not read, or a count that the far end refused,
//! leaves the count unknown, and nothing is kept: the next attach then
//! starts where the far end counted, as with no count.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use russh::client::Handle;
use russh::ChannelMsg;

use crate::handler::Client;
use crate::io::End;
use crate::keep::{check_name, Ask, KEEP, LIST};
use crate::keep_record;
use crate::log::Log;
use crate::options::Options;

/// The words that start each of `podssh serve`'s lines on a channel's
/// stderr.
const SERVE: &str = "podssh serve: ";
/// The words of a reset's line, before the name.
const RESET_HEAD: &str = "a reset of the kept shell ";
/// The words of a reset's line, before its offset.
const RESET_AT: &str = "from a clean boundary at offset ";
/// The words of a dropped part's line, after its size.
const DROPPED: &str = " bytes of this shell's output were dropped while no client had it";
/// A line of stderr longer than this is none of serve's, and is not read.
const LINE_MAX: usize = 512;
/// The most of the list that is read: a list is a few lines.
const LIST_MAX: usize = 64 * 1024;
/// How long the list may take; past it, the attach goes on with no count.
const LIST_WAIT: Duration = Duration::from_secs(10);

/// serve's line of a reset, before the ring's bytes from `from` on.
pub fn reset_line(name: &str, from: u64) -> String {
    format!("{SERVE}{RESET_HEAD}{name}: its last output follows, {RESET_AT}{from}\r\n")
}

/// serve's line of `bytes` of output that the ring dropped before a client
/// had them: the offsets go on that much later.
pub fn dropped_line(bytes: u64) -> String {
    format!("{SERVE}{bytes}{DROPPED}\r\n")
}

/// What a line of stderr says of the offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Said {
    /// A reset: the output goes on from this offset.
    Reset(u64),
    /// This many bytes were dropped before the next.
    Dropped(u64),
    /// A line of serve's about the offsets whose number does not read.
    Unread,
}

/// What `line`, one line of a channel's stderr, says of the offsets; `None`
/// for a line that says nothing of them.
pub fn said(line: &str) -> Option<Said> {
    let rest = line.trim_end_matches(['\r', '\n']).strip_prefix(SERVE)?;
    let number = |text: &str| text.parse::<u64>().ok().filter(|_| text.bytes().all(|b| b.is_ascii_digit()));
    if rest.starts_with(RESET_HEAD) {
        let at = rest.rsplit_once(RESET_AT).and_then(|(_, at)| number(at));
        return Some(at.map_or(Said::Unread, Said::Reset));
    }
    let size = rest.strip_suffix(DROPPED)?;
    Some(number(size).map_or(Said::Unread, Said::Dropped))
}

/// The offset after a line that said `said`, from `at`.
fn after(at: Option<u64>, said: Option<Said>) -> Option<u64> {
    match said {
        None => at,
        Some(Said::Reset(from)) => Some(from),
        Some(Said::Dropped(bytes)) => at.and_then(|at| at.checked_add(bytes)),
        Some(Said::Unread) => None,
    }
}

/// The offset of `name` in the text of `shells@podssh`: its line is `NAME
/// attached OFFSET` or `NAME detached OFFSET` from `podssh serve`; `None`
/// for a line with no offset, or no line.
pub fn listed_offset(text: &str, name: &str) -> Option<u64> {
    text.lines().find_map(|line| match line.split_ascii_whitespace().collect::<Vec<_>>()[..] {
        [named, "attached" | "detached", offset] if named == name => offset.parse().ok(),
        _ => None,
    })
}

/// A session's count of the shell's output, shared by the pump, which
/// feeds it, and the session, which keeps it at the end.
#[derive(Debug, Clone, Default)]
pub struct Counter(Arc<Mutex<Counted>>);

#[derive(Debug, Default)]
struct Counted {
    at: Option<u64>,
    /// Where the count started: a session whose count never moved got
    /// nothing of the shell, as a join that the far end refused.
    start: Option<u64>,
    /// The part of a line of stderr read so far.
    line: Vec<u8>,
    /// The line read so far is longer than [`LINE_MAX`].
    long: bool,
}

impl Counter {
    /// A count from `at`; `None` until a reset's line gives one.
    pub fn starting(at: Option<u64>) -> Counter {
        Counter(Arc::new(Mutex::new(Counted { at, start: at, ..Counted::default() })))
    }

    fn lock(&self) -> MutexGuard<'_, Counted> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `n` bytes of the shell's output came.
    pub fn data(&self, n: usize) {
        let mut counted = self.lock();
        counted.at = counted.at.and_then(|at| at.checked_add(u64::try_from(n).ok()?));
    }

    /// Bytes of the channel's stderr came: each whole line is read.
    pub fn stderr(&self, bytes: &[u8]) {
        let mut counted = self.lock();
        for &b in bytes {
            if b == b'\n' {
                let line = std::mem::take(&mut counted.line);
                if !std::mem::take(&mut counted.long) {
                    counted.at = after(counted.at, said(&String::from_utf8_lossy(&line)));
                }
            } else if counted.line.len() < LINE_MAX {
                counted.line.push(b);
            } else {
                counted.long = true;
            }
        }
    }

    /// The offset that the client has now, where it is known.
    pub fn at(&self) -> Option<u64> {
        self.lock().at
    }

    /// Start again from `at`.
    pub fn begin(&self, at: Option<u64>) {
        let mut counted = self.lock();
        counted.at = at;
        counted.start = at;
    }

    /// The far end did not take the start: the count is unknown.
    pub fn unknown(&self) {
        self.lock().at = None;
    }

    /// Whether the count moved from its start: any output, a reset or a
    /// line that did not read.
    pub fn moved(&self) -> bool {
        let counted = self.lock();
        counted.at != counted.start
    }
}

/// The count of a session on a far end that keeps shells: the far end's
/// id, the name of the shell, and the counter that the pump feeds.
pub(crate) struct Counting {
    host: String,
    name: Option<String>,
    pub(crate) counter: Counter,
}

impl Counting {
    /// For a session to a far end that keeps shells (`keep.v1`), known by
    /// its host key; `None` else. A new shell counts from 0, and is named
    /// by `keep@podssh` of SetEnv, or by `~d`'s detach; an attach counts
    /// from what [`Counting::to_give`] finds.
    pub(crate) fn of(handle: &Handle<Client>, opts: &Options) -> Option<Counting> {
        if !opts.keep.offer.offered() {
            return None;
        }
        let user = opts.destination.user.as_deref().unwrap_or(&opts.user);
        let host = crate::accepted::host_id(user, handle.agent_session_binding()?.host_key());
        let (name, start) = match &opts.keep.ask {
            Some(Ask::Attach { name, .. }) => (Some(name.clone()), None),
            Some(Ask::List) => return None,
            None => {
                let kept = opts.set_env.iter().rev().find(|(n, _)| n == KEEP).map(|(_, v)| v.clone());
                (kept.filter(|v| check_name(v).is_ok()), Some(0))
            }
        };
        Some(Counting { host, name, counter: Counter::starting(start) })
    }

    /// The offset that an attach gives (`count@podssh`): the one that this
    /// client kept after its last session of the shell, else the list's;
    /// none with a reset, which the reset's line counts from. The counter
    /// starts there.
    pub(crate) async fn to_give(&self, handle: &Handle<Client>, reset: bool, log: &Log) -> Option<u64> {
        let name = self.name.as_deref()?;
        if reset {
            return None;
        }
        let kept = keep_record::saved(&self.host, name).unwrap_or_else(|why| {
            log.debug(&why);
            None
        });
        let count = match kept {
            Some(count) => Some(count),
            None => listed(handle, name).await,
        };
        log.debug(&match count {
            Some(count) => format!("the kept shell {name}: this client has its output up to {count}"),
            None => format!("the kept shell {name}: no offset is known here; the far end's is taken"),
        });
        self.counter.begin(count);
        count
    }

    /// The session ended so: the offset is kept for the next attach where
    /// the shell may still be kept, under the name that the far end keeps
    /// it as; it is forgotten where the shell ended, where another client
    /// took it, and where it is not known. A session that got nothing of
    /// the shell, as a join that the far end refused ("has a client"),
    /// leaves what was kept.
    pub(crate) fn ended(&self, end: &End) {
        let name = match end {
            End::Detached(kept) => Some(kept.as_str()),
            _ => self.name.as_deref(),
        };
        if let (Some(old), End::Detached(kept)) = (self.name.as_deref(), end) {
            if old != kept {
                keep_record::forget(&self.host, old);
            }
        }
        let Some(name) = name else { return };
        let gone = matches!(end, End::Status(_) | End::Cut(_) | End::NoStatus);
        if gone && !self.counter.moved() {
            return;
        }
        match self.counter.at() {
            Some(at) if !gone => keep_record::save(&self.host, name, at),
            _ => keep_record::forget(&self.host, name),
        }
    }
}

/// The offset of `name` in the far end's list, on a channel of its own, in
/// [`LIST_WAIT`]; `None` for a far end that gives none, or a slow one.
async fn listed(handle: &Handle<Client>, name: &str) -> Option<u64> {
    let read = async {
        let mut channel = handle.channel_open_session().await.ok()?;
        channel.request_subsystem(true, LIST).await.ok()?;
        let (mut text, mut granted) = (Vec::new(), false);
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Success => granted = true,
                ChannelMsg::Failure => return None,
                ChannelMsg::Data { data } if granted => {
                    text.extend_from_slice(&data);
                    if text.len() > LIST_MAX {
                        return None;
                    }
                }
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        let _ = channel.close().await;
        listed_offset(&String::from_utf8_lossy(&text), name).filter(|_| granted)
    };
    tokio::time::timeout(LIST_WAIT, read).await.ok().flatten()
}

#[cfg(test)]
#[path = "keep_count_tests.rs"]
mod tests;
