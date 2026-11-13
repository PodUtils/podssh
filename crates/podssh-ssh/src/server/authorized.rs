//! The keys that may log in to `podssh serve` (T-107): lines of OpenSSH's
//! `authorized_keys`, from `--authorized-key`, from `--authorized-keys` files,
//! or from `~/.ssh/authorized_keys`. A key is compared by its key data alone:
//! the login name selects nothing, and a comment changes nothing.
//!
//! The options before a key (T-114, `options.rs`) are its rules. A line
//! whose options cannot all be honoured is not used at all: a server that
//! dropped one would let the key do more than the line says. Of the lines
//! of one key, the first whose `from=` and `expiry-time=` let it in now is
//! the one that holds, as in sshd.

use std::sync::Arc;

use russh::keys::ssh_key::public::KeyData;
use russh::keys::PublicKey;

use super::options::{self, Rules};
use super::rules::Context;

/// What one line of an `authorized_keys` file holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// Nothing: a blank line or a comment.
    Nothing,
    /// A key, and the rules of its options (the default with none).
    Key(Box<KeyData>, Box<Rules>),
    /// Not a line that is used: why, an option named where one is the cause.
    Bad(String),
}

/// Read one line of `authorized_keys`: `[options] TYPE BASE64 [COMMENT]`.
pub fn parse_line(line: &str) -> Line {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Line::Nothing;
    }
    if let Ok(key) = PublicKey::from_openssh(line) {
        return Line::Key(Box::new(key.key_data().clone()), Box::default());
    }
    let first = line.split_whitespace().next().unwrap_or_default();
    if is_key_type(first) {
        return Line::Bad(format!("a {first} key that cannot be read"));
    }
    // Options come first, and may hold quoted blanks: the key starts after
    // the first blank outside quotes, as sshd finds it.
    let (field, rest) = match options::split(line) {
        Ok(split) => split,
        Err(why) => return Line::Bad(format!("options: {why}")),
    };
    let Ok(key) = PublicKey::from_openssh(rest) else {
        let after = rest.split_whitespace().next().unwrap_or_default();
        return Line::Bad(if is_key_type(after) {
            format!("a {after} key that cannot be read")
        } else {
            "no public key".into()
        });
    };
    match options::parse(field) {
        Ok(rules) => Line::Key(Box::new(key.key_data().clone()), Box::new(rules)),
        Err(why) => Line::Bad(format!("{why}: the key is not used without it")),
    }
}

/// Whether `word` names a key type of OpenSSH's, a certificate's included.
fn is_key_type(word: &str) -> bool {
    word.starts_with("ssh-")
        || word.starts_with("ecdsa-sha2-")
        || word.starts_with("sk-ssh-")
        || word.starts_with("sk-ecdsa-sha2-")
        || word.starts_with("rsa-sha2-")
}

/// What one text gave: the keys added, how many of them have options, and
/// the lines left out by their numbers (from 1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Read {
    pub added: usize,
    pub limited: usize,
    pub bad: Vec<(usize, String)>,
}

/// One key line that is used: its key, its rules, and where it came from
/// for serve's log.
#[derive(Debug, Clone)]
struct Entry {
    key: KeyData,
    rules: Arc<Rules>,
    origin: String,
}

/// The answer to a key at authentication.
#[derive(Debug, Clone)]
pub enum Admission {
    /// No line names the key.
    Unlisted,
    /// Lines name it, and each refuses it now: why, one for each line.
    Refused(Vec<String>),
    /// It logs in, under these rules.
    Admitted(Arc<Rules>),
}

/// The keys that may log in. Empty allows nobody: no setting accepts each
/// key.
#[derive(Debug, Clone, Default)]
pub struct Authorized {
    entries: Vec<Entry>,
}

impl Authorized {
    pub fn new() -> Self {
        Authorized::default()
    }

    /// Add one key with no options; a key already held so is not added twice.
    pub fn add(&mut self, key: KeyData) -> bool {
        self.add_ruled(key, Rules::default(), String::new())
    }

    /// Add one key with `rules`, from `origin` (a file and a line, for the
    /// log); the same key with the same rules is not added twice.
    pub fn add_ruled(&mut self, key: KeyData, rules: Rules, origin: String) -> bool {
        if self.entries.iter().any(|e| e.key == key && *e.rules == rules) {
            return false;
        }
        self.entries.push(Entry { key, rules: Arc::new(rules), origin });
        true
    }

    /// Add each key line of `text`, as `authorized_keys` holds them.
    pub fn add_text(&mut self, text: &str) -> Read {
        self.add_text_from(text, "")
    }

    /// [`Authorized::add_text`], each line named `SOURCE, line N` in the log.
    pub fn add_text_from(&mut self, text: &str, source: &str) -> Read {
        let mut read = Read::default();
        for (i, line) in text.lines().enumerate() {
            match parse_line(line) {
                Line::Nothing => {}
                Line::Key(key, rules) => {
                    let limited = *rules != Rules::default();
                    let origin = match source {
                        "" => format!("line {}", i + 1),
                        source => format!("{source}, line {}", i + 1),
                    };
                    if self.add_ruled(*key, *rules, origin) {
                        read.added += 1;
                        read.limited += usize::from(limited);
                    }
                }
                Line::Bad(why) => read.bad.push((i + 1, why)),
            }
        }
        read
    }

    /// Whether `key` may log in under `at`, and with which rules: the first
    /// line of the key that lets it in now, as sshd takes it. A certificate
    /// is not its key, and is not taken here.
    pub fn admit(&self, key: &PublicKey, at: &Context) -> Admission {
        let mut refused = Vec::new();
        for entry in self.entries.iter().filter(|e| e.key == *key.key_data()) {
            match entry.rules.admits(at) {
                Ok(()) => return Admission::Admitted(entry.rules.clone()),
                Err(why) if entry.origin.is_empty() => refused.push(why),
                Err(why) => refused.push(format!("{}: {why}", entry.origin)),
            }
        }
        if refused.is_empty() {
            Admission::Unlisted
        } else {
            Admission::Refused(refused)
        }
    }

    /// Whether `key` may log in now, from no known address.
    pub fn allows(&self, key: &PublicKey) -> bool {
        matches!(self.admit(key, &Context::now(None)), Admission::Admitted(_))
    }

    /// How many lines are used.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
