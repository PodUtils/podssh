//! The keys that may log in to `podssh serve` (T-107): lines of OpenSSH's
//! `authorized_keys`, from `--authorized-key`, from `--authorized-keys` files,
//! or from `~/.ssh/authorized_keys`. A key is compared by its key data alone:
//! the login name selects nothing, and a comment changes nothing.
//!
//! A line with options (`command=`, `from=`, `restrict`, ...) is not used:
//! its options would limit the key, and a server that dropped them would let
//! the key do more than the line says. T-114 reads them; until then the line
//! is counted, so that the caller can say so.

use russh::keys::ssh_key::public::KeyData;
use russh::keys::PublicKey;

/// What one line of an `authorized_keys` file holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// Nothing: a blank line or a comment.
    Nothing,
    /// A key with no options.
    Key(Box<KeyData>),
    /// A key after options, which are not read (T-114).
    Options,
    /// Not a line of the format: why.
    Bad(String),
}

/// Read one line of `authorized_keys`: `[options] TYPE BASE64 [COMMENT]`.
pub fn parse_line(line: &str) -> Line {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Line::Nothing;
    }
    if let Ok(key) = PublicKey::from_openssh(line) {
        return Line::Key(Box::new(key.key_data().clone()));
    }
    // Options come first, and may hold quoted blanks: a key further on the
    // line, at the start of any word, marks the line as one with options.
    let words: Vec<&str> = line.split_whitespace().collect();
    let first = words.first().copied().unwrap_or_default();
    if is_key_type(first) {
        return Line::Bad(format!("a {first} key that cannot be read"));
    }
    let keyed =
        (1..words.len()).any(|at| is_key_type(words[at]) && PublicKey::from_openssh(&words[at..].join(" ")).is_ok());
    if keyed {
        return Line::Options;
    }
    Line::Bad("no public key".into())
}

/// Whether `word` names a key type of OpenSSH's, a certificate's included.
fn is_key_type(word: &str) -> bool {
    word.starts_with("ssh-")
        || word.starts_with("ecdsa-sha2-")
        || word.starts_with("sk-ssh-")
        || word.starts_with("sk-ecdsa-sha2-")
        || word.starts_with("rsa-sha2-")
}

/// What one text gave: the keys added, and the lines left out by their
/// numbers (from 1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Read {
    pub added: usize,
    pub options: Vec<usize>,
    pub bad: Vec<(usize, String)>,
}

/// The keys that may log in. Empty allows nobody: no setting accepts each
/// key.
#[derive(Debug, Clone, Default)]
pub struct Authorized {
    keys: Vec<KeyData>,
}

impl Authorized {
    pub fn new() -> Self {
        Authorized::default()
    }

    /// Add one key; a key already held is not added twice.
    pub fn add(&mut self, key: KeyData) -> bool {
        if self.keys.contains(&key) {
            return false;
        }
        self.keys.push(key);
        true
    }

    /// Add each key line of `text`, as `authorized_keys` holds them.
    pub fn add_text(&mut self, text: &str) -> Read {
        let mut read = Read::default();
        for (i, line) in text.lines().enumerate() {
            match parse_line(line) {
                Line::Nothing => {}
                Line::Key(key) => read.added += usize::from(self.add(*key)),
                Line::Options => read.options.push(i + 1),
                Line::Bad(why) => read.bad.push((i + 1, why)),
            }
        }
        read
    }

    /// Whether `key` may log in: its key data is one of the list's. A
    /// certificate is not its key, and is not taken here.
    pub fn allows(&self, key: &PublicKey) -> bool {
        self.keys.iter().any(|k| k == key.key_data())
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}
