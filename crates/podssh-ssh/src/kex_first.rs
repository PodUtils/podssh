//! The first key exchange and the first host key algorithm that each host
//! named in its last KEXINIT (T-752), kept in a private file of the cache,
//! so that the next login can send its own KEXINIT with its identification
//! and the first packet of that key exchange behind it, as a guess (RFC
//! 4253, section 7): a server whose first names are the client's answers at
//! once, a round trip before the usual way. The client guesses only where
//! the names say that the guess is right; a server that changed ignores the
//! guessed packet, and the exchange goes the usual way, which costs bytes
//! and no time. A host is kept by a hash of the name that known_hosts gives
//! it, never its name.

use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::accepted::KeptFile;

/// The file in the cache.
pub const FILE: &str = "kex-first.txt";
/// Its first line.
pub const HEADER: &str = "podssh kex first 1";
/// The most hosts kept: the latest.
pub const MOST: usize = 128;

/// A host's id in the file: SHA-256 of the name that known_hosts gives it
/// (with its port when not 22), in hex.
pub fn host_id(name: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"podssh kex first\0");
    hash.update(name.as_bytes());
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// One host's line: its id, the two names, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Line {
    host: String,
    kex: String,
    key: String,
    at_ms: i64,
}

/// An algorithm's name as the protocol writes it: no space and no comma.
fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-@._".contains(&b))
}

fn valid_host(host: &str) -> bool {
    host.len() == 64 && host.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The lines of `text`; a line that does not read is left out, and a file
/// of another header gives none.
fn read(text: &str) -> Vec<Line> {
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Vec::new();
    }
    lines
        .filter_map(|line| {
            let words: Vec<&str> = line.split(' ').collect();
            let [host, kex, key, at] = words.as_slice() else { return None };
            let at_ms = at.parse().ok()?;
            (valid_host(host) && valid_name(kex) && valid_name(key)).then(|| Line {
                host: host.to_string(),
                kex: kex.to_string(),
                key: key.to_string(),
                at_ms,
            })
        })
        .collect()
}

fn text(lines: &[Line]) -> String {
    let mut out = format!("{HEADER}\n");
    for l in lines {
        out.push_str(&format!("{} {} {} {}\n", l.host, l.kex, l.key, l.at_ms));
    }
    out
}

static KEPT: OnceLock<Box<dyn KeptFile>> = OnceLock::new();
static CHANGE: Mutex<()> = Mutex::new(());

/// Keep the names in `file`, once a run.
pub fn keep_in(file: Box<dyn KeptFile>) -> bool {
    KEPT.set(file).is_ok()
}

/// The first key exchange and host key algorithm that host `id` named last.
pub fn last(id: &str) -> Option<(String, String)> {
    let text = KEPT.get()?.load()?;
    read(&text).into_iter().find(|l| l.host == id).map(|l| (l.kex, l.key))
}

/// Host `id` named `kex` and `key` first.
pub fn named(id: &str, kex: &str, key: &str) {
    let Some(file) = KEPT.get() else { return };
    if !valid_host(id) || !valid_name(kex) || !valid_name(key) {
        return;
    }
    let _one = CHANGE.lock().unwrap_or_else(PoisonError::into_inner);
    let mut lines = file.load().map(|t| read(&t)).unwrap_or_default();
    if lines.iter().any(|l| l.host == id && l.kex == kex && l.key == key) {
        return;
    }
    lines.retain(|l| l.host != id);
    lines.push(Line { host: id.to_string(), kex: kex.to_string(), key: key.to_string(), at_ms: now_ms() });
    lines.sort_by_key(|l| std::cmp::Reverse(l.at_ms));
    lines.truncate(MOST);
    file.store(text(&lines).as_bytes());
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lines_read_back_and_a_bad_one_is_left_out() {
        let id = host_id("[127.0.0.1]:2222");
        let lines =
            vec![Line { host: id.clone(), kex: "curve25519-sha256".into(), key: "ssh-ed25519".into(), at_ms: 5 }];
        let mut written = text(&lines);
        written.push_str("zz bad line\n");
        written.push_str(&format!("{id} has,comma ssh-ed25519 6\n"));
        assert_eq!(read(&written), lines);
        assert!(read("another header\n").is_empty());
        assert_ne!(host_id("a"), host_id("b"));
    }
}
