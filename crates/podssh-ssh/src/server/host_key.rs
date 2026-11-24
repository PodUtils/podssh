//! The host key of `podssh serve` (T-107): one Ed25519 key in a state file,
//! made at the first start and read at each later one, so that a client's
//! `known_hosts` holds it once. Never overwritten: of two starts at once,
//! one makes the file, and the other reads that key.
//!
//! The files are made by the caller's functions, as [`crate::keygen::KeyFiles`]
//! does it: podssh-relay's cache makes a private file whole or not at all,
//! and this crate does not depend on it.

use std::path::{Path, PathBuf};

use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey};
use zeroize::Zeroizing;

use crate::keygen::{self, KeyKind};

/// The file's name in a directory of the cache.
pub const FILE: &str = "serve_host_ed25519_key";

/// The comment of a key made here, which `ssh-keygen -l` shows.
const COMMENT: &str = "podssh serve host key";

/// How the state file is read and made.
#[derive(Clone, Copy)]
pub struct StateFiles {
    /// The file's text, `Ok(None)` when there is none; a file that others
    /// can read, or that is not the user's, is an error.
    pub read: fn(&Path) -> Result<Option<String>, String>,
    /// Make the private file whole, never over one that is there:
    /// `Ok(false)` when another was there first.
    pub create: fn(&Path, &[u8]) -> std::io::Result<bool>,
    /// Make a private directory, when it is missing.
    pub dir: fn(&Path) -> std::io::Result<()>,
}

/// The key, where it is, and whether this start made it.
pub struct HostKey {
    pub key: PrivateKey,
    pub path: PathBuf,
    pub made: bool,
}

/// The key at `path`: read when it is there, else made there.
pub fn at(path: &Path, files: &StateFiles) -> Result<HostKey, String> {
    // Twice: a start that loses the race to make the file reads the
    // winner's key on its second turn.
    for _ in 0..2 {
        if let Some(text) = (files.read)(path)? {
            let key = parse(&Zeroizing::new(text)).map_err(|why| format!("{}: {why}", path.display()))?;
            return Ok(HostKey { key, path: path.to_path_buf(), made: false });
        }
        let key = keygen::generate(KeyKind::Ed25519, COMMENT)?;
        let text = key.to_openssh(LineEnding::LF).map_err(|e| format!("could not encode the host key: {e}"))?;
        match (files.create)(path, text.as_bytes()) {
            Ok(true) => return Ok(HostKey { key, path: path.to_path_buf(), made: true }),
            Ok(false) => continue,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    Err(format!("{}: could not be made or read", path.display()))
}

/// The key named [`FILE`]: the one kept in any of `read_dirs`, else one made
/// in the first of `dirs` that takes it. A file that is there and cannot be
/// used is an error, never a reason to make another key elsewhere: a client
/// would then see a new host key.
pub fn in_first(read_dirs: &[PathBuf], dirs: &[PathBuf], files: &StateFiles) -> Result<HostKey, String> {
    for dir in read_dirs {
        let path = dir.join(FILE);
        match (files.read)(&path) {
            Ok(Some(_)) => return at(&path, files),
            Ok(None) => {}
            // A directory that this user cannot search holds no key of theirs.
            Err(why) if std::fs::symlink_metadata(&path).is_ok() => return Err(why),
            Err(_) => {}
        }
    }
    let mut reasons = Vec::new();
    for dir in dirs {
        let path = dir.join(FILE);
        match (files.dir)(dir).map_err(|e| format!("{}: {e}", dir.display())).and_then(|()| at(&path, files)) {
            Ok(found) => return Ok(found),
            Err(why) => reasons.push(why),
        }
    }
    if reasons.is_empty() {
        return Err("no directory for the host key (the cache is none): name a file with --host-key".into());
    }
    Err(format!("no directory would take the host key ({})", reasons.join("; ")))
}

/// A host key from its file's text: an OpenSSH private key with no
/// passphrase, as nobody is there to type one, that serve can sign with
/// ([`check`]).
pub fn parse(text: &str) -> Result<PrivateKey, String> {
    // ssh-key's words for a file with no PEM block name a NUL byte that is
    // not there (T-869): what the file is comes first, in words of its own.
    if !text.contains(OPENSSH_BEGIN) {
        return Err(not_openssh(text));
    }
    let key = PrivateKey::from_openssh(text).map_err(|e| format!("not an OpenSSH private key: {e}"))?;
    if key.is_encrypted() {
        return Err("the key has a passphrase, which nobody can type at a server's start: use a key without one".into());
    }
    check(&key)?;
    Ok(key)
}

/// The first line of an OpenSSH private key.
const OPENSSH_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";

/// What a file that holds no OpenSSH private key holds instead, in one
/// line: nothing, a public key, a key in another format, or other text.
fn not_openssh(text: &str) -> String {
    const WANT: &str = "serve takes an OpenSSH private key (-----BEGIN OPENSSH PRIVATE KEY-----, as podssh keygen \
                        -t ed25519 writes it)";
    let start = text.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']);
    let first = start.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#'));
    let what = match first {
        None => "the file is empty".to_string(),
        Some(_) if text.contains('\0') => "the file holds binary data, not text".to_string(),
        Some(line) if line.starts_with("-----BEGIN ") => {
            let label = line.trim_start_matches("-----BEGIN ").trim_end_matches('-').trim();
            format!("the file holds a PEM block of {:?}, not an OpenSSH private key", one_line(label))
        }
        Some(line) if line.starts_with("PuTTY-User-Key-File-") => {
            "the file holds a PuTTY key, not an OpenSSH private key".to_string()
        }
        Some(line) if russh::keys::PublicKey::from_openssh(line).is_ok() => {
            "the file holds a public key, not a private key".to_string()
        }
        Some(_) => "the file holds text with no private key in it".to_string(),
    };
    format!("{what}: {WANT}")
}

/// At most 60 characters of `text`, with no control character: a label
/// read from a file goes into one line.
fn one_line(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(60).collect()
}

/// Whether serve can sign each key exchange with `key`: Ed25519 and ECDSA
/// as russh signs them, and RSA through aws-lc-rs alone (T-856), which takes
/// keys of 2048 to 8192 bits; russh's own RSA, which the `rsa` crate does
/// and a client could time (RUSTSEC-2023-0071), never.
pub fn check(key: &PrivateKey) -> Result<(), String> {
    match key.algorithm() {
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } => Ok(()),
        Algorithm::Rsa { .. } => match crate::rsa_key::RsaSigner::of(key) {
            Ok(_) => Ok(()),
            Err(why) => Err(format!("{why}, through aws-lc-rs; use an Ed25519 key (podssh keygen -t ed25519)")),
        },
        other => Err(format!("a key of {}, which podssh serve does not sign with: use an Ed25519 key", other.as_str())),
    }
}
