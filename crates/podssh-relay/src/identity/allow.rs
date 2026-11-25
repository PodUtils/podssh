//! The allowlist of `pod-identity`, read in podssh's one grammar of a key
//! (T-938): a line may also begin with OpenSSH's public line,
//! `ssh-ed25519 BASE64`, which `podssh keygen -y` prints, so that the line a
//! user pastes lets its key in. The crate reads a key in one word; the line
//! is made that word here before the crate reads it, and each line keeps its
//! number, so that a bad line is named as the user wrote it.

pub use pod_identity::allow::*;

use std::path::Path;

use base64::Engine;
use pod_core::files::{read_own, Others};
use pod_identity::{KeyName, PublicKey};

/// The forms of a key that each place of podssh reads, for its refusals.
pub const FORMS: &str = "a key as podssh keygen -y prints it (ssh-ed25519 BASE64, then an optional comment), \
                         64 hex digits, base32, or a fingerprint SHA256:...";

/// The first word of OpenSSH's public line of an Ed25519 key.
const KEY_TYPE: &str = "ssh-ed25519";

/// The key of OpenSSH's public line, from its first two words: the type,
/// then the base64 of the type and the 32 bytes, each after its length.
pub fn openssh(kind: &str, blob: &str) -> Option<PublicKey> {
    if kind != KEY_TYPE {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(blob).ok()?;
    let (named, rest) = field(&bytes)?;
    let (key, rest) = field(rest)?;
    if named != KEY_TYPE.as_bytes() || !rest.is_empty() {
        return None;
    }
    Some(PublicKey(key.try_into().ok()?))
}

/// One field of the wire: four bytes of length, then the bytes.
fn field(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    let end = 4usize.checked_add(len)?;
    Some((bytes.get(4..end)?, bytes.get(end..)?))
}

/// A key as a user gives it in one argument: OpenSSH's public line with an
/// optional comment, or one word that [`KeyName::parse`] reads. A word of
/// another form with more words after it is none: a stray word would
/// otherwise hide a key that is not the one meant.
pub fn key_name(text: &str) -> Option<KeyName> {
    let mut words = text.split_whitespace();
    let first = words.next()?;
    if first == KEY_TYPE {
        return openssh(first, words.next()?).map(KeyName::Key);
    }
    match words.next() {
        None => KeyName::parse(first),
        Some(_) => None,
    }
}

/// `text` with each line that begins with OpenSSH's public line made the
/// key's 64 hex digits and its other words; each other line as it is, so
/// that the crate reads it, or names it as not a key. One line out for each
/// line in, so that the numbers stay the user's.
pub fn normalised(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let key = match (words.next(), words.next()) {
            (Some(kind), Some(blob)) => openssh(kind, blob),
            _ => None,
        };
        match key {
            Some(key) => {
                out.push_str(&key.hex());
                for word in words {
                    out.push(' ');
                    out.push_str(word);
                }
            }
            None => out.push_str(line),
        }
        out.push('\n');
    }
    out
}

/// The keys of `text`, in podssh's grammar.
pub fn parse(text: &str) -> Allowlist {
    Allowlist::parse(&normalised(text))
}

/// The keys of `text`, in podssh's grammar, at most `limit` of them.
pub fn parse_with(text: &str, limit: usize) -> Allowlist {
    Allowlist::parse_with(&normalised(text), limit)
}

/// The allowlist in the file at `path`, as [`Allowlist::read`] checks the
/// file (this user's, that others cannot change), in podssh's grammar.
pub fn read(path: &Path) -> Result<Allowlist, String> {
    match read_own(path, Others::Read)? {
        Some(text) => Ok(parse(&text)),
        None => Err(format!("{}: no such file", path.display())),
    }
}

/// Whether the client `key` may connect, by the allowlist at `path`, read
/// again for each connection. `Err` is why not, for the node's log.
pub fn admits(path: &Path, key: &PublicKey) -> Result<(), String> {
    match read(path) {
        Ok(list) if list.admits(key) => Ok(()),
        Ok(_) => Err(format!("it is not in {}", path.display())),
        Err(why) => Err(why),
    }
}

/// Whether the client `key` may use `route` of the node, by the allowlist at
/// `path`, read again for each session.
pub fn grants(path: &Path, key: &PublicKey, route: &str) -> Result<(), String> {
    match read(path) {
        Ok(list) if list.grants(key, route) => Ok(()),
        Ok(_) => Err(format!("{} does not give it the route {route}", path.display())),
        Err(why) => Err(why),
    }
}

/// Whether the client `key` may reach the node's TARGET with no route, by
/// the allowlist at `path`, read again for each session (T-945): a line of
/// the key with no `routes=` word, or with `routes=*`. A line with
/// `routes=A,B` reaches those routes alone. The crate merges the lines of a
/// key into one, which keeps no mark of a line with no routes, so the lines
/// are read here for it, after the crate's read has let the key in.
pub fn reaches_target(path: &Path, key: &PublicKey) -> Result<(), String> {
    let text = read_own(path, Others::Read)?.ok_or_else(|| format!("{}: no such file", path.display()))?;
    if !parse(&text).admits(key) {
        return Err(format!("it is not in {}", path.display()));
    }
    let bare = normalised(&text).lines().any(|line| {
        let mut words = line.split_whitespace();
        let named = words.next().filter(|w| !w.starts_with('#')).and_then(KeyName::parse);
        named.is_some_and(|name| name.matches(key))
            && match words.next().and_then(|w| w.strip_prefix("routes=")) {
                None => true,
                Some(list) => list == "*",
            }
    });
    match bare {
        true => Ok(()),
        false => Err(format!(
            "its lines in {} give it routes alone, not the TARGET with no route: a line with no routes= or with \
             routes=* gives that",
            path.display()
        )),
    }
}

/// The words that a refusal of a list's bad lines ends with.
pub fn bad_lines_said(lines: &[usize]) -> String {
    format!("lines {lines:?} are not keys (a line holds {FORMS}, then routes=A,B and a comment, both optional)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pod_identity::Identity;

    fn line_of(key: &PublicKey) -> String {
        let mut blob = Vec::new();
        for part in [KEY_TYPE.as_bytes(), &key.0[..]] {
            blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
            blob.extend_from_slice(part);
        }
        format!("{KEY_TYPE} {}", base64::engine::general_purpose::STANDARD.encode(blob))
    }

    /// Each form of a key that a place of podssh takes lets the key in, and
    /// the routes after it count; a line that is none is named by its own
    /// number. One table, one rule.
    #[test]
    fn each_form_of_a_key_is_read_by_one_grammar() {
        let key = Identity::from_seed(&[0x31; 32]).public();
        let openssh_line = line_of(&key);
        // (the line, whether it is a key, whether it gives the route web)
        let rows: Vec<(String, bool, bool)> = vec![
            (openssh_line.clone(), true, false),
            (format!("{openssh_line} me@lab"), true, false),
            (format!("{openssh_line} routes=web me@lab"), true, true),
            (format!("  {openssh_line}\t routes=*"), true, true),
            (key.hex(), true, false),
            (format!("{} routes=web", key.fingerprint()), true, true),
            ("ssh-ed25519".to_string(), false, false),
            ("ssh-ed25519 !!!notbase64".to_string(), false, false),
            (format!("ssh-rsa {}", openssh_line.split(' ').nth(1).unwrap()), false, false),
            ("not a key".to_string(), false, false),
        ];
        for (line, is_key, web) in rows {
            let list = parse(&format!("# a comment\n{line}\n"));
            assert_eq!(list.admits(&key), is_key, "{line:?}");
            assert_eq!(list.grants(&key, "web"), web, "{line:?}");
            let bad: &[usize] = if is_key { &[] } else { &[2] };
            assert_eq!(list.bad_lines(), bad, "{line:?}");
        }
    }

    /// The TARGET with no route: a line of the key with no routes= or with
    /// routes=*; a line of routes alone reaches those routes alone (T-945).
    #[test]
    fn a_line_of_routes_alone_does_not_reach_the_target_with_no_route() {
        let key = Identity::from_seed(&[0x33; 32]).public();
        let other = Identity::from_seed(&[0x34; 32]).public();
        let dir = std::env::temp_dir().join(format!("podssh-allow-target-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        // A directory that others cannot change, as the read of the list asks.
        crate::cache::private_dir(&dir).unwrap();
        let path = dir.join("allow");
        let hex = key.hex();
        // (the file, whether the key reaches the TARGET with no route)
        let rows: Vec<(String, bool)> = vec![
            (format!("{hex}\n"), true),
            (format!("{hex} a comment\n"), true),
            (format!("{hex} routes=*\n"), true),
            (format!("{hex} routes=web\n"), false),
            (format!("{hex} routes=web,db\n# {hex}\n"), false),
            (format!("{hex} routes=web\n{hex}\n"), true),
            (format!("{} routes=web\n{hex}\n", line_of(&key)), true),
            (format!("{}\n", other.hex()), false),
        ];
        for (text, reaches) in rows {
            let _ = std::fs::remove_file(&path);
            crate::cache::create_private(&path, text.as_bytes()).unwrap();
            assert_eq!(reaches_target(&path, &key).is_ok(), reaches, "{text:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An argument takes OpenSSH's line with a comment, or one word; a word
    /// with a stray word after it is none.
    #[test]
    fn an_argument_is_openssh_s_line_or_one_word() {
        let key = Identity::from_seed(&[0x32; 32]).public();
        let openssh_line = line_of(&key);
        let rows: Vec<(String, bool)> = vec![
            (openssh_line.clone(), true),
            (format!("{openssh_line} me@lab two words"), true),
            (key.hex(), true),
            (key.fingerprint(), true),
            (format!("{} me@lab", key.hex()), false),
            (String::new(), false),
            ("ssh-ed25519".into(), false),
        ];
        for (text, is_key) in rows {
            let name = key_name(&text);
            assert_eq!(name.is_some(), is_key, "{text:?}");
            if let Some(name) = name {
                assert!(name.matches(&key), "{text:?}");
            }
        }
    }
}
