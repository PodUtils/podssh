//! The allowlist of `pod-identity` (PodUtils/podcrates v0.86.0, T-1406):
//! OpenSSH's public line (`ssh-ed25519 BASE64`), `KEY_FORMS`, `bad_lines_said`
//! and `reaches_target` are all in `pod-identity` now. Thin aliases stay here
//! for podssh callers (`FORMS`, `key_name`, `parse`, `parse_with`, `read`).

pub use pod_identity::allow::*;
pub use pod_identity::KEY_FORMS as FORMS;

use std::path::Path;

use pod_identity::KeyName;

/// A key as a user gives it in one argument: OpenSSH's public line with an
/// optional comment, or one word that [`KeyName::parse`] reads.
pub fn key_name(text: &str) -> Option<KeyName> {
    KeyName::parse(text)
}

/// The keys of `text`, as [`Allowlist::parse`].
pub fn parse(text: &str) -> Allowlist {
    Allowlist::parse(text)
}

/// The keys of `text`, at most `limit` of them, as [`Allowlist::parse_with`].
pub fn parse_with(text: &str, limit: usize) -> Allowlist {
    Allowlist::parse_with(text, limit)
}

/// The allowlist in the file at `path`, as [`Allowlist::read`].
pub fn read(path: &Path) -> Result<Allowlist, String> {
    Allowlist::read(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pod_identity::Identity;

    /// Each form of a key that a place of podssh takes lets the key in, and
    /// the routes after it count; a line that is none is named by its own
    /// number. One table, one rule.
    #[test]
    fn each_form_of_a_key_is_read_by_one_grammar() {
        let key = Identity::from_seed(&[0x31; 32]).public();
        let openssh_line = key.openssh();
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
            (format!("{} routes=web\n{hex}\n", key.openssh()), true),
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
        let openssh_line = key.openssh();
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
