//! What the key files of a login say of themselves (out of `keys.rs`, for
//! its length): a path that is no key file, a file that cannot be read, the
//! encrypted keys that no passphrase opened and why, and a key file that
//! others can read.

use std::path::{Path, PathBuf};

use crate::log::Log;

/// Why `path` is no key file to read: a directory. A FIFO or a device is
/// read as a file is.
pub(super) fn not_a_file(path: &Path) -> Option<String> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => Some("it is a directory, not a key file".into()),
        Ok(_) => None,
        Err(e) => Some(podssh_ws::text::said(&e)),
    }
}

/// Why a key file could not be read, in a sentence of podssh's: a file that
/// is not text is named so, never by the runtime's "stream did not contain
/// valid UTF-8", and no line ends with "(os error N)".
pub(super) fn unread(e: &russh::keys::Error) -> String {
    match e {
        russh::keys::Error::IO(io) if io.kind() == std::io::ErrorKind::InvalidData => {
            "it is not text, so it is no private key of a format that podssh reads".into()
        }
        russh::keys::Error::IO(io) => podssh_ws::text::said(io),
        other => podssh_ws::text::said(other),
    }
}

/// The lines of the encrypted keys that were not opened, one for each
/// reason, in the order met: BatchMode, no one to ask, or how SSH_ASKPASS
/// failed.
pub(super) fn skipped_lines(skipped: &[(PathBuf, String)]) -> Vec<String> {
    let mut reasons: Vec<&str> = Vec::new();
    for (_, why) in skipped {
        if !reasons.contains(&why.as_str()) {
            reasons.push(why);
        }
    }
    reasons
        .into_iter()
        .map(|why| {
            let files: Vec<String> =
                skipped.iter().filter(|(_, w)| w == why).map(|(p, _)| p.display().to_string()).collect();
            format!("skipped encrypted key(s) {}: {why}", files.join(", "))
        })
        .collect()
}

/// OpenSSH refuses a key file others can read; podssh uses it and says so,
/// because on the hosts it targets `chmod` may not work at all (the manual
/// says so beside -i).
pub(super) fn warn_if_readable_by_others(path: &Path, log: &Log) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                log.info(&format!(
                    "warning: the key file {} can be read by others (mode {mode:04o}); using it anyway",
                    path.display()
                ));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (path, log);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each encrypted key is named with its own reason, one line for each
    /// reason; none says "no SSH_ASKPASS" for a reason that is not that.
    #[test]
    fn each_skipped_key_is_named_with_its_reason() {
        let skipped = [
            (PathBuf::from("/k/a"), "BatchMode is yes, which forbids each question".to_string()),
            (PathBuf::from("/k/b"), "SSH_ASKPASS exited 1".to_string()),
            (PathBuf::from("/k/c"), "BatchMode is yes, which forbids each question".to_string()),
        ];
        assert_eq!(
            skipped_lines(&skipped),
            [
                "skipped encrypted key(s) /k/a, /k/c: BatchMode is yes, which forbids each question",
                "skipped encrypted key(s) /k/b: SSH_ASKPASS exited 1",
            ]
        );
        assert!(skipped_lines(&[]).is_empty());
    }

    /// A directory is said before its mode; a file that is not text, and an
    /// error of the system, in podssh's words.
    #[test]
    fn a_path_that_is_no_key_file_is_said_in_podssh_words() {
        let dir = std::env::temp_dir();
        assert_eq!(not_a_file(&dir).as_deref(), Some("it is a directory, not a key file"));
        let binary = russh::keys::Error::IO(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        ));
        let said = unread(&binary);
        assert!(said.starts_with("it is not text") && !said.contains("UTF-8"), "{said}");
        let denied = russh::keys::Error::IO(std::io::Error::from_raw_os_error(13));
        assert!(!unread(&denied).contains("os error"), "{}", unread(&denied));
    }
}
