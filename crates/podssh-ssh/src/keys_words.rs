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
        // russh's "Could not read key" names no cause (T-1044).
        russh::keys::Error::CouldNotReadKey => "it holds no private key that podssh reads".into(),
        other => podssh_ws::text::said(other),
    }
}

/// Why the file at `path` gave no private key (`e`): a public key or a
/// certificate is said as one, with the private key that `-i` names
/// (T-1044); anything else as [`unread`] says it.
pub(super) fn no_key(path: &Path, e: &russh::keys::Error) -> String {
    let text = crate::key_text::read_text(path).ok();
    text.as_deref().and_then(|text| public_of(path, text)).unwrap_or_else(|| unread(e))
}

/// The words of `text` at `path` when it is a public key or a certificate.
fn public_of(path: &Path, text: &str) -> Option<String> {
    let line = text.lines().map(str::trim).find(|line| !line.is_empty())?;
    let word = line.split_whitespace().next()?;
    let what = if word.ends_with("-cert-v01@openssh.com") {
        "a certificate"
    } else if line.starts_with("---- BEGIN SSH2 PUBLIC KEY") || russh::keys::PublicKey::from_openssh(line).is_ok() {
        "a public key"
    } else {
        return None;
    };
    let shown = path.display().to_string();
    let private = shown.strip_suffix("-cert.pub").or_else(|| shown.strip_suffix(".pub")).filter(|p| !p.is_empty());
    Some(match private {
        Some(private) => format!("it is {what}; -i names the private key, {private}"),
        None => format!("it is {what}; -i names the private key"),
    })
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
        assert_eq!(unread(&russh::keys::Error::CouldNotReadKey), "it holds no private key that podssh reads");
    }

    /// A public key or a certificate named where a private key goes is said
    /// as one, with the private key's name; other text is none (T-1044).
    #[test]
    fn a_public_key_named_by_i_names_its_private_key() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl github";
        let cert = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQ= me";
        let rfc = "---- BEGIN SSH2 PUBLIC KEY ----\nAAAA\n---- END SSH2 PUBLIC KEY ----\n";
        let padded = format!("\n{line}\n");
        for (path, text, want) in [
            ("/k/id.pub", line, Some("it is a public key; -i names the private key, /k/id")),
            ("/k/id", line, Some("it is a public key; -i names the private key")),
            ("/k/key", padded.as_str(), Some("it is a public key; -i names the private key")),
            ("/k/id-cert.pub", cert, Some("it is a certificate; -i names the private key, /k/id")),
            ("/k/id2.pub", rfc, Some("it is a public key; -i names the private key, /k/id2")),
            (".pub", line, Some("it is a public key; -i names the private key")),
            ("/k/notes.txt", "hello world", None),
            ("/k/empty", "", None),
        ] {
            assert_eq!(public_of(Path::new(path), text).as_deref(), want, "{path}");
        }
    }
}
