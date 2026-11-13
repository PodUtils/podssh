//! The keys of `podssh serve` and its life (T-107, T-114, T-117): where the
//! keys come from, read at the start and again on SIGHUP, each line with
//! its rules; and the signals of a running server: SIGTERM and SIGINT stop
//! it cleanly (a second one kills each child at once), SIGHUP reads the
//! authorized keys again.
//!
//! A reload reads each line as the start does: a line that is not used (no
//! key, or options that serve cannot all honour) is passed over and said,
//! and each other line keeps its rules. A file that is gone or cannot be
//! read, or a set with no key, keeps the set before, with one line, as a
//! reload must not lock each new login out. A session that logged in goes
//! on under the rules it logged in with; the next login meets the new set.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use podssh_relay::cache::{self, Others};
use podssh_ssh::russh::keys::PrivateKey;
use podssh_ssh::server::{self, Authorized, Control, Keys, Line, Settings};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::relay_settings::Refusal;

/// Where the keys come from: each `--authorized-key`, read once with its
/// rules, and the files, read at the start and at each reload. A file of
/// the flag must be there; `~/.ssh/authorized_keys`, read when no flag
/// names a key, may be missing.
#[derive(Debug, Clone, Default)]
pub struct Sources {
    given: Authorized,
    files: Vec<(PathBuf, bool)>,
}

impl Sources {
    /// The sources of the command line: each `--authorized-key` read here,
    /// each file named. A key line of the flag that is not used is a usage
    /// error, as the operator typed it.
    pub fn of(keys: &[String], files: &[String], default: Option<PathBuf>) -> Result<Sources, Refusal> {
        let mut given = Authorized::new();
        for text in keys {
            match server::parse_line(text) {
                Line::Key(key, rules) => {
                    given.add_ruled(*key, *rules, "--authorized-key".into());
                }
                Line::Bad(why) => return Err(Refusal::usage(format!("--authorized-key {text:?}: {why}"))),
                Line::Nothing => return Err(Refusal::usage("--authorized-key: give a key, TYPE BASE64 [COMMENT]")),
            }
        }
        let mut named: Vec<(PathBuf, bool)> = files.iter().map(|f| (PathBuf::from(f), true)).collect();
        if keys.is_empty() && named.is_empty() {
            named.extend(default.map(|f| (f, false)));
        }
        Ok(Sources { given, files: named })
    }

    /// The keys of each source now, each line that is not used said on
    /// `err` and passed over (T-114). No key at all is a refusal (78): a
    /// server that nobody can log in to is a setup that went wrong.
    pub fn read(&self, err: &mut dyn Write) -> Result<Authorized, Refusal> {
        let mut authorized = self.given.clone();
        let mut passed = 0;
        for (file, named) in &self.files {
            let shown = file.display();
            let text = match cache::read_own(file, Others::Read) {
                Ok(Some(text)) => text,
                Ok(None) if !*named => continue,
                Ok(None) => return Err(Refusal::config(format!("{shown}: no such file"))),
                Err(why) => return Err(Refusal::config(why)),
            };
            let read = authorized.add_text_from(&text, &shown.to_string());
            for (n, why) in &read.bad {
                let _ = writeln!(err, "podssh serve: {shown}, line {n}: {why}: passed over");
            }
            passed += read.bad.len();
        }
        if authorized.is_empty() {
            let tried: Vec<String> = self.files.iter().map(|(f, _)| f.display().to_string()).collect();
            let lines = if passed > 0 { format!(" ({passed} lines passed over, said above)") } else { String::new() };
            return Err(Refusal::config(format!(
                "no authorized key{lines}, so nobody could log in: give --authorized-key KEY or --authorized-keys \
                 FILE{}",
                if tried.is_empty() { String::new() } else { format!(" (read: {})", tried.join(", ")) }
            )));
        }
        Ok(authorized)
    }
}

/// Read the keys again into `keys` (SIGHUP): each line passed over is
/// said, then one line: how many lines are used now, or why the set before
/// stays.
pub fn reload(sources: &Sources, keys: &Keys, err: &mut dyn Write) {
    let line = match sources.read(err) {
        Ok(set) => {
            let count = set.len();
            if keys.replace(set) {
                format!("SIGHUP: the authorized keys read again, {count} in all")
            } else {
                format!("SIGHUP: the keys read gave none; the set before stays, {} keys", keys.len())
            }
        }
        Err(refusal) => format!("SIGHUP: {}; the set before stays, {} keys", refusal.message, keys.len()),
    };
    let _ = writeln!(err, "podssh serve: {line}");
}

/// What a signal asks of the server. Only Unix's signals are caught, so
/// another system never builds one.
#[cfg_attr(not(unix), allow(dead_code))]
enum Asked {
    Stop,
    Reload,
}

/// SIGTERM, SIGINT and SIGHUP, each caught where it could be installed;
/// one that could not keeps its default.
struct Signals {
    #[cfg(unix)]
    term: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    int: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    hup: Option<tokio::signal::unix::Signal>,
}

impl Signals {
    fn new() -> Signals {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Signals {
                term: signal(SignalKind::terminate()).ok(),
                int: signal(SignalKind::interrupt()).ok(),
                hup: signal(SignalKind::hangup()).ok(),
            }
        }
        #[cfg(not(unix))]
        {
            Signals {}
        }
    }

    async fn next(&mut self) -> Asked {
        #[cfg(unix)]
        {
            async fn one(signal: Option<&mut tokio::signal::unix::Signal>) {
                match signal {
                    Some(signal) => {
                        if signal.recv().await.is_none() {
                            std::future::pending::<()>().await;
                        }
                    }
                    None => std::future::pending().await,
                }
            }
            tokio::select! {
                () = one(self.term.as_mut()) => Asked::Stop,
                () = one(self.int.as_mut()) => Asked::Stop,
                () = one(self.hup.as_mut()) => Asked::Reload,
            }
        }
        #[cfg(not(unix))]
        {
            std::future::pending::<Asked>().await
        }
    }
}

/// Serve `stream` until the client leaves or a signal stops the server;
/// each SIGHUP in between reads the keys again. A stop is a clean end (0).
pub async fn serve_until_stopped<S>(
    stream: S,
    key: PrivateKey,
    keys: Keys,
    settings: Arc<Settings>,
    sources: &Sources,
    err: &mut dyn Write,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Caught before the first byte, so that no stop finds the default.
    let mut signals = Signals::new();
    let control = Control::new();
    let serving = server::serve_under(stream, key, keys.clone(), settings, control.clone());
    tokio::pin!(serving);
    loop {
        tokio::select! {
            ended = &mut serving => return ended,
            asked = signals.next() => match asked {
                Asked::Stop => control.stop(),
                Asked::Reload => reload(sources, &keys, err),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(name: &str) -> (PrivateKey, String) {
        let key = podssh_ssh::keygen::generate(podssh_ssh::keygen::KeyKind::Ed25519, name).unwrap();
        let text = key.public_key().to_openssh().unwrap();
        (key, text)
    }

    fn scratch(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
        let dir = std::env::temp_dir().join(format!("podssh-serve-keys-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_reload_takes_a_new_key_and_drops_a_removed_one() {
        let dir = scratch("new");
        let file = dir.join("authorized_keys");
        let ((one, one_line), (two, two_line)) = (line("one"), line("two"));
        std::fs::write(&file, format!("{one_line}\n")).unwrap();
        let sources = Sources::of(&[], &[file.display().to_string()], None).unwrap();
        let keys = Keys::new(sources.read(&mut Vec::new()).unwrap());
        std::fs::write(&file, format!("# the second alone now\n{two_line}\n")).unwrap();
        let mut said = Vec::new();
        reload(&sources, &keys, &mut said);
        let said = String::from_utf8_lossy(&said);
        assert!(said.contains("read again, 1 in all"), "{said}");
        assert!(keys.allows(two.public_key()) && !keys.allows(one.public_key()), "{said}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bad_line_is_passed_over_and_said_and_a_missing_file_keeps_the_keys_before() {
        let dir = scratch("broken");
        let file = dir.join("authorized_keys");
        let ((one, one_line), (two, two_line)) = (line("one"), line("two"));
        std::fs::write(&file, format!("{one_line}\n")).unwrap();
        let sources = Sources::of(&[], &[file.display().to_string()], None).unwrap();
        let keys = Keys::new(sources.read(&mut Vec::new()).unwrap());
        // A new key with its rules, and a line cut short: the line is said
        // and passed over, as at the start, and the rest is taken.
        std::fs::write(&file, format!("no-pty {two_line}\nssh-ed25519 AAAAC3Nza\n")).unwrap();
        let mut said = Vec::new();
        reload(&sources, &keys, &mut said);
        let text = String::from_utf8_lossy(&said).to_string();
        assert!(text.contains("line 2") && text.contains("passed over"), "{text}");
        assert!(text.contains("read again, 1 in all"), "{text}");
        assert!(keys.allows(two.public_key()) && !keys.allows(one.public_key()), "{text}");
        std::fs::remove_file(&file).unwrap();
        let mut said = Vec::new();
        reload(&sources, &keys, &mut said);
        let text = String::from_utf8_lossy(&said).to_string();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.contains("no such file") && text.contains("the set before stays, 1 keys"), "{text}");
        assert!(keys.allows(two.public_key()), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_key_of_the_command_line_stays_through_each_reload() {
        let dir = scratch("given");
        let file = dir.join("authorized_keys");
        let ((one, one_line), (two, two_line)) = (line("one"), line("two"));
        std::fs::write(&file, format!("{two_line}\n")).unwrap();
        let sources = Sources::of(&[one_line], &[file.display().to_string()], None).unwrap();
        let keys = Keys::new(sources.read(&mut Vec::new()).unwrap());
        std::fs::write(&file, "").unwrap();
        reload(&sources, &keys, &mut Vec::new());
        assert!(keys.allows(one.public_key()) && !keys.allows(two.public_key()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
