//! The keys of `podssh serve` and its life (T-107, T-114, T-117): where the
//! keys come from, read at the start and again on SIGHUP, each line with
//! its rules; and the signals of a running server: SIGTERM and SIGINT stop
//! it cleanly (a second one kills each child at once), SIGHUP reads the
//! authorized keys again; under `--stdio`, one at the end of the input is
//! the client's end, and reads nothing (T-869, `serve_end.rs`).
//!
//! A reload reads each line as the start does: a line that is not used (no
//! key, or options that serve cannot all honour) is passed over and said,
//! and each other line keeps its rules. A file that is gone or cannot be
//! read, or a set with no key, keeps the set before, with one line, as a
//! reload must not lock each new login out. A session that logged in goes
//! on under the rules it logged in with; the next login meets the new set.
//! With `--revoke-ends-sessions` (T-842), a reload that took a key out ends
//! that key's sessions, one line naming each; a reload that kept the set
//! before ends nothing. `podssh serve NAME` takes the same reload on SIGHUP
//! for each session of its node ([`Hangups`], T-855).

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use podssh_relay::cache::{self, Others};
use podssh_ssh::russh::keys::PrivateKey;
use podssh_ssh::server::{self, Authorized, Control, Keys, Line, Reloaded, Settings};
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
    /// `--gateway FILE` (T-836): the routes are the keys; a reload reads
    /// them again, and no authorized key is read.
    gateway: Option<Arc<server::gateway::Table>>,
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
        Ok(Sources { given, files: named, gateway: None })
    }

    /// The sources of a gateway: its route table alone (T-836).
    pub fn gateway(table: Arc<server::gateway::Table>) -> Sources {
        Sources { gateway: Some(table), ..Sources::default() }
    }

    /// The route table of `--gateway`, for the server's settings.
    pub fn table(&self) -> Option<Arc<server::gateway::Table>> {
        self.gateway.clone()
    }

    /// The keys of each source now, each line that is not used said on
    /// `err` and passed over (T-114). No key at all is a refusal (78): a
    /// server that nobody can log in to is a setup that went wrong.
    pub fn read(&self, err: &mut dyn Write) -> Result<Authorized, Refusal> {
        // A gateway's routes list its keys, and refused an empty table.
        if self.gateway.is_some() {
            return Ok(Authorized::new());
        }
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
/// stays. With `ends` (`--revoke-ends-sessions`), each session of `control`
/// whose key the new set takes out ends, and one more line names each key.
pub fn reload(sources: &Sources, keys: &Keys, control: &Control, ends: bool, err: &mut dyn Write) {
    // A gateway reads its routes again; a table that does not read keeps
    // the one before (T-836), and a net's says each route it left out (T-902).
    if let Some(table) = &sources.gateway {
        let line = match table.reload() {
            Ok((count, notes)) => {
                for note in notes {
                    let _ = writeln!(err, "podssh serve: SIGHUP: {note}");
                }
                format!("SIGHUP: the routes of {} read again, {count} in all", table.shown())
            }
            Err(why) => format!("SIGHUP: {why}; the routes before stay, {}", table.now().len()),
        };
        let _ = writeln!(err, "podssh serve: {line}");
        return;
    }
    let (line, ended) = match sources.read(err) {
        Ok(set) => {
            let count = set.len();
            match server::live::reload(keys, control, set, ends) {
                Reloaded::Taken(ended) => (format!("SIGHUP: the authorized keys read again, {count} in all"), ended),
                Reloaded::Refused => {
                    (format!("SIGHUP: the keys read gave none; the set before stays, {} keys", keys.len()), Vec::new())
                }
            }
        }
        // A file that does not read keeps the set before, and ends nothing.
        Err(refusal) => (format!("SIGHUP: {}; the set before stays, {} keys", refusal.message, keys.len()), Vec::new()),
    };
    let _ = writeln!(err, "podssh serve: {line}");
    for one in ended {
        let _ = writeln!(err, "podssh serve: SIGHUP: {one}");
    }
}

/// SIGHUP for `podssh serve NAME` (T-855): each one reads the keys again
/// into the node's set, with the table of its live connections, as
/// [`reload`] does for `--stdio`. The task ends when the guard drops.
pub struct Hangups(Option<tokio::task::AbortHandle>);

impl Hangups {
    /// No reload: another kind of node.
    pub fn none() -> Hangups {
        Hangups(None)
    }

    /// Catch SIGHUP now, in the runtime of the node. Where it cannot be
    /// caught, one line says so and the keys of the start stay.
    pub fn start(sources: Sources, keys: Keys, control: Control, ends: bool) -> Hangups {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut hup = match signal(SignalKind::hangup()) {
                Ok(hup) => hup,
                Err(e) => {
                    podssh_ssh::err_line!(
                        "podssh serve: SIGHUP cannot be caught here ({}): the keys stay as read",
                        podssh_ws::text::said(&e)
                    );
                    return Hangups(None);
                }
            };
            let task = tokio::spawn(async move {
                while hup.recv().await.is_some() {
                    let mut said = Vec::new();
                    reload(&sources, &keys, &control, ends, &mut said);
                    // One write, so that a reload's lines stay together
                    // among the node's own.
                    let mut err = std::io::stderr().lock();
                    let _ = err.write_all(&said);
                    let _ = err.flush();
                }
            });
            Hangups(Some(task.abort_handle()))
        }
        #[cfg(not(unix))]
        {
            // No SIGHUP: the keys of the start stay.
            let _ = (sources, keys, control, ends);
            Hangups(None)
        }
    }
}

impl Drop for Hangups {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

/// What a signal asks of the server. Only Unix's signals are caught, so
/// another system never builds one.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) enum Asked {
    Stop,
    Reload,
}

/// SIGTERM, SIGINT and SIGHUP, each caught where it could be installed;
/// one that could not keeps its default.
pub(crate) struct Signals {
    #[cfg(unix)]
    term: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    int: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    hup: Option<tokio::signal::unix::Signal>,
}

impl Signals {
    pub(crate) fn new() -> Signals {
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

    pub(crate) async fn next(&mut self) -> Asked {
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
/// each SIGHUP in between reads the keys again, but one that comes with the
/// end of `input`, the client's end, reads nothing and says nothing
/// (T-869). A stop is a clean end (0).
pub async fn serve_until_stopped<S>(
    stream: S,
    input: crate::serve_end::Input,
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
    let ends = settings.revoke_ends_sessions;
    let serving = server::serve_under(stream, key, keys.clone(), settings, control.clone());
    tokio::pin!(serving);
    loop {
        let asked = tokio::select! {
            ended = &mut serving => return ended,
            asked = signals.next() => asked,
        };
        match asked {
            Asked::Stop => control.stop(),
            Asked::Reload => {
                // OpenSSH closes its ProxyCommand's pipes, then hangs it up:
                // a SIGHUP at the end of the input is the client's end, and
                // the connection ends with it.
                let at_end = tokio::select! {
                    ended = &mut serving => return ended,
                    at_end = input.ends_within(crate::serve_end::GRACE) => at_end,
                };
                if !at_end {
                    reload(sources, &keys, &control, ends, err);
                }
            }
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
        reload(&sources, &keys, &Control::new(), false, &mut said);
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
        reload(&sources, &keys, &Control::new(), false, &mut said);
        let text = String::from_utf8_lossy(&said).to_string();
        assert!(text.contains("line 2") && text.contains("passed over"), "{text}");
        assert!(text.contains("read again, 1 in all"), "{text}");
        assert!(keys.allows(two.public_key()) && !keys.allows(one.public_key()), "{text}");
        std::fs::remove_file(&file).unwrap();
        let mut said = Vec::new();
        reload(&sources, &keys, &Control::new(), false, &mut said);
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
        reload(&sources, &keys, &Control::new(), false, &mut Vec::new());
        assert!(keys.allows(one.public_key()) && !keys.allows(two.public_key()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
