//! `podssh serve --stdio` (T-107, milestone M5): podssh's own SSH server
//! for one connection on stdin and stdout, as `sshd -i`, so that OpenSSH's
//! client reaches it through a ProxyCommand and nothing listens (rule 2 of
//! `AGENTS.md`). The server is `podssh_ssh::server`; this file is the
//! command line: the authorized keys, the shell that sessions run (T-222),
//! the host key in its state file, the drop of each capability of the start
//! (T-698), then the connection.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::ArgMatches;
use podssh_relay::cache::{self, Others};
use podssh_ssh::server::{self, host_key, Authorized, HostKey, Line, Settings, StateFiles};

use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
use crate::relay_settings::Refusal;

/// Every value `podssh serve` accepts, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServeArgs {
    pub stdio: bool,
    pub host_key: Option<String>,
    pub authorized_key: Vec<String>,
    pub authorized_keys: Vec<String>,
    pub accept_env: Vec<String>,
    pub shell: Option<String>,
    pub no_shell: bool,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl ServeArgs {
    pub fn from_matches(matches: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> Self {
        let many = |id: &str| matches.get_many::<String>(id).map(|v| v.cloned().collect()).unwrap_or_default();
        ServeArgs {
            stdio: matches.get_flag("stdio"),
            host_key: matches.get_one::<String>("host-key").cloned(),
            authorized_key: many("authorized-key"),
            authorized_keys: many("authorized-keys"),
            accept_env: many("accept-env"),
            shell: matches.get_one::<String>("shell").cloned(),
            no_shell: matches.get_flag("no-shell"),
            refused,
        }
    }
}

/// The host key's file, read with no link followed and closed to others,
/// and made whole by the cache, never over one that is there.
const FILES: StateFiles = StateFiles { read: read_secret, create: cache::create_private, dir: cache::private_dir };

fn read_secret(path: &Path) -> Result<Option<String>, String> {
    cache::read_own(path, Others::NoAccess)
}

pub fn run(args: &ServeArgs, err: &mut dyn Write) -> i32 {
    // The server's later parts, a shell and a pty, are Unix's.
    if cfg!(windows) {
        let _ = writeln!(err, "podssh serve: not on Windows: it serves a Unix host");
        return EXIT_NOT_IMPLEMENTED;
    }
    if !args.stdio {
        let _ = writeln!(
            err,
            "podssh serve: give --stdio: one SSH connection on stdin and stdout, as the ProxyCommand of a client"
        );
        return EXIT_USAGE;
    }
    if args.no_shell && args.shell.is_some() {
        let _ = writeln!(err, "podssh serve: --shell and --no-shell: give one of them");
        return EXIT_USAGE;
    }
    if std::io::stdin().is_terminal() {
        let _ = writeln!(
            err,
            "podssh serve: --stdio speaks SSH on stdin, which is a terminal here: run it as a client's ProxyCommand"
        );
        return EXIT_USAGE;
    }
    // Nothing of the start needs a privilege: each one held is dropped
    // before a file is read and before the runtime makes its threads.
    match crate::harden::give_up_at(&[], crate::harden::Moment::AtStart) {
        // The words are the tail of a line: here they stand alone.
        Ok(Some(line)) => {
            let line = line.trim_start_matches([',', ' ']);
            let _ = writeln!(err, "podssh serve: {line}");
        }
        Ok(None) => {}
        Err(refusal) => return refused(err, refusal),
    }
    let authorized = match authorized(args, err) {
        Ok(authorized) => Arc::new(authorized),
        Err(refusal) => return refused(err, refusal),
    };
    let settings = Settings {
        accept_env: args.accept_env.clone(),
        shell: args.shell.as_ref().map(PathBuf::from),
        no_shell: args.no_shell,
        base_env: None,
    };
    // Before the host key, so a start that cannot serve makes none.
    if let Err(refusal) = crate::serve_shell::at_start(&settings, err) {
        return refused(err, refusal);
    }
    let found = match args.host_key.as_deref() {
        Some(file) => host_key::at(Path::new(file), &FILES),
        None => host_key::in_first(&cache::read_dirs(), &cache::candidate_dirs(), &FILES),
    };
    let HostKey { key, path, made } = match found {
        Ok(found) => found,
        Err(why) => return refused(err, Refusal::config(format!("the host key: {why}"))),
    };
    say_host_key(err, &key, &path, made);
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = writeln!(err, "podssh serve: no runtime: {e}");
            return EXIT_NOT_IMPLEMENTED;
        }
    };
    let stream = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
    match runtime.block_on(server::serve_with(stream, key, authorized, Arc::new(settings))) {
        Ok(()) => 0,
        Err(why) => {
            let _ = writeln!(err, "podssh serve: {why}");
            podssh_ssh::EXIT_FAILURE
        }
    }
}

fn refused(err: &mut dyn Write, refusal: Refusal) -> i32 {
    let _ = writeln!(err, "podssh serve: {}", refusal.message);
    refusal.code
}

/// The keys that may log in: each `--authorized-key`, each line of each
/// `--authorized-keys` file, else of `~/.ssh/authorized_keys`. None at all
/// refuses the start (78): a server that nobody can log in to is a setup
/// that went wrong.
fn authorized(args: &ServeArgs, err: &mut dyn Write) -> Result<Authorized, Refusal> {
    let mut authorized = Authorized::new();
    for text in &args.authorized_key {
        match server::parse_line(text) {
            Line::Key(key) => {
                authorized.add(*key);
            }
            Line::Options => {
                return Err(Refusal::usage(format!(
                    "--authorized-key {text:?}: options are not read here; give the key alone"
                )))
            }
            Line::Bad(why) => return Err(Refusal::usage(format!("--authorized-key {text:?}: {why}"))),
            Line::Nothing => return Err(Refusal::usage("--authorized-key: give a key, TYPE BASE64 [COMMENT]")),
        }
    }
    let mut files: Vec<(PathBuf, bool)> = args.authorized_keys.iter().map(|f| (PathBuf::from(f), true)).collect();
    if args.authorized_key.is_empty() && files.is_empty() {
        files.extend(default_file().map(|f| (f, false)));
    }
    let mut passed = 0;
    for (file, named) in &files {
        let shown = file.display();
        let text = match cache::read_own(file, Others::Read) {
            Ok(Some(text)) => text,
            Ok(None) if !*named => continue,
            Ok(None) => return Err(Refusal::config(format!("{shown}: no such file"))),
            Err(why) => return Err(Refusal::config(why)),
        };
        let read = authorized.add_text(&text);
        for n in &read.options {
            let _ =
                writeln!(err, "podssh serve: {shown}, line {n}: a key with options, which are not read yet: not used");
        }
        for (n, why) in &read.bad {
            let _ = writeln!(err, "podssh serve: {shown}, line {n}: {why}: passed over");
        }
        passed += read.options.len();
    }
    if authorized.is_empty() {
        let tried: Vec<String> = files.iter().map(|(f, _)| f.display().to_string()).collect();
        let options =
            if passed > 0 { format!(" ({passed} with options, which are not read yet)") } else { String::new() };
        return Err(Refusal::config(format!(
            "no authorized key{options}, so nobody could log in: give --authorized-key KEY or --authorized-keys \
             FILE{}",
            if tried.is_empty() { String::new() } else { format!(" (read: {})", tried.join(", ")) }
        )));
    }
    Ok(authorized)
}

/// `~/.ssh/authorized_keys`, as sshd reads it; none with no home.
fn default_file() -> Option<PathBuf> {
    let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
    let home = var("HOME").or_else(|| if cfg!(windows) { var("USERPROFILE") } else { None })?;
    Some(PathBuf::from(home).join(".ssh").join("authorized_keys"))
}

/// The host key's fingerprint and its file, for the client's
/// `known_hosts`; a warning when the file may not outlive a reboot, as a
/// new key would then meet each client's old one.
fn say_host_key(err: &mut dyn Write, key: &podssh_ssh::russh::keys::PrivateKey, path: &Path, made: bool) {
    let fingerprint = podssh_ssh::known_hosts::fingerprint(key.public_key());
    let now = if made { ", made now" } else { "" };
    let _ = writeln!(err, "podssh serve: host key {fingerprint} ({}{now})", path.display());
    if temporary(path) {
        let _ = writeln!(
            err,
            "podssh serve: {} is in a temporary directory: a reboot can take it, and each client then meets a new \
             host key; --host-key FILE keeps it where you choose",
            path.display()
        );
    }
    if let Some(note) = cache::places().kept_note(path) {
        let _ = writeln!(err, "podssh serve: {note}");
    }
}

/// Whether `path` is in a directory that a reboot or a logout empties.
fn temporary(path: &Path) -> bool {
    let mut places = vec![std::env::temp_dir(), PathBuf::from("/tmp"), PathBuf::from("/dev/shm")];
    places.extend(std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()).map(PathBuf::from));
    places.iter().any(|place| path.starts_with(place))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exitmap::sysexits::EX_CONFIG;

    fn args(stdio: bool) -> ServeArgs {
        ServeArgs { stdio, ..ServeArgs::default() }
    }

    #[test]
    fn a_run_without_stdio_is_a_usage_error() {
        let mut err = Vec::new();
        let code = run(&args(false), &mut err);
        let said = String::from_utf8_lossy(&err);
        if cfg!(windows) {
            assert_eq!(code, EXIT_NOT_IMPLEMENTED, "{said}");
        } else {
            assert_eq!(code, EXIT_USAGE, "{said}");
            assert!(said.contains("--stdio"), "{said}");
        }
    }

    #[test]
    fn a_key_with_options_or_no_key_is_refused_on_the_command_line() {
        let key = podssh_ssh::keygen::generate(podssh_ssh::keygen::KeyKind::Ed25519, "t").unwrap();
        let mut a = args(true);
        a.authorized_key = vec![format!("no-pty {}", key.public_key().to_openssh().unwrap())];
        let refusal = authorized(&a, &mut Vec::new()).expect_err("refused");
        assert_eq!(refusal.code, EXIT_USAGE, "{}", refusal.message);
        a.authorized_key = vec!["not a key".into()];
        assert_eq!(authorized(&a, &mut Vec::new()).expect_err("refused").code, EXIT_USAGE);
    }

    #[test]
    fn a_named_file_that_is_missing_is_a_setup_error() {
        let mut a = args(true);
        a.authorized_keys = vec!["/nonexistent/podssh/authorized_keys".into()];
        let refusal = authorized(&a, &mut Vec::new()).expect_err("refused");
        assert_eq!(refusal.code, EX_CONFIG, "{}", refusal.message);
    }

    #[test]
    fn a_key_given_is_enough() {
        let key = podssh_ssh::keygen::generate(podssh_ssh::keygen::KeyKind::Ed25519, "t").unwrap();
        let mut a = args(true);
        a.authorized_key = vec![key.public_key().to_openssh().unwrap()];
        let found = authorized(&a, &mut Vec::new()).expect("a key");
        assert!(found.allows(key.public_key()));
    }

    #[test]
    fn the_temporary_places_are_known() {
        assert!(temporary(Path::new("/tmp/podssh-1000/serve_host_ed25519_key")));
        assert!(!temporary(Path::new("/home/u/.cache/podssh/serve_host_ed25519_key")));
    }
}
