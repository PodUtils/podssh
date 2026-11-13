//! The environment of a child of `podssh serve` (T-108): serve's own, as the
//! cage gave it, minus podssh's credentials, plus the login's variables and
//! the `env` requests that `--accept-env` lets in.
//!
//! The cage's environment is kept because it holds what no login database
//! gives again (`HTTPS_PROXY`, `PATH`, a library path): a fresh one, as sshd
//! builds it, would leave the shell with no way out.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::known_hosts::wildcard;

/// The names of `env` requests taken when no `--accept-env` is given, as
/// OpenSSH's `AcceptEnv` in most systems' `sshd_config`.
pub const DEFAULT_ACCEPT: &[&str] = &["LANG", "LC_*"];

/// The most `env` requests one channel keeps: a bound on what a client can
/// make the server hold.
pub const MAX_REQUESTS: usize = 256;

/// The `PATH` of a child when serve itself has none, as sshd's default.
pub const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// podssh's credentials by name; [`credential`] adds each name of their
/// shape.
const CREDENTIALS: &[&str] =
    &["PODSSH_RELAY_TOKEN", "PODSSH_CF_ACCESS_TOKEN", "PODSSH_CF_ACCESS_CLIENT_ID", "PODSSH_CF_ACCESS_CLIENT_SECRET"];

/// Whether `name` is one of podssh's credentials, which a child never gets:
/// a user who logs in must not read the token that serve's node holds. A
/// variable that names a file of one is no credential itself.
pub fn credential(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else { return false };
    if CREDENTIALS.contains(&name) {
        return true;
    }
    name.starts_with("PODSSH_")
        && !name.ends_with("_FILE")
        && ["TOKEN", "SECRET", "PASSWORD", "PASSPHRASE"].iter().any(|word| name.contains(word))
}

/// Names that no pattern lets a client set: each changes which program
/// runs, or what a shell reads at its start, and the login's own names.
fn never(name: &str) -> bool {
    name.starts_with("LD_")
        || matches!(name, "PATH" | "HOME" | "SHELL" | "IFS" | "USER" | "LOGNAME")
        // ENV and BASH_ENV name a file that the shell runs.
        || matches!(name, "ENV" | "BASH_ENV")
        // A forced command's wrapper decides by it (T-114).
        || name == ORIGINAL
}

/// The variable that holds a client's command when a key's `command=`
/// replaced it, as sshd sets it (T-114).
pub const ORIGINAL: &str = "SSH_ORIGINAL_COMMAND";

/// Why an `env` request is refused, or None when it is taken. `patterns`
/// are `--accept-env`'s (`*` and `?`, case-sensitive), or the default.
pub fn refused(patterns: &[String], name: &str, value: &str) -> Option<&'static str> {
    if name.is_empty() || name.contains(['=', '\0']) || value.contains('\0') {
        return Some("not a variable");
    }
    if never(name) {
        return Some("never taken from a client");
    }
    if credential(OsStr::new(name)) {
        return Some("a name of podssh's credentials");
    }
    if !patterns.iter().any(|p| wildcard(p.as_bytes(), name.as_bytes())) {
        return Some("not in --accept-env");
    }
    None
}

/// The patterns in force: `--accept-env`'s, else [`DEFAULT_ACCEPT`].
pub fn patterns(given: &[String]) -> Vec<String> {
    if given.is_empty() {
        DEFAULT_ACCEPT.iter().map(|p| p.to_string()).collect()
    } else {
        given.to_vec()
    }
}

/// The value of `name` in `env`, when it is set and not empty.
pub fn lookup<'a>(env: &'a [(OsString, OsString)], name: &str) -> Option<&'a OsStr> {
    env.iter().rev().find(|(k, _)| k == name).map(|(_, v)| v.as_os_str()).filter(|v| !v.is_empty())
}

/// `env` without podssh's credentials: the environment of a probe of a
/// shell (T-222), and the base of a child's.
pub fn without_credentials(env: &[(OsString, OsString)]) -> Vec<(OsString, OsString)> {
    env.iter().filter(|(k, _)| !credential(k)).cloned().collect()
}

/// The environment of a child: `base` (serve's) minus podssh's credentials;
/// `USER` and `LOGNAME` from serve's own, else the uid's number, as no
/// passwd entry is read; `HOME` (`/` with none), `SHELL` the shell that
/// runs, `PATH` (sshd's default with none); then the requests that were
/// taken, each checked by [`refused`] when it came.
pub fn child_env(base: &[(OsString, OsString)], shell: &Path, taken: &[(String, String)]) -> Vec<(OsString, OsString)> {
    let mut env: BTreeMap<OsString, OsString> = without_credentials(base).into_iter().collect();
    let user = lookup(base, "USER").or_else(|| lookup(base, "LOGNAME")).map(OsStr::to_os_string).unwrap_or_else(uid);
    env.insert("USER".into(), user.clone());
    env.insert("LOGNAME".into(), user);
    let home = lookup(base, "HOME").map_or_else(|| OsString::from("/"), OsStr::to_os_string);
    env.insert("HOME".into(), home);
    env.insert("SHELL".into(), shell.as_os_str().to_os_string());
    if lookup(base, "PATH").is_none() {
        env.insert("PATH".into(), DEFAULT_PATH.into());
    }
    for (name, value) in taken {
        env.insert(name.into(), value.into());
    }
    env.into_iter().collect()
}

/// `env` with the variables of a pty (T-110): `TERM` the request's, and
/// `SSH_TTY` the slave's path, as sshd sets them; each replaces serve's own.
/// A slave with no path (a devpts instance of podssh's, T-775) has no
/// `SSH_TTY`, and serve's own does not pass for it.
pub fn with_tty(env: Vec<(OsString, OsString)>, term: &str, tty: Option<&str>) -> Vec<(OsString, OsString)> {
    let mut env: BTreeMap<OsString, OsString> = env.into_iter().collect();
    env.insert("TERM".into(), term.into());
    match tty {
        Some(tty) => env.insert("SSH_TTY".into(), tty.into()),
        None => env.remove(std::ffi::OsStr::new("SSH_TTY")),
    };
    env.into_iter().collect()
}

/// `env` with [`ORIGINAL`] set to `original`, or with none: serve's own,
/// when serve itself runs under a forced command, never reaches a child.
pub fn with_original(env: Vec<(OsString, OsString)>, original: Option<OsString>) -> Vec<(OsString, OsString)> {
    let mut env: BTreeMap<OsString, OsString> = env.into_iter().collect();
    env.remove(OsStr::new(ORIGINAL));
    if let Some(original) = original {
        env.insert(ORIGINAL.into(), original);
    }
    env.into_iter().collect()
}

/// The working directory of a child: its `HOME` when that is a directory,
/// else `/`.
pub fn workdir(env: &[(OsString, OsString)]) -> PathBuf {
    lookup(env, "HOME").map(PathBuf::from).filter(|home| home.is_dir()).unwrap_or_else(|| PathBuf::from("/"))
}

/// The effective uid as a number: the login name of a cage with no name.
fn uid() -> OsString {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no precondition and cannot fail.
        OsString::from(unsafe { libc::geteuid() }.to_string())
    }
    #[cfg(not(unix))]
    {
        OsString::from("0")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        list.iter().map(|(k, v)| (OsString::from(k), OsString::from(v))).collect()
    }

    #[test]
    fn the_default_takes_the_locale_alone() {
        let p = patterns(&[]);
        assert_eq!(refused(&p, "LANG", "C.UTF-8"), None);
        assert_eq!(refused(&p, "LC_ALL", "C"), None);
        assert_eq!(refused(&p, "TZ", "UTC"), Some("not in --accept-env"));
    }

    #[test]
    fn no_pattern_lets_in_what_changes_the_program() {
        let p = vec!["*".to_string()];
        let names = ["LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "HOME", "SHELL", "ENV", "BASH_ENV", "IFS", "USER"];
        for name in names.into_iter().chain([ORIGINAL]) {
            assert_eq!(refused(&p, name, "x"), Some("never taken from a client"), "{name}");
        }
        assert_eq!(refused(&p, "PODSSH_RELAY_TOKEN", "x"), Some("a name of podssh's credentials"));
        assert_eq!(refused(&p, "MY_ENV", "x"), None, "only ENV and BASH_ENV are files that a shell runs");
        assert_eq!(refused(&p, "A=B", "x"), Some("not a variable"));
        assert_eq!(refused(&p, "TZ", "a\0b"), Some("not a variable"));
    }

    #[test]
    fn the_child_gets_no_credential_and_the_login_names() {
        let base = pairs(&[
            ("PATH", "/cage/bin"),
            ("HTTPS_PROXY", "http://proxy:3128"),
            ("PODSSH_RELAY_TOKEN", "secret"),
            ("PODSSH_CF_ACCESS_CLIENT_SECRET", "secret"),
            ("PODSSH_CF_ACCESS_TOKEN_FILE", "/run/token"),
            ("USER", "cage"),
        ]);
        let env = child_env(&base, Path::new("/bin/sh"), &[("LANG".into(), "C.UTF-8".into())]);
        let get = |name: &str| lookup(&env, name).map(|v| v.to_string_lossy().into_owned());
        assert_eq!(get("PODSSH_RELAY_TOKEN"), None);
        assert_eq!(get("PODSSH_CF_ACCESS_CLIENT_SECRET"), None);
        assert_eq!(get("PODSSH_CF_ACCESS_TOKEN_FILE").as_deref(), Some("/run/token"), "a path is no credential");
        assert_eq!(get("HTTPS_PROXY").as_deref(), Some("http://proxy:3128"), "the cage's way out stays");
        assert_eq!(get("PATH").as_deref(), Some("/cage/bin"));
        assert_eq!((get("USER"), get("LOGNAME")), (Some("cage".into()), Some("cage".into())));
        assert_eq!(get("HOME").as_deref(), Some("/"));
        assert_eq!(get("SHELL").as_deref(), Some("/bin/sh"));
        assert_eq!(get("LANG").as_deref(), Some("C.UTF-8"));
    }

    #[test]
    fn a_pty_sets_term_and_ssh_tty_over_serves_own() {
        let env = with_tty(pairs(&[("TERM", "dumb"), ("PATH", "/bin")]), "vt100", Some("/dev/pts/7"));
        assert_eq!(lookup(&env, "TERM"), Some(OsStr::new("vt100")));
        assert_eq!(lookup(&env, "SSH_TTY"), Some(OsStr::new("/dev/pts/7")));
        assert_eq!(env.iter().filter(|(k, _)| k == "TERM").count(), 1);
        // A slave with no path: no SSH_TTY, not even serve's own.
        let env = with_tty(pairs(&[("SSH_TTY", "/dev/pts/serve")]), "vt100", None);
        assert_eq!(lookup(&env, "SSH_TTY"), None);
    }

    #[test]
    fn the_original_command_is_the_forced_one_s_alone() {
        let env = with_original(pairs(&[(ORIGINAL, "serve's own"), ("PATH", "/bin")]), None);
        assert_eq!(lookup(&env, ORIGINAL), None, "serve's own never reaches a child");
        let env = with_original(env, Some("ls -l".into()));
        assert_eq!(lookup(&env, ORIGINAL), Some(OsStr::new("ls -l")));
        assert_eq!(env.iter().filter(|(k, _)| k == ORIGINAL).count(), 1);
    }

    #[test]
    fn a_cage_with_no_path_and_no_name_still_gets_both() {
        let env = child_env(&[], Path::new("/bin/sh"), &[]);
        assert_eq!(lookup(&env, "PATH"), Some(OsStr::new(DEFAULT_PATH)));
        assert!(lookup(&env, "USER").is_some_and(|u| u.to_string_lossy().chars().all(|c| c.is_ascii_digit())));
        assert_eq!(workdir(&env), PathBuf::from("/"));
    }
}
