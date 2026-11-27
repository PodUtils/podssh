//! `podssh node NAME --install --system --run-as USER` and `--uninstall
//! --system`: the node as a system unit of systemd that runs as USER, with
//! its hardening (`system_text`). Each part that it needs is probed first,
//! in this order: root, systemd as this host's manager
//! (`/run/systemd/system`, as `sd_booted` reads it), USER's entry in
//! `/etc/passwd`, and USER's cache of podssh, which holds the pair and the
//! keys; a missing part is refused with its words (77, else 69). The probes
//! are given, so that the tests run with no root. root writes no file of
//! USER's tree: the file of the variables goes into a state directory under
//! `/var/lib`, a directory of root's, made USER's.

use std::path::{Path, PathBuf};

use super::system_text::UNIT_DIR;
use crate::exitmap::sysexits::{EX_NOPERM, EX_UNAVAILABLE};
use crate::relay_settings::Refusal;

/// The user database, read as a file: a static binary has no NSS.
const PASSWD: &str = "/etc/passwd";

/// The most of that file that is read.
const PASSWD_MOST: u64 = 16 << 20;

/// There when systemd is this host's service manager (`sd_booted`).
pub(crate) const SYSTEMD_RUNS: &str = pod_unit::install::SYSTEMD_BOOTED;

/// The user that a system unit runs as, from its passwd entry.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct Account {
    pub user: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    /// The login shell, for serve's sessions.
    pub shell: Option<String>,
}

impl Account {
    /// `HOME/.cache/podssh`, the cache that the unit's `XDG_CACHE_HOME` gives.
    pub fn cache_dir(&self) -> PathBuf {
        self.home.join(".cache").join("podssh")
    }

    /// `HOME/.config/podssh`, where the settings are.
    pub fn config_dir(&self) -> PathBuf {
        self.home.join(".config").join("podssh")
    }
}

/// What the checks read of this host; the tests give their own.
pub(crate) struct Probes<'a> {
    /// The effective uid; none where there is no such thing.
    pub euid: &'a dyn Fn() -> Option<u32>,
    /// Whether systemd is this host's service manager.
    pub systemd: &'a dyn Fn() -> bool,
    /// USER's passwd entry.
    pub account: &'a dyn Fn(&str) -> Option<Account>,
    /// The owner of a directory, read with no link followed; none when it is
    /// missing or no directory.
    pub owner: &'a dyn Fn(&Path) -> Option<u32>,
}

impl Probes<'static> {
    /// This host's.
    pub fn host() -> Probes<'static> {
        Probes { euid: &effective_uid, systemd: &systemd_runs, account: &passwd_account, owner: &dir_owner }
    }
}

#[cfg(unix)]
fn effective_uid() -> Option<u32> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    Some(unsafe { libc::geteuid() })
}

#[cfg(not(unix))]
fn effective_uid() -> Option<u32> {
    None
}

fn systemd_runs() -> bool {
    std::fs::symlink_metadata(SYSTEMD_RUNS).is_ok_and(|meta| meta.is_dir())
}

fn passwd_account(user: &str) -> Option<Account> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(PASSWD).ok()?.take(PASSWD_MOST).read_to_end(&mut bytes).ok()?;
    account_in(&String::from_utf8_lossy(&bytes), user)
}

#[cfg(unix)]
fn dir_owner(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).ok().filter(|meta| meta.is_dir()).map(|meta| meta.uid())
}

#[cfg(not(unix))]
fn dir_owner(_: &Path) -> Option<u32> {
    None
}

/// The entry of `user` in the text of a passwd file
/// (`name:password:uid:gid:gecos:home:shell`); a comment and a line of NIS
/// are passed over, as the C library passes them over.
pub(crate) fn account_in(text: &str, user: &str) -> Option<Account> {
    text.lines().filter(|line| !line.starts_with(['#', '+', '-'])).find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 || fields[0] != user {
            return None;
        }
        Some(Account {
            user: user.to_string(),
            uid: fields[2].parse().ok()?,
            gid: fields[3].parse().ok()?,
            home: PathBuf::from(fields[5]),
            shell: Some(fields[6].trim()).filter(|shell| !shell.is_empty()).map(str::to_string),
        })
    })
}

/// A name that a unit's `User=` holds as it is.
pub(crate) fn user_name_ok(user: &str) -> bool {
    let fits = !user.is_empty() && user.len() <= 32 && !user.starts_with('-');
    fits && user.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

/// An absolute path that a unit's list of paths holds as it is: no blank,
/// no quote, no `:` (which splits a bind), no `%` (a specifier).
pub(crate) fn path_ok(path: &Path) -> bool {
    let text = path.to_string_lossy();
    path.is_absolute() && text.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-+@".contains(&b))
}

fn unavailable(message: String) -> Refusal {
    Refusal { message, code: EX_UNAVAILABLE }
}

/// The flags of a system unit, before anything is probed (64).
pub(crate) fn flags(
    install: bool,
    uninstall: bool,
    print: bool,
    system: bool,
    run_as: Option<&str>,
) -> Result<(), Refusal> {
    let why = if print && (install || uninstall) {
        "--print-unit prints what --install would write: give it alone"
    } else if system && !(install || uninstall || print) {
        "--system goes with --install, --uninstall or --print-unit"
    } else if run_as.is_some() && !system {
        "--run-as USER goes with --system, the system unit that runs as USER"
    } else if system && !uninstall && run_as.is_none() {
        "--system needs --run-as USER: a system unit runs as a named user, never as root"
    } else {
        return Ok(());
    };
    Err(Refusal::usage(why))
}

/// The account of `--run-as USER`, once each part that the unit of NAME
/// needs is there. `install`: also root, systemd, and USER's cache, which
/// a printed unit needs none of.
pub(crate) fn check(probes: &Probes, user: &str, name: &str, install: bool) -> Result<Account, Refusal> {
    if !user_name_ok(user) {
        return Err(Refusal::usage(format!("--run-as {user:?}: a user's name of letters, digits and _.- alone")));
    }
    if install && (probes.euid)() != Some(0) {
        let message = format!("--install --system writes {UNIT_DIR}: run it as root, such as with sudo");
        return Err(Refusal { message, code: EX_NOPERM });
    }
    if install && !(probes.systemd)() {
        return Err(unavailable(format!("systemd is not this host's service manager: {SYSTEMD_RUNS} is missing")));
    }
    let Some(account) = (probes.account)(user) else {
        return Err(unavailable(format!("--run-as {user}: {PASSWD} has no entry of {user}")));
    };
    if account.uid == 0 {
        return Err(Refusal::usage("--run-as names a user with no privilege, not root, whom the hardening then holds"));
    }
    if !path_ok(&account.home) {
        let home = account.home.display();
        return Err(Refusal::config(format!("the home of {user}, {home}, is no path that a unit's list holds")));
    }
    let cache = account.cache_dir();
    if install && (probes.owner)(&cache) != Some(account.uid) {
        return Err(unavailable(format!(
            "{} is missing or not {user}'s: run podssh relay pair {name} as {user} first, which makes it",
            cache.display()
        )));
    }
    Ok(account)
}

#[cfg(unix)]
pub(crate) use super::system_install::{install_node, uninstall};

/// Where no systemd can run.
#[cfg(not(unix))]
pub(crate) fn install_node(_: &crate::node::NodeArgs, err: &mut dyn std::io::Write) -> i32 {
    unavailable("a system unit of systemd is for Linux".into()).report("node", err)
}

#[cfg(not(unix))]
pub(crate) fn uninstall(_: super::Kind, _: &str, _: &Probes, err: &mut dyn std::io::Write) -> i32 {
    unavailable("a system unit of systemd is for Linux".into()).report("node", err)
}
