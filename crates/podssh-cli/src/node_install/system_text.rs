//! The system unit of systemd that runs as a named user (T-709, T-820):
//! `/etc/systemd/system/podssh-node-NAME.service`, rendered by `pod-unit`
//! with `User=`, that user's places, a state directory for the file of
//! variables, and the hardening of `pod_unit::Hardening`. Each user may read
//! a unit, so no secret is in it: the variables are in a private file of the
//! user's. A run that needs a line relaxed says which line, and why, in a
//! comment of the unit. It is built on each system, so that each tests it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::system::{path_ok, Account};
use super::{env, Kind, Spec};
use crate::relay_settings::Refusal;

/// Where systemd reads the units of the administrator.
pub(crate) const UNIT_DIR: &str = "/etc/systemd/system";

/// Where `StateDirectory=` puts a unit's state.
pub(crate) const STATE_ROOT: &str = "/var/lib";

/// `/etc/systemd/system/podssh-node-NAME.service`, as `pod-unit` names it.
#[cfg(test)]
pub(crate) fn unit_path(kind: Kind, name: &str) -> PathBuf {
    let unit = super::text::base_unit(kind, name, Path::new("/usr/bin/podssh"));
    pod_unit::SystemPlaces::default().systemd.join(pod_unit::systemd::file_name(&unit))
}

/// The name of `StateDirectory=`: `podssh-node-NAME`.
pub(crate) fn state_name(kind: Kind, name: &str) -> String {
    format!("podssh-{}", kind.stem(name))
}

/// `/var/lib/podssh-node-NAME`, the user's own, where the file of the
/// variables and its lock are: a directory of root's above it, so that no
/// link of the user's can lead a write of root's elsewhere.
pub(crate) fn state_dir(kind: Kind, name: &str) -> PathBuf {
    Path::new(STATE_ROOT).join(state_name(kind, name))
}

/// The file of the variables of a system unit, in its state directory.
pub(crate) fn env_path(kind: Kind, name: &str) -> PathBuf {
    state_dir(kind, name).join(env::file_name(kind, name))
}

/// The hardening lines of `pod_unit::hardening::LINES` relaxed for `serve`,
/// whose sessions run the user's own programs as sshd's do. `pod-unit`
/// automatically relaxes `SystemCallErrorNumber` with `SystemCallFilter` and
/// relaxes `RemoveIPC` for every named user account.
pub(super) const SERVE_RELAXED: &[(&str, &str)] = &[
    ("NoNewPrivileges", "sudo in a session needs it"),
    ("CapabilityBoundingSet", "sudo in a session needs it"),
    ("AmbientCapabilities", "sudo in a session needs it"),
    ("RestrictSUIDSGID", "a session may make such files, as with sshd"),
    ("ProtectSystem", "a session writes where its user may"),
    ("ProtectHome", "a session works in its home"),
    ("PrivateTmp", "a session shares /tmp with its user's other logins"),
    ("PrivateDevices", "a session may use the devices of its user"),
    ("ProtectProc", "a session lists the processes of this host"),
    ("RestrictNamespaces", "a session may run containers"),
    ("LockPersonality", "a session may run programs of another personality"),
    ("MemoryDenyWriteExecute", "a session may run a compiler at run time"),
    ("SystemCallArchitectures", "a session may run 32-bit programs"),
    ("SystemCallFilter", "a session's programs make any call"),
    ("RestrictAddressFamilies", "a session's programs open any socket"),
    ("UMask", "a session keeps the umask of its user"),
];

/// The hardening lines that `serve` keeps active; a test checks that every
/// line of `pod_unit::hardening::LINES` is here, in [`SERVE_RELAXED`], or
/// handled automatically by `pod-unit` (`SystemCallErrorNumber`, `RemoveIPC`).
#[cfg(test)]
pub(super) const SERVE_KEPT: &[&str] = &[
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectKernelLogs",
    "ProtectControlGroups",
    "ProtectClock",
    "ProtectHostname",
    "RestrictRealtime",
];

/// The flags whose file the run may make: its directory must be writable.
const MADE: &[&str] = &["--key", "--iroh-key", "--host-key"];

/// The flags whose file the run reads alone.
const READ: &[&str] =
    &["--ca-file", "--pair-file", "--allow", "--iroh-allow", "--shares", "--gsr-secret-file", "--authorized-keys"];

/// The trees that `ProtectHome=` hides.
const HOMES: &[&str] = &["/home", "/root", "/run/user"];

/// The trees that `PrivateTmp=` replaces.
const TEMPS: &[&str] = &["/tmp", "/var/tmp"];

/// What the run does that a line of the hardening would stop.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Needs {
    /// The flag that reads this host's own addresses, which the kernel gives
    /// by netlink: an exit, whose own addresses it dials only when a range
    /// names them alone, and the iroh road, which watches the interfaces.
    pub netlink: Option<&'static str>,
    /// serve, whose sessions run the user's programs.
    pub sessions: bool,
}

impl Needs {
    pub(super) fn of(spec: &Spec) -> Needs {
        let has = |flag: &str| spec.args.iter().any(|word| word == flag);
        Needs {
            netlink: ["--exit", "--routes", "--iroh"].into_iter().find(|flag| has(flag)),
            sessions: spec.kind == Kind::Serve,
        }
    }
}

/// Apply podssh's hardening relaxations and extra address families to
/// `hardening`, for both user units (seccomp lines) and system units.
pub(super) fn apply_hardening(spec: &Spec, hardening: &mut pod_unit::Hardening) -> Result<(), Refusal> {
    let needs = Needs::of(spec);
    if needs.sessions {
        for &(key, why) in SERVE_RELAXED {
            hardening.relax(key, &format!("serve runs user sessions: {why}")).map_err(super::refusal_of)?;
        }
    } else if let Some(flag) = needs.netlink {
        hardening
            .family("AF_NETLINK", &format!("{flag} reads this host's own addresses by netlink"))
            .map_err(super::refusal_of)?;
    }
    Ok(())
}

/// The `pod_unit::Unit` of a system unit of `spec`, which runs as `account`.
/// A path that a unit's list cannot hold as it is, is refused (78).
pub(crate) fn pod_unit(spec: &Spec, account: &Account) -> Result<pod_unit::Unit, Refusal> {
    let (kind, name, user) = (spec.kind, &spec.name, &account.user);
    let home = account.home.display().to_string();
    let mut unit = super::text::pod_unit(spec)?.system(Some(user));
    unit.description = format!("podssh {} {name}, as {user}", kind.verb());
    unit = unit
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", &format!("{home}/.cache"))
        .env("XDG_CONFIG_HOME", &format!("{home}/.config"));
    if kind == Kind::Serve {
        if let Some(shell) = account.shell.as_deref().filter(|shell| path_ok(Path::new(shell))) {
            // The login shell of the passwd entry, as sshd gives it.
            unit = unit.env("SHELL", shell);
        }
    } else {
        unit.state_dir = Some(state_name(kind, name));
        paths(spec, account, &mut unit.hardening)?;
    }
    Ok(unit)
}

/// The system unit of `spec`, rendered by `pod-unit`, which runs as `account`.
pub(crate) fn unit(spec: &Spec, account: &Account) -> Result<String, Refusal> {
    pod_unit::systemd::render(&pod_unit(spec, account)?).map_err(super::refusal_of)
}

/// What `ProtectHome=tmpfs` and `ProtectSystem=strict` must let through: the
/// user's cache of podssh, read and written; its settings, read; the binary
/// itself if hidden; and the directory of each file that a flag names, where
/// it is hidden or must be written.
fn paths(spec: &Spec, account: &Account, hardening: &mut pod_unit::Hardening) -> Result<(), Refusal> {
    let (cache, config) = (account.cache_dir(), account.config_dir());
    for dir in [&cache, &config] {
        if !path_ok(dir) {
            return Err(unit_path_refusal("the home of --run-as", dir));
        }
    }
    hardening.bind.push(cache.clone());
    hardening.bind_read.push(config);
    // The binary itself, where a line above hides it: under a home, or in
    // the temporary directory that PrivateTmp replaces (T-828).
    let exe = &spec.exe;
    let hidden = HOMES.iter().chain(TEMPS).any(|top| exe.starts_with(top)) || exe.starts_with(&account.home);
    if hidden {
        if !path_ok(exe) {
            return Err(unit_path_refusal("the binary", exe));
        }
        hardening.bind_read.push(exe.clone());
    }
    // Each directory once: written when any of its files is made there.
    let mut dirs: BTreeMap<PathBuf, bool> = BTreeMap::new();
    for pair in spec.args.windows(2) {
        let (flag, value) = (pair[0].as_str(), Path::new(&pair[1]));
        let made = MADE.contains(&flag);
        if !made && !READ.contains(&flag) {
            continue;
        }
        let Some(dir) = value.parent().filter(|dir| !dir.starts_with(&cache)) else { continue };
        if !path_ok(dir) {
            return Err(unit_path_refusal(flag, value));
        }
        *dirs.entry(dir.to_path_buf()).or_default() |= made;
    }
    // The directory of each socket of a Unix route, which a connect only
    // reads (T-714); `prepare` refused a relative one.
    for socket in crate::node_unix::service_sockets(&spec.args)? {
        let Some(dir) = socket.parent() else { continue };
        if !path_ok(dir) {
            return Err(unit_path_refusal("the socket of a Unix route", &socket));
        }
        dirs.entry(dir.to_path_buf()).or_default();
    }
    for (dir, made) in dirs {
        let hidden = HOMES.iter().any(|home| dir.starts_with(home)) || dir.starts_with(&account.home);
        match (hidden, made) {
            (true, true) => hardening.bind.push(dir),
            (true, false) => hardening.bind_read.push(dir),
            (false, true) => hardening.write.push(dir),
            (false, false) => {}
        }
    }
    Ok(())
}

fn unit_path_refusal(what: &str, path: &Path) -> Refusal {
    Refusal::config(format!(
        "{what} {}: a path of a unit's list may hold letters, digits and /._-+@ alone",
        path.display()
    ))
}
