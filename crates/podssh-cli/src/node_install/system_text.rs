//! The text of a system unit of systemd that runs as a named user:
//! `/etc/systemd/system/podssh-node-NAME.service`, with `User=`, that
//! user's places, a state directory for the file of variables, and the
//! hardening that `systemd-analyze security` scores. Each user may read a
//! unit, so no secret is in it: the variables are in a private file of the
//! user's. A run that needs a line relaxed says which line, and why, in a
//! comment of the unit. It is built on each system, so that each tests it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::system::{path_ok, Account};
use super::text::{systemd_word, UNIT_MARK};
use super::{env, Kind, Spec};
use crate::relay_settings::Refusal;

/// Where systemd reads the units of the administrator.
pub(crate) const UNIT_DIR: &str = "/etc/systemd/system";

/// Where `StateDirectory=` puts a unit's state.
pub(crate) const STATE_ROOT: &str = "/var/lib";

/// `podssh-node-NAME.service`.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn unit_name(kind: Kind, name: &str) -> String {
    format!("podssh-{}.service", kind.stem(name))
}

/// `/etc/systemd/system/podssh-node-NAME.service`.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn unit_path(kind: Kind, name: &str) -> PathBuf {
    Path::new(UNIT_DIR).join(unit_name(kind, name))
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

/// One line of the hardening, and why the sessions of serve go without it.
struct Hard {
    key: &'static str,
    value: &'static str,
    /// None: serve keeps it too.
    sessions: Option<&'static str>,
}

/// The hardening of each system unit. serve's sessions run the user's own
/// programs, as sshd's do, so the lines that would change what they may do
/// are left out of serve's unit, each with its reason.
const HARDENING: &[Hard] = &[
    Hard { key: "NoNewPrivileges", value: "yes", sessions: Some("sudo in a session needs it") },
    Hard { key: "CapabilityBoundingSet", value: "", sessions: Some("sudo in a session needs it") },
    Hard { key: "RestrictSUIDSGID", value: "yes", sessions: Some("a session may make such files, as with sshd") },
    Hard { key: "ProtectSystem", value: "strict", sessions: Some("a session writes where its user may") },
    Hard { key: "ProtectHome", value: "tmpfs", sessions: Some("a session works in its home") },
    Hard { key: "PrivateTmp", value: "yes", sessions: Some("a session shares /tmp with its user's other logins") },
    Hard { key: "PrivateDevices", value: "yes", sessions: Some("a session may use the devices of its user") },
    Hard { key: "ProtectKernelTunables", value: "yes", sessions: None },
    Hard { key: "ProtectKernelModules", value: "yes", sessions: None },
    Hard { key: "ProtectKernelLogs", value: "yes", sessions: None },
    Hard { key: "ProtectControlGroups", value: "yes", sessions: None },
    Hard { key: "ProtectClock", value: "yes", sessions: None },
    Hard { key: "ProtectHostname", value: "yes", sessions: None },
    Hard { key: "ProtectProc", value: "invisible", sessions: Some("a session lists the processes of this host") },
    Hard { key: "RestrictNamespaces", value: "yes", sessions: Some("a session may run containers") },
    Hard { key: "RestrictRealtime", value: "yes", sessions: None },
    Hard { key: "LockPersonality", value: "yes", sessions: Some("a session may run programs of another personality") },
    Hard { key: "MemoryDenyWriteExecute", value: "yes", sessions: Some("a session may run a compiler at run time") },
    Hard { key: "SystemCallArchitectures", value: "native", sessions: Some("a session may run 32-bit programs") },
    Hard { key: "SystemCallFilter", value: "@system-service", sessions: Some("a session's programs make any call") },
    Hard { key: "SystemCallErrorNumber", value: "EPERM", sessions: Some("it goes with SystemCallFilter") },
    Hard {
        key: "RestrictAddressFamilies",
        value: "AF_INET AF_INET6 AF_UNIX",
        sessions: Some("a session's programs open any socket"),
    },
    Hard { key: "UMask", value: "0077", sessions: Some("a session keeps the umask of its user") },
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
    /// A roost (`--sshd`): it dials an sshd of this host.
    pub roost: bool,
    /// serve, whose sessions run the user's programs.
    pub sessions: bool,
}

impl Needs {
    pub(super) fn of(spec: &Spec) -> Needs {
        let has = |flag: &str| spec.args.iter().any(|word| word == flag);
        Needs {
            netlink: ["--exit", "--routes", "--iroh"].into_iter().find(|flag| has(flag)),
            roost: has("--sshd"),
            sessions: spec.kind == Kind::Serve,
        }
    }
}

/// How the first line names what wrote the unit.
fn made_words(kind: Kind, name: &str, user: &str) -> String {
    match kind {
        Kind::Serve => format!("serve {name} --print-unit --system --run-as {user}"),
        _ => format!("{} --system --run-as {user}", kind.install_words(name)),
    }
}

/// The system unit of `spec`, which runs as `account`. A path that a unit's
/// list cannot hold as it is, is refused (78).
pub(crate) fn unit(spec: &Spec, account: &Account) -> Result<String, Refusal> {
    let (kind, name, user) = (spec.kind, &spec.name, &account.user);
    let words: Vec<String> = std::iter::once(spec.exe.display().to_string())
        .chain(spec.args.iter().cloned())
        .map(|word| systemd_word(&word))
        .collect();
    let home = account.home.display().to_string();
    let mut lines = vec![
        format!("{UNIT_MARK}{}; {}.", made_words(kind, name, user), kind.removal(name, true)),
        "# No secret is in this file, which each user may read: the variables are in a private file of the user's."
            .to_string(),
        "[Unit]".to_string(),
        format!("Description=podssh {} {name}, as {user}", kind.verb()),
        "Wants=network-online.target".to_string(),
        "After=network-online.target".to_string(),
        "# No limit of starts: a tunnel that stays down locks its server out.".to_string(),
        "StartLimitIntervalSec=0".to_string(),
        String::new(),
        "[Service]".to_string(),
        format!("User={user}"),
        "# The places of the user, where the user's own runs keep the pair, the keys and the settings.".to_string(),
        format!("Environment=HOME={home}"),
        format!("Environment=XDG_CACHE_HOME={home}/.cache"),
        format!("Environment=XDG_CONFIG_HOME={home}/.config"),
    ];
    if kind == Kind::Serve {
        if let Some(shell) = account.shell.as_deref().filter(|shell| path_ok(Path::new(shell))) {
            // The login shell of the passwd entry, as sshd gives it.
            lines.push(format!("Environment=SHELL={shell}"));
        }
    } else {
        lines.extend([
            "# The file of the variables and its lock: the user's alone.".to_string(),
            format!("StateDirectory={}", state_name(kind, name)),
            "StateDirectoryMode=0700".to_string(),
        ]);
    }
    lines.push(format!("ExecStart={}", words.join(" ")));
    lines.extend(
        [
            "Restart=always",
            "RestartSec=5",
            "RestartPreventExitStatus=64 78",
            "# The same limit, where a systemd older than 230 reads it.",
            "StartLimitInterval=0",
        ]
        .map(String::from),
    );
    hardening(spec, account, &mut lines)?;
    lines.extend([String::new(), "[Install]".to_string(), "WantedBy=multi-user.target".to_string()]);
    Ok(lines.join("\n") + "\n")
}

/// The lines of the hardening, each relaxed line said in a comment, then
/// the paths that the run must reach through it.
fn hardening(spec: &Spec, account: &Account, lines: &mut Vec<String>) -> Result<(), Refusal> {
    let needs = Needs::of(spec);
    lines.push("# The hardening, which systemd-analyze security scores.".to_string());
    if needs.roost {
        lines.push("# A roost (--sshd) dials an sshd of this host, which no line here limits: none is relaxed.".into());
    }
    for hard in HARDENING {
        let line = format!("{}={}", hard.key, hard.value);
        match (needs.sessions, hard.sessions, needs.netlink) {
            (true, Some(why), _) => lines.push(format!("# Relaxed for serve, as {why}: {line}")),
            (_, _, Some(flag)) if hard.key == "RestrictAddressFamilies" => lines.extend([
                format!("# Relaxed for {flag}: AF_NETLINK, by which the kernel gives this host's own addresses."),
                format!("{line} AF_NETLINK"),
            ]),
            _ => lines.push(line),
        }
    }
    if !needs.sessions {
        paths(spec, account, lines)?;
    }
    Ok(())
}

/// What `ProtectHome=tmpfs` and `ProtectSystem=strict` must let through: the
/// user's cache of podssh, read and written; its settings, read; and the
/// directory of each file that a flag names, where it is hidden or must be
/// written. A `-` lets a missing one be.
fn paths(spec: &Spec, account: &Account, lines: &mut Vec<String>) -> Result<(), Refusal> {
    let (cache, config) = (account.cache_dir(), account.config_dir());
    for dir in [&cache, &config] {
        if !path_ok(dir) {
            return Err(unit_path_refusal("the home of --run-as", dir));
        }
    }
    lines.push("# The user's cache of podssh, which holds the pair and the keys; its settings, read.".to_string());
    lines.push(format!("BindPaths={}", cache.display()));
    lines.push(format!("BindReadOnlyPaths=-{}", config.display()));
    // The binary itself, where a line above hides it: under a home, or in
    // the temporary directory that PrivateTmp replaces (T-828).
    let exe = &spec.exe;
    let hidden = HOMES.iter().chain(TEMPS).any(|top| exe.starts_with(top)) || exe.starts_with(&account.home);
    if hidden {
        if !path_ok(exe) {
            return Err(unit_path_refusal("the binary", exe));
        }
        lines.push("# This binary, which the lines above hide: a copy outside a home and /tmp needs none.".into());
        lines.push(format!("BindReadOnlyPaths={}", exe.display()));
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
    let mut more = Vec::new();
    for (dir, made) in dirs {
        let hidden = HOMES.iter().any(|home| dir.starts_with(home)) || dir.starts_with(&account.home);
        let key = match (hidden, made) {
            (true, true) => "BindPaths",
            (true, false) => "BindReadOnlyPaths",
            (false, true) => "ReadWritePaths",
            (false, false) => continue,
        };
        more.push(format!("{key}=-{}", dir.display()));
    }
    if !more.is_empty() {
        lines.push("# The directories of the files of the flags, which the lines above hide or keep read-only.".into());
        lines.extend(more);
    }
    Ok(())
}

fn unit_path_refusal(what: &str, path: &Path) -> Refusal {
    Refusal::config(format!(
        "{what} {}: a path of a unit's list may hold letters, digits and /._-+@ alone",
        path.display()
    ))
}
