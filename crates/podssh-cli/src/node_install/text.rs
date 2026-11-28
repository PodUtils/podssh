//! The text of each kind of service (T-121, T-393, T-820), built on each
//! system so that each is tested on each: the node's words with each file by
//! its absolute path, and the [`pod_unit::Unit`] from which `pod-unit`
//! renders a user unit of systemd, the lines of the crontab, a LaunchAgent
//! of launchd and a task of the Task Scheduler, each with its own quoting.
//! None holds a token: the words are the run's flags, and its variables are
//! in the file of `--env-file`. Each starts the run again whenever it ends,
//! with no limit of starts: a tunnel that stays down locks its server out.

use std::path::Path;

#[cfg(test)]
pub(super) use pod_unit::cron::WATCHDOG;
pub(super) use pod_unit::quote::{sh_word, windows_word};
#[cfg(test)]
pub(super) use pod_unit::quote::{systemd_word, xml};

use super::{Kind, Spec};
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

/// The start of the first line of a systemd unit that older podssh wrote,
/// passed to `pod-unit` as an older mark so `--install` and `--uninstall`
/// still recognize units written before the move to `pod-unit`.
pub(super) const UNIT_MARK: &str = "# Written by podssh ";

/// The start of the comment of a LaunchAgent that older podssh wrote,
/// passed to `pod-unit` as an older mark. A comment of XML may hold no `--`.
pub(super) const PLIST_MARK: &str = "<!-- Written by podssh";

/// The node's words for its service: NAME, each TARGET and the flags of this
/// run, each file by its absolute path, as the service does not start in
/// this directory; then `--env-file`.
pub(super) fn service_args(args: &NodeArgs, name: &str, env_file: &Path) -> Result<Vec<String>, Refusal> {
    let mut words = vec!["node".to_string(), name.to_string()];
    words.extend(args.targets.iter().cloned());
    let values = [
        ("--relay-addr", &args.relay_addr),
        ("--iroh-relay", &args.iroh_relay),
        ("--derp-server", &args.derp_server),
        // The exit's ranges (T-431).
        ("--routes", &args.routes),
        // The sessions that its relay readies ahead (T-650).
        ("--spares", &args.spares),
        // The caller's line on a route to a Unix socket (T-714).
        ("--caller-line", &args.caller_line),
        // The net's document at a URL (T-715).
        ("--net-url", &args.net_url),
        ("--net-owner", &args.net_owner),
        ("--net-ttl", &args.net_ttl),
        ("--net-stale", &args.net_stale),
    ];
    for (flag, value) in values {
        if let Some(value) = value {
            words.extend([flag.to_string(), value.clone()]);
        }
    }
    let files = [
        ("--ca-file", &args.ca_file),
        ("--pair-file", &args.pair_file),
        ("--key", &args.key),
        ("--allow", &args.allow),
        ("--iroh-key", &args.iroh_key),
        ("--iroh-allow", &args.iroh_allow),
        // The node's share file (T-433), which `podssh share` edits.
        ("--shares", &args.shares),
        // The GSRN road's secret (T-707): its path, never its text.
        ("--gsr-secret-file", &args.gsr_secret_file),
    ];
    for (flag, value) in files {
        if let Some(value) = value {
            let path = std::path::absolute(value)
                .map_err(|e| Refusal::config(format!("{flag} {value}: {}", podssh_ws::text::said(&e))))?;
            words.extend([flag.to_string(), path.display().to_string()]);
        }
    }
    // The hosts of Cloudflare Access (T-718): host names alone; the
    // credentials' files go in the file of variables.
    for host in &args.access_hosts {
        words.extend(["--access-host".to_string(), host.clone()]);
    }
    let switches = [
        ("--plain", args.plain),
        ("--iroh", args.iroh),
        ("--derp", args.derp),
        ("--opentunnel", args.opentunnel),
        ("--pinggy", args.pinggy),
        ("--serveo", args.serveo),
        ("--ssh-j", args.ssh_j),
        ("--localhost-run", args.localhost_run),
        ("--sandhole", args.sandhole),
        ("--srv-us", args.srv_us),
        ("--tunnl-gg", args.tunnl_gg),
        ("--localtunnel", args.localtunnel),
        ("--bore", args.bore),
        ("--gsr", args.gsr),
        ("--no-e2e", args.no_e2e),
        ("--sshd", args.sshd),
        ("--exit", args.exit),
    ];
    for (flag, on) in switches {
        if on {
            words.push(flag.to_string());
        }
    }
    words.extend(["--env-file".to_string(), env_file.display().to_string()]);
    one_line(&words)?;
    Ok(words)
}

/// No word with a line break, which no service's command can hold.
pub(super) fn one_line(words: &[String]) -> Result<(), Refusal> {
    match words.iter().find(|w| w.contains(['\n', '\r', '\0'])) {
        Some(bad) => {
            Err(Refusal::usage(format!("--install: {bad:?} has a line break, which no service's command can hold")))
        }
        None => Ok(()),
    }
}

/// `podssh-node-NAME`, `podssh-ssh-NAME`, `podssh-serve-NAME`, `podssh-pipe-NAME`.
pub(super) fn service_name(kind: Kind, name: &str) -> String {
    format!("podssh-{}", kind.stem(name))
}

/// `dev.podssh.node.NAME`, `dev.podssh.ssh.NAME`.
pub(super) fn launchd_label(kind: Kind, name: &str) -> String {
    format!("dev.podssh.{}.{name}", kind.verb())
}

/// The `pod-unit` mark (`podssh node`, `podssh ssh`, `podssh serve`,
/// `podssh pipe`): holds no `--` even when a pair's name contains `--`.
pub(super) fn mark(kind: Kind) -> String {
    format!("podssh {}", kind.verb())
}

/// The pre-`pod-unit` crontab comment (T-393) above the two lines of `kind`'s
/// `name`, kept as an older mark so `--install` and `--uninstall` find it.
pub(super) fn cron_mark(kind: Kind, name: &str) -> String {
    let (made, removes) = (kind.install_words(name), kind.uninstall_words(name));
    format!("# podssh {made} wrote the lines below; podssh {removes} removes them")
}

/// The T-121 crontab comment above its one `@reboot` line, kept as an older
/// mark so `--install` and `--uninstall` still find it.
pub(super) fn old_cron_mark(kind: Kind, name: &str) -> String {
    let (made, removes) = (kind.install_words(name), kind.uninstall_words(name));
    format!("# podssh {made} wrote the line below; podssh {removes} removes it")
}

/// The pre-`pod-unit` Windows task description, kept as an older mark so
/// `--install` and `--uninstall` recognize tasks written by older podssh.
pub(super) fn old_task_mark(kind: Kind, name: &str) -> String {
    format!("podssh {} {name}; podssh {} removes it", kind.verb(), kind.uninstall_words(name))
}

/// The identity and older marks of a service of `kind` and `name`, used as
/// the base of [`pod_unit`] and for removals (which have no command).
pub(super) fn base_unit(kind: Kind, name: &str, program: &Path) -> pod_unit::Unit {
    let mut unit = pod_unit::Unit::new(&service_name(kind, name), program, &mark(kind))
        .older_mark(UNIT_MARK)
        .older_mark(PLIST_MARK)
        .older_mark(&cron_mark(kind, name))
        .older_mark(&old_cron_mark(kind, name))
        .older_mark(&old_task_mark(kind, name));
    unit.label = Some(launchd_label(kind, name));
    unit.description = format!("podssh {} {name}", kind.verb());
    unit
}

/// The `pod_unit::Unit` of a user service from `spec`, with podssh's
/// hardening choices (`AF_NETLINK` for `--exit`, `--routes`, `--iroh`;
/// session relaxations for `serve`).
pub(super) fn pod_unit(spec: &Spec) -> Result<pod_unit::Unit, Refusal> {
    let mut unit = base_unit(spec.kind, &spec.name, &spec.exe).args(&spec.args);
    unit.dir = spec.dir.clone();
    // T-718: keep exit 77 from looping every 5 s on bad or revoked Cloudflare
    // Access credentials; services without `--access-host` keep `64 78`.
    if spec.args.iter().any(|w| w == crate::access::HOST_FLAG || w.starts_with("--access-host=")) {
        unit.restart.prevent = vec![64, 77, 78];
    }
    super::system_text::apply_hardening(spec, &mut unit.hardening)?;
    Ok(unit)
}

/// The user unit of systemd, rendered by `pod-unit`.
pub(super) fn unit(spec: &Spec) -> Result<String, Refusal> {
    pod_unit::systemd::render(&pod_unit(spec)?).map_err(super::refusal_of)
}

/// The lines of the crontab, rendered by `pod-unit`: one at boot and the
/// watchdog each 5 minutes.
#[cfg(test)]
pub(super) fn cron_lines(spec: &Spec) -> Result<Vec<String>, Refusal> {
    pod_unit::cron::lines(&pod_unit(spec)?).map_err(super::refusal_of)
}

/// `table` without the lines of `kind`'s `name`, then with `lines` when
/// given, through `pod_unit::cron::table`.
#[cfg(test)]
pub(super) fn cron_table(table: &str, kind: Kind, name: &str, lines: Option<&[String]>) -> (String, bool) {
    let unit = base_unit(kind, name, Path::new("/usr/bin/podssh"));
    pod_unit::cron::table(table, &unit, lines)
}

/// The XML of the Windows task at logon, rendered by `pod-unit`.
#[cfg(test)]
pub(super) fn task_xml(spec: &Spec, user: &str) -> Result<String, Refusal> {
    pod_unit::windows::task_xml(&pod_unit(spec)?, user).map_err(super::refusal_of)
}

/// The LaunchAgent plist, rendered by `pod-unit`.
#[cfg(test)]
pub(super) fn plist(spec: &Spec, label: &str, log: &Path) -> Result<String, Refusal> {
    let mut unit = pod_unit(spec)?;
    unit.label = Some(label.to_string());
    unit.log = Some(log.to_path_buf());
    pod_unit::launchd::render(&unit).map_err(super::refusal_of)
}

/// The binary, then the words.
fn command(spec: &Spec) -> impl Iterator<Item = String> + '_ {
    std::iter::once(spec.exe.display().to_string()).chain(spec.args.iter().cloned())
}

/// The command to run at login, in this system's shell.
pub(super) fn login_line(spec: &Spec) -> String {
    let words: Vec<String> =
        command(spec).map(|w| if cfg!(windows) { windows_word(&w) } else { sh_word(&w) }).collect();
    let line = words.join(" ");
    match spec.dir.as_ref().map(|dir| dir.display().to_string()) {
        Some(dir) if cfg!(windows) => format!("cd /d {} && {line}", windows_word(&dir)),
        Some(dir) => format!("cd {} && {line}", sh_word(&dir)),
        None => line,
    }
}
