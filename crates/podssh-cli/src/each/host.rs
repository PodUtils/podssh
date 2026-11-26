//! One host of `podssh each` (T-183), on the road that `podssh ssh` takes:
//! the first hop reached through the relay or with `--direct`
//! ([`crate::ssh::transport`]), then the login and the command on the one
//! SSH client, `podssh_ssh::run`, with its output into the host's place as
//! it comes. No second SSH client. The session has a record of its own
//! (`podssh_ssh::outcome::scoped`), which the host's record reads (T-484).

use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_relay::token::Origin;
use podssh_ssh::outcome::Record;
use podssh_ssh::{Log, Request};
use tokio::sync::mpsc;

use super::fan::Ended;
use super::out::{self, Kept, Place};
use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{self, Env, Resolved, Transport};
use crate::ssh::transport;

/// One host, resolved before anything connects.
pub(crate) struct Plan {
    /// The host as the list names it, which each of its lines starts with.
    pub label: String,
    pub resolved: Resolved,
    pub log: Arc<Log>,
    /// `BatchMode` as `-o` and ssh_config give it, before each turns it on:
    /// with it, a snippet asks nothing (T-187).
    pub batch_mode: bool,
}

/// The plan of the host `label`: the command line of `args` with that
/// destination, no terminal, no input and no prompt, as `podssh ssh` would
/// resolve it, with the `Host` blocks of ssh_config for that host. Each
/// refusal names the host.
pub(crate) fn plan(label: &str, args: &SshArgs, env: &Env) -> Result<Plan, Refusal> {
    planned(label, args, env, false)
}

/// The plan of the host `label` for the broadcast (T-185): as [`plan`], with
/// a shell with no pty in place of a command, whose input the broadcast
/// gives it.
pub(crate) fn shell_plan(label: &str, args: &SshArgs, env: &Env) -> Result<Plan, Refusal> {
    planned(label, args, env, true)
}

fn planned(label: &str, args: &SshArgs, env: &Env, shell: bool) -> Result<Plan, Refusal> {
    let mut ssh = args.clone();
    ssh.destination = Some(label.to_string());
    // `-p` is for each host that names no port: a host's own port wins.
    if names_port(label) {
        ssh.port = None;
    }
    // Many sessions cannot share one terminal or one stdin.
    ssh.no_tty = true;
    ssh.stdin_null = true;
    let named = |r: Refusal| Refusal { message: format!("{label}: {}", r.message), code: r.code };
    let mut resolved = resolve::resolve_or_refuse(&ssh, env).map_err(named)?;
    if shell {
        shell_only(&mut resolved).map_err(named)?;
    } else if !matches!(resolved.options.request, Request::Exec(_)) {
        return Err(named(Refusal::usage(
            "SessionType in ssh_config asks for no command here, and podssh each runs one on each host",
        )));
    }
    // N questions at once cannot be answered: an unknown host key refuses
    // its host and names its fingerprint and accept-new.
    let batch_mode = resolved.options.batch_mode;
    resolved.options.set_batch_mode();
    let forwards = !resolved.local.is_empty() || !resolved.options.remote_forwards.is_empty();
    if forwards || resolved.x11.is_some() || resolved.control.path.is_some() {
        let note = "podssh each opens no forward, no X11 and no control socket: those of ssh_config are not used";
        resolved.notes.push(note.to_string());
    }
    resolved.options.remote_forwards.clear();
    // A LocalCommand's output would come with no host's label (T-191).
    if resolved.options.local_command.take().is_some() {
        resolved.notes.push("podssh each runs no LocalCommand: the one of ssh_config is not used".to_string());
    }
    let log = Arc::new(Log::new(resolved.options.log_level).with_prefix(format!("{label}: ")));
    Ok(Plan { label: label.to_string(), resolved, log, batch_mode })
}

/// Whether the host `label` names its own port: `host:PORT`,
/// `[v6]:PORT`, or a URI's `:PORT`, with or without a user. A bare IPv6
/// address names none.
pub(crate) fn names_port(label: &str) -> bool {
    let rest = ["ssh+tls://", "ssh://"].iter().find_map(|s| label.strip_prefix(s)).unwrap_or(label);
    let rest = rest.trim_end_matches('/');
    let rest = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    match rest.strip_prefix('[') {
        Some(inner) => inner.split_once(']').is_some_and(|(_, after)| after.len() > 1 && after.starts_with(':')),
        None => rest.matches(':').count() == 1 && !rest.ends_with(':'),
    }
}

/// A line of a host's session without the host that each's own prefix
/// names already: OpenSSH's `user@host: Permission denied` would read
/// `HOST: HOST: ...` (T-981).
pub(crate) fn unlabeled<'a>(label: &str, line: &'a str) -> &'a str {
    let Some((head, rest)) = line.split_once(": ") else { return line };
    let ours = label.strip_prefix(head).is_some_and(|after| after.is_empty() || after.starts_with(':'));
    if ours && !head.is_empty() && !rest.is_empty() {
        rest
    } else {
        line
    }
}

/// Each line of `text`, without the host that the prefix names, as one
/// error line of its own: a message of several lines keeps the prefix on
/// each.
fn say_error(log: &Log, label: &str, text: &str) {
    for line in text.lines().map(str::trim_end).filter(|l| !l.trim().is_empty()) {
        log.error(unlabeled(label, line.trim_start()));
    }
}

/// The one line of the summary for a failure of several lines: its first,
/// without the host (T-981).
pub(crate) fn first_line(label: &str, text: &str) -> String {
    let first = text.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("no connection");
    unlabeled(label, first).to_string()
}

/// The broadcast's shell (T-185): a `RemoteCommand` of ssh_config is not
/// used, with a note, and a `SessionType` that asks for no shell is
/// refused. Ctrl-C goes to no host there, so no session sends `signal INT`
/// for it; `:intr` asks for one.
fn shell_only(resolved: &mut Resolved) -> Result<(), Refusal> {
    let command = match &resolved.options.request {
        Request::Shell => false,
        Request::Exec(_) => true,
        _ => return Err(Refusal::usage("SessionType in ssh_config asks for no shell, and --interactive opens one")),
    };
    if command {
        let note = "podssh each --interactive opens a shell on each host: the RemoteCommand of ssh_config is not used";
        resolved.notes.push(note.to_string());
        resolved.options.request = Request::Shell;
    }
    resolved.options.interrupt_signal = false;
    Ok(())
}

/// What one host's session did, beside its end, for its record (T-484):
/// the session's own record, its time, and the streams that `--json` kept.
#[derive(Debug, Clone, Default)]
pub(crate) struct Ran {
    pub record: Record,
    pub took: Duration,
    pub kept: Option<Kept>,
}

/// `user@host:port` of the host of `plan`, as its login goes.
pub(crate) fn destination(plan: &Plan) -> String {
    let opts = &plan.resolved.options;
    let user = opts.destination.user.as_deref().unwrap_or(&opts.user);
    format!("{user}@{}", podssh_ws::dial::authority(&opts.destination.host, opts.destination.port))
}

/// Run the command on the host of `plan`, its output into `place` as it
/// comes; with `--output-dir`, its status into its status file at the end.
/// How it ended.
pub(crate) async fn run(plan: &Plan, place: Place) -> Ended {
    ran(plan, place).await.0
}

/// [`run`], and what the session did.
pub(crate) async fn ran(plan: &Plan, place: Place) -> (Ended, Ran) {
    let started = Instant::now();
    let status_file = match &place {
        Place::Files(files) => Some(files.status.clone()),
        Place::Lines { .. } | Place::Kept => None,
    };
    let (sink, pieces) = mpsc::channel(16);
    let mut opts = plan.resolved.options.clone();
    opts.output = Some(sink);
    let log = plan.log.clone();
    // The options, and with them the sink, go when the session ends: then
    // the drain has each piece, and ends too.
    let session = async move {
        let reached = match crate::layer_told::claimed(crate::ssh::node_roads::reach_any(&plan.resolved, &log)).await {
            Ok(reached) => reached,
            Err(failure) => {
                for line in &failure.lines {
                    say_error(&log, &plan.label, line);
                }
                // The class of the road that failed, as `podssh ssh` gives it.
                let leg = if matches!(plan.resolved.transport, Transport::Relay { .. }) { "relay" } else { "connect" };
                podssh_ssh::outcome::failure_is(leg);
                let why = failure.lines.first().map_or("no connection", String::as_str);
                return Ended::Failed(first_line(&plan.label, why));
            }
        };
        let relay = reached.relay.clone();
        opts.window_cap = crate::ssh::window::road(&plan.resolved.transport, &reached).cap();
        let mut outcome = podssh_ssh::run::run_outcome(reached.stream, &opts, reached.relay, log.clone()).await;
        let layered = reached.layer.is_some();
        transport::settle(reached.layer).await;
        // The road's cause once, not the client's echo of it (T-824).
        crate::layer_told::once(&mut outcome.lines, layered);
        // The relay's close, as `podssh ssh` keeps it.
        if let Some(end) = relay.as_ref().and_then(podssh_ssh::RelayStatus::get) {
            podssh_ssh::outcome::relay_end(&end);
        }
        for line in &outcome.lines {
            say_error(&log, &plan.label, line);
        }
        match outcome.lines.first() {
            Some(why) => Ended::Failed(first_line(&plan.label, why)),
            None => Ended::Status(outcome.code),
        }
    };
    // The session's own record: hosts at once each write theirs, and none
    // the process's (T-484).
    let session = podssh_ssh::outcome::scoped(session);
    let ((ended, record), drained) = tokio::join!(Box::pin(session), out::drain(pieces, place));
    let kept = drained.unwrap_or_else(|why| {
        plan.log.error(&why);
        None
    });
    if let (Some(path), Some(code)) = (status_file, ended.code()) {
        if let Err(why) = out::status(&path, code).await {
            plan.log.error(&why);
        }
    }
    (ended, Ran { record, took: started.elapsed(), kept })
}

/// A relay token before the fan-out, so that the hosts read the one that the
/// cache keeps, and the relay sees one mint, not one for each host. With no
/// cache (`PODSSH_CACHE_DIR=none`), each host mints its own, as each run
/// does; offline or with `--direct`, there is none to get.
pub(crate) async fn first_token(resolved: &Resolved, log: &Log) {
    let Transport::Relay { relays, trust, .. } = &resolved.transport else { return };
    if podssh_relay::open::offline() || matches!(podssh_relay::cache::chosen(), podssh_relay::cache::Chosen::Nothing) {
        return;
    }
    let proxy = podssh_ws::ProxyChoice::FromEnvironment;
    let ctx = podssh_relay::token::MintContext {
        relay: relays.primary(),
        trust,
        ctx: &podssh_relay::context::of(&proxy),
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
    };
    match podssh_relay::token::obtain(&ctx, false).await {
        Ok(token) => {
            let from = match token.origin {
                Origin::Environment => "PODSSH_RELAY_TOKEN",
                Origin::Cache => "the cache",
                Origin::Minted => "a mint, kept in the cache",
            };
            log.verbose(&format!("one relay token for each host, from {from}"));
        }
        Err(e) => {
            log.verbose(&format!(
                "no relay token before the hosts ({}); each host gets its own",
                podssh_ws::text::said(&e)
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_names_its_port_or_takes_p() {
        for (label, names) in [
            ("web1", false),
            ("u@web1", false),
            ("u@127.0.0.1:2201", true),
            ("127.0.0.1:1", true),
            ("[::1]:2201", true),
            ("u@[fe80::1]:22", true),
            ("[::1]", false),
            ("fe80::1", false),
            ("ssh://u@web1:2222/", true),
            ("ssh://web1", false),
            ("ssh+tls://web1:8443", true),
            ("u:x@web1", false),
        ] {
            assert_eq!(names_port(label), names, "{label}");
        }
    }

    #[test]
    fn a_line_names_its_host_once_and_the_summary_has_one_line() {
        for (label, line, want) in [
            ("nobody@127.0.0.1", "nobody@127.0.0.1: Permission denied (publickey).", "Permission denied (publickey)."),
            ("u@h:2201", "u@h: Permission denied (publickey).", "Permission denied (publickey)."),
            ("127.0.0.1", "nobody@127.0.0.1: Permission denied", "nobody@127.0.0.1: Permission denied"),
            ("web1", "connection refused", "connection refused"),
            ("web1", "web10: x", "web10: x"),
        ] {
            assert_eq!(unlabeled(label, line), want, "{label} {line}");
        }
        let three = "host key verification failed: 'h' is not a known host.\n  Its key is SHA256:x;\n  accept-new.";
        assert_eq!(first_line("h", three), "host key verification failed: 'h' is not a known host.");
        assert_eq!(first_line("h", "\n"), "no connection");
    }
}
