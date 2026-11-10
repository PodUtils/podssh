//! `podssh node NAME [TARGET] --localtunnel` (T-568): the node behind a
//! tunnel of localtunnel's public server, which needs no account, or of the
//! server of `PODSSH_LOCALTUNNEL` (`podssh_relay::localtunnel`). The node
//! asks the server's API over HTTPS, through `HTTPS_PROXY` when one is set,
//! for a name that its key gives, then keeps the tunnel's TCP connections to
//! the port that the server names, directly or by the proxy's CONNECT: the
//! server's OS chose that port, so a proxy that lets CONNECT reach port 443
//! alone refuses it, and the node needs an egress that reaches it; a client
//! reaches the name on 443. Each visitor's WebSocket is one link of the
//! resumable layer, with the end-to-end channel above it, to TARGET; with
//! `--relay`, the relay role of `podssh relay serve` answers its own paths
//! on the same connections, as behind the quick tunnel (T-428,
//! `node_quick_relay`), and TARGET may be left out. The tunnel's URL is the
//! one line on stdout, the relay host of `--relay-host`.
//!
//! A last fallback (the operator's ruling Q78), after the ssh-j road and
//! localhost.run's (T-565), before bore's (T-569, `crate::node_bore`): a node that would serve the
//! OpenTunnel road, the Pinggy road, Serveo's, ssh-j's or localhost.run's
//! unasked serves this one when none of them reached a service, or when
//! each is off or has no server, and says that a third
//! party that nobody vouches for carries its sessions; unasked it serves
//! TARGET alone, as `--relay` is asked. `PODSSH_LOCALTUNNEL=no` turns the
//! road off, and so does `PODSSH_LAST_RESORT=no`. The road is served alone:
//! a pair is not served beside it (T-568's Decision).

use std::io::Write;
use std::time::Duration;

use podssh_relay::localtunnel::{self, Service, Setting};
use podssh_relay::reverse::routes::Route;
use podssh_relay::session::Settings;
use podssh_ws::Trust;

use crate::exitmap::Fault;
use crate::node::NodeArgs;
use crate::node_derp::Door;
use crate::node_quick_relay::Role;
use crate::relay_settings::Refusal;

/// The bound on a node's first tunnel when it serves the road unasked.
pub(crate) const UNASKED_LIMIT: Duration = Duration::from_secs(30);

/// `PODSSH_LOCALTUNNEL` and `PODSSH_LAST_RESORT`, read: a value that is none
/// of their forms is a setting that cannot be used (78).
pub(crate) fn setting() -> Result<Setting, Refusal> {
    localtunnel::from_env().map_err(Refusal::config)
}

/// `--quick-tunnel`, or `--localtunnel`: a node whose name is public and
/// whose relay role `--relay` serves with no listener (T-428). Both at once
/// are refused by the quick tunnel's checks.
pub(crate) fn or_quick(args: &NodeArgs, err: &mut dyn Write) -> i32 {
    if args.localtunnel && !args.quick_tunnel {
        return run(args, None, err);
    }
    crate::node_quick::run(args, err)
}

/// Whether a road of a tunnel, or the frp road, was asked of the node.
fn asked_any(args: &NodeArgs) -> bool {
    args.tunnel_asked() || args.frp.is_some()
}

/// The OpenTunnel road, then the Pinggy road, Serveo's, ssh-j's and
/// localhost.run's (`node_sshj::tunnels`), each asked, or unasked as the
/// last of a node with no other road; then this one, unasked, before bore's
/// (`node_bore::tunnels` wraps this): the exit code of the run; none when
/// the node takes another road.
pub(crate) fn tunnels(args: &NodeArgs, err: &mut dyn Write) -> Option<i32> {
    match crate::node_sshj::tunnels(args, err) {
        Some(code) => Some(after(args, code, err).unwrap_or(code)),
        None => unasked(args, err),
    }
}

/// After a road of a tunnel that a node served unasked ended with `code`:
/// when it reached no service, this road, the last, unasked too (Q78).
fn after(args: &NodeArgs, code: i32, err: &mut dyn Write) -> Option<i32> {
    if code != Fault::RelayUnreachable.code() || asked_any(args) {
        return None;
    }
    let why = crate::node_sshj::last_of_all(args)?;
    if !matches!(setting(), Ok(Setting::On(_))) {
        return None;
    }
    let why = format!("{why}, and no road of a tunnel before this one reached its service");
    Some(run(args, Some(why), err))
}

/// Unasked, by a node that no road of a tunnel before this one took, as
/// each is off or has no server.
fn unasked(args: &NodeArgs, err: &mut dyn Write) -> Option<i32> {
    if asked_any(args) {
        return None;
    }
    let why = crate::node_sshj::last_of_all(args)?;
    match setting() {
        Ok(Setting::On(_)) => {}
        Ok(_) => return None,
        Err(refusal) => return Some(refusal.report("node", err)),
    }
    let why = format!("{why}, and each road of a tunnel before this one is off or has no server");
    Some(run(args, Some(why), err))
}

/// The flags of the road, checked before anything is read.
pub(crate) fn check(args: &NodeArgs) -> Result<(), Refusal> {
    if args.plain {
        let why = "--plain is for the pair's road: the localtunnel road always runs the resumable layer";
        return Err(Refusal::usage(why));
    }
    if args.no_e2e {
        return Err(Refusal::usage(
            "--no-e2e cannot go with --localtunnel: anyone may reach a tunnel's name, or connect to its port at the \
             server, which is a third party that nobody vouches for and ends the visitors' TLS, so the end-to-end \
             channel and its allowlist are the node's only door",
        ));
    }
    if crate::node_derp::has_udp(args) {
        return Err(Refusal::usage("a udp: TARGET goes on the pair's road: the localtunnel road carries TCP only"));
    }
    if args.exit {
        return Err(Refusal::usage(
            "--exit goes on the pair's road and the DERP road: --localtunnel does not carry it",
        ));
    }
    let others = [
        (args.opentunnel, "--opentunnel"),
        (args.pinggy, "--pinggy"),
        (args.serveo, "--serveo"),
        (args.ssh_j, "--ssh-j"),
        (args.localhost_run, "--localhost-run"),
        (args.bore, "--bore"),
        (args.iroh, "--iroh"),
        (args.derp, "--derp"),
        (args.quick_tunnel, "--quick-tunnel"),
        (args.frp.is_some(), "--frp"),
    ];
    if let Some((_, flag)) = others.iter().find(|(given, _)| *given) {
        let why = format!("--localtunnel is one road and {flag} is another: give one; run a second node for another");
        return Err(Refusal::usage(why));
    }
    Ok(())
}

/// Each check of the node that needs no network, done.
pub(crate) struct Ready {
    pub label: String,
    /// None with `--relay` alone: the node is the relay, with no TARGET.
    pub targets: Vec<Route>,
    pub roost: bool,
    pub key: podssh_relay::identity::file::Key,
    pub door: Door,
    pub service: Service,
    pub trust: Trust,
    pub unasked: Option<String>,
    /// Why a pair of the node is not served beside the road, when it has one.
    pub pair_left: Option<String>,
    /// The relay role behind the tunnel (`--relay`).
    pub role: Option<Role>,
}

/// The trust of the server: the hosted one is a public service, whose names
/// the host's roots check (`SSL_CERT_FILE`, else the default stores), never
/// the pair relay's `--ca-file`; a server that `PODSSH_LOCALTUNNEL` names
/// takes `--ca-file`, as it may be the user's own, under the same CA.
fn trust_for(service: &Service, ca_file: Option<&str>) -> Trust {
    match Service::hosted() {
        Some(hosted) if hosted == *service => crate::pairs::trust(None),
        _ => crate::pairs::trust(ca_file),
    }
}

fn prepare(args: &NodeArgs, unasked: Option<String>) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the node's name, which labels its key")?;
    crate::pairs::check_label(&label)?;
    check(args)?;
    let service = match setting()? {
        Setting::On(service) => service,
        Setting::Off(by) => {
            return Err(Refusal::usage(format!("--localtunnel: {by}=no turns the localtunnel road off")));
        }
        // No server to name in the list of services: a setting that is missing.
        Setting::Unnamed => return Err(Refusal::config(format!("--localtunnel: {}", localtunnel::unnamed_words()))),
    };
    // With --relay and no TARGET, the node is the relay alone (T-428).
    let words = crate::node::words_of(args);
    let targets = match words.is_empty() && args.relay {
        true => Vec::new(),
        false => crate::node::targets_of(&words, false)?,
    };
    let flags = crate::node::key_flags(args)?;
    let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    let why_open = "anyone may reach a tunnel's name, or its port at the server, a third party that nobody vouches for";
    let door = crate::node_derp::door_of("--localtunnel", why_open, flags.allow.as_deref(), &place)?;
    // The role's lists, read before anything connects (T-646).
    crate::node_quick_relay::precheck(args, &door)?;
    let pair_left = match &args.pair_file {
        Some(_) => Some("--pair-file".to_string()),
        None => crate::pairs::stored(&label).ok().map(|_| format!("the pair {label}")),
    };
    crate::pairs::online()?;
    let trust = trust_for(&service, args.ca_file.as_deref());
    // The key is made only once each check passed; one for this run only
    // stays across an upgrade in place (T-679).
    let key = crate::node_upgrade::parts::node_key(&place)?;
    // After the key: the net's `relay:NAME` names the node by it (T-455).
    let role = crate::node_quick_relay::role(args, &label, &door, key.identity.public())?;
    Ok(Ready { label, targets, roost: args.sshd, key, door, service, trust, unasked, pair_left, role })
}

/// Run the node of the localtunnel road; `unasked` is why it serves the road
/// with no `--localtunnel`. Returns the process exit code.
pub fn run(args: &NodeArgs, unasked: Option<String>, err: &mut dyn Write) -> i32 {
    let ready = match prepare(args, unasked.clone()) {
        Ok(ready) => ready,
        Err(refusal) => return refusal.report("node", err),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh node: could not start the async runtime: {e}");
            return Fault::SessionFault.code();
        }
    };
    // A run of --restart beats from this runtime, while it polls (T-394).
    crate::detach::beat::keep(runtime.handle());
    // On the heap: Windows gives the main thread 1 MiB of stack.
    let mut code = runtime.block_on(Box::pin(crate::node_localtunnel_serve::serve(ready, err)));
    // An upgrade whose binary did not start: this one serves its sessions
    // again, from a new start of the road (T-679).
    while code == crate::node_upgrade::AGAIN {
        code = match prepare(args, unasked.clone()) {
            Ok(ready) => runtime.block_on(Box::pin(crate::node_localtunnel_serve::serve(ready, err))),
            Err(refusal) => refusal.report("node", err),
        };
    }
    // A session may still be closing; the node has ended, so none is waited for.
    runtime.shutdown_background();
    code
}

/// The settings of the layer on the road: no window of the pair's relay.
pub(crate) fn settings() -> Settings {
    crate::layered::settings().off_the_pair()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_of_the_road_takes_no_flag_that_would_open_its_door_or_change_its_road() {
        let base = || NodeArgs {
            name: Some("lab".into()),
            targets: vec!["127.0.0.1:22".into()],
            localtunnel: true,
            ..NodeArgs::default()
        };
        for (flag, args) in [
            ("--plain", NodeArgs { plain: true, ..base() }),
            ("--no-e2e", NodeArgs { no_e2e: true, ..base() }),
            ("udp:", NodeArgs { targets: vec!["udp:127.0.0.1:53".into()], ..base() }),
            ("--exit", NodeArgs { exit: true, ..base() }),
            ("--pinggy", NodeArgs { pinggy: true, ..base() }),
            ("--ssh-j", NodeArgs { ssh_j: true, ..base() }),
            ("--localhost-run", NodeArgs { localhost_run: true, ..base() }),
            ("--bore", NodeArgs { bore: true, ..base() }),
            ("--quick-tunnel", NodeArgs { quick_tunnel: true, ..base() }),
            ("--frp", NodeArgs { frp: Some("frp.toml".into()), ..base() }),
        ] {
            let refusal = check(&args).unwrap_err();
            assert_eq!(refusal.code, 64, "{flag}: {}", refusal.message);
            assert!(refusal.message.contains(flag), "{flag}: {}", refusal.message);
        }
        assert!(check(&base()).is_ok());
    }

    #[test]
    fn a_node_that_asked_for_a_road_never_serves_this_one_unasked() {
        for args in [
            NodeArgs { localtunnel: true, ..NodeArgs::default() },
            NodeArgs { ssh_j: true, ..NodeArgs::default() },
            NodeArgs { pinggy: true, ..NodeArgs::default() },
            NodeArgs { serveo: true, ..NodeArgs::default() },
            NodeArgs { opentunnel: true, ..NodeArgs::default() },
            NodeArgs { frp: Some("frp.toml".into()), ..NodeArgs::default() },
        ] {
            let mut sink = Vec::new();
            assert_eq!(after(&args, Fault::RelayUnreachable.code(), &mut sink), None, "{args:?}");
            assert_eq!(unasked(&args, &mut sink), None, "{args:?}");
            assert!(sink.is_empty(), "{args:?}");
        }
    }
}
