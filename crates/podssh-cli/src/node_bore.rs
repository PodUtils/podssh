//! `podssh node NAME TARGET --bore` (T-569): the node in front of the TCP
//! service TARGET over the bore road (`podssh_relay::bore`), through
//! bore.pub, a public server of bore's protocol with no account, or the
//! server of `PODSSH_BORE`. Its control connection is raw TCP to the
//! server's port 7835, directly or by `HTTPS_PROXY`'s CONNECT; it asks a
//! public port that its key gives, the next of a series of four where the
//! server refuses one, so a client that holds the key derives the ports
//! with no other word. Anyone may take any port there, so the road needs
//! the end-to-end channel and a door: `--allow`, or the net's members where
//! the node's key is one.
//!
//! A last fallback (the operator's ruling Q78), the last of all, after the
//! localtunnel road: a node that would serve the OpenTunnel road, the Pinggy
//! road, Serveo's, ssh-j's, localhost.run's or localtunnel's unasked serves
//! this one when none of them reached a service, or when each is off, and says that a third party that nobody
//! vouches for carries its sessions. `PODSSH_BORE=no` turns the road off,
//! and so does `PODSSH_LAST_RESORT=no`. The road is served alone, as the
//! ssh-j road is: a pair is not served beside it. stdout stays empty.

use std::io::Write;

use podssh_relay::bore::{self, Service, Setting};
use podssh_relay::reverse::routes::Route;
use podssh_relay::session::Settings;

use crate::exitmap::Fault;
use crate::node::NodeArgs;
use crate::node_derp::Door;
use crate::relay_settings::Refusal;

/// `PODSSH_BORE` and `PODSSH_LAST_RESORT`, read: a value that is none of
/// their forms is a setting that cannot be used (78).
pub(crate) fn setting() -> Result<Setting, Refusal> {
    bore::from_env().map_err(Refusal::config)
}

/// Each road of a tunnel before this one, asked, or unasked as the last of a
/// node with no other road (`crate::node_localtunnel::tunnels`, which wraps
/// `crate::node_sshj::tunnels`), then this one: the exit code of the run;
/// none when the node takes another road.
pub(crate) fn tunnels(args: &NodeArgs, err: &mut dyn Write) -> Option<i32> {
    if args.bore {
        return Some(run(args, None, err));
    }
    match crate::node_localtunnel::tunnels(args, err) {
        Some(code) => Some(after(args, code, err).unwrap_or(code)),
        None => dispatch(args, err),
    }
}

/// After a road of a tunnel that a node served unasked ended with `code`:
/// when it reached no service, this road, the last of all, unasked too (Q78).
fn after(args: &NodeArgs, code: i32, err: &mut dyn Write) -> Option<i32> {
    let asked = args.tunnel_asked() || args.frp.is_some();
    if code != Fault::RelayUnreachable.code() || asked {
        return None;
    }
    let why = crate::node_sshj::last_of_all(args)?;
    if !matches!(setting(), Ok(Setting::On(_))) {
        return None;
    }
    let why = format!("{why}, and no road of a tunnel before this one reached its service");
    Some(run(args, Some(why), err))
}

/// Unasked, by a node that none of the roads of a tunnel before it took, as
/// each is off.
fn dispatch(args: &NodeArgs, err: &mut dyn Write) -> Option<i32> {
    let why = crate::node_sshj::last_of_all(args)?;
    match setting() {
        Ok(Setting::On(_)) => {}
        Ok(_) => return None,
        Err(refusal) => return Some(refusal.report("node", err)),
    }
    // The ssh-j, localhost.run and localtunnel roads, the ones before it,
    // are each off by a switch or have no server; the roads before them are
    // off too (`last_of_all`).
    let said = |off: Option<&str>, road: &str| match off {
        Some(by) => format!("{by}=no turns the {road} road off"),
        None => format!("the {road} road has no server"),
    };
    let ssh_j = match crate::node_sshj::setting() {
        Ok(crate::sshj::Setting::Off(by)) => Some(by),
        _ => None,
    };
    let ssh_r = match crate::node_ssh_http::setting(podssh_relay::ssh_http::LOCALHOST_RUN) {
        Ok(podssh_relay::ssh_http::Setting::Off(by)) => Some(by),
        _ => None,
    };
    let localtunnel = match crate::node_localtunnel::setting() {
        Ok(podssh_relay::localtunnel::Setting::Off(by)) => Some(by),
        _ => None,
    };
    let (ssh_j, ssh_r, lt) = (said(ssh_j, "ssh-j"), said(ssh_r, "localhost.run"), said(localtunnel, "localtunnel"));
    let why = format!("{why}, and {ssh_j}, {ssh_r} and {lt}, as each road of a tunnel before the bore road is off");
    Some(run(args, Some(why), err))
}

/// The flags of the road, checked before anything is read.
pub(crate) fn check(args: &NodeArgs) -> Result<(), Refusal> {
    if args.plain {
        return Err(Refusal::usage("--plain is for the pair's road: the bore road always runs the resumable layer"));
    }
    if args.no_e2e {
        return Err(Refusal::usage(
            "--no-e2e cannot go with --bore: anyone may take any port at bore.pub, which carries raw TCP and is a \
             third party that nobody vouches for, so the end-to-end channel and its allowlist are the node's only \
             door",
        ));
    }
    if crate::node_derp::has_udp(args) {
        return Err(Refusal::usage("a udp: TARGET goes on the pair's road: the bore road carries TCP only"));
    }
    if args.exit {
        return Err(Refusal::usage("--exit goes on the pair's road and the DERP road: --bore does not carry it"));
    }
    let others = [
        (args.opentunnel, "--opentunnel"),
        (args.pinggy, "--pinggy"),
        (args.serveo, "--serveo"),
        (args.ssh_j, "--ssh-j"),
        (args.localhost_run, "--localhost-run"),
        (args.sandhole, "--sandhole"),
        (args.srv_us, "--srv-us"),
        (args.localtunnel, "--localtunnel"),
        (args.iroh, "--iroh"),
        (args.derp, "--derp"),
        (args.quick_tunnel, "--quick-tunnel"),
        (args.frp.is_some(), "--frp"),
    ];
    if let Some((_, flag)) = others.iter().find(|(given, _)| *given) {
        let why = format!("--bore is one road and {flag} is another: give one; run a second node for another");
        return Err(Refusal::usage(why));
    }
    Ok(())
}

/// Each check of the node that needs no network, done.
pub(crate) struct Ready {
    pub label: String,
    pub targets: Vec<Route>,
    pub roost: bool,
    pub key: podssh_relay::identity::file::Key,
    pub door: Door,
    pub service: Service,
    pub unasked: Option<String>,
    /// Why a pair of the node is not served beside the road, when it has one.
    pub pair_left: Option<String>,
}

fn prepare(args: &NodeArgs, unasked: Option<String>) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the node's name, which labels its key")?;
    crate::pairs::check_label(&label)?;
    check(args)?;
    let service = match setting()? {
        Setting::On(service) => service,
        Setting::Off(by) => return Err(Refusal::usage(format!("--bore: {by}=no turns the bore road off"))),
        // No server to name in the list of services: a setting that is missing.
        Setting::Unnamed => return Err(Refusal::config(format!("--bore: {}", bore::unnamed_words()))),
    };
    let targets = crate::node::targets_of(&crate::node::words_of(args), args.no_e2e)?;
    let flags = crate::node::key_flags(args)?;
    let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    let why_open = "anyone may take any port at bore.pub, which is a third party that nobody vouches for";
    let door = crate::node_derp::door_of("--bore", why_open, flags.allow.as_deref(), &place)?;
    let pair_left = match &args.pair_file {
        Some(_) => Some("--pair-file".to_string()),
        None => crate::pairs::stored(&label).ok().map(|_| format!("the pair {label}")),
    };
    crate::pairs::online()?;
    // The key is made only once each check passed; one for this run only
    // stays across an upgrade in place (T-679).
    let key = crate::node_upgrade::parts::node_key(&place)?;
    Ok(Ready { label, targets, roost: args.sshd, key, door, service, unasked, pair_left })
}

/// Run the node of the bore road; `unasked` is why it serves the road with
/// no `--bore`. Returns the process exit code.
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
    let mut code = runtime.block_on(Box::pin(crate::node_bore_serve::serve(ready, err)));
    // An upgrade whose binary did not start: this one serves its sessions
    // again, from a new start of the road (T-679).
    while code == crate::node_upgrade::AGAIN {
        code = match prepare(args, unasked.clone()) {
            Ok(ready) => runtime.block_on(Box::pin(crate::node_bore_serve::serve(ready, err))),
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
            bore: true,
            ..NodeArgs::default()
        };
        for (flag, args) in [
            ("--plain", NodeArgs { plain: true, ..base() }),
            ("--no-e2e", NodeArgs { no_e2e: true, ..base() }),
            ("udp:", NodeArgs { targets: vec!["udp:127.0.0.1:53".into()], ..base() }),
            ("--exit", NodeArgs { exit: true, ..base() }),
            ("--pinggy", NodeArgs { pinggy: true, ..base() }),
            ("--opentunnel", NodeArgs { opentunnel: true, ..base() }),
            ("--serveo", NodeArgs { serveo: true, ..base() }),
            ("--ssh-j", NodeArgs { ssh_j: true, ..base() }),
            ("--localhost-run", NodeArgs { localhost_run: true, ..base() }),
            ("--localtunnel", NodeArgs { localtunnel: true, ..base() }),
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
            NodeArgs { bore: true, ..NodeArgs::default() },
            NodeArgs { ssh_j: true, ..NodeArgs::default() },
            NodeArgs { pinggy: true, ..NodeArgs::default() },
            NodeArgs { serveo: true, ..NodeArgs::default() },
            NodeArgs { opentunnel: true, ..NodeArgs::default() },
            NodeArgs { localhost_run: true, ..NodeArgs::default() },
            NodeArgs { localtunnel: true, ..NodeArgs::default() },
            NodeArgs { frp: Some("frp.toml".into()), ..NodeArgs::default() },
        ] {
            assert_eq!(crate::node_sshj::last_of_all(&args), None, "{args:?}");
            let mut sink = Vec::new();
            assert_eq!(after(&args, Fault::RelayUnreachable.code(), &mut sink), None, "{args:?}");
        }
    }
}
