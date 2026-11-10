//! `podssh node NAME TARGET --ssh-j` (T-570): the node in front of the TCP
//! service TARGET over the ssh-j road (`crate::sshj`), through `ssh-j.com`,
//! a public SSH jump and forwarding server with no account, or the server of
//! `PODSSH_SSH_J`. Its leg is SSH to the server on port 22, directly or by
//! `HTTPS_PROXY`'s CONNECT, logged in as a user derived from the node's key,
//! with one remote forward of an address derived from it too: a client that
//! holds the key reaches the node by that name with no other word. Anyone
//! may take any name there, so the road needs the end-to-end channel and a
//! door: `--allow`, or the net's members where the node's key is one.
//!
//! A last fallback (the operator's ruling Q78), after the Pinggy road: a
//! node that would serve the OpenTunnel road or the Pinggy road unasked
//! serves this one when neither reached a service, or when both are off,
//! and says that a third party that nobody vouches for carries its
//! sessions. `PODSSH_SSH_J=no` turns the road off, and so does
//! `PODSSH_LAST_RESORT=no`. The road is served alone: a pair is not served
//! beside it (T-570's Decision). stdout stays empty.

use std::io::Write;
use std::time::Duration;

use podssh_relay::reverse::routes::Route;
use podssh_relay::session::Settings;

use crate::exitmap::Fault;
use crate::node::NodeArgs;
use crate::node_derp::Door;
use crate::relay_settings::Refusal;
use crate::sshj::{self, Service, Setting};

/// The bound on a node's first leg when it serves the road unasked.
pub(crate) const UNASKED_LIMIT: Duration = Duration::from_secs(30);

/// `PODSSH_SSH_J` and `PODSSH_LAST_RESORT`, read: a value that is none of
/// their forms is a setting that cannot be used (78).
pub(crate) fn setting() -> Result<Setting, Refusal> {
    sshj::from_env().map_err(Refusal::config)
}

/// Why a node that no road was asked of would serve a last fallback
/// unasked: the node of the OpenTunnel road's unasked serving, else of the
/// Pinggy road's (`crate::node_pinggy::last_node`).
fn last_of_all(args: &NodeArgs) -> Option<String> {
    let opentunnel = crate::node_opentunnel::unasked(args).ok().flatten();
    opentunnel.or_else(|| crate::node_pinggy::last_node(args).ok().flatten())
}

/// The OpenTunnel road, then the Pinggy road, then this one, each asked, or
/// unasked as the last of a node with no other road: the exit code of the
/// run; none when the node takes another road.
pub(crate) fn tunnels(args: &NodeArgs, err: &mut dyn Write) -> Option<i32> {
    if args.ssh_j && (args.opentunnel || args.pinggy) {
        let why =
            "--ssh-j is one road and --opentunnel and --pinggy are others: give one; run a second node for another";
        return Some(Refusal::usage(why).report("node", err));
    }
    let tunnel = crate::node_opentunnel::dispatch(args, err);
    let tunnel = tunnel.map(|code| crate::node_pinggy::after_opentunnel(args, code, err).unwrap_or(code));
    match tunnel.or_else(|| crate::node_pinggy::dispatch(args, err)) {
        Some(code) => Some(after_pinggy(args, code, err).unwrap_or(code)),
        None => dispatch(args, err),
    }
}

/// After a road of a tunnel that a node served unasked ended with `code`:
/// when it reached no service, this road, the last, unasked too (Q78).
fn after_pinggy(args: &NodeArgs, code: i32, err: &mut dyn Write) -> Option<i32> {
    if code != Fault::RelayUnreachable.code() || args.opentunnel || args.pinggy || args.ssh_j {
        return None;
    }
    let why = last_of_all(args)?;
    if !matches!(setting(), Ok(Setting::On(_))) {
        return None;
    }
    let why = format!("{why}, and no road of a tunnel before this one reached its service");
    Some(run(args, Some(why), err))
}

/// The road asked with `--ssh-j`; or unasked, by a node that neither the
/// OpenTunnel road nor the Pinggy road took, as both are off.
fn dispatch(args: &NodeArgs, err: &mut dyn Write) -> Option<i32> {
    if args.ssh_j {
        return Some(run(args, None, err));
    }
    let why = last_of_all(args)?;
    match setting() {
        Ok(Setting::On(_)) => {}
        Ok(_) => return None,
        Err(refusal) => return Some(refusal.report("node", err)),
    }
    let why = format!("{why}, and {}=no turns the Pinggy road off", podssh_relay::pinggy::ENV);
    Some(run(args, Some(why), err))
}

/// The flags of the road, checked before anything is read.
pub(crate) fn check(args: &NodeArgs) -> Result<(), Refusal> {
    if args.plain {
        return Err(Refusal::usage("--plain is for the pair's road: the ssh-j road always runs the resumable layer"));
    }
    if args.no_e2e {
        return Err(Refusal::usage(
            "--no-e2e cannot go with --ssh-j: anyone may take any name at ssh-j.com, which ends the leg's SSH and \
             is a third party that nobody vouches for, so the end-to-end channel and its allowlist are the node's \
             only door",
        ));
    }
    if crate::node_derp::has_udp(args) {
        return Err(Refusal::usage("a udp: TARGET goes on the pair's road: the ssh-j road carries TCP only"));
    }
    if args.exit {
        return Err(Refusal::usage("--exit goes on the pair's road and the DERP road: --ssh-j does not carry it"));
    }
    if args.opentunnel || args.pinggy || args.iroh || args.derp {
        return Err(Refusal::usage(
            "--ssh-j is one road and --opentunnel, --pinggy, --iroh and --derp are others: give one; run a second \
             node for another",
        ));
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
        Setting::Off(by) => return Err(Refusal::usage(format!("--ssh-j: {by}=no turns the ssh-j road off"))),
        // No server to name in the list of services: a setting that is missing.
        Setting::Unnamed => return Err(Refusal::config(format!("--ssh-j: {}", sshj::unnamed_words()))),
    };
    let targets = crate::node::targets_of(&crate::node::words_of(args), args.no_e2e)?;
    let flags = crate::node::key_flags(args)?;
    let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    let why_open = "anyone may take any name at ssh-j.com, which is a third party that nobody vouches for";
    let door = crate::node_derp::door_of("--ssh-j", why_open, flags.allow.as_deref(), &place)?;
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

/// Run the node of the ssh-j road; `unasked` is why it serves the road with
/// no `--ssh-j`. Returns the process exit code.
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
    let mut code = runtime.block_on(Box::pin(crate::node_sshj_serve::serve(ready, err)));
    // An upgrade whose binary did not start: this one serves its sessions
    // again, from a new start of the road (T-679).
    while code == crate::node_upgrade::AGAIN {
        code = match prepare(args, unasked.clone()) {
            Ok(ready) => runtime.block_on(Box::pin(crate::node_sshj_serve::serve(ready, err))),
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
            ssh_j: true,
            ..NodeArgs::default()
        };
        for (flag, args) in [
            ("--plain", NodeArgs { plain: true, ..base() }),
            ("--no-e2e", NodeArgs { no_e2e: true, ..base() }),
            ("udp:", NodeArgs { targets: vec!["udp:127.0.0.1:53".into()], ..base() }),
            ("--exit", NodeArgs { exit: true, ..base() }),
            ("--pinggy", NodeArgs { pinggy: true, ..base() }),
            ("--opentunnel", NodeArgs { opentunnel: true, ..base() }),
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
            NodeArgs { ssh_j: true, ..NodeArgs::default() },
            NodeArgs { pinggy: true, ..NodeArgs::default() },
            NodeArgs { opentunnel: true, ..NodeArgs::default() },
            NodeArgs { frp: Some("frp.toml".into()), ..NodeArgs::default() },
        ] {
            assert_eq!(crate::node_pinggy::last_node(&args).ok().flatten(), None, "{args:?}");
            let mut sink = Vec::new();
            assert_eq!(after_pinggy(&args, Fault::RelayUnreachable.code(), &mut sink), None, "{args:?}");
        }
    }
}
