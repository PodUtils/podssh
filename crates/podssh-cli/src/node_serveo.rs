//! `podssh node NAME TARGET --serveo` (T-549): the node in front of the TCP
//! service TARGET over the Serveo road of `podssh-relay`, through a private
//! alias at Serveo, which needs no account, or at the server of
//! `PODSSH_SERVEO`. Its leg is raw SSH on port 443, then 22 (`serveo_leg`);
//! the alias is derived from the node's key, so a client that holds the key
//! (its pins of NAME, `--node-key`, the net) computes it, and the node only
//! says it. Where another tunnel holds the alias, the node takes the next of
//! its series. The tunnel is opened again after each end, with the first
//! alias first; a session that the layer keeps moves to the new tunnel when
//! its client links again. With the pair NAME, or the one of `--pair-file`,
//! it serves the pair's road too, with one keeper for both, as Pinggy's node
//! does. Anyone who knows the alias may open a channel to it, so the road
//! needs the end-to-end channel and a door: `--allow`, or the net's members
//! where the node's key is one (T-452).
//!
//! A last fallback (the operator's ruling Q78), the last of all: a node with
//! no road asked of it, which would serve the Pinggy road unasked, serves
//! this one after the Pinggy road reached no server, or in its place where
//! it is off, and says that a third party that nobody vouches for carries
//! its sessions. `PODSSH_SERVEO=no` turns the road off, and so does
//! `PODSSH_LAST_RESORT=no`. Serveo's server is the one of `pod-services`;
//! where it names none, only `PODSSH_SERVEO=HOST` gives the road a server.
//! stdout stays empty.

use std::io::Write;

use podssh_relay::pair::Pair;
use podssh_relay::reverse::routes::Route;
use podssh_relay::serveo::{self, Service, Setting};
use podssh_ws::Trust;

use crate::exitmap::Fault;
use crate::node::NodeArgs;
use crate::node_derp::Door;
use crate::relay_settings::Refusal;

/// `PODSSH_SERVEO` and `PODSSH_LAST_RESORT`, read: a value that is none of
/// their forms is a setting that cannot be used (78).
pub(crate) fn setting() -> Result<Setting, Refusal> {
    let value = std::env::var(serveo::ENV).ok();
    let last = std::env::var(serveo::LAST_RESORT).ok();
    serveo::setting(value.as_deref(), last.as_deref()).map_err(Refusal::config)
}

/// The server of the road, when the road is on and has one; else why not.
pub(crate) fn service() -> Result<Result<Service, String>, Refusal> {
    Ok(match setting()? {
        Setting::On(service) => Ok(service),
        Setting::Off(by) => Err(format!("{by}=no turns the Serveo road off")),
        Setting::Unnamed => Err(serveo::UNNAMED.to_string()),
    })
}

/// The road of `args`: asked with `--serveo`; else unasked, the last of all,
/// for the node that the Pinggy road would serve unasked
/// (`node_pinggy::last_node`), or with `why`, after the OpenTunnel road that
/// reached no service, while the Pinggy road is off. None when the node
/// takes another road.
pub(crate) fn dispatch(args: &NodeArgs, why: Option<String>, err: &mut dyn Write) -> Option<i32> {
    if args.serveo {
        return Some(run(args, None, err));
    }
    let why = match why.map(Ok).or_else(|| crate::node_pinggy::last_node(args).transpose()) {
        Some(Ok(why)) => why,
        Some(Err(refusal)) => return Some(refusal.report("node", err)),
        None => return None,
    };
    let pinggy_off = match crate::node_pinggy::service() {
        Ok(Ok(_)) => return None,
        Ok(Err(by)) => by,
        Err(refusal) => return Some(refusal.report("node", err)),
    };
    match service() {
        Ok(Ok(_)) => Some(run(args, Some(format!("{why}, and {pinggy_off}=no turns the Pinggy road off")), err)),
        Ok(Err(_)) => None,
        Err(refusal) => Some(refusal.report("node", err)),
    }
}

/// After the Pinggy road that a node served unasked for `why` ended with
/// `code`: when it reached no server, this road, unasked too, the last.
pub(crate) fn after(args: &NodeArgs, code: i32, why: &str, err: &mut dyn Write) -> Option<i32> {
    if code != Fault::RelayUnreachable.code() || args.serveo || !matches!(service(), Ok(Ok(_))) {
        return None;
    }
    Some(run(args, Some(format!("{why}, and the Pinggy road reached no server")), err))
}

/// The flags of the road, checked before anything is read.
pub(crate) fn check(args: &NodeArgs) -> Result<(), Refusal> {
    if args.plain {
        return Err(Refusal::usage("--plain is for the pair's road: the Serveo road always runs the resumable layer"));
    }
    if args.no_e2e {
        return Err(Refusal::usage(
            "--no-e2e cannot go with --serveo: anyone who knows the alias may connect to it, and Serveo is a third \
             party that nobody vouches for, so the end-to-end channel and its allowlist are the node's only door",
        ));
    }
    if crate::node_derp::has_udp(args) {
        return Err(Refusal::usage("a udp: TARGET goes on the pair's road: the Serveo road carries TCP only"));
    }
    if args.exit {
        return Err(Refusal::usage("--exit goes on the pair's road and the DERP road: --serveo does not carry it"));
    }
    if args.opentunnel || args.pinggy || args.ssh_j || args.iroh || args.derp {
        return Err(Refusal::usage(
            "--serveo is one road and --opentunnel, --pinggy, --ssh-j, --iroh and --derp are others: give one; run a \
             second node for another",
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
    pub trust: Trust,
    pub pair: Result<(Pair, bool), String>,
    pub unasked: Option<String>,
}

fn prepare(args: &NodeArgs, unasked: Option<String>) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the node's name, which labels its key")?;
    crate::pairs::check_label(&label)?;
    check(args)?;
    let service = match service()? {
        Ok(service) => service,
        Err(why) => return Err(Refusal::usage(format!("--serveo: {why}"))),
    };
    let targets = crate::node::targets_of(&crate::node::words_of(args), args.no_e2e)?;
    let flags = crate::node::key_flags(args)?;
    let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    let why_open = "anyone who knows the alias may connect to it, and Serveo is a third party that nobody vouches for";
    let door = crate::node_derp::door_of("--serveo", why_open, flags.allow.as_deref(), &place)?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    let pair = match &args.pair_file {
        Some(file) => Ok((crate::pairs::usable(crate::pairs::from_file(file)?, &label)?, false)),
        None => crate::pairs::stored(&label).map(|pair| (pair, true)).map_err(|refusal| refusal.message),
    };
    crate::pairs::online()?;
    crate::node_transit::check()?; // PODSSH_TRANSIT (T-436), before anything connects
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    // The key is made only once each check passed; one for this run only
    // stays across an upgrade in place (T-679).
    let key = crate::node_upgrade::parts::node_key(&place)?;
    Ok(Ready { label, targets, roost: args.sshd, key, door, service, trust, pair, unasked })
}

/// Run the node of the Serveo road; `unasked` is why it serves the road
/// with no `--serveo`. Returns the process exit code.
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
    let mut code = runtime.block_on(Box::pin(crate::node_serveo_serve::serve(ready, err)));
    // An upgrade whose binary did not start: this one serves its sessions
    // again, from a new start of the road (T-679).
    while code == crate::node_upgrade::AGAIN {
        code = match prepare(args, unasked.clone()) {
            Ok(ready) => runtime.block_on(Box::pin(crate::node_serveo_serve::serve(ready, err))),
            Err(refusal) => refusal.report("node", err),
        };
    }
    // A session may still be closing; the node has ended, so none is waited for.
    runtime.shutdown_background();
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_of_the_road_takes_no_flag_that_would_open_its_door_or_change_its_road() {
        let base = || NodeArgs {
            name: Some("lab".into()),
            targets: vec!["127.0.0.1:22".into()],
            serveo: true,
            ..NodeArgs::default()
        };
        for (flag, args) in [
            ("--plain", NodeArgs { plain: true, ..base() }),
            ("--no-e2e", NodeArgs { no_e2e: true, ..base() }),
            ("udp:", NodeArgs { targets: vec!["udp:127.0.0.1:53".into()], ..base() }),
            ("--exit", NodeArgs { exit: true, ..base() }),
            ("--pinggy", NodeArgs { pinggy: true, ..base() }),
            ("--opentunnel", NodeArgs { opentunnel: true, ..base() }),
            ("--ssh-j", NodeArgs { ssh_j: true, ..base() }),
        ] {
            let refusal = check(&args).unwrap_err();
            assert_eq!(refusal.code, 64, "{flag}: {}", refusal.message);
            assert!(refusal.message.contains(flag), "{flag}: {}", refusal.message);
        }
        assert!(check(&base()).is_ok());
    }

    #[test]
    fn a_node_that_asked_for_another_road_never_serves_a_last_fallback_unasked() {
        for args in [
            NodeArgs { pinggy: true, ..NodeArgs::default() },
            NodeArgs { serveo: true, ..NodeArgs::default() },
            NodeArgs { ssh_j: true, ..NodeArgs::default() },
            NodeArgs { opentunnel: true, ..NodeArgs::default() },
            NodeArgs { frp: Some("frp.toml".into()), ..NodeArgs::default() },
        ] {
            assert_eq!(crate::node_pinggy::last_node(&args).ok().flatten(), None, "{args:?}");
        }
    }
}
