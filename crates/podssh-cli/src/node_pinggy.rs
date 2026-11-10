//! `podssh node NAME TARGET --pinggy` (T-548): the node in front of the TCP
//! service TARGET over the Pinggy road of `podssh-relay`, through Pinggy's
//! free TLS tunnels, which need no account, or the server of `PODSSH_PINGGY`.
//! Its leg is SSH on port 443, raw, else inside TLS that the host's trust
//! verifies (`pinggy_leg`); it says its tunnel's name and the pin of its TLS
//! key (`pinggy_cert`) on stderr, which a client gives as `--pinggy-name
//! NAME#PIN`, and keeps them in the cache. A free tunnel ends at 60 minutes:
//! the node opens the next, under a new name, and says it; a session that the
//! layer keeps moves to it when its client dials the new name. In a build
//! with the iroh road, it puts each tunnel's address in its record of pkarr
//! (T-445), where a client with the node's key from the net finds it with no
//! `--pinggy-name`. With the pair
//! NAME, or the one of `--pair-file`, it serves the pair's road too, with one
//! keeper for both, as the OpenTunnel road's node does. Anyone may open a
//! connection to a tunnel's name, so the road needs the end-to-end channel
//! and a door: `--allow`, or the net's members where the node's key is one
//! (T-452).
//!
//! A last fallback (the operator's ruling Q78): a node with no pair, a door,
//! no other road asked of it, the DERP road off, and the OpenTunnel road off
//! (`PODSSH_OPENTUNNEL=no`) or with no service reached, serves it unasked,
//! and says that a third party that nobody vouches for carries its
//! sessions. `PODSSH_PINGGY=no` turns the road off, and so does
//! `PODSSH_LAST_RESORT=no`, the switch of each last fallback (T-548's
//! Decision); Serveo's road (T-549, `node_serveo`) comes after it, or in its
//! place when it is off. stdout stays empty.

use std::io::Write;
use std::time::Duration;

use podssh_relay::pair::Pair;
use podssh_relay::pinggy::{self, Service, Setting};
use podssh_relay::reverse::routes::Route;
use podssh_relay::session::Settings;
use podssh_ws::Trust;

use crate::exitmap::Fault;
use crate::node::NodeArgs;
use crate::node_derp::Door;
use crate::relay_settings::Refusal;

/// The bound on a node's first tunnel when it serves the road unasked.
pub(crate) const UNASKED_LIMIT: Duration = Duration::from_secs(30);

/// `PODSSH_PINGGY` and `PODSSH_LAST_RESORT`, read: a value that is none of
/// their forms is a setting that cannot be used (78).
pub(crate) fn setting() -> Result<Setting, Refusal> {
    let value = std::env::var(pinggy::ENV).ok();
    let last = std::env::var(pinggy::LAST_RESORT).ok();
    pinggy::setting(value.as_deref(), last.as_deref()).map_err(Refusal::config)
}

/// The server of the road, when the road is on; else the variable that
/// turned it off.
pub(crate) fn service() -> Result<Result<Service, &'static str>, Refusal> {
    Ok(match setting()? {
        Setting::On(service) => Ok(service),
        Setting::Off(by) => Err(by),
    })
}

/// Why a node with no road asked of it serves a last fallback of Q78, before
/// the fallback's own switch is read: the node that the OpenTunnel road would
/// serve unasked (no pair, a door, no other road asked, the DERP road off),
/// with that road off too. Pinggy's road, then Serveo's (T-549), then the
/// ssh-j road (T-570, `node_sshj`), take it.
pub(crate) fn last_node(args: &NodeArgs) -> Result<Option<String>, Refusal> {
    let asked = args.pinggy || args.serveo || args.ssh_j || args.opentunnel || args.frp.is_some();
    if asked || crate::node_opentunnel::service()?.is_some() {
        return Ok(None);
    }
    let other = args.derp || args.iroh || args.plain || args.no_e2e || args.exit;
    if other || args.pair_file.is_some() || crate::node_derp::has_udp(args) || crate::node_derp::fallback_on()? {
        return Ok(None);
    }
    let Some(label) = args.name.as_deref().filter(|label| crate::pairs::check_label(label).is_ok()) else {
        return Ok(None);
    };
    let door = args.allow.is_some() || args.iroh_allow.is_some() || crate::node_derp::net_door(args, label);
    if !door {
        return Ok(None);
    }
    let why = crate::pairs::stored(label).err().map(|refusal| refusal.message);
    Ok(why.map(|why| format!("{why}, and {}=no turns the OpenTunnel road off", podssh_relay::opentunnel::ENV)))
}

/// Why a node with no `--pinggy` serves the road, when it does: the last
/// node of [`last_node`], with this road on (Q78: last).
pub(crate) fn unasked(args: &NodeArgs) -> Result<Option<String>, Refusal> {
    let Some(why) = last_node(args)? else { return Ok(None) };
    Ok(service()?.is_ok().then_some(why))
}

/// The road of `args`, asked or unasked: the exit code of its run; none when
/// the node takes another road. `--serveo` goes to Serveo's road; a node that
/// served this one unasked and reached no server, or that has it off, takes
/// Serveo's unasked, the last of all (T-549).
pub(crate) fn dispatch(args: &NodeArgs, err: &mut dyn Write) -> Option<i32> {
    if args.serveo {
        return crate::node_serveo::dispatch(args, None, err);
    }
    let unasked = match unasked(args) {
        Ok(unasked) => unasked,
        Err(refusal) => return Some(refusal.report("node", err)),
    };
    match unasked {
        Some(why) => {
            let code = run(args, Some(why.clone()), err);
            Some(crate::node_serveo::after(args, code, &why, err).unwrap_or(code))
        }
        None if args.pinggy => Some(run(args, None, err)),
        None => crate::node_serveo::dispatch(args, None, err),
    }
}

/// After the OpenTunnel road that a node served unasked ended with `code`:
/// when it reached no service, the Pinggy road, the last, unasked too (Q78),
/// and after it, or in its place when it is off, Serveo's (T-549).
pub(crate) fn after_opentunnel(args: &NodeArgs, code: i32, err: &mut dyn Write) -> Option<i32> {
    if code != Fault::RelayUnreachable.code() || args.opentunnel || args.pinggy || args.serveo || args.ssh_j {
        return None;
    }
    let why = crate::node_opentunnel::unasked(args).ok().flatten()?;
    let why = format!("{why}, and the OpenTunnel road reached no service");
    if !matches!(service(), Ok(Ok(_))) {
        return crate::node_serveo::dispatch(args, Some(why), err);
    }
    let code = run(args, Some(why.clone()), err);
    Some(crate::node_serveo::after(args, code, &why, err).unwrap_or(code))
}

/// The flags of the road, checked before anything is read.
pub(crate) fn check(args: &NodeArgs) -> Result<(), Refusal> {
    if args.plain {
        return Err(Refusal::usage("--plain is for the pair's road: the Pinggy road always runs the resumable layer"));
    }
    if args.no_e2e {
        return Err(Refusal::usage(
            "--no-e2e cannot go with --pinggy: anyone may connect to a tunnel's name, and Pinggy is a third party \
             that nobody vouches for, so the end-to-end channel and its allowlist are the node's only door",
        ));
    }
    if crate::node_derp::has_udp(args) {
        return Err(Refusal::usage("a udp: TARGET goes on the pair's road: the Pinggy road carries TCP only"));
    }
    if args.exit {
        return Err(Refusal::usage("--exit goes on the pair's road and the DERP road: --pinggy does not carry it"));
    }
    if args.opentunnel || args.iroh || args.derp {
        return Err(Refusal::usage(
            "--pinggy is one road and --opentunnel, --iroh and --derp are others: give one; run a second node for \
             another",
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
    /// The server of its record: n0's, or the one of PODSSH_IROH_PKARR
    /// (T-445, Q81), which names each tunnel's address.
    pub record: Option<crate::node_record::Named>,
}

fn prepare(args: &NodeArgs, unasked: Option<String>) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the node's name, which labels its key and its tunnel")?;
    crate::pairs::check_label(&label)?;
    check(args)?;
    let service = match service()? {
        Ok(service) => service,
        Err(by) => return Err(Refusal::usage(format!("--pinggy: {by}=no turns the Pinggy road off"))),
    };
    let targets = crate::node::targets_of(&crate::node::words_of(args), args.no_e2e)?;
    let flags = crate::node::key_flags(args)?;
    let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    let why_open = "anyone may connect to a tunnel's name, and Pinggy is a third party that nobody vouches for";
    let door = crate::node_derp::door_of("--pinggy", why_open, flags.allow.as_deref(), &place)?;
    crate::pins::apply(args.relay_addr.as_deref())?;
    let pair = match &args.pair_file {
        Some(file) => Ok((crate::pairs::usable(crate::pairs::from_file(file)?, &label)?, false)),
        None => crate::pairs::stored(&label).map(|pair| (pair, true)).map_err(|refusal| refusal.message),
    };
    crate::pairs::online()?;
    crate::node_transit::check()?; // PODSSH_TRANSIT (T-436), before anything connects
    let trust = crate::pairs::trust(args.ca_file.as_deref());
    let record = crate::node_record::named()?;
    // The key is made only once each check passed; one for this run only
    // stays across an upgrade in place (T-679).
    let key = crate::node_upgrade::parts::node_key(&place)?;
    Ok(Ready { label, targets, roost: args.sshd, key, door, service, trust, pair, unasked, record })
}

/// Run the node of the Pinggy road; `unasked` is why it serves the road
/// with no `--pinggy`. Returns the process exit code.
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
    let mut code = runtime.block_on(Box::pin(crate::node_pinggy_serve::serve(ready, err)));
    // An upgrade whose binary did not start: this one serves its sessions
    // again, from a new start of the road (T-679).
    while code == crate::node_upgrade::AGAIN {
        code = match prepare(args, unasked.clone()) {
            Ok(ready) => runtime.block_on(Box::pin(crate::node_pinggy_serve::serve(ready, err))),
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

/// The file of the tunnel's address (`NAME#PIN`) kept under `label`, in the
/// cache.
pub(crate) fn name_file(label: &str) -> String {
    format!("pinggy-{}.name", podssh_relay::cache::safe_name(label))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_of_the_road_takes_no_flag_that_would_open_its_door_or_change_its_road() {
        let base = || NodeArgs {
            name: Some("lab".into()),
            targets: vec!["127.0.0.1:22".into()],
            pinggy: true,
            ..NodeArgs::default()
        };
        for (flag, args) in [
            ("--plain", NodeArgs { plain: true, ..base() }),
            ("--no-e2e", NodeArgs { no_e2e: true, ..base() }),
            ("udp:", NodeArgs { targets: vec!["udp:127.0.0.1:53".into()], ..base() }),
            ("--exit", NodeArgs { exit: true, ..base() }),
            ("--opentunnel", NodeArgs { opentunnel: true, ..base() }),
        ] {
            let refusal = check(&args).unwrap_err();
            assert_eq!(refusal.code, 64, "{flag}: {}", refusal.message);
            assert!(refusal.message.contains(flag), "{flag}: {}", refusal.message);
        }
        assert!(check(&base()).is_ok());
    }

    #[test]
    fn a_node_that_asked_for_another_road_never_serves_this_one_unasked() {
        for args in [
            NodeArgs { pinggy: true, ..NodeArgs::default() },
            NodeArgs { opentunnel: true, ..NodeArgs::default() },
            NodeArgs { frp: Some("frp.toml".into()), ..NodeArgs::default() },
        ] {
            assert_eq!(unasked(&args).ok().flatten(), None, "{args:?}");
        }
        assert_eq!(name_file("lab"), "pinggy-lab.name");
    }
}
