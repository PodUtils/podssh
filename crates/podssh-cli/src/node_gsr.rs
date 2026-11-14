//! `podssh node NAME TARGET --gsr` (T-707): the node in front of the TCP
//! service TARGET over the GSRN road, the relay of gsocket, where two ends
//! that share a secret meet with no account and no token. The secret comes
//! from the private file of `--gsr-secret-file` or `PODSSH_GSR_SECRET_FILE`
//! (`crate::gsr`), never from argv or a line. The node keeps one
//! registration at the address that the secret gives, by one outbound TCP
//! connection to the relay's port 443, directly or through `HTTPS_PROXY`;
//! each client of the same secret pairs with it, and the node registers
//! again at once. TLS with SRP of the secret keeps the bytes from the relay,
//! and the resumable layer and the end-to-end channel run above it, as on
//! the bore road: whoever holds the secret reaches the door, so the road
//! needs the channel and a door, `--allow` or the net's members where the
//! node's key is one. The road is served alone, with no pair's road beside
//! it. A build without the feature `gsr` refuses `--gsr` and
//! `--gsr-secret-file` with exit 70. stdout stays empty.

use std::io::Write;

use podssh_relay::reverse::routes::Route;
use podssh_relay::session::Settings;

use crate::exit_codes::EXIT_NOT_IMPLEMENTED;
use crate::exitmap::Fault;
use crate::node::NodeArgs;
use crate::node_derp::Door;
use crate::relay_settings::Refusal;

/// The flags of the road, checked before anything is read.
pub(crate) fn check(args: &NodeArgs) -> Result<(), Refusal> {
    if !args.gsr {
        return Err(Refusal::usage("--gsr-secret-file is for the GSRN road: add --gsr"));
    }
    if args.plain {
        return Err(Refusal::usage("--plain is for the pair's road: the GSRN road always runs the resumable layer"));
    }
    if args.no_e2e {
        return Err(Refusal::usage(
            "--no-e2e cannot go with --gsr: whoever holds the secret reaches the node through a third party that \
             nobody vouches for, so the end-to-end channel and its allowlist are the node's only door",
        ));
    }
    if crate::node_derp::has_udp(args) {
        return Err(Refusal::usage("a udp: TARGET goes on the pair's road: the GSRN road carries TCP only"));
    }
    if args.exit {
        return Err(Refusal::usage("--exit goes on the pair's road and the DERP road: --gsr does not carry it"));
    }
    let others = [
        (args.opentunnel, "--opentunnel"),
        (args.pinggy, "--pinggy"),
        (args.serveo, "--serveo"),
        (args.ssh_j, "--ssh-j"),
        (args.localhost_run, "--localhost-run"),
        (args.sandhole, "--sandhole"),
        (args.srv_us, "--srv-us"),
        (args.tunnl_gg, "--tunnl-gg"),
        (args.localtunnel, "--localtunnel"),
        (args.hostc, "--hostc"),
        (args.bore, "--bore"),
        (args.iroh, "--iroh"),
        (args.derp, "--derp"),
        (args.quick_tunnel, "--quick-tunnel"),
        (args.frp.is_some(), "--frp"),
        (args.spares.is_some(), "--spares"),
    ];
    if let Some((_, flag)) = others.iter().find(|(given, _)| *given) {
        let why = format!("--gsr is one road and {flag} is another: give one; run a second node for another");
        return Err(Refusal::usage(why));
    }
    Ok(())
}

/// Each check of the node that needs no network, done.
#[cfg_attr(not(feature = "gsr"), allow(dead_code))]
pub(crate) struct Ready {
    pub label: String,
    pub targets: Vec<Route>,
    pub roost: bool,
    pub key: podssh_relay::identity::file::Key,
    pub door: Door,
    pub secret: crate::gsr::Secret,
    /// Why a pair of the node is not served beside the road, when it has one.
    pub pair_left: Option<String>,
}

fn prepare(args: &NodeArgs) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the node's name, which labels its key")?;
    crate::pairs::check_label(&label)?;
    check(args)?;
    let missing = format!("--gsr: no secret: give --gsr-secret-file FILE, or {}", crate::gsr::SECRET_ENV);
    let secret = crate::gsr::secret(args.gsr_secret_file.as_deref())?.ok_or_else(|| Refusal::usage(missing))?;
    #[cfg(feature = "gsr")]
    {
        // The relay's facts and the length of the secret, before the key is made.
        let settings = podssh_gsr::settings().map_err(|why| Refusal::config(format!("--gsr: {why}")))?;
        podssh_gsr::check_secret(&settings, secret.expose())
            .map_err(|why| Refusal::config(format!("--gsr: the secret: {why}")))?;
        podssh_gsr::check_tls(&settings).map_err(|why| Refusal::config(format!("--gsr: TLS with SRP: {why}")))?;
    }
    let targets = crate::node::targets_of(&crate::node::words_of(args), args.no_e2e)?;
    let flags = crate::node::key_flags(args)?;
    let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    let why_open = "whoever holds the secret reaches the node at the relay of gsocket, a third party that nobody \
                    vouches for";
    let door = crate::node_derp::door_of("--gsr", why_open, flags.allow.as_deref(), &place)?;
    let pair_left = match &args.pair_file {
        Some(_) => Some("--pair-file".to_string()),
        None => crate::pairs::stored(&label).ok().map(|_| format!("the pair {label}")),
    };
    crate::pairs::online()?;
    // The key is made only once each check passed; one for this run only
    // stays across an upgrade in place (T-679).
    let key = crate::node_upgrade::parts::node_key(&place)?;
    Ok(Ready { label, targets, roost: args.sshd, key, door, secret, pair_left })
}

/// Run the node of the GSRN road. Returns the process exit code.
pub fn run(args: &NodeArgs, err: &mut dyn Write) -> i32 {
    if !cfg!(feature = "gsr") {
        let flag = if args.gsr { "--gsr" } else { "--gsr-secret-file" };
        let _ = writeln!(err, "podssh node: {}", crate::gsr::not_built(flag));
        return EXIT_NOT_IMPLEMENTED;
    }
    let ready = match prepare(args) {
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
    let mut code = runtime.block_on(Box::pin(serve(ready, err)));
    // An upgrade whose binary did not start: this one serves its sessions
    // again, from a new start of the road (T-679).
    while code == crate::node_upgrade::AGAIN {
        code = match prepare(args) {
            Ok(ready) => runtime.block_on(Box::pin(serve(ready, err))),
            Err(refusal) => refusal.report("node", err),
        };
    }
    // A session may still be closing; the node has ended, so none is waited for.
    runtime.shutdown_background();
    code
}

#[cfg(feature = "gsr")]
async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    crate::node_gsr_serve::serve(ready, err).await
}

#[cfg(not(feature = "gsr"))]
async fn serve(_: Ready, _: &mut dyn Write) -> i32 {
    // `run` refuses first in a build without the road.
    EXIT_NOT_IMPLEMENTED
}

/// The settings of the layer on the road: no window of the pair's relay.
#[cfg_attr(not(feature = "gsr"), allow(dead_code))]
pub(crate) fn settings() -> Settings {
    crate::layered::settings().off_the_pair()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> NodeArgs {
        NodeArgs { name: Some("lab".into()), targets: vec!["127.0.0.1:22".into()], gsr: true, ..NodeArgs::default() }
    }

    #[test]
    fn a_node_of_the_road_takes_no_flag_that_would_open_its_door_or_change_its_road() {
        for (flag, args) in [
            ("--plain", NodeArgs { plain: true, ..base() }),
            ("--no-e2e", NodeArgs { no_e2e: true, ..base() }),
            ("udp:", NodeArgs { targets: vec!["udp:127.0.0.1:53".into()], ..base() }),
            ("--exit", NodeArgs { exit: true, ..base() }),
            ("--bore", NodeArgs { bore: true, ..base() }),
            ("--pinggy", NodeArgs { pinggy: true, ..base() }),
            ("--derp", NodeArgs { derp: true, ..base() }),
            ("--quick-tunnel", NodeArgs { quick_tunnel: true, ..base() }),
            ("--frp", NodeArgs { frp: Some("frp.toml".into()), ..base() }),
            ("--spares", NodeArgs { spares: Some("2".into()), ..base() }),
            ("--gsr", NodeArgs { gsr: false, gsr_secret_file: Some("s".into()), ..base() }),
        ] {
            let refusal = check(&args).unwrap_err();
            assert_eq!(refusal.code, 64, "{flag}: {}", refusal.message);
            assert!(refusal.message.contains(flag), "{flag}: {}", refusal.message);
        }
        assert!(check(&base()).is_ok());
    }

    #[cfg(not(feature = "gsr"))]
    #[test]
    fn a_build_without_the_road_refuses_each_of_its_flags_with_70() {
        for args in [base(), NodeArgs { gsr: false, gsr_secret_file: Some("s".into()), ..base() }] {
            let mut err = Vec::new();
            assert_eq!(run(&args, &mut err), 70, "{args:?}");
            let said = String::from_utf8_lossy(&err);
            assert!(said.contains("--features gsr"), "{said}");
        }
    }
}
