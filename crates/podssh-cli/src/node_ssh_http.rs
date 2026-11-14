//! `podssh node NAME TARGET --localhost-run` (T-565): the node in front of
//! the TCP service TARGET over a tunnel of HTTP made by `ssh -R`
//! (`podssh_relay::ssh_http`), at localhost.run, which needs no account,
//! where podssh's list of services names it, or at the server of
//! `PODSSH_LOCALHOST_RUN`. Its leg is SSH to the server on port 22 as
//! `nokey`, with the remote forward of port 80 (`ssh_http_leg`); the server
//! names the tunnel's HTTPS name, new each few hours, which the node says,
//! keeps under NAME in the cache and puts in its record (T-445); a client
//! takes a WebSocket at `/` of that name, as of a quick tunnel's, under the
//! resumable layer and the end-to-end channel (`crate::ssh::ssh_http`).
//! Anyone may visit the name, so the road needs that channel and a door:
//! `--allow`, or the net's members where the node's key is one. With
//! `--relay`, the node is its owner's relay too, behind the tunnel and with
//! no listener, as behind a quick tunnel (T-428, `crate::node_quick_relay`),
//! and TARGET may be left out.
//!
//! A last fallback (the operator's ruling Q78), after the ssh-j road and
//! before localtunnel's (T-568, `crate::node_localtunnel`): a node that would serve the OpenTunnel road, the Pinggy road,
//! Serveo's or the ssh-j road unasked serves this one when none of them
//! reached a service, or when each is off, and says that a third party that
//! nobody vouches for carries its sessions. `PODSSH_LOCALHOST_RUN=no` turns
//! the road off, and so does `PODSSH_LAST_RESORT=no`. `--sandhole` serves the
//! same road at Sandhole's public server (T-743), which a node serves unasked
//! after localhost.run's; `PODSSH_SANDHOLE=no` turns it off. `--srv-us`
//! serves it at srv.us (T-566), whose name is a function of the node's own
//! key, with which the leg logs in, so a client derives it; `--tunnl-gg` at
//! tunnl.gg (T-567), whose random name the record carries. A node serves
//! them unasked after Sandhole's, in that order; `PODSSH_SRV_US=no` and
//! `PODSSH_TUNNL_GG=no` turn them off. The road is served alone, as the
//! ssh-j road is (T-570's Decision). stdout stays empty.

use std::io::Write;

use podssh_relay::reverse::routes::Route;
use podssh_relay::ssh_http::{self, Service, Setting, Word};

use crate::exitmap::Fault;
use crate::node::NodeArgs;
use crate::node_derp::Door;
use crate::node_quick_relay::Role;
use crate::relay_settings::Refusal;

/// The words of the module, in the order that a node serves them unasked:
/// localhost.run's, then Sandhole's (T-743), srv.us's (T-566) and
/// tunnl.gg's (T-567).
pub(crate) const WORDS: &[Word] = ssh_http::WORDS;

/// The word that the node's flags ask for: the first of [`WORDS`] whose
/// flag is given ([`check`] refuses two).
pub(crate) fn asked(args: &NodeArgs) -> Option<Word> {
    let given = [args.localhost_run, args.sandhole, args.srv_us, args.tunnl_gg];
    WORDS.iter().zip(given).find(|(_, given)| *given).map(|(word, _)| *word)
}

/// The word's variable and `PODSSH_LAST_RESORT`, read: a value that is none
/// of their forms is a setting that cannot be used (78).
pub(crate) fn setting(word: Word) -> Result<Setting, Refusal> {
    ssh_http::from_env(word).map_err(Refusal::config)
}

/// After the ssh-j road that a node served unasked for `why` ended with
/// `code`: when it reached no service, this road, unasked too (Q78).
pub(crate) fn after(args: &NodeArgs, code: i32, why: &str, err: &mut dyn Write) -> Option<i32> {
    if code != Fault::RelayUnreachable.code() {
        return None;
    }
    unasked(args, format!("{why}, and the ssh-j road reached no service"), err)
}

/// With each road of a tunnel before it off, for `why`: this road unasked,
/// and the line names the ssh-j road's switch too.
pub(crate) fn dispatch(args: &NodeArgs, why: String, err: &mut dyn Write) -> Option<i32> {
    let sshj = match crate::node_sshj::setting() {
        Ok(crate::sshj::Setting::Off(by)) => format!("{by}=no turns the ssh-j road off"),
        _ => crate::sshj::unnamed_words(),
    };
    unasked(args, format!("{why}, and {sshj}"), err)
}

/// Each word that is on, in the order of [`WORDS`], unasked for `why`: the
/// next only when the one before it reached no server. None when each is
/// off, or when the node asked for a road (it ran already).
pub(crate) fn unasked(args: &NodeArgs, mut why: String, err: &mut dyn Write) -> Option<i32> {
    if asked(args).is_some() {
        return None;
    }
    let mut code = None;
    for &word in WORDS {
        match setting(word) {
            Ok(Setting::On(_)) => {}
            Ok(_) => continue,
            Err(refusal) => return Some(refusal.report("node", err)),
        }
        let ran = run(args, word, Some(why.clone()), err);
        if ran != Fault::RelayUnreachable.code() {
            return Some(ran);
        }
        why = format!("{why}, and the {} road reached no server", word.name);
        code = Some(ran);
    }
    code
}

/// The flags of the road, checked before anything is read.
pub(crate) fn check(args: &NodeArgs, word: Word) -> Result<(), Refusal> {
    let (flag, road) = (word.flag, word.name);
    if args.plain {
        let why = format!("--plain is for the pair's road: the {road} road always runs the resumable layer");
        return Err(Refusal::usage(why));
    }
    if args.no_e2e {
        return Err(Refusal::usage(format!(
            "--no-e2e cannot go with {flag}: anyone may visit the tunnel's name, and {road} ends its TLS and is \
             a third party that nobody vouches for, so the end-to-end channel and its allowlist are the node's \
             only door"
        )));
    }
    if crate::node_derp::has_udp(args) {
        return Err(Refusal::usage(format!("a udp: TARGET goes on the pair's road: the {road} road carries TCP only")));
    }
    if args.exit {
        let why = format!("--exit goes on the pair's road and the DERP road: {flag} does not carry it");
        return Err(Refusal::usage(why));
    }
    let others = [
        (args.opentunnel, "--opentunnel"),
        (args.pinggy, "--pinggy"),
        (args.serveo, "--serveo"),
        (args.ssh_j, "--ssh-j"),
        (args.localhost_run && flag != "--localhost-run", "--localhost-run"),
        (args.sandhole && flag != "--sandhole", "--sandhole"),
        (args.srv_us && flag != "--srv-us", "--srv-us"),
        (args.tunnl_gg && flag != "--tunnl-gg", "--tunnl-gg"),
        (args.localtunnel, "--localtunnel"),
        (args.bore, "--bore"),
        (args.iroh, "--iroh"),
        (args.derp, "--derp"),
        (args.quick_tunnel, "--quick-tunnel"),
        (args.frp.is_some(), "--frp"),
    ];
    if let Some((_, other)) = others.iter().find(|(given, _)| *given) {
        return Err(Refusal::usage(format!("{flag} is one road and {other} is another: give one; run a second node")));
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
    /// The relay role behind the tunnel (`--relay`).
    pub relay: Option<Role>,
    /// The server of its record: n0's, or the one of PODSSH_IROH_PKARR (T-445, Q81).
    pub record: Option<crate::node_record::Named>,
}

fn prepare(args: &NodeArgs, word: Word, unasked: Option<String>) -> Result<Ready, Refusal> {
    let label = args.name.clone().ok_or("missing NAME: the node's name, which labels its key")?;
    crate::pairs::check_label(&label)?;
    check(args, word)?;
    let flag = word.flag;
    let service = match setting(word)? {
        Setting::On(service) => service,
        Setting::Off(by) => return Err(Refusal::usage(format!("{flag}: {by}=no turns the {} road off", word.name))),
        // No server to name in the list of services: a setting that is missing.
        Setting::Unnamed => return Err(Refusal::config(format!("{flag}: {}", ssh_http::unnamed_words(word)))),
    };
    // With --relay and no TARGET, the node is the relay alone, as behind a
    // quick tunnel (T-428).
    let words = crate::node::words_of(args);
    let targets = match words.is_empty() && args.relay {
        true => Vec::new(),
        false => crate::node::targets_of(&words, args.no_e2e)?,
    };
    let flags = crate::node::key_flags(args)?;
    let place = crate::channel::node_place(&label, flags.key.as_deref(), flags.ephemeral)?;
    let why_open = "anyone may visit the tunnel's name, and its service is a third party that nobody vouches for";
    let door = crate::node_derp::door_of(flag, why_open, flags.allow.as_deref(), &place)?;
    crate::node_quick_relay::precheck(args, &door)?;
    let pair_left = match &args.pair_file {
        Some(_) => Some("--pair-file".to_string()),
        None => crate::pairs::stored(&label).ok().map(|_| format!("the pair {label}")),
    };
    crate::pairs::online()?;
    let record = crate::node_record::named()?;
    // The key is made only once each check passed; one for this run only
    // stays across an upgrade in place (T-679).
    let key = crate::node_upgrade::parts::node_key(&place)?;
    // After the key: the net's `relay:NAME` names the node by it (T-455).
    let relay = crate::node_quick_relay::role(args, &label, &door, key.identity.public())?;
    Ok(Ready { label, targets, roost: args.sshd, key, door, service, unasked, pair_left, relay, record })
}

/// Run the node of `word`'s road; `unasked` is why it serves the road with
/// no flag of it. Returns the process exit code.
pub fn run(args: &NodeArgs, word: Word, unasked: Option<String>, err: &mut dyn Write) -> i32 {
    let ready = match prepare(args, word, unasked.clone()) {
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
    let mut code = runtime.block_on(Box::pin(crate::node_ssh_http_serve::serve(ready, err)));
    // An upgrade whose binary did not start: this one serves its sessions
    // again, from a new start of the road (T-679).
    while code == crate::node_upgrade::AGAIN {
        code = match prepare(args, word, unasked.clone()) {
            Ok(ready) => runtime.block_on(Box::pin(crate::node_ssh_http_serve::serve(ready, err))),
            Err(refusal) => refusal.report("node", err),
        };
    }
    // A session may still be closing; the node has ended, so none is waited for.
    runtime.shutdown_background();
    code
}

/// The file of the cache that keeps the tunnel's name of the node `label`,
/// for a client of this host (`crate::ssh::ssh_http`).
pub(crate) fn name_file(label: &str) -> String {
    format!("ssh-http-{}.name", podssh_relay::cache::safe_name(label))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> NodeArgs {
        NodeArgs {
            name: Some("lab".into()),
            targets: vec!["127.0.0.1:22".into()],
            localhost_run: true,
            ..NodeArgs::default()
        }
    }

    #[test]
    fn a_node_of_the_road_takes_no_flag_that_would_open_its_door_or_change_its_road() {
        for (flag, args) in [
            ("--plain", NodeArgs { plain: true, ..base() }),
            ("--no-e2e", NodeArgs { no_e2e: true, ..base() }),
            ("udp:", NodeArgs { targets: vec!["udp:127.0.0.1:53".into()], ..base() }),
            ("--exit", NodeArgs { exit: true, ..base() }),
            ("--pinggy", NodeArgs { pinggy: true, ..base() }),
            ("--serveo", NodeArgs { serveo: true, ..base() }),
            ("--ssh-j", NodeArgs { ssh_j: true, ..base() }),
            ("--localtunnel", NodeArgs { localtunnel: true, ..base() }),
            ("--bore", NodeArgs { bore: true, ..base() }),
            ("--quick-tunnel", NodeArgs { quick_tunnel: true, ..base() }),
            ("--frp", NodeArgs { frp: Some("frp.toml".into()), ..base() }),
        ] {
            let refusal = check(&args, ssh_http::LOCALHOST_RUN).unwrap_err();
            assert_eq!(refusal.code, 64, "{flag}: {}", refusal.message);
            assert!(refusal.message.contains(flag), "{flag}: {}", refusal.message);
        }
        assert!(check(&base(), ssh_http::LOCALHOST_RUN).is_ok());
        let both = NodeArgs { sandhole: true, ..base() };
        assert!(check(&both, ssh_http::LOCALHOST_RUN).unwrap_err().message.contains("--sandhole"));
        let sandhole = NodeArgs { localhost_run: false, sandhole: true, ..base() };
        assert!(check(&sandhole, ssh_http::SANDHOLE).is_ok());
        assert_eq!(asked(&sandhole), Some(ssh_http::SANDHOLE));
        assert!(check(&NodeArgs { relay: true, ..base() }, ssh_http::LOCALHOST_RUN).is_ok(), "the relay role");
        for (word, args) in [
            (ssh_http::SRV_US, NodeArgs { localhost_run: false, srv_us: true, ..base() }),
            (ssh_http::TUNNL_GG, NodeArgs { localhost_run: false, tunnl_gg: true, ..base() }),
        ] {
            assert!(check(&args, word).is_ok(), "{}", word.flag);
            assert_eq!(asked(&args), Some(word));
            let both = NodeArgs { sandhole: true, ..args };
            assert!(check(&both, word).unwrap_err().message.contains("--sandhole"), "{}", word.flag);
        }
    }

    #[test]
    fn a_node_that_asked_for_a_road_never_serves_this_one_unasked() {
        assert_eq!(asked(&base()), Some(ssh_http::LOCALHOST_RUN));
        let mut sink = Vec::new();
        assert_eq!(unasked(&base(), "why".into(), &mut sink), None, "asked: it ran already");
        for args in [
            NodeArgs { localhost_run: true, ..NodeArgs::default() },
            NodeArgs { ssh_j: true, ..NodeArgs::default() },
            NodeArgs { pinggy: true, ..NodeArgs::default() },
            NodeArgs { frp: Some("frp.toml".into()), ..NodeArgs::default() },
        ] {
            assert_eq!(crate::node_sshj::last_of_all(&args), None, "{args:?}");
        }
        assert_eq!(after(&base(), 0, "why", &mut sink), None, "a road that served ends the node");
        assert!(sink.is_empty());
    }

    #[test]
    fn the_name_of_a_label_is_kept_in_a_file_of_its_own() {
        assert_eq!(name_file("lab"), "ssh-http-lab.name");
        assert_ne!(name_file("lab"), crate::node_pinggy::name_file("lab"));
    }
}
