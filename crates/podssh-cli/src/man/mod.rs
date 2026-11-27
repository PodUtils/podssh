//! `podssh man`: the manual of this binary, generated from its own tables.
//!
//! The manual must be enough on a host that has only the binary: no man(1),
//! no groff, no pager, no network, no documents. So it is plain text that
//! podssh writes itself, and it covers each command, argument, flag, `-o`
//! keyword, variable, file, relay fact and exit code. Nothing in it is typed
//! twice: [`pod_model`] builds pod-manual's model from the tables that the
//! parser and the commands use, and the tests check it against them.
//!
//! Each form is pod-manual's writer over that one model, so no two forms
//! can differ, and `--help` shows a command's section:
//! - `podssh man` pages the text on a terminal, else writes it to stdout.
//! - `--no-pager` writes it to stdout, also on a terminal.
//! - `--roff` writes a man(7) page instead, for `man -l` or a man directory.
//! - `--json` writes the model as one JSON object, for a program.
//! - `podssh man SECTION` writes one section: a command, or a topic.
//!
//! The pager stays podssh's own ([`crate::pager`]): its probe and its
//! variables are the facts of this manual.

pub mod data;
pub mod examples;
pub mod facts;
pub mod llms;
pub mod model;
pub mod notes;
// The manual as the model of pod-manual, whose writers make each form.
pub mod pod_model;
// A node's person, asked after its door (T-638).
mod notes_ask;
mod notes_chat;
mod notes_config;
mod notes_containers;
// croc's relay road, a last fallback of Q78 (T-694).
mod notes_croc;
// ZeroTier's road, a last fallback of Q78 after croc's (T-733).
mod notes_hyperdht;
// The onion road, a last fallback of Q78 after Syncthing's relay road (T-578).
mod notes_onion;
// The smee.io road, a last fallback of Q78 after the onion road (T-741).
mod notes_smee;
// The file hosts' road, the last of the last fallbacks of Q78 (T-738).
mod notes_filehost;
mod notes_strelay;
mod notes_tox;
mod notes_ygg;
mod notes_zerotier;
// relay's notes on the signed list of deployments (T-346).
mod notes_deployments;
mod notes_detached;
// The dialect of the reverse road (T-643).
mod notes_dialect;
// doctor's notes on the time of a run (T-511).
mod notes_doctor;
mod notes_each;
mod notes_edit;
// The frp road (T-498).
mod notes_frp;
mod notes_grant;
// The tokens of one leg and the stop token's rotation (T-615).
mod notes_health;
mod notes_job;
mod notes_keygen;
mod notes_legs;
mod notes_mcp;
mod notes_net;
mod notes_pair;
// The Pinggy road, a last fallback of Q78 (T-548).
mod notes_ping;
mod notes_pinggy;
mod notes_pipe;
mod notes_play;
mod notes_policy;
mod notes_proxy;
// `podssh serve`, and its host key's file (T-107).
mod notes_serve;
// `podssh serve --listen`: its addresses, the bind and the caps (T-124).
mod notes_serve_listen;
// The audit log of `podssh serve` (T-116).
mod notes_serve_audit;
// The one-time code of `podssh serve --totp` (T-115).
mod notes_serve_totp;
// The gateway of `podssh serve --gateway` (T-836).
mod notes_serve_gateway;
// The Serveo road, a last fallback of Q78, before the ssh-j road (T-549).
mod notes_serveo;
// ssh's note on the public services that podssh tries last (T-533).
mod notes_outline;
mod notes_public;
// relay's and node's notes on a name published by its ClientHello (T-649).
mod notes_publish;
mod notes_relay;
// The ssh-j road, a last fallback of Q78, after Serveo's (T-570).
mod notes_sshj;
// The localhost.run road, the last fallback of Q78, after the ssh-j road's (T-565).
mod notes_ssh_http;
// The localtunnel road, the last fallback of Q78, after ssh-j's (T-568).
mod notes_localtunnel;
// The bore road, the last fallback of Q78, after ssh-j's (T-569).
mod notes_bore;
// ssh's notes on the roads to a server of the user's (T-441).
mod notes_roads;
mod notes_run;
mod notes_session;
// The far end of the 7-bit envelope (T-831).
mod notes_tx;
// `podssh share` (T-433).
mod notes_funnel;
mod notes_share;
// The sessions that the relay readies ahead for a node that asks (T-650).
mod notes_spares;
mod notes_ssh;
mod notes_ssh_more;
// The note of --predict (T-160).
mod notes_predict;
// The note of --frames (T-303).
mod notes_frames;
// The notes of --tuic (T-581).
mod notes_tuic;
// A unit read before it is installed, and a system unit (T-709).
mod notes_unit;
// A node's route to a Unix socket, and the caller's line (T-714).
mod notes_unix_route;
// A node's net from a signed document at a URL (T-715).
mod notes_net_url;
mod notes_update;
// A node's upgrade in place (T-668).
mod notes_upgrade;
// The notes of --vless (T-440).
mod notes_vless;
// The notes of --hysteria, where UDP passes (T-580).
mod notes_hysteria;
// The notes of --turn, a TURN server's TCP allocations (T-621).
mod notes_turn;
// The notes of devtunnel://, Microsoft Dev Tunnels' relay (T-755).
mod notes_devtunnel;
// The notes of the GSRN road, gsocket's relay by a shared secret (T-707).
mod notes_gsr;
// The notes of --carrier s3:FILE, a bucket as a node's stream (T-725).
mod notes_bucket;
// The notes of the DNS road: doctor's --dns-zone (T-875), --carrier dns:FILE (T-877).
mod notes_dns;
pub mod roff;

use std::io::{BufRead, Write};

/// What the command line asked for.
#[derive(Clone, Copy, Debug, Default)]
pub struct Request<'a> {
    pub section: Option<&'a str>,
    pub no_pager: bool,
    pub roff: bool,
    pub json: bool,
}

/// The whole manual as text, as `podssh man --no-pager` writes it.
pub fn page() -> String {
    pod_manual::text::render(&pod_model::manual())
}

/// The whole manual as a man(7) page, as `podssh man --roff` writes it.
pub fn roff_page() -> String {
    roff::page()
}

/// The whole manual as one JSON object, as `podssh man --json` writes it.
pub fn json_page() -> String {
    pod_manual::json::text(&pod_manual::json::document(&pod_model::manual()))
}

/// The bytes for `req`, or the refusal: an unknown section (with the list
/// of the sections), or two forms at once.
pub fn body(req: &Request<'_>) -> Result<String, String> {
    let ask = pod_manual::Request {
        section: req.section.map(str::to_string),
        no_pager: req.no_pager,
        roff: req.roff,
        json: req.json,
    };
    pod_manual::body(&pod_model::manual(), &ask)
}

/// Run `podssh man`; returns the exit code. The manual goes to stdout, the
/// same bytes on each path; a pager is used only when both stdin and stdout
/// are a terminal. `keys` is where the built-in pager reads its keys.
pub fn run(
    req: &Request<'_>,
    tty: crate::pager::Tty,
    keys: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let body = match body(req) {
        Ok(b) => b,
        Err(refusal) => {
            let _ = writeln!(err, "{refusal}");
            return crate::exit_codes::EXIT_USAGE;
        }
    };
    if req.no_pager || req.roff || req.json || !tty.can_page() {
        // A reader that went away (`podssh man | head`) is not a failure.
        let _ = out.write_all(body.as_bytes());
        let _ = out.flush();
        return 0;
    }
    crate::pager::show(&body, &crate::pager::PagerEnv::from_process(), keys, out, err);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pager::Tty;
    use std::io::Cursor;

    fn run_with(req: Request<'_>, tty: Tty) -> (i32, String, String) {
        let mut keys = Cursor::new(Vec::new());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let rc = run(&req, tty, &mut keys, &mut out, &mut err);
        (rc, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
    }

    /// With no terminal there is no pager: the whole manual, nothing on stderr.
    #[test]
    fn with_no_terminal_the_whole_manual_is_written() {
        let (rc, out, err) = run_with(Request::default(), Tty::none());
        assert_eq!(rc, 0);
        assert_eq!(out, page());
        assert!(err.is_empty(), "{err}");
    }

    /// T-975: a pager that fails before reading the text (`PAGER=false`) gets
    /// one line on stderr and the manual follows unpaged; a pager that reads
    /// it all and exits 0 says nothing on stderr.
    #[cfg(unix)]
    #[test]
    fn a_pager_that_fails_says_so_and_writes_the_manual_without_it() {
        let text = body(&Request { section: Some("man"), ..Default::default() }).expect("man section");
        let env = crate::pager::PagerEnv { pager: Some("false".into()), ..Default::default() };
        let mut keys = Cursor::new(Vec::new());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        crate::pager::show(&text, &env, &mut keys, &mut out, &mut err);
        let out = String::from_utf8(out).unwrap();
        let err = String::from_utf8(err).unwrap();
        assert_eq!(out, text, "the manual follows with no pager");
        assert!(err.contains("false") && err.contains("exit 1") && err.contains("no pager"), "{err}");

        let ok_env = crate::pager::PagerEnv { pager: Some("sh -c cat>/dev/null".into()), ..Default::default() };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        crate::pager::show(&text, &ok_env, &mut keys, &mut out, &mut err);
        assert!(out.is_empty(), "the pager took the text");
        assert!(err.is_empty(), "a pager that read all and exited 0 says nothing: {}", String::from_utf8_lossy(&err));
    }

    #[test]
    fn no_pager_and_roff_write_at_once_even_on_a_terminal() {
        let tty = Tty { stdin: true, stdout: true };
        let (rc, out, _) = run_with(Request { no_pager: true, ..Default::default() }, tty);
        assert_eq!((rc, out), (0, page()));
        let (rc, out, _) = run_with(Request { roff: true, ..Default::default() }, tty);
        assert_eq!((rc, out), (0, roff_page()));
    }

    #[test]
    fn json_writes_at_once_and_reads_back_as_the_model() {
        let tty = Tty { stdin: true, stdout: true };
        let (rc, out, _) = run_with(Request { json: true, ..Default::default() }, tty);
        assert_eq!((rc, out.as_str()), (0, json_page().as_str()));
        assert_eq!(pod_manual::json::read(&out), Ok(pod_model::manual()));
    }

    #[test]
    fn a_section_is_found_by_its_name_or_an_alias() {
        for (name, heading) in [
            ("ssh", "podssh ssh\n"),
            ("connect", "podssh ssh\n"),
            ("keywords", "podssh ssh\n"),
            ("env", "ENVIRONMENT\n"),
            ("EXIT-STATUS", "EXIT STATUS\n"),
            ("retired-variables", "RETIRED VARIABLES\n"),
        ] {
            let (rc, out, _) = run_with(Request { section: Some(name), ..Default::default() }, Tty::none());
            assert_eq!(rc, 0, "{name}");
            assert!(out.starts_with(heading), "{name}: {out}");
        }
        let (rc, out, _) = run_with(Request { section: Some("proxy"), roff: true, ..Default::default() }, Tty::none());
        assert_eq!(rc, 0);
        // The crate's writer escapes the hyphen, as man(7) asks.
        assert!(out.starts_with(".TH PODSSH\\-PROXY 1 "), "{out}");
    }

    /// An unknown section is a usage error that lists the real sections, and
    /// nothing reaches stdout.
    #[test]
    fn an_unknown_section_is_refused_with_the_list() {
        let (rc, out, err) = run_with(Request { section: Some("nonsense"), ..Default::default() }, Tty::none());
        assert_eq!(rc, crate::exit_codes::EXIT_USAGE);
        assert!(out.is_empty(), "{out}");
        assert!(err.contains("nonsense"), "{err}");
        for s in pod_manual::sections::sections(&pod_model::manual()) {
            assert!(err.contains(&s.key), "the refusal does not list {}: {err}", s.key);
        }
        // Two forms at once are refused the same way.
        let (rc, out, _) = run_with(Request { json: true, roff: true, ..Default::default() }, Tty::none());
        assert_eq!((rc, out.as_str()), (crate::exit_codes::EXIT_USAGE, ""));
    }
}
