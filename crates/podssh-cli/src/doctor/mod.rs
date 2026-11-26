//! `podssh doctor`: what this host allows and whether the way out works,
//! measured rather than assumed. One line per check: `ok`, `FAIL` or `????`
//! (the check could not run), what was checked, and what was actually found
//! or opened.
//!
//! A condition podssh is built for (no listener, no pty, no user database
//! entry, no DNS) is a fact, reported `ok` with the fact. `FAIL` is kept for
//! what stops podssh, or one of its fallbacks, from working here. Unknowns are
//! counted apart and never fail the run: the exit is 1 when a check failed
//! and 0 otherwise. Servers are identified by equality (the relay by its
//! certificate and the service name in `/health`, an SSH server by its
//! published host key), never by the shape of a banner. The token is used and
//! never shown, and proxy credentials never appear.
//!
//! The sections that connect run at once, each into a part of its own, and
//! the report keeps their order (`parts.rs`, `sections.rs`; T-511).
//!
//! The bind probes here listen once, accept nothing and close at once (T-358).
//! Each other bind of podssh is a listener that the user asks for, or the UDP
//! socket of a road; the listener scan of `scripts/check-repo.py` holds their
//! files, and `listeners.rs` names the listeners for doctor's lines.

use std::io::Write;

use podssh_relay::relay;
use podssh_ws::Trust;

// Whether the way out takes an address as well as a name (T-366).
mod address;
// Handshakes at once against one at a time (T-747).
mod agent;
mod burst;
pub(crate) mod clock;
// What a request with no TLS meets on the way (T-326).
mod cleartext;
mod cover;
mod hop;
// The DERP road's servers and its home (T-379).
mod derp;
// The exit of --exit NAME and one session from it (T-458).
mod exit;
mod opentunnel;
// How each TLS handshake ended, and what they show together (T-487).
mod diagnosis;
// What Encrypted Client Hello did for the relay host (T-642).
mod ech;
// The forwarders of --forwarder (T-369).
mod forwarder;
mod host;
// What a host offers the WebSocket over HTTP/2 (T-321).
mod http2;
// The servers of --hysteria, where UDP passes (T-580).
mod hysteria;
// Whether a resolver passes a TXT query for the user's own zone (T-875).
mod dns_zone;
// The servers of --tuic, where UDP passes (T-581).
mod ipv6;
#[cfg(feature = "iroh")]
mod iroh;
pub mod listeners;
mod names;
mod tuic;
// The TURN server of --turn (T-621).
mod turn;
// The tunnel of --devtunnel (T-755).
mod devtunnel;
// Whether the NAT keeps one mapping across destinations (T-641).
mod nat;
mod net;
mod pairs;
// The algorithm policy of --hop HOST --policy FILE (T-838).
mod policy;
// The sections that run at once, each into its own part (T-511).
mod parts;
mod quick;
mod relay_checks;
// The road that carried the forward check: a WebSocket, or the HTTP road (T-319).
mod road;
// The lines so far, their text and their JSON.
mod report;
mod samples;
// Which sections connect, in their order, and how many start together.
mod sections;
// The first server of --shadowsocks (T-373).
mod shadowsocks;
// The sshd of a roost, on this host (T-590).
mod sshd;
// The verdict of --tier: what this host allows, and what each closed capability closes (T-706).
mod tier;
// What the path does to a stream: buffering, a cap on bodies, a quiet end (T-325).
mod stream;
#[cfg(feature = "tor")]
mod tor;
// The GSRN road's TLS with SRP and its relay, with the feature `gsr` (T-707).
#[cfg(feature = "gsr")]
mod gsr;
#[cfg(unix)]
mod unix;
// The second proxy of --via (T-439).
mod via;
// The servers of --vless (T-440).
mod vless;
// Trojan's controls by name (T-761).
mod trojan;

// What doctor was given, and its parse (split from here to keep this file short).
mod args;
pub use args::{parsed, DoctorArgs};
pub use dns_zone::Flags as DnsFlags;
pub use exit::Flags as ExitFlags;
pub(crate) use report::Report;

// The words of `DoctorJobs`, which the settings file checks as it is read.
pub(crate) use sections::{count as jobs_count, MOST_JOBS};

/// The exit when at least one check failed.
pub const EXIT_FAILED: i32 = 1;

/// Run every check; returns the exit code. The report goes to `out`; only a
/// bad setting (64 for a flag, 78 for a variable) goes to `err`.
pub fn run_doctor(args: &DoctorArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if args.early_data.is_some() && args.vless.is_none() {
        return crate::relay_settings::Refusal::usage(
            "--early-data chooses the VLESS road's early data; it goes with --vless FILE",
        )
        .report("doctor", err);
    }
    // A word of the flag is a usage error; a word of the variable is a fault
    // in the environment. Both are refused before a probe, as a road's own
    // settings are.
    if let Some(word) = args.early_data.as_deref() {
        if let Err(why) = crate::vless::early_flag_word(word) {
            let _ = writeln!(err, "podssh doctor: {why}");
            return crate::exit_codes::EXIT_USAGE;
        }
    } else if args.vless.is_some()
        && let Ok(word) = std::env::var(crate::vless::EARLY_ENV)
        && let Err(why) = crate::vless::early_word(Some(&word))
    {
        let _ = writeln!(err, "podssh doctor: {why}");
        return crate::exitmap::sysexits::EX_CONFIG;
    }
    // A hop that does not read, or names no host that a dial can take, is a
    // usage error before any probe, as a bad port is (T-972).
    let hop_read = args
        .hop
        .as_deref()
        .map(|text| crate::ssh::hop::parse_hop(text).and_then(|hop| podssh_ws::names::check_direct_target(&hop.host)));
    if let Some(Err(why)) = hop_read {
        let _ = writeln!(err, "podssh doctor: --hop {why}");
        return crate::exit_codes::EXIT_USAGE;
    }
    // --tier gives the tier alone, from this host's facts: a flag of another
    // section would be passed over in silence, so it is refused (T-972).
    if args.tier {
        let others = [
            (args.hop.is_some(), "--hop"),
            (args.policy.is_some(), "--policy"),
            (args.dns.zone.is_some() || args.dns.server.is_some(), "--dns-zone and --dns-server"),
        ];
        if let Some((_, flag)) = others.iter().find(|(given, _)| *given) {
            let why = format!("--tier gives this host's tier alone; {flag} cannot go with it");
            return crate::relay_settings::Refusal::usage(why).report("doctor", err);
        }
    }
    // A policy judges the hop alone, and a file that does not load is a
    // fault of the setup (78); both before any probe.
    if args.policy.is_some() && args.hop.is_none() {
        let why = "--policy FILE judges a hop's algorithms; it goes with --hop HOST";
        return crate::relay_settings::Refusal::usage(why).report("doctor", err);
    }
    let policy = match args.policy.as_deref().map(crate::policy::load).transpose() {
        Ok(policy) => policy,
        Err(refusal) => return refusal.report("doctor", err),
    };
    if let Err(refusal) = crate::pins::apply(args.relay_addr.as_deref()) {
        return refusal.report("doctor", err);
    }
    let relays = match crate::relay_settings::relays(args.relay_host.as_deref(), std::env::var(relay::RELAY_ENV).ok()) {
        Ok(r) => r,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let failover = match crate::relay_settings::failover(
        args.relay_failover.as_deref(),
        std::env::var(podssh_relay::failover::MODE_ENV).ok(),
    ) {
        Ok(mode) => mode,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let forwarders = match crate::forwarder::for_doctor(args.forwarder.as_deref()) {
        Ok(forwarders) => forwarders,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let servers = match crate::shadowsocks::for_doctor(args.shadowsocks.as_deref()) {
        Ok(servers) => servers,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let road = match crate::via::chosen(&args.via, crate::via::trust(args.ca_file.as_deref())) {
        Ok(road) => road,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let links = match crate::vless::for_doctor(args.vless.as_deref()) {
        Ok(links) => links,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let quic_links = match crate::hysteria::for_doctor(args.hysteria.as_deref()) {
        Ok(links) => links,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let tuic_links = match crate::tuic::for_doctor(args.tuic.as_deref()) {
        Ok(links) => links,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let turn = match crate::turn::for_doctor(&args.turn, args.ca_file.as_deref()) {
        Ok(turn) => turn,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let tunnel = match devtunnel::asked(args.devtunnel.as_deref()) {
        Ok(tunnel) => tunnel,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let exit = match exit::asked(&args.exit, args.ca_file.as_deref()) {
        Ok(exit) => exit,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let dns = match dns_zone::asked(&args.dns) {
        Ok(dns) => dns,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let cert_env = std::env::var("SSL_CERT_FILE").ok().filter(|v| !v.trim().is_empty());
    let settings = crate::settings::here();
    let jobs = match sections::jobs(args.jobs.as_deref(), settings) {
        Ok(jobs) => jobs,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let stream = match stream::asked(args, &relays) {
        Ok(asked) => asked,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let stun = match nat::setting() {
        Ok(stun) => stun,
        Err(refusal) => return refusal.report("doctor", err),
    };
    let (trust, trust_from) = match (&args.ca_file, cert_env, &settings.ca_file) {
        (Some(file), ..) => (Trust::File(file.into()), "--ca-file"),
        (None, Some(file), _) => (Trust::File(file.into()), "SSL_CERT_FILE"),
        (None, None, Some(value)) => (Trust::File(value.text.clone().into()), "CaFile of the settings file"),
        (None, None, None) => (Trust::Default, "the default"),
    };

    let mut report = Report::new(out);
    report.json = args.json;
    if !report.json {
        let _ = writeln!(report.out, "podssh doctor: what this host allows, measured rather than assumed");
        let _ = writeln!(report.out, "{}, {} {}", crate::version::line(), std::env::consts::OS, std::env::consts::ARCH);
    }

    report.section("this host");
    let facts = host::check(&mut report);
    if args.tier {
        return tier::only(report, &facts, &relays.primary().host);
    }
    if let Some(text) = &args.hop {
        return hop::only(report, text, &trust, policy.as_ref());
    }
    if let stream::Asked::Only(plan) = &stream {
        return stream::only(report, plan, &trust);
    }
    match &settings.path {
        Some(path) => report.ok("settings", format!("podssh's settings are read from {}", path.display())),
        None => report.ok("settings", "no settings file; the flags, the variables and the defaults hold".to_string()),
    }
    if args.trojan {
        report.section("trojan");
        trojan::check(&mut report);
    }
    // The relay hosts that a run tries last now (T-059), and first (T-563).
    relay_record(&mut report);
    agent::check(&mut report);
    #[cfg(feature = "iroh")]
    {
        if !args.quick {
            iroh::udp(&mut report);
        }
    }

    report.section("egress");
    net::check_local(&mut report, &relays, &trust, trust_from);
    // The day of cloudflared's roots belongs to the quick tunnel's edge.
    if !args.quick {
        quick::check(&mut report);
    }
    if podssh_relay::open::offline() {
        report.unknown("network", crate::doctor::not_attempted());
        if args.cover.is_some() {
            report.unknown("cover credential", crate::doctor::not_attempted());
        }
        if args.full {
            report.unknown("login", crate::doctor::not_attempted());
        }
        if !forwarders.is_empty() {
            report.unknown("forwarder", crate::doctor::not_attempted());
        }
        if servers.is_some() {
            report.unknown("shadowsocks", crate::doctor::not_attempted());
        }
        if road.is_some() {
            report.unknown("via", crate::doctor::not_attempted());
        }
        if links.is_some() {
            report.unknown("vless", crate::doctor::not_attempted());
        }
        if quic_links.is_some() {
            report.unknown("hysteria", crate::doctor::not_attempted());
        }
        if tuic_links.is_some() {
            report.unknown("tuic", crate::doctor::not_attempted());
        }
        if turn.is_some() {
            report.unknown("turn", crate::doctor::not_attempted());
        }
        if tunnel.is_some() {
            report.unknown("devtunnel", crate::doctor::not_attempted());
        }
        if exit.is_some() {
            report.unknown("exit", crate::doctor::not_attempted());
        }
        if dns.is_some() {
            dns_zone::offline(&mut report);
        }
        if !args.quick {
            nat::offline(&mut report, &stun);
        }
        if args.quick {
            sections::left_out_line(&mut report);
            return report.finish();
        }
        report.section("pairs");
        let stored = pairs::stored(&mut report);
        pairs::not_asked(&mut report, &stored, &not_asked());
        return members::offline(report);
    }
    match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => {
            let checks = sections::Checks {
                relays: &relays,
                trust: &trust,
                failover,
                full: args.full,
                forwarders: &forwarders,
                servers: servers.as_ref(),
                road: road.as_ref(),
                links: links.as_ref(),
                early: args.early_data.as_deref(),
                hysteria: quic_links.as_ref(),
                tuic: tuic_links.as_ref(),
                turn: turn.as_ref(),
                devtunnel: tunnel.as_ref(),
                cover: args.cover.as_deref(),
                exit: exit.as_ref(),
                dns: dns.as_ref(),
                quick: args.quick,
                jobs,
                stream: stream.section(),
                stun: &stun,
            };
            runtime.block_on(sections::network(&mut report, &checks));
            // A probe may have left a task behind (a relay leg still closing);
            // the report is done, so none is waited for.
            runtime.shutdown_background();
        }
        Err(e) => report.fail("network", format!("could not start the async runtime: {}", podssh_ws::text::said(&e))),
    }
    if args.quick {
        sections::left_out_line(&mut report);
    }
    report.finish()
}

/// A check that `PODSSH_OFFLINE` kept from connecting, in the one wording of
/// each command (T-1032).
pub(crate) fn not_attempted() -> String {
    format!("not attempted: {}", podssh_relay::open::offline_line())
}

/// A pair or a member that `PODSSH_OFFLINE` kept from being asked.
pub(crate) fn not_asked() -> String {
    format!("not asked: {}", podssh_relay::open::offline_line())
}

/// The line of the relay hosts that a run tries last now (T-059), for a
/// failure or a rest; and, when there are any, the line of those that it
/// tries first, as they opened lately (T-563). A road other than the
/// WebSocket road is named.
fn relay_record(report: &mut Report<'_>) {
    use podssh_relay::failures::{self, Seen};
    let recent = failures::recent(&failures::Records::load(&podssh_relay::context::cache()), crate::pairs::now_ms());
    let window = failures::WINDOW.as_secs() / 60;
    let named = |s: &Seen| match s.road.as_str() {
        failures::WEBSOCKET => s.host.clone(),
        road => format!("{} on {road}", s.host),
    };
    let (mut last, mut opened) = (Vec::new(), Vec::new());
    for s in &recent {
        if let Some((ago, why)) = &s.last {
            last.push(format!("{} ({ago} s ago: {why})", named(s)));
        }
        if let Some((ago, n)) = s.opened {
            opened.push(format!("{} ({ago} s ago, {n} in all)", named(s)));
        }
    }
    match last.is_empty() {
        true => report.ok("failed relays", format!("no relay host failed in the last {window} min")),
        false => report.ok("failed relays", format!("tried last now: {}", last.join(", "))),
    }
    if !opened.is_empty() {
        report.ok("opened relays", format!("tried first while their sessions hold: {}", opened.join(", ")));
    }
}

// The public carriers of Q65, and the net held with its member relays (T-435).
mod carriers;
mod members;

#[cfg(test)]
mod tests {
    use podssh_ws::Verdict;

    use super::*;

    fn finish(lines: &[Verdict]) -> (i32, String) {
        let mut out = Vec::new();
        let code = {
            let mut report = Report::new(&mut out);
            for v in lines {
                report.line("check", v.clone());
            }
            report.finish()
        };
        (code, String::from_utf8(out).unwrap())
    }

    #[test]
    fn unknowns_are_counted_apart_and_only_a_failure_fails_the_run() {
        let ok = Verdict::Ok { detail: "fine".into() };
        let unknown = Verdict::Unknown { why: "could not run".into() };
        let failed = Verdict::Failed { detail: "broken".into() };
        let (code, text) = finish(&[ok.clone(), unknown.clone(), unknown.clone()]);
        assert_eq!(code, 0, "{text}");
        assert!(text.contains("1 ok, 0 FAIL, 2 ????"), "{text}");
        let (code, text) = finish(&[ok, unknown, failed]);
        assert_eq!(code, EXIT_FAILED, "{text}");
        assert!(text.contains("1 ok, 1 FAIL, 1 ????"), "{text}");
    }

    #[test]
    fn a_line_shows_its_label_and_no_terminal_controls() {
        let (_, text) = finish(&[Verdict::Failed { detail: "evil\u{1b}[2Jtext\r\nmore".into() }]);
        assert!(text.contains("  FAIL  check"), "{text}");
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(text.contains("evil[2Jtext more"), "{text:?}");
        let (_, text) = finish(&[Verdict::Unknown { why: "no".into() }]);
        assert!(text.contains("  ????  check"), "{text}");
    }
}
