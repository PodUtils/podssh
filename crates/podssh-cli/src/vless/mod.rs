//! `--vless FILE` (T-440, the operator's ruling Q66): VLESS servers that the
//! user runs (Xray-core, shoes, sing-box), in place of the relay, so that a
//! server of the user's own is a road with no relay. FILE is private, as a
//! pair file is (`podssh_relay::cache::read_private`): each line is a share
//! link, `vless://ID@HOST:PORT?type=ws|xhttp&security=tls&...`, whose ID never
//! goes to argv, a log or a message; `#` starts a comment. The servers are
//! tried in the order of the file, as the relay hosts are (T-220). The stream
//! goes over a WebSocket, or over XHTTP's plain requests on HTTP/2, which pass
//! where a proxy or a front end refuses the upgrade (`podssh_ws::vless`). The
//! host key of SSH protects the session, as on each road: the server sees the
//! target's name and SSH's encrypted bytes.

pub mod pipe;
pub mod reach;

use std::path::Path;
use std::sync::{Arc, OnceLock};

use podssh_ws::vless::early::Early;
use podssh_ws::vless::{FirstWrite, ReplayWindow, Server};
use podssh_ws::Trust;
use zeroize::Zeroizing;

use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{Resolved, Transport};

/// The servers of a run, in the order of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Servers {
    pub servers: Vec<Server>,
}

/// The file of `--vless`: refused (78) when it is not this user's private
/// file, or when a line cannot go.
pub fn read(path: &str) -> Result<Servers, Refusal> {
    let text =
        podssh_relay::cache::read_private(Path::new(path)).map_err(|why| Refusal::config(format!("--vless: {why}")))?;
    let text = Zeroizing::new(text);
    parse(&text, path).map_err(Refusal::config)
}

/// The lines of the file named `file`. A refusal names the file and the
/// line's number, never the line: it holds an ID.
pub fn parse(text: &str, file: &str) -> Result<Servers, String> {
    let mut servers = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        servers.push(Server::parse(line).map_err(|why| format!("--vless {file}:{}: {why}", i + 1))?);
    }
    if servers.is_empty() {
        return Err(format!("--vless {file}: it has no vless:// line"));
    }
    Ok(Servers { servers })
}

/// The flag of another road beside `--vless`, if one is given.
fn other_road(args: &SshArgs) -> Option<&'static str> {
    let flags = [
        ("--relay-host", args.relay_host.is_some()),
        ("--relay-failover", args.relay_failover.is_some()),
        ("--forwarder", args.forwarder.is_some()),
        ("--shadowsocks", args.shadowsocks.is_some()),
        ("--via", args.via.is_some()),
        ("--wstunnel", args.wstunnel.is_some()),
    ];
    flags.into_iter().find(|(_, given)| *given).map(|(flag, _)| flag)
}

/// The road of a run that resolved to the relay: the servers of the file
/// when `--vless` names one, with the relay's trust for their TLS; else the
/// road as it was. `-4` and `-6` choose the family that the relay dials,
/// and a server dials as it chooses.
pub fn or_relay(args: &SshArgs, transport: Transport) -> Result<Transport, Refusal> {
    let Some(path) = args.vless.as_deref() else { return Ok(transport) };
    let (trust, family) = match transport {
        Transport::Relay { trust, family, .. } => (trust, family),
        // A road of its own: `check` names it.
        other => return Ok(other),
    };
    if let Some(flag) = other_road(args) {
        return Err(Refusal::usage(format!("--vless and {flag} name two roads; a run has one")));
    }
    if family.is_some() {
        return Err(Refusal::usage(
            "-4 and -6 choose the family that the relay dials; a VLESS server dials as it chooses",
        ));
    }
    Ok(Transport::Vless { servers: read(path)?, trust, early: args.early_data.clone() })
}

/// `--vless` beside a road of its own, which [`or_relay`] never took: a
/// usage error.
pub fn check(args: &SshArgs, resolved: &Resolved) -> Result<(), Refusal> {
    if args.early_data.is_some() && args.vless.is_none() {
        return Err(Refusal::usage("--early-data chooses the VLESS road's early data; it goes with --vless FILE"));
    }
    if args.vless.is_none() {
        return Ok(());
    }
    let other = match &resolved.transport {
        Transport::Vless { .. } => return Ok(()),
        Transport::Direct => "--direct",
        Transport::Relay { .. } => "the relay",
        Transport::Forwarder { .. } => "the forwarders",
        Transport::Shadowsocks { .. } => "--shadowsocks",
        Transport::Via { .. } => "--via",
        Transport::Wstunnel { .. } => "--wstunnel",
        Transport::Node { .. } => "a node:// destination",
        Transport::Iroh { .. } => "an iroh: destination",
        Transport::Cloudflare { .. } => "a cf://HOST destination or first hop",
        Transport::Cloud { .. } => "an iap://, eice://, warp:// or tor:// destination or first hop",
        Transport::Derp { .. } => "a derp: destination",
        Transport::Chisel { .. } => "--chisel",
        Transport::Trojan { .. } => "--trojan",
        Transport::Tuic { .. } => "--tuic",
        Transport::Hysteria { .. } => "--hysteria",
        Transport::Turn { .. } => "--turn",
    };
    Err(Refusal::usage(format!("--vless cannot go with {other}, which is a road of its own; a run has one road")))
}

/// The servers that `podssh doctor --vless FILE` checks.
pub fn for_doctor(path: Option<&str>) -> Result<Option<Servers>, Refusal> {
    path.map(read).transpose()
}

/// The trust of the servers' TLS: `--ca-file`, else `SSL_CERT_FILE` or
/// `CaFile`, else podssh's default stores, as the relay's.
pub fn trust(ca_file: Option<&str>) -> Trust {
    crate::settings::ca_file(ca_file).map_or(Trust::Default, |file| Trust::File(file.into()))
}

/// The variable that chooses early data on the VLESS road: `0rtt`, `1rtt`
/// or `off`, the default.
pub const EARLY_ENV: &str = "PODSSH_VLESS_EARLY_DATA";

/// The nonces of this process's 0-RTT sessions: one window, so that a
/// nonce used twice inside ten minutes is a replay of the first.
fn early_window() -> &'static Arc<ReplayWindow> {
    static WINDOW: OnceLock<Arc<ReplayWindow>> = OnceLock::new();
    WINDOW.get_or_init(|| Arc::new(ReplayWindow::new()))
}

/// The early data that [`EARLY_ENV`] asks for, or none. The nonce is a
/// session's own and goes in no line and no log.
pub fn early_from_env() -> Result<Option<Early>, String> {
    let word = std::env::var(EARLY_ENV).ok();
    early_of(word.as_deref().map(str::trim).filter(|v| !v.is_empty()))
}

/// The words that [`EARLY_ENV`] and `--early-data` take, checked with no
/// nonce and no window: `0rtt`, `1rtt`, `off`, or `no` for off. A word that
/// is not one is refused with the variable's name.
pub fn early_word(value: Option<&str>) -> Result<(), String> {
    let word = match value {
        None => return Ok(()),
        Some(word) => word.trim(),
    };
    if word.is_empty() {
        return Err(format!("{EARLY_ENV}: 0rtt, 1rtt or off, not an empty word"));
    }
    if word.eq_ignore_ascii_case("off")
        || word.eq_ignore_ascii_case("no")
        || word.eq_ignore_ascii_case("0rtt")
        || word.eq_ignore_ascii_case("1rtt")
    {
        return Ok(());
    }
    Err(format!("{EARLY_ENV}: 0rtt, 1rtt or off, not {word}"))
}

/// [`early_word`] of the word of `--early-data`: a refusal names the flag, never the variable that the
/// word did not come from (64 at the caller, where the variable's is 78).
pub fn early_flag_word(word: &str) -> Result<(), String> {
    early_word(Some(word)).map_err(|why| flag_words(&why))
}

/// A refusal of [`early_word`] or [`early_of`], said of the flag.
fn flag_words(why: &str) -> String {
    why.replacen(EARLY_ENV, "--early-data", 1)
}

/// [`early_from_env`] of `value`, which a test gives. `1rtt` puts the nonce
/// in the window first, so that the session takes the 1-RTT fallback of a
/// nonce the window has seen.
pub fn early_of(value: Option<&str>) -> Result<Option<Early>, String> {
    use podssh_relay::session::{Entropy, OsEntropy};
    early_word(value)?;
    let word = value.map(str::trim).filter(|v| !v.is_empty()).unwrap_or("off");
    if word.eq_ignore_ascii_case("off") || word.eq_ignore_ascii_case("no") {
        return Ok(None);
    }
    let mut nonce = [0u8; 16];
    OsEntropy.fill(&mut nonce).map_err(|_| format!("{EARLY_ENV}: the OS gave no random bytes for the nonce"))?;
    let window = early_window().clone();
    let early = Early::new(window.clone(), nonce.to_vec());
    if word.eq_ignore_ascii_case("1rtt") {
        window.admit(&nonce);
    }
    Ok(Some(early))
}

/// The early data that `--early-data` names, or the variable's, or none.
pub fn early_from(flag: Option<&str>) -> Result<Option<Early>, String> {
    match flag {
        Some(word) => early_of(Some(word)).map_err(|why| flag_words(&why)),
        None => early_from_env(),
    }
}

/// The line of a session's early data: what the TLS handshake did with the
/// upgrade request, or nothing where the road offers no early data.
/// `Some(false)` is both a process with no ticket for the name and a server
/// that refused the ticket it was offered; the two are one outcome on the
/// wire, and the line says no more than that.
pub fn early_line(accepted: Option<bool>) -> String {
    match accepted {
        Some(true) => "; the TLS handshake carried the upgrade request as early data (0-RTT)".to_string(),
        Some(false) => {
            "; TLS accepted no early data (no ticket in this process, or the server refused it), so the request went \
             at 1-RTT on the same connection"
                .to_string()
        }
        None => String::new(),
    }
}

/// The record of a session's first write, for a status or doctor line: the
/// bytes, whether it was short of the 3,333-byte target and padded, and that
/// it was coalesced. A WebSocket's write is the upgrade head alone: a frame
/// before the handshake is refused by Xray-core's gorilla/websocket, so
/// VLESS's request follows in the first message and is not part of it.
pub fn first_write_line(report: FirstWrite, how: &str) -> String {
    if !report.coalesced {
        return "; no first write was coalesced".to_string();
    }
    let short = if report.short { ", padded short of 3,333 bytes" } else { "" };
    match how.contains("WebSocket") {
        true => format!(
            "; the first write was {} bytes{short}, coalesced: the upgrade head alone, as Xray-core's server refuses a \
             frame before the handshake; VLESS's request followed in its first message",
            report.bytes
        ),
        false => format!(
            "; the first write was {} bytes{short}, coalesced: the request and its first data went in one write",
            report.bytes
        ),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    // Built from its parts: a scanner of secrets takes a whole link with an
    // ID for a credential.
    fn line(rest: &str) -> String {
        ["vless://550e8400-e29b-41d4", "-a716-446655440000@", rest, "\n"].concat()
    }

    /// REPLAY-1 and REPLAY-2: the setting is a word of three, `off` is no
    /// early data, `1rtt` takes the fallback of a nonce the window has seen,
    /// and another word is refused with the variable's name.
    #[test]
    fn the_early_data_setting_is_one_of_three_words() {
        assert!(early_of(None).unwrap().is_none());
        assert!(early_of(Some("off")).unwrap().is_none());
        assert!(early_of(Some("no")).unwrap().is_none());
        let zero = early_of(Some("0rtt")).unwrap().expect("0-RTT");
        assert_eq!(podssh_ws::vless::early::Offer::of(Some(&zero)), podssh_ws::vless::early::Offer::ZeroRtt);
        let one = early_of(Some("1rtt")).unwrap().expect("1-RTT");
        assert_eq!(podssh_ws::vless::early::Offer::of(Some(&one)), podssh_ws::vless::early::Offer::OneRtt);
        let refused = early_of(Some("2rtt")).unwrap_err();
        assert!(refused.starts_with("PODSSH_VLESS_EARLY_DATA: 0rtt, 1rtt or off"), "{refused}");
        assert!(early_word(Some("  ")).is_err(), "an empty word is not off");
    }

    /// A word that is refused is said with the name of its source: the flag's with `--early-data`, the
    /// variable's with the variable.
    #[test]
    fn a_refused_word_names_the_flag_or_the_variable_it_came_from() {
        for (word, rest) in [("2rtt", "not 2rtt"), ("", "not an empty word"), ("  ", "not an empty word")] {
            let flag = format!("--early-data: 0rtt, 1rtt or off, {rest}");
            let variable = format!("{EARLY_ENV}: 0rtt, 1rtt or off, {rest}");
            assert_eq!(early_flag_word(word).unwrap_err(), flag, "{word:?}");
            assert_eq!(early_from(Some(word)).unwrap_err(), flag, "{word:?}");
            assert_eq!(early_word(Some(word)).unwrap_err(), variable, "{word:?}");
            assert_eq!(early_of(Some(word)).unwrap_err(), variable, "{word:?}");
        }
        for word in ["0rtt", "1RTT", "off", "No"] {
            assert!(early_flag_word(word).is_ok(), "{word}");
        }
    }

    #[test]
    fn the_flag_names_the_early_data_and_the_first_write_line_records_it() {
        assert!(early_from(Some("off")).unwrap().is_none());
        let one = early_from(Some("1rtt")).unwrap().expect("1-RTT");
        assert_eq!(podssh_ws::vless::early::Offer::of(Some(&one)), podssh_ws::vless::early::Offer::OneRtt);
        assert!(early_from(Some("2rtt")).is_err());
        let line =
            first_write_line(FirstWrite { bytes: 3_333, short: true, coalesced: true }, "XHTTP packet-up over HTTP/2");
        assert!(line.contains("the first write was 3333 bytes, padded short of 3,333 bytes, coalesced"), "{line}");
        let ws = first_write_line(FirstWrite { bytes: 3_333, short: true, coalesced: true }, "a WebSocket");
        assert!(ws.contains("the upgrade head alone"), "{ws}");
        assert_eq!(first_write_line(FirstWrite::default(), "a WebSocket"), "; no first write was coalesced");
    }

    #[test]
    fn a_file_holds_links_and_comments_and_a_refusal_names_the_line_never_its_id() {
        let (first, second) = (line("a.example:443?type=ws&security=tls"), line("b.example:443?type=xhttp"));
        let text = format!("# mine\n\n{first}{second}");
        let servers = parse(&text, "v.list").unwrap();
        assert_eq!(servers.servers.len(), 2);
        assert_eq!(servers.servers[1].shown(), "vless://b.example:443/");
        assert!(!format!("{servers:?}").contains("550e8400"));
        let bad = parse(&format!("\n{}", line("a.example:443?type=ws&flow=xtls-rprx-vision")), "f").unwrap_err();
        assert!(bad.starts_with("--vless f:2: flow=") && !bad.contains("550e8400"), "{bad}");
        let other = parse("vmess://secret\n", "f").unwrap_err();
        assert!(other.starts_with("--vless f:1: a line is vless://") && !other.contains("secret"), "{other}");
        assert!(parse("# only\n", "f").unwrap_err().contains("no vless:// line"));
    }
}
