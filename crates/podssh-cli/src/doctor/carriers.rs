//! The section `carriers` (T-435): the public carriers of the operator's
//! ruling Q65 that this host reaches, which the roads try unasked: the
//! magic-wormhole transit relay (a pair's transit road, T-436), the
//! mailboxes of the pairing by a short code (T-086, T-616) and the Piping
//! Server (T-437). Each is one connection through the proxy, one after
//! another, and carries nothing of the user's: the transit relay's
//! WebSocket is opened and closed with no line said, so it pairs nothing; a
//! mailbox says its welcome and is bound to podssh's application, with no
//! nameplate claimed; the Piping Server is asked its `/version`. croc's
//! bridge (T-694), a last fallback of Q78 that a pair's roads also try
//! unasked, has its WebSocket to its first relay opened and closed with no
//! frame said, so it joins no room. A carrier that its variable turns off
//! is not asked. The Wisp demo server of Q65 is a forwarder: the line
//! `fallback` says how `--forwarder wisp` asks it.

use std::sync::Arc;
use std::time::Duration;

use podssh_relay::code::mailbox::Mailbox;
use podssh_relay::croc::{self, Bridge};
use podssh_relay::piping::Server;
use podssh_relay::session::{Entropy, OsEntropy};
use podssh_relay::transit::{self, Setting};
use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};
use tokio::time::Instant;

use super::Report;
use crate::piping_road::Want;

/// The bound of each carrier's probe, whatever its steps' own: the section's
/// probes, one after another, end within 10 s each.
const WAIT: Duration = Duration::from_secs(10);
/// The most bytes of a Piping Server's `/version` that are read.
const VERSION_MOST: usize = 256;

/// What the section asks, read from the variables of the roads: each
/// carrier, `None` when its variable turns it off, or the fault of its
/// variable.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Plan {
    transit: Result<Option<WsUrl>, String>,
    mailboxes: Result<Option<Vec<WsUrl>>, String>,
    piping: Result<Option<Vec<Server>>, String>,
    croc: Result<croc::Setting, String>,
}

/// The words of a variable that turn a carrier off.
fn off(value: Option<&str>) -> bool {
    matches!(value.map(|v| v.trim().to_ascii_lowercase()).as_deref(), Some("no" | "off" | "false" | "0"))
}

/// The values of `PODSSH_CROC` and `PODSSH_LAST_RESORT`, which croc's road reads together.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct CrocValues<'a> {
    pub(super) croc: Option<&'a str>,
    pub(super) last: Option<&'a str>,
}

/// The plan of the variables' values: `PODSSH_TRANSIT`, `PODSSH_PAIR_MAILBOX`,
/// `PODSSH_PIPING`, and croc's, read as their roads read them.
pub(super) fn plan(
    transit_value: Option<&str>,
    mailbox_value: Option<&str>,
    piping_value: Option<&str>,
    croc_values: CrocValues<'_>,
) -> Plan {
    let transit = transit::setting(transit_value).map(|setting| match setting {
        Setting::On(url) => Some(url),
        Setting::Off => None,
    });
    let mailboxes = match off(mailbox_value) {
        true => Ok(None),
        false => podssh_relay::code::mailboxes(None, mailbox_value).map(Some),
    };
    let piping = match crate::piping_road::want_from(piping_value) {
        Ok(Want::Off) => Ok(None),
        Ok(Want::Unasked(servers) | Want::Asked(servers)) => Ok(Some(servers)),
        Err(refusal) => Err(refusal.message),
    };
    let croc = croc::setting(croc_values.croc, croc_values.last);
    Plan { transit, mailboxes, piping, croc }
}

/// The plan of this process's variables.
fn plan_here() -> Plan {
    let var = |name: &str| std::env::var(name).ok();
    let (transit, mailbox) = (var(transit::ENV), var(podssh_relay::code::ENV));
    let (croc_value, last) = (var(croc::ENV), var(croc::LAST_RESORT));
    let croc_values = CrocValues { croc: croc_value.as_deref(), last: last.as_deref() };
    plan(transit.as_deref(), mailbox.as_deref(), var(crate::piping_road::ENV).as_deref(), croc_values)
}

/// The lines of the carriers that `plan` does not ask, with no connection:
/// each one turned off, ????; each variable that cannot be used, FAIL.
fn unasked_lines(report: &mut Report<'_>, plan: &Plan) {
    let lines = [
        ("transit relay", plan.transit.as_ref().map(Option::is_none), transit::ENV),
        ("mailbox", plan.mailboxes.as_ref().map(Option::is_none), podssh_relay::code::ENV),
        ("Piping Server", plan.piping.as_ref().map(Option::is_none), crate::piping_road::ENV),
    ];
    for (label, turned_off, variable) in lines {
        match turned_off {
            Ok(true) => report.unknown(label, format!("{variable}=no turns it off, so it was not asked")),
            Ok(false) => {}
            Err(why) => report.fail(label, why.clone()),
        }
    }
    match &plan.croc {
        Ok(croc::Setting::Off("pod-services")) => {
            report.unknown("croc's bridge", "pod-services names no bridge, so it was not asked")
        }
        Ok(croc::Setting::Off(variable)) => {
            report.unknown("croc's bridge", format!("{variable}=no turns it off, so it was not asked"))
        }
        Ok(croc::Setting::On(_)) => {}
        Err(why) => report.fail("croc's bridge", why.clone()),
    }
}

/// The section's lines.
pub(super) async fn check(report: &mut Report<'_>, trust: &Trust) {
    let plan = plan_here();
    unasked_lines(report, &plan);
    if let Ok(Some(url)) = &plan.transit {
        transit_line(report, url, trust).await;
    }
    if let Ok(Some(urls)) = &plan.mailboxes {
        for url in urls {
            mailbox_line(report, url, trust).await;
        }
    }
    // Each server of the road, as a node may wait at any (T-497).
    if let Ok(Some(servers)) = &plan.piping {
        for server in servers {
            piping_line(report, server, trust).await;
        }
    }
    if let Ok(croc::Setting::On(bridge)) = &plan.croc {
        croc_line(report, bridge, trust).await;
    }
}

/// The URL of the first relay through `bridge`, as a pair's rooms name one.
fn first_relay(bridge: &Bridge) -> WsUrl {
    if bridge.url.target.contains('?') {
        return bridge.url.clone();
    }
    let target = format!("{}?relay=0&port={}", bridge.url.target, croc::PORT);
    WsUrl { target, ..bridge.url.clone() }
}

/// croc's bridge: its WebSocket to the first relay, opened and closed with
/// no frame, so that no room is joined and no password said.
async fn croc_line(report: &mut Report<'_>, bridge: &Bridge, trust: &Trust) {
    let label = format!("croc's bridge {}", bridge.url.shown());
    let started = Instant::now();
    let url = first_relay(bridge);
    let dialed = tokio::time::timeout(WAIT, croc::far::dial(&url, trust, &ProxyChoice::FromEnvironment)).await;
    match dialed {
        Ok(Ok(session)) => {
            let ms = started.elapsed().as_millis();
            let _ = tokio::time::timeout(Duration::from_secs(2), session.send_close(1000, "")).await;
            let whose = if bridge.public { ", a third party's (Q78)" } else { "" };
            report.ok(&label, format!("the WebSocket to relay 0 opened in {ms} ms{whose}; no room joined"));
        }
        Ok(Err(why)) => report.fail(&label, why),
        Err(_) => report.fail(&label, format!("no WebSocket within {} s", WAIT.as_secs())),
    }
}

/// The transit relay's WebSocket, opened and closed with no line: Least
/// Authority's takes the host's trust, as the road takes it, and another
/// one doctor's.
async fn transit_line(report: &mut Report<'_>, url: &WsUrl, trust: &Trust) {
    let label = format!("transit relay {}", url.shown());
    let least = WsUrl::parse(&transit::default_url()).is_ok_and(|least| least == *url);
    let trust = if least { crate::pairs::trust(None) } else { trust.clone() };
    let started = Instant::now();
    let dialed = tokio::time::timeout(WAIT, transit::far::dial(url, &trust, &ProxyChoice::FromEnvironment)).await;
    match dialed {
        Ok(Ok(session)) => {
            let ms = started.elapsed().as_millis();
            let _ = tokio::time::timeout(Duration::from_secs(2), session.send_close(1000, "")).await;
            let line = format!("the WebSocket opened in {ms} ms, certificate verified; no line said, nothing paired");
            report.ok(&label, line);
        }
        Ok(Err(why)) => report.fail(&label, why),
        Err(_) => report.fail(&label, format!("no WebSocket within {} s", WAIT.as_secs())),
    }
}

/// A mailbox's welcome, bound to podssh's application, then left at once.
async fn mailbox_line(report: &mut Report<'_>, url: &WsUrl, trust: &Trust) {
    let label = format!("mailbox {}", url.shown());
    let mut bytes = [0u8; 5];
    if OsEntropy.fill(&mut bytes).is_err() {
        return report.unknown(&label, "not asked: this host gave no random side");
    }
    let side: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let started = Instant::now();
    let config = podssh_relay::code::config(trust, &ProxyChoice::FromEnvironment, Arc::new(|_| {}));
    match tokio::time::timeout(WAIT, Mailbox::connect(url, &config, &side)).await {
        Ok(Ok(mailbox)) => {
            let ms = started.elapsed().as_millis();
            let motd = mailbox.motd.as_ref().map(|motd| format!("; it says: {motd}")).unwrap_or_default();
            let _ = tokio::time::timeout(Duration::from_secs(2), mailbox.end()).await;
            report.ok(&label, format!("welcomed in {ms} ms, certificate verified; no nameplate claimed{motd}"));
        }
        Ok(Err(failed)) => report.fail(&label, failed.to_string()),
        Err(_) => report.fail(&label, format!("no welcome within {} s", WAIT.as_secs())),
    }
}

/// The Piping Server's `/version`, which waits for no sender.
async fn piping_line(report: &mut Report<'_>, server: &Server, trust: &Trust) {
    let label = format!("Piping Server {server}");
    let http = crate::piping_road::http(server, trust);
    let started = Instant::now();
    // The dial has its own bound for TCP and for TLS: the whole probe, this one.
    let asked = tokio::time::timeout(WAIT, http.get_all(&server.path("version"), Some(WAIT), VERSION_MOST)).await;
    match asked {
        Ok(Ok(body)) => {
            let ms = started.elapsed().as_millis();
            let version = podssh_ws::text::one_line(&String::from_utf8_lossy(&body));
            let proto = http.proto().map(|proto| format!(" over {proto}")).unwrap_or_default();
            report.ok(&label, format!("/version answered {version:?}{proto} in {ms} ms, certificate verified"));
        }
        Ok(Err(failed)) => report.fail(&label, failed.to_string()),
        Err(_) => report.fail(&label, format!("no answer within {} s", WAIT.as_secs())),
    }
    http.close().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With no variable each carrier of Q65 is asked: Least Authority's
    /// transit relay, the two public mailboxes in order, and ppng.io. A
    /// variable's no asks none of its carrier, and says so with no
    /// connection; a word that its road refuses fails.
    #[test]
    fn each_carrier_is_asked_unless_its_variable_turns_it_off() {
        let all = plan(None, None, None, CrocValues::default());
        assert_eq!(all.transit, Ok(Some(WsUrl::parse(&transit::default_url()).unwrap())));
        let shown: Vec<String> = all.mailboxes.clone().unwrap().unwrap().iter().map(WsUrl::shown).collect();
        let public = podssh_relay::code::public_mailboxes().into_iter().map(|url| WsUrl::parse(&url).unwrap().shown());
        let public: Vec<String> = public.collect();
        assert_eq!(shown, public);
        assert_eq!(all.piping, Ok(Some(podssh_relay::piping::server::public())));
        let off = CrocValues { croc: Some("no"), last: None };
        let none = plan(Some("no"), Some("No"), Some("off"), off);
        assert_eq!(none.transit, Ok(None), "{none:?}");
        assert_eq!(none.mailboxes, Ok(None), "{none:?}");
        assert_eq!(none.piping, Ok(None), "{none:?}");
        assert_eq!(none.croc, Ok(croc::Setting::Off(croc::ENV)), "{none:?}");
        // The switch of the last fallbacks turns croc's public bridge off too.
        let last = plan(None, None, None, CrocValues { croc: None, last: Some("no") });
        assert_eq!(last.croc, Ok(croc::Setting::Off(croc::LAST_RESORT)));
        // A bridge of the user's own is asked whatever the switch says.
        let own = plan(None, None, None, CrocValues { croc: Some("ws://127.0.0.1:8099/ws"), last: Some("no") });
        assert!(matches!(&own.croc, Ok(croc::Setting::On(bridge)) if !bridge.public), "{own:?}");
        let mut out = Vec::new();
        let mut report = Report::new(&mut out);
        unasked_lines(&mut report, &none);
        unasked_lines(&mut report, &plan(Some("maybe"), None, None, CrocValues::default()));
        let _ = report.finish();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("PODSSH_TRANSIT=no turns it off, so it was not asked"), "{text}");
        assert!(text.contains("PODSSH_PAIR_MAILBOX=no turns it off") && text.contains("PODSSH_PIPING=no"), "{text}");
        assert!(text.contains("croc's bridge") && text.contains("PODSSH_CROC=no turns it off"), "{text}");
        assert!(text.contains("0 ok, 1 FAIL, 4 ????"), "{text}");
    }
}
