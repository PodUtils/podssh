//! The TURN server of `--turn` (T-621): its software where it says it, the
//! allocation (its relayed address and lifetime) and its time, the time of
//! Connect and ConnectionBind, then a session to GitHub's SSH port through
//! it, whose host key must be one that GitHub publishes, as the relay's
//! forward check identifies the far end, never by its banner. A proxy that
//! re-terminates TLS stops this road (`docs/carriers.md`), and its line says
//! so where TLS failed.

use podssh_ws::turn::{self, Dial, TurnError};
use podssh_ws::{dial, ConnectError, ProxyChoice};

use super::relay_checks::{forward_host, github_keys, judge_unlisted, published_keys, TIMEOUT};
use super::Report;
use crate::turn::Road;

/// The line of the server.
pub(super) async fn check(report: &mut Report<'_>, road: &Road) {
    let target = dial::authority(forward_host(), 22);
    let shown = road.shown();
    let dial =
        Dial { trust: &road.trust, proxy: &ProxyChoice::FromEnvironment, timeout: TIMEOUT, note: turn::silent() };
    let opened = match turn::open(&road.server, &road.credentials, forward_host(), 22, &dial).await {
        Ok(opened) => opened,
        Err(e @ TurnError::Connect(ConnectError::Tls(_))) if proxied() => {
            let why = "a proxy of HTTPS_PROXY that re-terminates TLS stops this road";
            report.fail("turn", format!("{}; {why}", e.line(&shown)));
            return;
        }
        Err(e) => {
            report.fail("turn", e.line(&shown));
            return;
        }
    };
    let reached = crate::turn::reach::said_of(&shown, &target, &opened);
    let key = match podssh_ssh::probe::host_key(opened.stream, TIMEOUT).await {
        Ok(key) => key,
        Err(why) => {
            report.fail("turn", format!("{reached}, then {why}"));
            return;
        }
    };
    let fingerprint = podssh_ssh::known_hosts::fingerprint(&key);
    let kind = podssh_ssh::known_hosts::key_type(&key);
    let line = format!("{reached}; {kind} host key {fingerprint}");
    if published_keys().contains(&fingerprint.as_str()) {
        report.ok("turn", format!("{line}, one of GitHub's published keys"));
        return;
    }
    let current = github_keys(&road.trust).await;
    report.line("turn", judge_unlisted(&line, &fingerprint, current));
}

/// Whether the host has a proxy for HTTPS, which a failed TLS may be.
fn proxied() -> bool {
    dial::PROXY_VARS.iter().any(|name| std::env::var(name).is_ok_and(|v| !v.trim().is_empty()))
}
