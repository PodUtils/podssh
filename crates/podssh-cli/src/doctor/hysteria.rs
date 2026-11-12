//! The servers of `--hysteria FILE` (T-580): for each, the probe of UDP to
//! its port and its round trip, then QUIC, the credential and a session to
//! GitHub's SSH port, whose host key must be one that GitHub publishes, as
//! the relay's forward check identifies the server, never by its banner.
//! Where the probe gets no answer, the line says that UDP does not pass here,
//! and nothing waits for QUIC; where a proxy is set for the server's host,
//! which carries no UDP, the line says so and nothing is sent.

use podssh_ws::dial;
use podssh_ws::hysteria::{self, Dial};
use podssh_ws::Trust;

use super::relay_checks::{forward_host, github_keys, judge_unlisted, published_keys, TIMEOUT};
use super::Report;
use crate::hysteria::Servers;

/// A line for each server.
pub(super) async fn check(report: &mut Report<'_>, servers: &Servers, trust: &Trust) {
    let target = dial::authority(forward_host(), 22);
    let road = Dial { trust, timeout: TIMEOUT, probe_wait: hysteria::probe::WAIT };
    for server in &servers.servers {
        let shown = server.shown();
        let started = std::time::Instant::now();
        let opened = match hysteria::open(server, forward_host(), 22, &road).await {
            Ok(opened) => opened,
            Err(e) => {
                report.fail("hysteria", e.line(&shown, &target));
                continue;
            }
        };
        let ms = started.elapsed().as_millis();
        let probe = opened.probe.as_millis();
        let reached = format!(
            "{target} through {shown}: UDP answered at {} in {probe} ms, and the session opened in {ms} ms",
            opened.addr
        );
        let key = match podssh_ssh::probe::host_key(opened.stream, TIMEOUT).await {
            Ok(key) => key,
            Err(why) => {
                report.fail("hysteria", format!("{reached}, then {why}"));
                continue;
            }
        };
        let fingerprint = podssh_ssh::known_hosts::fingerprint(&key);
        let kind = podssh_ssh::known_hosts::key_type(&key);
        let line = format!("{reached}; {kind} host key {fingerprint}");
        if published_keys().contains(&fingerprint.as_str()) {
            report.ok("hysteria", format!("{line}, one of GitHub's published keys"));
            continue;
        }
        let current = github_keys(trust).await;
        report.line("hysteria", judge_unlisted(&line, &fingerprint, current));
    }
}
