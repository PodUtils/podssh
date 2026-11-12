//! The servers of `--tuic FILE` (T-581): for each, the probe of UDP to its
//! port, then QUIC, the token and a session to GitHub's SSH port, whose host
//! key must be one that GitHub publishes, as the relay's forward check
//! identifies the server, never by its banner. Where the probe gets no
//! answer, the line says that UDP does not pass here, and nothing waits for
//! QUIC.

use podssh_ws::dial;
use podssh_ws::tuic::{self, Dial};
use podssh_ws::Trust;

use super::relay_checks::{forward_host, github_keys, judge_unlisted, published_keys, TIMEOUT};
use super::Report;
use crate::tuic::Servers;

/// A line for each server.
pub(super) async fn check(report: &mut Report<'_>, servers: &Servers, trust: &Trust) {
    let target = dial::authority(forward_host(), 22);
    // GitHub's sshd speaks first: its banner is the answer.
    let road = Dial {
        trust,
        timeout: TIMEOUT,
        answer: tuic::ANSWER_WAIT,
        silence_is_ready: false,
        probe_wait: tuic::PROBE_WAIT,
    };
    for server in &servers.servers {
        let shown = server.shown();
        let started = std::time::Instant::now();
        let opened = match tuic::open(server, forward_host(), 22, &road).await {
            Ok(opened) => opened,
            Err(e) => {
                report.fail("tuic", e.line(&shown, &target));
                continue;
            }
        };
        let ms = started.elapsed().as_millis();
        let reached = format!("{target} through {shown}: the session opened over {} in {ms} ms", opened.how);
        let key = match podssh_ssh::probe::host_key(opened.stream, TIMEOUT).await {
            Ok(key) => key,
            Err(why) => {
                report.fail("tuic", format!("{reached}, then {why}"));
                continue;
            }
        };
        let fingerprint = podssh_ssh::known_hosts::fingerprint(&key);
        let kind = podssh_ssh::known_hosts::key_type(&key);
        let line = format!("{reached}; {kind} host key {fingerprint}");
        if published_keys().contains(&fingerprint.as_str()) {
            report.ok("tuic", format!("{line}, one of GitHub's published keys"));
            continue;
        }
        let current = github_keys(trust).await;
        report.line("tuic", judge_unlisted(&line, &fingerprint, current));
    }
}
