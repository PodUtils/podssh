//! The servers of `--vless FILE` (T-440): for each, its link's transport,
//! and each mode of XHTTP where the link says auto, through `HTTPS_PROXY` as
//! a run dials, then a session to GitHub's SSH port, whose host key must be
//! one that GitHub publishes, as the relay's forward check identifies the
//! server, never by its banner. Each line names the transport that carried
//! it, so that the user learns which one passes here; a mode of XHTTP that
//! went over HTTP/1.1, where HTTP/2 was refused, says its second connection
//! (Q67).

use podssh_ws::dial::{self, ProxyChoice};
use podssh_ws::vless::{self, AtEnd, Dial, Mode, Server, Transport};
use podssh_ws::Trust;

use super::relay_checks::{forward_host, github_keys, judge_unlisted, published_keys, TIMEOUT};
use super::Report;
use crate::vless::Servers;

/// A line for each server and each transport that it is tried on.
pub(super) async fn check(report: &mut Report<'_>, servers: &Servers, trust: &Trust, early: Option<&str>) {
    let target = dial::authority(forward_host(), 22);
    let early = match crate::vless::early_from(early) {
        Ok(early) => early,
        Err(why) => {
            report.fail("vless", why);
            return;
        }
    };
    let road = Dial {
        trust: trust.clone(),
        way: podssh_ws::client::way(&ProxyChoice::FromEnvironment),
        timeout: TIMEOUT,
        answer: vless::ANSWER_WAIT,
        silence_is_ready: false,
        at_end: AtEnd::Now,
        early,
    };
    for server in &servers.servers {
        let shown = server.shown();
        if let Some(line) = stream_one_line(server) {
            report.ok("vless stream-one", line);
        }
        let first = match dial::proxy_from_env(&server.host) {
            Ok(Some(proxy)) => format!(", through the proxy {proxy}"),
            _ => String::new(),
        };
        for transport in vless::modes(server.transport) {
            let started = std::time::Instant::now();
            let opened = match vless::open_as(server, transport, forward_host(), 22, &road).await {
                Ok(opened) => opened,
                Err(e) => {
                    report.fail("vless", format!("{}{first}: {}", transport.name(), e.line(&shown, &target)));
                    continue;
                }
            };
            let ms = started.elapsed().as_millis();
            let wrote = crate::vless::first_write_line(opened.first_write, &opened.how);
            let reached = format!("{target} through {shown}{first} over {}, answered in {ms} ms{wrote}", opened.how);
            let key = match podssh_ssh::probe::host_key(opened.stream, TIMEOUT).await {
                Ok(key) => key,
                Err(why) => {
                    report.fail("vless", format!("{reached}, then {why}"));
                    continue;
                }
            };
            let fingerprint = podssh_ssh::known_hosts::fingerprint(&key);
            let kind = podssh_ssh::known_hosts::key_type(&key);
            let line = format!("{reached}; {kind} host key {fingerprint}");
            if published_keys().contains(&fingerprint.as_str()) {
                report.ok("vless", format!("{line}, one of GitHub's published keys"));
                continue;
            }
            let current = github_keys(trust).await;
            report.line("vless", judge_unlisted(&line, &fingerprint, current));
        }
    }
}

/// XHTTP-3: a link that names stream-one says, before any connection, why
/// HTTP/1.1 refuses it (78) and what carries it instead.
fn stream_one_line(server: &Server) -> Option<String> {
    let Transport::Xhttp(Mode::StreamOne) = server.transport else { return None };
    Some(format!(
        "{}: mode=stream-one is carried over HTTP/2; over HTTP/1.1 it is refused with 78, because the server reads a \
         request's whole body before it answers and a session's body never ends; use packet-up or stream-up over two \
         connections, serve h2, or type=ws",
        server.shown()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// XHTTP-3: the line names the refusal and the modes that pass; a link
    /// of another mode has no line.
    #[test]
    fn a_stream_one_link_names_the_http_1_1_refusal() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let one = Server::parse(&format!("vless://{id}@v.example:443?type=xhttp&mode=stream-one&security=tls"))
            .expect("a link");
        let line = stream_one_line(&one).expect("a line for stream-one");
        assert!(line.contains("refused with 78"), "{line}");
        assert!(line.contains("packet-up or stream-up"), "{line}");
        assert!(!line.contains(id), "the ID is not in the line: {line}");
        let up = Server::parse(&format!("vless://{id}@v.example:443?type=xhttp&mode=stream-up&security=tls"))
            .expect("a link");
        assert!(stream_one_line(&up).is_none());
    }
}
