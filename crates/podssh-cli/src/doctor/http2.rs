//! The line `http2` (T-321, RFC 8441), in the section `relay`, after
//! `cleartext`: what the first relay host that answered (else the first
//! host) offers the WebSocket over HTTP/2, with nothing sent but HTTP/2's
//! preface, its SETTINGS and a PING: the protocol that its TLS chose when
//! podssh offered `h2` then `http/1.1`, and on `h2` whether its SETTINGS
//! offer extended CONNECT; then whether the sessions of a run share one
//! connection to it, by `PODSSH_H2`. The section of the forwarders has the
//! line for each `wss://` one, whose road keeps the upgrade.

use std::time::Duration;

use podssh_relay::h2_road::Choice;
use podssh_relay::relay::Relay;
use podssh_ws::h2_road::Offered;
use podssh_ws::{ConnectError, DialError, ProxyChoice, Trust, Verdict};

use super::Report;

/// The line of the section relay, for `relay`, a host of a list that the
/// user named when `explicit`.
pub(super) async fn check(report: &mut Report<'_>, relay: &Relay, explicit: bool, trust: &Trust, timeout: Duration) {
    let offered = probe(&relay.host, relay.port, trust, timeout).await;
    report.line("http2", verdict(&relay.host, offered, podssh_relay::h2_road::from_env(), explicit));
    // H2-2: the client's shape, where the user chose one: the SETTINGS and
    // their order, the window and the fields. The PRIORITY frames and the
    // padding of a large DATA frame are recorded in the shape and are not
    // sent through h2 0.4; the line says that, so it claims no more.
    if let Some(shape) = named_shape() {
        report.line("http2 shape", shape);
    }
}

/// The shape that `--h2-shape` or `PODSSH_H2_SHAPE` names, as a line: unset
/// leaves the road's own shape and adds no line; another word fails.
pub(super) fn named_shape() -> Option<Verdict> {
    if let Some(chosen) = podssh_ws::h2_road::chosen() {
        return Some(shape_verdict(Ok(chosen)));
    }
    let word = std::env::var(podssh_ws::h2_road::SHAPE_ENV).ok().filter(|v| !v.trim().is_empty())?;
    named_shape_of(Some(&word))
}

/// [`named_shape`] of `value`, which a test gives.
fn named_shape_of(value: Option<&str>) -> Option<Verdict> {
    let word = value.map(str::trim).filter(|v| !v.is_empty())?;
    Some(shape_verdict(podssh_ws::h2_road::shape_of(Some(word))))
}

/// The line of a shape, or of the word that is not one.
fn shape_verdict(shape: Result<podssh_ws::h2_road::Shape, String>) -> Verdict {
    match shape {
        Ok(shape) => Verdict::Ok {
            detail: format!(
                "{}; PRIORITY frames and padded DATA are recorded and not sent through h2 0.4",
                shape.words()
            ),
        },
        Err(why) => Verdict::Failed { detail: why },
    }
}

/// The line of a forwarder whose host is `host:port`, over TLS.
pub(super) async fn forwarder(report: &mut Report<'_>, host: &str, port: u16, trust: &Trust, timeout: Duration) {
    let offered = probe(host, port, trust, timeout).await;
    report.line("http2", forwarder_verdict(host, offered));
}

async fn probe(host: &str, port: u16, trust: &Trust, timeout: Duration) -> Result<Offered, ConnectError> {
    podssh_ws::h2_road::probe(host, port, host, trust, &ProxyChoice::FromEnvironment, timeout).await
}

/// Whether no probe could run: the proxy setting or the name cannot be
/// used, so nothing was measured.
fn unmeasured(e: &ConnectError) -> bool {
    matches!(e, ConnectError::Config(_) | ConnectError::Dial(DialError::BadProxy(_) | DialError::InvalidTarget(_)))
}

/// The verdict of a relay host: a fact, `ok`; `????` where no probe could
/// run or the host was not reached, which the lines above name; `FAIL` for a
/// word of `PODSSH_H2` that is none of its own, which offers the road to no
/// host.
pub(super) fn verdict(
    host: &str,
    offered: Result<Offered, ConnectError>,
    choice: Result<Choice, String>,
    explicit: bool,
) -> Verdict {
    let choice = match choice {
        Ok(choice) => choice,
        Err(why) => return Verdict::Failed { detail: format!("{why}: no session takes the road of HTTP/2") },
    };
    let offered = match offered {
        Ok(offered) => offered,
        Err(e) if unmeasured(&e) => {
            return Verdict::Unknown { why: format!("not measured: {host}: {}", podssh_ws::text::said(&e)) }
        }
        Err(e) => {
            return Verdict::Unknown {
                why: format!("not measured, as {host} was not reached: {}", podssh_ws::text::said(&e)),
            }
        }
    };
    let road = match (offered.extended, choice.offers(explicit)) {
        (Some(true), true) => "the sessions of a run share one connection to it".to_string(),
        (Some(true), false) if choice == Choice::No => {
            "PODSSH_H2=no keeps each session on a connection of its own".to_string()
        }
        (Some(true), false) => {
            "a session takes the road where you name the host (--relay-host) or set PODSSH_H2=yes".to_string()
        }
        (Some(false), true) => {
            "each session takes the upgrade of HTTP/1.1, after one connection of HTTP/2 in a run".to_string()
        }
        (_, _) => "each session takes the upgrade of HTTP/1.1".to_string(),
    };
    Verdict::Ok { detail: format!("{host}: {}; {road}", offered.words()) }
}

/// The verdict of a forwarder's host: a fact too; its road keeps the
/// upgrade of HTTP/1.1.
pub(super) fn forwarder_verdict(host: &str, offered: Result<Offered, ConnectError>) -> Verdict {
    match offered {
        Ok(offered) => Verdict::Ok {
            detail: format!("{host}: {}; podssh's road to a forwarder takes its upgrade of HTTP/1.1", offered.words()),
        },
        Err(e) => Verdict::Unknown { why: format!("not measured: {host}: {}", podssh_ws::text::said(&e)) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offered(extended: Option<bool>) -> Result<Offered, ConnectError> {
        let alpn = Some(if extended.is_some() { "h2" } else { "http/1.1" }.to_string());
        Ok(Offered { alpn, extended, streams: extended.map(|_| 16) })
    }

    fn detail(verdict: Verdict) -> String {
        match verdict {
            Verdict::Ok { detail } => detail,
            other => panic!("not ok: {other:?}"),
        }
    }

    /// A host whose SETTINGS offer extended CONNECT is named so, and the
    /// line says whether the run's sessions share a connection to it; one
    /// that lacks it, or chose HTTP/1.1, is a fact, not a fault.
    #[test]
    fn a_named_shape_is_a_line_and_another_word_fails() {
        let browser = named_shape_of(Some("browser"));
        assert!(matches!(&browser, Some(Verdict::Ok { detail }) if detail.contains("SETTINGS 1:65536")), "{browser:?}");
        assert!(
            matches!(&browser, Some(Verdict::Ok { detail }) if detail.contains("not sent through h2 0.4")),
            "{browser:?}"
        );
        let firefox = named_shape_of(Some("firefox"));
        assert!(matches!(&firefox, Some(Verdict::Ok { detail }) if detail.contains("5 PRIORITY")), "{firefox:?}");
        assert!(named_shape_of(None).is_none());
        let bad = named_shape_of(Some("safari"));
        assert!(matches!(&bad, Some(Verdict::Failed { detail }) if detail.starts_with("PODSSH_H2_SHAPE")), "{bad:?}");
    }

    #[test]
    fn the_line_names_the_setting_and_the_road_of_the_run() {
        let shared = detail(verdict("r.test", offered(Some(true)), Ok(Choice::Auto), true));
        assert!(shared.starts_with("r.test: its TLS chose h2, whose SETTINGS offer extended CONNECT"), "{shared}");
        assert!(shared.ends_with("the sessions of a run share one connection to it"), "{shared}");
        let unnamed = detail(verdict("r.test", offered(Some(true)), Ok(Choice::Auto), false));
        assert!(unnamed.ends_with("(--relay-host) or set PODSSH_H2=yes"), "{unnamed}");
        let off = detail(verdict("r.test", offered(Some(true)), Ok(Choice::No), true));
        assert!(off.ends_with("PODSSH_H2=no keeps each session on a connection of its own"), "{off}");
        let lacks = detail(verdict("r.test", offered(Some(false)), Ok(Choice::Yes), false));
        assert!(lacks.contains("offer no extended CONNECT") && lacks.contains("after one connection"), "{lacks}");
        let http1 = detail(verdict("r.test", offered(None), Ok(Choice::Auto), true));
        assert!(http1.ends_with("its TLS chose http/1.1, not h2; each session takes the upgrade of HTTP/1.1"));
    }

    /// A bad word fails; a host that was not reached is not measured.
    #[test]
    fn a_bad_word_fails_and_an_unreached_host_is_not_measured() {
        let bad = verdict("r.test", offered(Some(true)), Err("PODSSH_H2: auto, yes or no".into()), true);
        assert!(matches!(&bad, Verdict::Failed { detail } if detail.starts_with("PODSSH_H2: auto, yes or no")));
        let unreached = ConnectError::Timeout { step: "the TLS handshake", after: Duration::from_secs(10) };
        let unknown = verdict("r.test", Err(unreached), Ok(Choice::Auto), true);
        assert!(matches!(&unknown, Verdict::Unknown { why } if why.contains("was not reached")), "{unknown:?}");
        let forwarder = forwarder_verdict("w.example", offered(Some(false)));
        assert!(detail(forwarder).ends_with("podssh's road to a forwarder takes its upgrade of HTTP/1.1"));
    }
}
