//! The forward road's checks of `podssh relay conform` (T-713): the
//! documents, the mint and the token's form, the upgrades that a relay must
//! refuse, `?dial=lazy`, a Ping, the Close of a session that dialed nothing
//! and a private target; with `--target`, bytes through a session, its
//! Close, the keepalive and the idle cut. Each upgrade is made here, step by
//! step, so that one can go with no token, or with one in its query string,
//! which podssh's own client never sends.

use std::time::{Duration, Instant};

use podssh_ws::client::{self as ws, ConnectError};
use podssh_ws::frame::{OPCODE_BINARY, OPCODE_CLOSE, OPCODE_CONTINUATION};
use podssh_ws::session::close_code_and_reason;
use podssh_ws::{ProxyChoice, RelaySession};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::relay_conform::{clause, lazy_target, Check, Offers, Plan, Report, STEP};

/// The address that a relay never dials: the cloud's metadata service, in
/// the link-local range that the contract's policy refuses.
const PRIVATE: (&str, u16) = ("169.254.169.254", 80);
/// The longest life of a token, by the contract, and a minute for clocks.
const TOKEN_LIFE_MS: i64 = 72 * 3600 * 1000 + 60_000;
/// The bytes that go to `--target`.
const PROBE: &[u8] = b"podssh relay conform\n";

/// `/health` and `/relays.json`. A host that does not answer the first ends
/// the run; the second gives the limits and the offers.
pub(crate) async fn documents(plan: &Plan, report: &mut Report) -> Offers {
    let (relay, proxy) = (&plan.relay, ProxyChoice::FromEnvironment);
    let started = Instant::now();
    match podssh_ws::https_get(&relay.host, relay.port, "/health", 64 * 1024, &plan.trust, &proxy, STEP).await {
        Ok(r) if r.status == 200 => {
            let doc: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
            let check = match doc["service"].as_str() {
                Some("tcp-ssh-relay") => {
                    let version = doc["version"].as_str().unwrap_or("no version");
                    Check::pass("health", clause::DIAGNOSTICS, format!("tcp-ssh-relay, {version}"), started)
                }
                _ => Check::fail("health", clause::DIAGNOSTICS, "/health names no service tcp-ssh-relay", started),
            };
            report.push(check);
        }
        Ok(r) => report.push(Check::fail(
            "health",
            clause::DIAGNOSTICS,
            format!("/health answered HTTP {}: {}", r.status, r.body_text(120)),
            started,
        )),
        Err(e) => {
            report.push(Check::fail(
                "health",
                clause::DIAGNOSTICS,
                format!("no answer: {}", podssh_ws::text::said(&e)),
                started,
            ));
            report.unreachable = true;
            return Offers::default();
        }
    }
    let started = Instant::now();
    let got = podssh_ws::https_get(&relay.host, relay.port, "/relays.json", 512 * 1024, &plan.trust, &proxy, STEP);
    match got.await {
        Ok(r) if r.status == 200 => match serde_json::from_slice::<Value>(&r.body) {
            Ok(doc) if doc["limits"]["max_frame_bytes"].is_u64() => {
                let offers = Offers::of(&doc);
                let idle = offers.idle_ms.map_or("no idle cut".to_string(), |ms| format!("an idle cut of {ms} ms"));
                report.push(Check::pass("relays-json", clause::DIAGNOSTICS, format!("its limits, {idle}"), started));
                offers
            }
            _ => {
                report.push(Check::fail("relays-json", clause::DIAGNOSTICS, "no limits.max_frame_bytes", started));
                Offers::default()
            }
        },
        Ok(r) => {
            let why = format!("/relays.json answered HTTP {}: {}", r.status, r.body_text(120));
            report.push(Check::fail("relays-json", clause::DIAGNOSTICS, why, started));
            Offers::default()
        }
        Err(e) => {
            report.push(Check::fail("relays-json", clause::DIAGNOSTICS, podssh_ws::text::said(&e), started));
            Offers::default()
        }
    }
}

/// The forward road's checks; those of a quiet session to `--target` run
/// beside the others, as they wait for the relay's own clocks.
pub(crate) async fn run(plan: &Plan, offers: &Offers, report: &mut Report) {
    let token = mint(plan, report).await;
    let Some(token) = token else {
        for id in ["upgrade-no-token", "upgrade-wrong-token", "token-in-query", "dial-lazy", "private-target"] {
            report.push(Check::skip(id, clause::TOKENS, "no token: the mint gave none"));
        }
        return;
    };
    let (quiet, mut checks) = tokio::join!(crate::relay_conform_quiet::quiet(plan, offers, &token), main(plan, &token));
    checks.extend(quiet);
    for check in checks {
        report.push(check);
    }
}

/// The checks that take a token and do not wait for the relay's clocks.
async fn main(plan: &Plan, token: &str) -> Vec<Check> {
    let mut checks = Vec::new();
    let (host, port) = lazy_target(plan);
    let lazy = match podssh_relay::relay::forward_path(&host, port) {
        Ok(path) => format!("{path}?dial=lazy"),
        Err(why) => {
            checks.push(Check::fail("dial-lazy", clause::OPTIONS, why, Instant::now()));
            return checks;
        }
    };
    checks.push(refused("upgrade-no-token", plan, &lazy, None).await);
    // The contract's form, with a MAC that this relay never made.
    let forged = format!("ephm1.{}.forward.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", now_ms() + 3_600_000);
    checks.push(refused("upgrade-wrong-token", plan, &lazy, Some(&forged)).await);
    checks.push(token_in_query(plan, &lazy).await);
    checks.extend(lazy_session(plan, &lazy, token).await);
    checks.push(private_target(plan, token).await);
    match &plan.target {
        Some((host, port)) => checks.extend(target_bytes(plan, host, *port, token).await),
        None => {
            checks.push(Check::skip("target-bytes", clause::FORWARD, "no --target"));
            checks.push(Check::skip("close-after-bytes", clause::CLOSES, "no --target"));
        }
    }
    checks
}

/// `POST /v1/mint` with `{}`: `{token, expires, scope}`, the token of the
/// form `ephm1.<expiry-ms>.forward.<mac>` and 72 h at most. A token whose
/// form is wrong still serves the checks after.
async fn mint(plan: &Plan, report: &mut Report) -> Option<Zeroizing<String>> {
    let (relay, started) = (&plan.relay, Instant::now());
    let proxy = ProxyChoice::FromEnvironment;
    let answer = podssh_ws::https_post_json(&relay.host, relay.port, "/v1/mint", b"{}", &plan.trust, &proxy, STEP);
    let r = match answer.await {
        Ok(r) => r,
        Err(e) => {
            report.push(Check::fail("mint", clause::TOKENS, podssh_ws::text::said(&e), started));
            return None;
        }
    };
    match r.status {
        200 => {}
        // A relay that mints for keys alone, or for no one, mints no token
        // for a stranger: no fault of the contract's.
        401 | 503 => {
            let why = format!("HTTP {}: {}; the checks that take a token are skipped", r.status, r.body_text(120));
            report.push(Check::skip("mint", clause::TOKENS, why));
            return None;
        }
        status => {
            let why = format!("HTTP {status}: {}", r.body_text(120));
            report.push(Check::fail("mint", clause::TOKENS, why, started));
            return None;
        }
    }
    let doc: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
    let Some(token) = doc["token"].as_str().map(|t| Zeroizing::new(t.to_string())) else {
        report.push(Check::fail("mint", clause::TOKENS, "the answer holds no token", started));
        return None;
    };
    let expires = doc["expires"].as_i64();
    let scope = doc["scope"].as_str();
    let check = match (expires, scope) {
        (Some(expires), Some("forward")) => match token_form(&token, expires, now_ms()) {
            Ok(()) => Check::pass("mint", clause::TOKENS, "ephm1.<expiry>.forward.<mac>, 72 h at most", started),
            Err(why) => Check::fail("mint", clause::TOKENS, why, started),
        },
        (None, _) => Check::fail("mint", clause::TOKENS, "the answer has no expires in ms", started),
        (_, _) => Check::fail("mint", clause::TOKENS, "the answer's scope is not forward", started),
    };
    report.push(check);
    Some(token)
}

/// Whether `token` has the contract's form, ends at `expires` and lives 72 h
/// at most from `now_ms`. The words never quote the token.
pub(crate) fn token_form(token: &str, expires: i64, now_ms: i64) -> Result<(), String> {
    let parts: Vec<&str> = token.split('.').collect();
    let [first, expiry, scope, mac] = parts[..] else {
        return Err("the token has not the four parts of ephm1.<expiry-ms>.forward.<mac>".into());
    };
    if first != "ephm1" || scope != "forward" {
        return Err("the token is not of the form ephm1.<expiry-ms>.forward.<mac>".into());
    }
    if expiry.parse::<i64>().ok() != Some(expires) {
        return Err("the token's expiry is not the answer's expires".into());
    }
    if mac.is_empty() || !mac.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("the token's MAC is empty, or not printable".into());
    }
    if expires <= now_ms {
        return Err("the token ended before it was given".into());
    }
    if expires - now_ms > TOKEN_LIFE_MS {
        return Err(format!("the token lives {} h, more than 72 h", (expires - now_ms) / 3_600_000));
    }
    Ok(())
}

/// An upgrade of `path` that must get `403`: with no token, or a wrong one.
async fn refused(id: &'static str, plan: &Plan, path: &str, token: Option<&str>) -> Check {
    let started = Instant::now();
    match upgrade(plan, path, token).await {
        Err(ConnectError::Refused { status: 403, body }) => {
            Check::pass(id, clause::TOKENS, format!("403: {body}"), started)
        }
        Err(e) => Check::fail(id, clause::TOKENS, format!("not 403: {}", podssh_ws::text::said(&e)), started),
        Ok(session) => {
            let _ = session.send_close(1000, "").await;
            Check::fail(id, clause::TOKENS, "the relay upgraded it", started)
        }
    }
}

/// A token in the query string, never in the header: a relay that takes it
/// takes a credential that logs keep. Asked with a token of one session
/// alone, which the next upgrade spends, so that the URL keeps nothing of
/// worth; a relay that mints none is a skip.
async fn token_in_query(plan: &Plan, lazy: &str) -> Check {
    const ID: &str = "token-in-query";
    let (relay, started) = (&plan.relay, Instant::now());
    let proxy = ProxyChoice::FromEnvironment;
    let path = "/v1/mint?once=1";
    let answer = podssh_ws::https_post_json(&relay.host, relay.port, path, b"{}", &plan.trust, &proxy, STEP);
    let once = match answer.await {
        Ok(r) if r.status == 200 => {
            let doc: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
            match (doc["once"].as_bool(), doc["token"].as_str()) {
                (Some(true), Some(token)) => Zeroizing::new(token.to_string()),
                _ => return Check::skip(ID, clause::TOKENS, "no token of one session; none of 72 h goes in a URL"),
            }
        }
        _ => return Check::skip(ID, clause::TOKENS, "no token of one session; none of 72 h goes in a URL"),
    };
    let encoded = once.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if !encoded {
        return Check::skip(ID, clause::TOKENS, "the token of one session has characters that a query would change");
    }
    let path = Zeroizing::new(format!("{lazy}&token={}", once.as_str()));
    let check = match upgrade(plan, &path, None).await {
        Err(ConnectError::Refused { status: 401 | 403, body }) => {
            Check::pass(ID, clause::TOKENS, format!("refused in the query: {body}"), started)
        }
        Err(e) => {
            Check::fail(ID, clause::TOKENS, format!("not refused as a token: {}", podssh_ws::text::said(&e)), started)
        }
        Ok(session) => {
            let _ = session.send_close(1000, "").await;
            Check::fail(ID, clause::TOKENS, "the relay took a token in the query string", started)
        }
    };
    // Spend it in its header, so that what a log kept is worth nothing.
    if let Ok(session) = upgrade(plan, lazy, Some(once.as_str())).await {
        let _ = session.send_close(1000, "").await;
        let _ = next(&session, STEP).await;
    }
    check
}

/// `?dial=lazy`: the upgrade with no dial, a Ping answered, and the Close of
/// a session that dialed nothing, `1000`.
async fn lazy_session(plan: &Plan, lazy: &str, token: &str) -> Vec<Check> {
    let started = Instant::now();
    let session = match upgrade(plan, lazy, Some(token)).await {
        Ok(session) => session,
        Err(e) => {
            return vec![
                Check::fail("dial-lazy", clause::OPTIONS, podssh_ws::text::said(&e), started),
                Check::skip("ping", clause::FORWARD, "no session"),
                Check::skip("close-before-dial", clause::CLOSES, "no session"),
            ];
        }
    };
    let mut checks = vec![Check::pass("dial-lazy", clause::OPTIONS, "101, and no byte sent", started)];
    let started = Instant::now();
    checks.push(match ping(&session).await {
        Ok(()) => Check::pass("ping", clause::FORWARD, "a Pong with the Ping's payload", started),
        Err(why) => Check::fail("ping", clause::FORWARD, why, started),
    });
    let started = Instant::now();
    let _ = session.send_close(1000, "").await;
    checks.push(match closed(&session, STEP).await {
        Ok((Some(1000), reason)) => Check::pass("close-before-dial", clause::CLOSES, format!("1000 {reason}"), started),
        Ok((code, reason)) => Check::fail("close-before-dial", clause::CLOSES, close_words(code, &reason), started),
        Err(why) => Check::fail("close-before-dial", clause::CLOSES, why, started),
    });
    checks
}

/// A Ping, and its Pong with the same payload.
async fn ping(session: &RelaySession) -> Result<(), String> {
    const PAYLOAD: &[u8] = b"podssh-conform";
    session.send_ping(PAYLOAD).await.map_err(|e| podssh_ws::text::said(&e))?;
    let waited = tokio::time::timeout(STEP, async {
        loop {
            // The reader takes the Pong in; it returns data and the Close.
            tokio::select! {
                _ = session.pong_arrived() => return Ok(()),
                frame = session.read_frame() => match frame {
                    Ok(f) if f.opcode == OPCODE_CLOSE => {
                        let (code, reason) = close_code_and_reason(&f.payload);
                        return Err(format!("the relay closed the session: {}", close_words(code, &reason)));
                    }
                    Ok(_) => {}
                    Err(e) => return Err(podssh_ws::text::said(&e)),
                },
            }
        }
    });
    waited.await.map_err(|_| format!("no Pong within {} s", STEP.as_secs()))??;
    let pongs = session.take_pongs();
    match pongs.iter().any(|(payload, _)| payload == PAYLOAD) {
        true => Ok(()),
        false => Err("a Pong whose payload is not the Ping's".into()),
    }
}

/// A target that the policy refuses before any dial: podssh's role answers
/// `403` (not in the ALLOW list), the default relay `400` (a blocked address
/// range); a `502` means the relay tried to reach it.
async fn private_target(plan: &Plan, token: &str) -> Check {
    const ID: &str = "private-target";
    let started = Instant::now();
    let path = match podssh_relay::relay::forward_path(PRIVATE.0, PRIVATE.1) {
        Ok(path) => path,
        Err(why) => return Check::fail(ID, clause::LIMITS, why, started),
    };
    match upgrade(plan, &path, Some(token)).await {
        Err(ConnectError::Refused { status: status @ (400 | 403), body }) => {
            Check::pass(ID, clause::LIMITS, format!("{status}: {body}"), started)
        }
        Err(ConnectError::Refused { status, body }) => {
            Check::fail(ID, clause::LIMITS, format!("{status}, not a refusal before any dial: {body}"), started)
        }
        Err(e) => Check::fail(ID, clause::LIMITS, podssh_ws::text::said(&e), started),
        Ok(session) => {
            let _ = session.send_close(1000, "").await;
            Check::fail(ID, clause::LIMITS, "the relay upgraded a session to the metadata address", started)
        }
    }
}

/// Bytes each way through a session that the relay dialed, then the Close
/// after them, `1000` once the target ends, as the contract's half-close.
async fn target_bytes(plan: &Plan, host: &str, port: u16, token: &str) -> Vec<Check> {
    let started = Instant::now();
    let session = match podssh_relay::relay::forward_path(host, port) {
        Ok(path) => upgrade(plan, &path, Some(token)).await.map_err(|e| podssh_ws::text::said(&e)),
        Err(why) => Err(why),
    };
    let session = match session {
        Ok(session) => session,
        Err(why) => {
            return vec![
                Check::fail("target-bytes", clause::FORWARD, why, started),
                Check::skip("close-after-bytes", clause::CLOSES, "no session"),
            ]
        }
    };
    let mut checks = Vec::new();
    let sent = session.send_binary(PROBE).await.map_err(|e| podssh_ws::text::said(&e));
    let back = match sent {
        Ok(()) => payload(&session, STEP).await,
        Err(why) => Err(why),
    };
    checks.push(match back {
        Ok(bytes) if bytes.starts_with(PROBE) => {
            Check::pass("target-bytes", clause::FORWARD, format!("{} bytes each way, an echo", PROBE.len()), started)
        }
        Ok(bytes) => Check::pass("target-bytes", clause::FORWARD, format!("{} bytes back", bytes.len()), started),
        Err(why) => Check::fail("target-bytes", clause::FORWARD, why, started),
    });
    let started = Instant::now();
    let _ = session.send_close(1000, "").await;
    // The target's bytes may come after the Close, up to 15 s of its silence.
    checks.push(match closed(&session, STEP + Duration::from_secs(15)).await {
        Ok((Some(1000), reason)) => Check::pass("close-after-bytes", clause::CLOSES, format!("1000 {reason}"), started),
        Ok((code, reason)) => Check::fail("close-after-bytes", clause::CLOSES, close_words(code, &reason), started),
        Err(why) => Check::fail("close-after-bytes", clause::CLOSES, why, started),
    });
    checks
}

/// TCP or CONNECT, TLS and the upgrade of `path`, with `token` in its
/// header, or none at all.
pub(crate) async fn upgrade(plan: &Plan, path: &str, token: Option<&str>) -> Result<RelaySession, ConnectError> {
    let (relay, proxy) = (&plan.relay, ProxyChoice::FromEnvironment);
    let opened = ws::open_tls_offering(&relay.host, relay.port, &relay.host, &plan.trust, &proxy, STEP, &[]);
    let (tls, peer) = opened.await?;
    let host_header = podssh_ws::dial::authority(&relay.host, relay.port);
    let key = podssh_ws::handshake::generate_key().map_err(|e| ConnectError::Upgrade(e.to_string()))?;
    let request = Zeroizing::new(match token {
        Some(token) => podssh_ws::handshake::build_request(&host_header, path, token, &key),
        None => format!(
            "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .into_bytes(),
    });
    let upgraded = tokio::time::timeout(STEP, ws::upgrade_with(tls, &request, &key)).await;
    let (tls, pending) =
        upgraded.map_err(|_| ConnectError::Timeout { step: "the WebSocket upgrade", after: STEP })??;
    Ok(RelaySession::over_tls(tls, peer, pending, None, ws::WRITE_TIMEOUT))
}

/// The first non-empty payload within `limit`; keepalives are skipped.
async fn payload(session: &RelaySession, limit: Duration) -> Result<Vec<u8>, String> {
    let read = async {
        loop {
            let f = session.read_frame().await.map_err(|e| podssh_ws::text::said(&e))?;
            match f.opcode {
                OPCODE_CLOSE => {
                    let (code, reason) = close_code_and_reason(&f.payload);
                    return Err(format!("the relay closed the session: {}", close_words(code, &reason)));
                }
                OPCODE_BINARY | OPCODE_CONTINUATION if !f.payload.is_empty() => return Ok(f.payload),
                _ => {}
            }
        }
    };
    tokio::time::timeout(limit, read).await.map_err(|_| format!("no byte within {} s", limit.as_secs()))?
}

/// Read until the relay's Close within `limit`; its code and reason.
async fn closed(session: &RelaySession, limit: Duration) -> Result<(Option<u16>, String), String> {
    let read = async {
        loop {
            let f = session.read_frame().await.map_err(|e| podssh_ws::text::said(&e))?;
            if f.opcode == OPCODE_CLOSE {
                return Ok(close_code_and_reason(&f.payload));
            }
        }
    };
    tokio::time::timeout(limit, read).await.map_err(|_| format!("no Close within {} s", limit.as_secs()))?
}

/// The next frame within `limit`, whatever it is.
async fn next(session: &RelaySession, limit: Duration) -> Option<podssh_ws::Frame> {
    tokio::time::timeout(limit, session.read_frame()).await.ok()?.ok()
}

pub(crate) fn close_words(code: Option<u16>, reason: &str) -> String {
    match code {
        Some(code) => format!("Close {code} {reason}, not 1000"),
        None => "a Close with no code".into(),
    }
}

fn now_ms() -> i64 {
    crate::pairs::now_ms()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_form_is_the_contracts() {
        let now = 1_700_000_000_000;
        let end = now + 3_600_000;
        assert_eq!(token_form(&format!("ephm1.{end}.forward.abc-_x"), end, now), Ok(()));
        for (token, says) in [
            (format!("ephm1.{end}.forward"), "four parts"),
            (format!("ephm2.{end}.forward.abc"), "not of the form"),
            (format!("ephm1.{}.forward.abc", end + 1), "not the answer's"),
            (format!("ephm1.{end}.forward."), "MAC is empty"),
        ] {
            let why = token_form(&token, end, now).unwrap_err();
            assert!(why.contains(says) && !why.contains("abc"), "{token}: {why}");
        }
        let far = now + 73 * 3_600_000;
        assert!(token_form(&format!("ephm1.{far}.forward.m"), far, now).unwrap_err().contains("more than 72 h"));
        assert!(token_form(&format!("ephm1.{now}.forward.m"), now, now).unwrap_err().contains("ended"));
    }

    #[test]
    fn a_close_is_said_with_its_code_or_its_lack() {
        assert_eq!(close_words(Some(1011), "write failed"), "Close 1011 write failed, not 1000");
        assert_eq!(close_words(None, ""), "a Close with no code");
    }
}
