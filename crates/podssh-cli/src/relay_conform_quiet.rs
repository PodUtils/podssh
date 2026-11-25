//! The quiet session of `podssh relay conform` (T-713): a session to
//! `--target` that sends nothing, which waits for the relay's own clocks:
//! the keepalive, an empty binary frame every 25 s, and the idle cut,
//! `1001` at the limit that `/relays.json` publishes. Apart from the other
//! forward checks, beside which it runs, so that each file stays short.

use std::time::{Duration, Instant};

use podssh_ws::frame::{OPCODE_BINARY, OPCODE_CLOSE, OPCODE_CONTINUATION};
use podssh_ws::session::close_code_and_reason;

use crate::relay_conform::{clause, Check, Offers, Plan, Verdict};
use crate::relay_conform_forward::{close_words, upgrade};

/// The keepalive comes every 25 s by the contract; a little more is waited.
const KEEPALIVE_WAIT: Duration = Duration::from_secs(35);
/// The longest idle cut that a run waits for; past it the check is a skip.
const IDLE_MAX: Duration = Duration::from_secs(300);
/// What the relay may take after its idle cut to send its Close.
const IDLE_SLACK: Duration = Duration::from_secs(20);

/// A session to `--target` that sends nothing: the keepalive, an empty
/// binary frame, then the idle cut, `1001`, at the limit that the relay
/// publishes. A longer cut than [`IDLE_MAX`] is not waited for.
pub(crate) async fn quiet(plan: &Plan, offers: &Offers, token: &str) -> Vec<Check> {
    let Some((host, port)) = &plan.target else {
        return vec![
            Check::skip("keepalive", clause::FORWARD, "no --target: a session that dialed nothing may have none"),
            Check::skip("idle-cut", clause::LIMITS, "no --target"),
        ];
    };
    let started = Instant::now();
    let session = match podssh_relay::relay::forward_path(host, *port) {
        Ok(path) => upgrade(plan, &path, Some(token)).await.map_err(|e| podssh_ws::text::said(&e)),
        Err(why) => Err(why),
    };
    let session = match session {
        Ok(session) => session,
        Err(why) => {
            return vec![
                Check::fail("keepalive", clause::FORWARD, why, started),
                Check::skip("idle-cut", clause::LIMITS, "no session"),
            ]
        }
    };
    let idle = offers.idle_ms.map(Duration::from_millis).filter(|idle| *idle <= IDLE_MAX);
    let until = idle.map_or(KEEPALIVE_WAIT, |idle| (idle + IDLE_SLACK).max(KEEPALIVE_WAIT));
    let (mut keepalive, mut last_payload) = (None, started);
    let end = loop {
        let left = until.saturating_sub(started.elapsed());
        if left.is_zero() {
            break Err("no Close".to_string());
        }
        match tokio::time::timeout(left, session.read_frame()).await {
            Err(_) => break Err("no Close".to_string()),
            Ok(Err(e)) => break Err(podssh_ws::text::said(&e)),
            Ok(Ok(f)) if f.opcode == OPCODE_CLOSE => break Ok(close_code_and_reason(&f.payload)),
            Ok(Ok(f)) if matches!(f.opcode, OPCODE_BINARY | OPCODE_CONTINUATION) && f.payload.is_empty() => {
                keepalive.get_or_insert(started.elapsed());
                if idle.is_none() && keepalive.is_some() {
                    let _ = session.send_close(1000, "").await;
                    break Err("closed by the check".to_string());
                }
            }
            // The target's own bytes are payload: the cut counts from them.
            Ok(Ok(_)) => last_payload = Instant::now(),
        }
    };
    let mut checks = vec![match keepalive {
        Some(at) => Check::new(
            "keepalive",
            clause::FORWARD,
            Verdict::Pass,
            format!("an empty binary frame after {} ms", at.as_millis()),
            started,
        ),
        None => Check::fail("keepalive", clause::FORWARD, format!("no empty frame; {}", end_words(&end)), started),
    }];
    checks.push(idle_cut(offers, idle, &end, last_payload, started));
    checks
}

/// The verdict of the idle cut from how the quiet session ended.
fn idle_cut(
    offers: &Offers,
    idle: Option<Duration>,
    end: &Result<(Option<u16>, String), String>,
    last_payload: Instant,
    started: Instant,
) -> Check {
    const ID: &str = "idle-cut";
    let Some(idle) = idle else {
        return match offers.idle_ms {
            Some(ms) => {
                let words = format!("{ms} ms is past the {} s that a run waits", IDLE_MAX.as_secs());
                Check::skip(ID, clause::LIMITS, words)
            }
            None => Check::skip(ID, clause::LIMITS, "/relays.json publishes no idle_timeout_ms"),
        };
    };
    let quiet_for = last_payload.elapsed();
    match end {
        Ok((Some(1001), reason)) if quiet_for + Duration::from_secs(1) >= idle => {
            let words = format!("1001 {reason}, {} ms after the last payload", quiet_for.as_millis());
            Check::pass(ID, clause::LIMITS, words, started)
        }
        Ok((Some(1001), reason)) => {
            Check::fail(ID, clause::LIMITS, format!("1001 {reason}, before the published cut"), started)
        }
        Ok((Some(1000), reason)) => Check::skip(ID, clause::LIMITS, format!("the target ended first: 1000 {reason}")),
        Ok((code, reason)) => Check::fail(ID, clause::LIMITS, close_words(*code, reason), started),
        Err(why) => {
            let words = format!("{why} within the published cut and {} s", IDLE_SLACK.as_secs());
            Check::fail(ID, clause::LIMITS, words, started)
        }
    }
}

fn end_words(end: &Result<(Option<u16>, String), String>) -> String {
    match end {
        Ok((code, reason)) => format!("the session ended: {}", close_words(*code, reason)),
        Err(why) => why.clone(),
    }
}
