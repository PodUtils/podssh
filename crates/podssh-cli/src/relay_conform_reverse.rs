//! The reverse road's checks of `podssh relay conform --reverse` (T-713):
//! a pair of the check's own, its node's `hello`, an operator's leg opened
//! and readied, a byte each way, the leg's end, the status, the refusal of a
//! wrong stop token, the extensions that the relay offers, and the stop,
//! with the pair's tokens refused after it. The node and the operator are
//! spoken here frame by frame, as the contract writes them, not through
//! podssh's own node, whose layer would hide a fault of the relay's.
//!
//! The pair is stopped at the end whatever happened before: the checks that
//! use it have their own limit, and the stop has its own after them.

use std::time::{Duration, Instant};

use podssh_relay::pair::halt::{self, Halted, Resumed};
use podssh_relay::pair::renew::{self, Renewed};
use podssh_relay::pair::{self, OperatorPart, Pair, PairContext, PairError};
use podssh_ws::frame::{OPCODE_BINARY, OPCODE_CLOSE, OPCODE_TEXT};
use podssh_ws::session::close_code_and_reason;
use podssh_ws::{Endpoint, ProxyChoice, RelaySession, WsClientConfig};
use serde_json::{json, Value};

use crate::relay_conform::{clause, Check, Offers, Plan, Report, STEP};

/// The limit on the checks that use the pair, before its stop.
const USE_LIMIT: Duration = Duration::from_secs(90);
/// The bytes of each way.
const UP: &[u8] = b"conform-up";
const DOWN: &[u8] = b"conform-down";
/// The length of a session's id in a node's binary frame.
const ID_LEN: usize = 32;

/// The reverse road's checks, then the stop of the check's pair.
pub(crate) async fn run(plan: &Plan, offers: &Offers, report: &mut Report) {
    let context = podssh_relay::context::process();
    let ctx = crate::pairs::context(&plan.relay, &plan.trust, &context);
    let started = Instant::now();
    let made = match pair::create(&ctx).await {
        Ok(made) => made,
        // A relay that pairs for keys alone, or for no one, pairs no stranger.
        Err(e @ (PairError::NotIssued { .. } | PairError::Failed { status: 401, .. })) => {
            report.push(Check::skip(
                "pair",
                clause::REVERSE,
                format!("{}; the reverse road is not checked", podssh_ws::text::said(&e)),
            ));
            return;
        }
        Err(e) => {
            report.push(Check::fail("pair", clause::REVERSE, podssh_ws::text::said(&e), started));
            return;
        }
    };
    let words = format!("a name of {} characters, {} h of life", made.name.len(), hours_left(&made));
    report.push(Check::pass("pair", clause::REVERSE, words, started));
    let mut checks = Vec::new();
    if tokio::time::timeout(USE_LIMIT, use_pair(plan, offers, &ctx, &made, &mut checks)).await.is_err() {
        checks.push(Check::fail("reverse", clause::REVERSE, format!("past {} s", USE_LIMIT.as_secs()), started));
    }
    for check in checks {
        report.push(check);
    }
    // The pair is the check's own: it ends here, also after a failure.
    let started = Instant::now();
    let stopped = tokio::time::timeout(STEP * 2, pair::stop(&ctx, &made)).await;
    report.push(match stopped {
        Ok(Ok(answer)) => Check::pass("stop", clause::REVERSE, format!("stopped: {}", answer.stopped), started),
        Ok(Err(e)) => Check::fail("stop", clause::REVERSE, podssh_ws::text::said(&e), started),
        Err(_) => Check::fail("stop", clause::REVERSE, "no answer to the stop", started),
    });
    let started = Instant::now();
    report.push(match pair::status(&ctx, &OperatorPart::of(&made)).await {
        Err(PairError::Forbidden) => Check::pass("stopped", clause::REVERSE, "403 for the connect token", started),
        Ok(_) => Check::fail("stopped", clause::REVERSE, "the connect token still works after the stop", started),
        Err(e) => Check::fail("stopped", clause::REVERSE, format!("not 403: {}", podssh_ws::text::said(&e)), started),
    });
}

/// Each check that uses the pair; each result goes into `checks` as it
/// comes, so that a run cut by its limit keeps them.
async fn use_pair(plan: &Plan, offers: &Offers, ctx: &PairContext<'_>, made: &Pair, checks: &mut Vec<Check>) {
    let started = Instant::now();
    let node = match socket(plan, podssh_relay::relay::node_path(&made.name), made.node_token()).await {
        Ok(node) => node,
        Err(why) => {
            checks.push(Check::fail("node-hello", clause::REVERSE, why, started));
            return;
        }
    };
    let hello = match text(&node, "hello").await {
        Ok(hello) => hello,
        Err(why) => {
            checks.push(Check::fail("node-hello", clause::REVERSE, why, started));
            return;
        }
    };
    let (sessions, frame) = (hello["maxSessions"].as_u64(), hello["maxFrameBytes"].as_u64());
    checks.push(match (sessions, frame) {
        (Some(s), Some(f)) => {
            Check::pass("node-hello", clause::REVERSE, format!("maxSessions {s}, maxFrameBytes {f}"), started)
        }
        _ => Check::fail("node-hello", clause::REVERSE, "no maxSessions or maxFrameBytes", started),
    });
    leg(plan, &node, made, checks).await;
    let started = Instant::now();
    checks.push(match pair::status(ctx, &OperatorPart::of(made)).await {
        Ok(p) if p.online => {
            Check::pass("status", clause::REVERSE, format!("online, {} sessions", p.sessions), started)
        }
        Ok(_) => Check::fail("status", clause::REVERSE, "the node is joined, and the status says offline", started),
        Err(e) => Check::fail("status", clause::REVERSE, podssh_ws::text::said(&e), started),
    });
    checks.push(wrong_stop(plan, made).await);
    checks.extend(extensions(offers, &hello, ctx, made).await);
    let _ = node.send_close(1000, "").await;
}

/// An operator's leg: `open` to the node, `ready` to the operator, a byte
/// each way, and the leg's Close heard by the node as `close {id}`.
async fn leg(plan: &Plan, node: &RelaySession, made: &Pair, checks: &mut Vec<Check>) {
    let started = Instant::now();
    let path = podssh_relay::relay::operator_path(&made.name);
    // The relay may answer the operator's upgrade only once the node readied
    // the session: both ends go at once.
    let operator = async {
        let operator = socket(plan, path, made.connect_token()).await?;
        let ready = text(&operator, "ready").await?;
        Ok::<_, String>((operator, ready))
    };
    let readied = async {
        let open = text(node, "open").await?;
        let id = open["id"].as_str().filter(|id| id.len() == ID_LEN).ok_or("an open with no id of 32 characters")?;
        node.send_text(&json!({ "type": "ready", "id": id }).to_string())
            .await
            .map_err(|e| podssh_ws::text::said(&e))?;
        Ok::<_, String>(id.to_string())
    };
    let (operator, id) = match tokio::join!(operator, readied) {
        (Ok((operator, ready)), Ok(id)) => {
            let same = ready["id"].as_str().is_none_or(|said| said == id);
            checks.push(match same {
                true => Check::pass("open", clause::REVERSE, "open, ready, then ready to the operator", started),
                false => Check::fail("open", clause::REVERSE, "the operator's ready names another id", started),
            });
            (operator, id)
        }
        (Err(why), _) | (_, Err(why)) => {
            checks.push(Check::fail("open", clause::REVERSE, why, started));
            return;
        }
    };
    let started = Instant::now();
    checks.push(match bytes(node, &operator, &id).await {
        Ok(()) => Check::pass("bytes", clause::REVERSE, "a frame each way, the node's with the id first", started),
        Err(why) => Check::fail("bytes", clause::REVERSE, why, started),
    });
    let started = Instant::now();
    let _ = operator.send_close(1000, "").await;
    let ended = async {
        let close = text(node, "close").await?;
        match close["id"].as_str() == Some(id.as_str()) {
            true => Ok(()),
            false => Err("a close of another id".to_string()),
        }
    };
    checks.push(match ended.await {
        Ok(()) => Check::pass("leg-close", clause::REVERSE, "the node heard close of the leg's id", started),
        Err(why) => Check::fail("leg-close", clause::REVERSE, why, started),
    });
}

/// The operator's bytes reach the node after the id; the node's reach the
/// operator with no framing.
async fn bytes(node: &RelaySession, operator: &RelaySession, id: &str) -> Result<(), String> {
    operator.send_binary(UP).await.map_err(|e| podssh_ws::text::said(&e))?;
    let up = binary(node).await?;
    if up.len() < ID_LEN || &up[..ID_LEN] != id.as_bytes() || &up[ID_LEN..] != UP {
        return Err("the node's frame is not the id and the operator's bytes".into());
    }
    let mut down = id.as_bytes().to_vec();
    down.extend_from_slice(DOWN);
    node.send_binary(&down).await.map_err(|e| podssh_ws::text::said(&e))?;
    match binary(operator).await? {
        got if got == DOWN => Ok(()),
        _ => Err("the operator's frame is not the node's bytes alone".into()),
    }
}

/// `/v1/stop/<name>` with a token that is not the pair's: `403`, and the
/// pair lives on.
async fn wrong_stop(plan: &Plan, made: &Pair) -> Check {
    let (relay, started) = (&plan.relay, Instant::now());
    let path = format!("/v1/stop/{}", made.name);
    let wrong = "0".repeat(64);
    let proxy = ProxyChoice::FromEnvironment;
    let asked = podssh_ws::client::https_with_token(
        "POST",
        &relay.host,
        relay.port,
        &path,
        b"{}",
        &wrong,
        16 * 1024,
        &plan.trust,
        &proxy,
        STEP,
    );
    match asked.await {
        Ok(r) if r.status == 403 => Check::pass("stop-wrong-token", clause::REVERSE, "403", started),
        Ok(r) => Check::fail("stop-wrong-token", clause::REVERSE, format!("HTTP {}, not 403", r.status), started),
        Err(e) => Check::fail("stop-wrong-token", clause::REVERSE, podssh_ws::text::said(&e), started),
    }
}

/// The extensions, each from the relay's own offer: the halt (in
/// `/relays.json` or the `hello`), the renewal (a path that a relay of the
/// contract does not have), the liveness of a `hello` and the layer.
async fn extensions(offers: &Offers, hello: &Value, ctx: &PairContext<'_>, made: &Pair) -> Vec<Check> {
    let mut checks = Vec::new();
    let started = Instant::now();
    let renewed = renew::renew(ctx, made).await;
    checks.push(match renewed {
        Ok(Renewed::Until(ms)) => Check::pass("ext.renew", clause::ROLE_REVERSE, format!("until {ms}"), started),
        Ok(Renewed::NotServed) => {
            Check::skip("ext.renew", clause::ROLE_REVERSE, "no renewal (404, 405, or the list of its paths)")
        }
        Err(e) => Check::fail("ext.renew", clause::ROLE_REVERSE, podssh_ws::text::said(&e), started),
    });
    let started = Instant::now();
    if offers.halt || hello["halt"].as_bool() == Some(true) {
        let done = match halt::halt(ctx, made, None).await {
            Ok(Halted::Now { .. }) => match halt::resume(ctx, made).await {
                Ok(Resumed::Now) => Ok(()),
                Ok(other) => Err(format!("the resume answered {other:?}")),
                Err(e) => Err(podssh_ws::text::said(&e)),
            },
            Ok(other) => Err(format!("offered, and the halt answered {other:?}")),
            Err(e) => Err(podssh_ws::text::said(&e)),
        };
        checks.push(match done {
            Ok(()) => Check::pass("ext.halt", clause::ROLE_REVERSE, "halted, then resumed", started),
            Err(why) => Check::fail("ext.halt", clause::ROLE_REVERSE, why, started),
        });
    } else {
        checks.push(Check::skip("ext.halt", clause::ROLE_REVERSE, "not offered"));
    }
    let liveness = match hello.get("liveness") {
        Some(_) => "offered in the hello; its check comes with its contract",
        None => "not offered",
    };
    checks.push(Check::skip("ext.liveness", clause::REVERSE, liveness));
    let layer = match offers.layer {
        true => "offered in /relays.json; podssh's own tests check its sessions",
        false => "not offered",
    };
    checks.push(Check::skip("ext.layer", clause::LAYER, layer));
    checks
}

/// A socket of the reverse road with its token in the header.
async fn socket(plan: &Plan, path: Result<String, String>, token: &str) -> Result<RelaySession, String> {
    let config = WsClientConfig {
        endpoint: Endpoint { host: plan.relay.host.clone(), port: plan.relay.port, path: path? },
        trust: plan.trust.clone(),
        server_name: plan.relay.host.clone(),
        timeout: STEP,
        idle_timeout: None,
        proxy: ProxyChoice::FromEnvironment,
    };
    podssh_ws::connect(&config, token).await.map_err(|e| podssh_ws::text::said(&e))
}

/// The next text frame of `kind` within [`STEP`]; others of the relay's
/// (`spent`, `halted`) are passed over.
async fn text(session: &RelaySession, kind: &str) -> Result<Value, String> {
    let read = async {
        loop {
            let f = session.read_frame().await.map_err(|e| podssh_ws::text::said(&e))?;
            match f.opcode {
                OPCODE_TEXT => {
                    let v: Value = serde_json::from_slice(&f.payload).map_err(|_| "a text frame that is not JSON")?;
                    if v["type"].as_str() == Some(kind) {
                        return Ok(v);
                    }
                }
                OPCODE_CLOSE => return Err(format!("the relay closed the socket: {}", words(&f.payload))),
                _ => {}
            }
        }
    };
    tokio::time::timeout(STEP, read).await.map_err(|_| format!("no {kind} within {} s", STEP.as_secs()))?
}

/// The next binary frame within [`STEP`].
async fn binary(session: &RelaySession) -> Result<Vec<u8>, String> {
    let read = async {
        loop {
            let f = session.read_frame().await.map_err(|e| podssh_ws::text::said(&e))?;
            match f.opcode {
                OPCODE_BINARY if !f.payload.is_empty() => return Ok(f.payload),
                OPCODE_CLOSE => return Err(format!("the relay closed the socket: {}", words(&f.payload))),
                _ => {}
            }
        }
    };
    tokio::time::timeout(STEP, read).await.map_err(|_| format!("no bytes within {} s", STEP.as_secs()))?
}

fn words(payload: &[u8]) -> String {
    match close_code_and_reason(payload) {
        (Some(code), reason) => format!("{code} {reason}"),
        (None, _) => "no code".into(),
    }
}

fn hours_left(made: &Pair) -> i64 {
    made.expires_ms.saturating_sub(crate::pairs::now_ms()).max(0) / 3_600_000
}
