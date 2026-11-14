//! The HTTP road (T-319) in podssh's relay role: the sessions of the wire of
//! `crate::http_road`, each to a target of the forward road, checked and
//! dialed as `/connect/` checks and dials one, with its token, its policy,
//! its way out through the host's proxy and its limits ([`sessions`]). A
//! connection carries one request after another while its client keeps it,
//! as the split form's two connections need ([`serve`]); a request of
//! another path that comes on it goes back to the role's routes. Behind a
//! quick tunnel's node, which takes a request's body whole, 32 KiB at most,
//! and reads an answer to the end of its connection, each answer closes its
//! connection, and the open names the node's bound on a batch.

pub mod answers;
pub mod one;
pub mod pumps;
pub mod sessions;

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::http::request::{read_request, Request};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::egress::{self, Missed};
use super::policy::shown;
use super::{forward, tokens, Config};
use crate::http_road::window::Refusal;
use crate::http_road::{query, route, Kind, Route, BATCH_MAX, DOWN_MAX, KEY, OPEN, PREFIX, WAIT_MAX};
use answers::{refusal, refuse, whole, write};
use sessions::Session;

/// How long a kept connection waits for its next request.
const KEEP_IDLE: Duration = Duration::from_secs(60);
/// The largest body of a request that carries no batch.
const SMALL_BODY: usize = 4096;

/// Whether the request-target `target` is one of the road's.
pub fn serves(target: &str) -> bool {
    target.split('?').next().unwrap_or_default().starts_with(PREFIX)
}

/// The largest batch that the role takes: behind a quick tunnel's node, the
/// node's bound on a body.
#[cfg(feature = "quick")]
fn batch_max() -> usize {
    if super::probe::is_behind_node() {
        crate::quick::origin::BODY_MAX.min(BATCH_MAX)
    } else {
        BATCH_MAX
    }
}

#[cfg(not(feature = "quick"))]
fn batch_max() -> usize {
    BATCH_MAX
}

/// The road's own limits, which `/relays.json` names in `limits.http`
/// beside the contract's five: the bounds of the open's answer, and the
/// role's windows and waits, which a client otherwise learns only by
/// meeting them (a `503 full`, a `1001 client gone`). An older client reads
/// no such field, so it changes nothing for one.
pub fn limits() -> serde_json::Value {
    json!({
        "paths": [OPEN, crate::http_road::SESSION, one::ONE],
        "forms": ["split", "serial", "one"],
        "batch_max_bytes": batch_max(),
        "window_batches": sessions::WINDOW,
        "hold_ms": sessions::HOLD.as_millis() as u64,
        "down_window_bytes": sessions::DOWN_WINDOW,
        "down_max_bytes": DOWN_MAX,
        "wait_max_ms": WAIT_MAX.as_millis() as u64,
        "absent_ms": sessions::ABSENT.as_millis() as u64,
        "kept_ended_ms": sessions::KEPT_ENDED.as_millis() as u64,
        "sessions_max": sessions::MOST,
    })
}

/// Serve the road's requests on `stream`, `head` the first, `pending` the
/// bytes after its head; the stream and a request of another path, when one
/// came on a connection that the road kept.
pub async fn serve<S>(
    mut stream: S,
    mut head: Request,
    mut pending: Vec<u8>,
    cfg: Arc<Config>,
) -> Option<(S, Request, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Behind a quick tunnel's node, an answer ends with its connection.
    let may_keep = !super::probe::is_behind_node();
    loop {
        let keep = may_keep && head.minor == 1 && !head.has_token("connection", "close");
        let path = head.target.split('?').next().unwrap_or_default().to_string();
        // The one-POST form takes the connection: its body is the way up.
        if one::serves(&path) {
            one::serve(stream, head, pending, cfg).await;
            return None;
        }
        let asked = route(&path);
        let max = match asked {
            Some(Route::Session(_, Kind::Up | Kind::Exchange)) => batch_max(),
            _ => SMALL_BODY,
        };
        let (batch, rest) = match answers::body(&mut stream, &head, pending, max).await {
            Ok(read) => read,
            Err(Some((status, why))) => {
                let _ = write(&mut stream, refuse(status, &why, &[], false), false).await;
                let _ = stream.shutdown().await;
                return None;
            }
            Err(None) => return None,
        };
        let kept = match asked {
            None => write(&mut stream, refuse(404, &format!("{path}: not found"), &[], keep), keep).await,
            Some(Route::Open) => open(&mut stream, &head, &cfg, keep).await,
            Some(Route::Session(id, kind)) => match sessions::find(&id, head.header(KEY), &cfg) {
                None => {
                    let reply = refusal(Refusal::UnknownSession, "http: no such session", &[], keep);
                    write(&mut stream, reply, keep).await
                }
                Some(session) => {
                    let q = query(&head.target);
                    match kind {
                        Kind::Up => answers::up(&mut stream, &session, q, batch, keep).await,
                        Kind::Down => answers::down(&mut stream, &session, q, keep).await,
                        Kind::Exchange => answers::exchange(&mut stream, &session, q, batch, keep).await,
                        Kind::Close => answers::close(&mut stream, &session, keep).await,
                    }
                }
            },
        };
        if kept != Some(true) {
            let _ = stream.shutdown().await;
            return None;
        }
        let Ok(Ok((next, after))) = tokio::time::timeout(KEEP_IDLE, read_request(&mut stream, rest)).await else {
            let _ = stream.shutdown().await;
            return None;
        };
        if !serves(&next.target) {
            return Some((stream, next, after));
        }
        (head, pending) = (next, after);
    }
}

/// `POST /v1/http/open/HOST/PORT[?family=4|6]`, with the forward token:
/// the target checked and dialed, then a new session.
async fn open<S>(stream: &mut S, head: &Request, cfg: &Arc<Config>, keep: bool) -> Option<bool>
where
    S: AsyncWrite + Unpin,
{
    let (tcp, meter) = match dial(stream, head, cfg, OPEN, keep).await {
        Ok(dialed) => dialed,
        Err(kept) => return kept,
    };
    let (session, key) = match Session::open(cfg.clone(), meter) {
        Ok(opened) => opened,
        Err(why) => return write(stream, refuse(503, &format!("http: {why}"), &[], keep), keep).await,
    };
    sessions::insert(session.clone());
    pumps::start(&session, tcp);
    cfg.event("http open");
    let doc = json!({
        "session": session.id,
        "key": key,
        "batch_max": batch_max(),
        "wait_max_ms": WAIT_MAX.as_millis() as u64,
        "down_max": DOWN_MAX,
        "forms": ["split", "serial"],
    });
    write(stream, whole(200, &[], doc.to_string().as_bytes(), "application/json", keep), keep).await
}

/// The checks of a new session of the road, of either form, at the path
/// `path` (its prefix before `HOST/PORT`): the token and its budget, the
/// target by the policy, the bound on sessions at once; then the target
/// dialed as the forward road dials it. A refusal is written, and `Err`
/// holds what its write gave.
async fn dial<S>(
    stream: &mut S,
    head: &Request,
    cfg: &Arc<Config>,
    path: &str,
    keep: bool,
) -> Result<(tokio::net::TcpStream, super::usage::Meter), Option<bool>>
where
    S: AsyncWrite + Unpin,
{
    let token_ok = head.header("x-relay-token").is_some_and(|t| cfg.tokens.check(t, tokens::now_ms()));
    if !token_ok {
        let reply = refusal(Refusal::NotAllowed, "http: missing or wrong token", &[], keep);
        return Err(write(stream, reply, keep).await);
    }
    // The token's key, and its budget, before anything is dialed (T-636).
    let meter = match super::usage::meter_of(cfg, head) {
        Ok(meter) => meter,
        Err(why) => {
            let reply = refusal(Refusal::NotAllowed, &format!("http: {why}"), &[], keep);
            return Err(write(stream, reply, keep).await);
        }
    };
    let Some(asked) = forward::asked(&head.target.replacen(path, "/connect/", 1)) else {
        let shown_path = head.target.split('?').next().unwrap_or_default();
        return Err(
            write(stream, refuse(400, &format!("{shown_path}: the path is {path}HOST/PORT"), &[], keep), keep).await
        );
    };
    if sessions::live() + one::live() >= sessions::MOST {
        let why = format!("http: {} sessions at once at most", sessions::MOST);
        return Err(write(stream, refuse(503, &why, &[("Retry-After", "5".to_string())], keep), keep).await);
    }
    let target = shown(&asked.host, asked.port);
    let plan = match cfg.policy.plan(&asked.host, asked.port, asked.family, &cfg.egress).await {
        Ok(plan) => plan,
        Err(refused) => {
            if let Some(line) = refused.logged() {
                cfg.event(&line);
            }
            // The policy's refusal is the role's `not allowed`; another
            // status (a target that cannot be reached) keeps its own words.
            let reply = match refused.status() {
                403 => refusal(Refusal::NotAllowed, &refused.answer(), &[], keep),
                status => refuse(status, &refused.answer(), &[], keep),
            };
            return Err(write(stream, reply, keep).await);
        }
    };
    // As the forward road dials: through the host's proxy when one is set,
    // the owner told of the proxy's fault, and the unsent bytes bounded.
    let tcp = match egress::dial(&asked.host, &plan, &cfg.egress, &cfg.policy.ipv6, cfg.limits.connect).await {
        Ok((tcp, _)) => tcp,
        Err(Missed { said, line }) => {
            if let Some(line) = line {
                cfg.event(&format!("proxy: {line}"));
            }
            let why = format!("relay: cannot reach {target}: {said}");
            return Err(write(stream, refuse(502, &why, &[], keep), keep).await);
        }
    };
    super::sockets::bound_unsent(&tcp);
    Ok((tcp, meter))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_road_s_paths_are_its_own() {
        assert!(serves("/v1/http/open/github.com/22?family=4"));
        assert!(serves("/v1/http/s/0123456789abcdef0123456789abcdef/down?at=0"));
        assert!(!serves("/v1/httpx") && !serves("/connect/h/22") && !serves("/v1/probe/drip"));
        assert!(super::super::serves("/v1/http/open/github.com/22"), "a quick tunnel's node gives them to the role");
    }

    /// The limits that `/relays.json` names are the ones that the role
    /// holds, so that a client that reads them meets no other.
    #[test]
    fn the_limits_are_the_ones_the_role_holds() {
        let l = limits();
        assert_eq!(l["paths"], json!(["/v1/http/open/", "/v1/http/s/", "/v1/http/one/"]));
        assert_eq!(l["forms"], json!(["split", "serial", "one"]));
        assert_eq!(l["batch_max_bytes"], json!(BATCH_MAX), "no node in front of a plain role");
        assert_eq!((&l["window_batches"], &l["hold_ms"]), (&json!(8), &json!(10_000)));
        assert_eq!((&l["down_window_bytes"], &l["down_max_bytes"]), (&json!(2 << 20), &json!(1 << 20)));
        assert_eq!((&l["wait_max_ms"], &l["absent_ms"]), (&json!(25_000), &json!(60_000)));
        assert_eq!((&l["kept_ended_ms"], &l["sessions_max"]), (&json!(60_000), &json!(256)));
    }

    /// Behind a quick tunnel's node, a batch is the node's bound on a body,
    /// as the open says.
    #[cfg(feature = "quick")]
    #[tokio::test]
    async fn behind_a_node_the_batch_is_the_node_s() {
        let behind = super::super::probe::behind_node(async { limits() }).await;
        assert_eq!(behind["batch_max_bytes"], json!(crate::quick::origin::BODY_MAX));
        assert_eq!(limits()["batch_max_bytes"], json!(BATCH_MAX), "outside the node's request");
    }
}
