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
//!
//! A session of the road may carry a link of the resumable layer instead of
//! a target's connection (`OPEN_LAYER`, `ONE_LAYER`): where a way refuses
//! the upgrade of `/v1/layer/`, the client opens one of the road for each
//! link, with the same checks, and the role gives its bytes to the layer
//! (`super::layer::link`), which holds the target across links.

pub mod answers;
pub mod one;
pub mod pumps;
pub mod sessions;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::http::request::{read_request, Request};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::egress::{self, Missed, Plan};
use super::forward::Asked;
use super::policy::shown;
use super::said::Of;
use super::{forward, tokens, Config};
use crate::http_road::window::Refusal;
use crate::http_road::{
    layer_route, query, route, Kind, Route, BATCH_MAX, DOWN_MAX, KEY, ONE_LAYER, OPEN, OPEN_LAYER, PREFIX, WAIT_MAX,
};
use answers::{refusal, refuse, whole, write};
use sessions::Session;

/// How long a kept connection waits for its next request.
const KEEP_IDLE: Duration = Duration::from_secs(60);
/// The largest body of a request that carries no batch.
const SMALL_BODY: usize = 4096;

/// The far side of a new session of the road, as two halves: its target's
/// connection, or a link of the resumable layer.
pub type Far = (Box<dyn AsyncRead + Send + Unpin>, Box<dyn AsyncWrite + Send + Unpin>);

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
        // A link of the resumable layer in each form, where a way refuses
        // the upgrade of `/v1/layer/`.
        "layer_paths": [OPEN_LAYER, ONE_LAYER],
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
/// came on a connection that the road kept. The lines of its sessions name
/// the client at `from` and the target (T-1035).
pub async fn serve<S>(
    mut stream: S,
    mut head: Request,
    mut pending: Vec<u8>,
    cfg: Arc<Config>,
    from: Option<IpAddr>,
) -> Option<(S, Request, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Behind a quick tunnel's node, an answer ends with its connection.
    let may_keep = !super::probe::is_behind_node();
    loop {
        let keep = may_keep && head.minor == 1 && !head.has_token("connection", "close");
        let path = head.target.split('?').next().unwrap_or_default().to_string();
        // A link of the layer opens as a session does, at its own paths.
        let (asked, layer) = match layer_route(&path) {
            Some(opened) => (Some(opened), true),
            None => (route(&path), false),
        };
        // The one-POST form takes the connection: its body is the way up.
        if asked == Some(Route::One) {
            one::serve(stream, head, pending, cfg, layer, from).await;
            return None;
        }
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
            Some(Route::Open) => open(&mut stream, &head, &cfg, keep, layer, from).await,
            // Served above, before a body is read.
            Some(Route::One) => Some(false),
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
/// the target checked and dialed, then a new session. With `layer`, `POST
/// /v1/http/open-layer/HOST/PORT`: the target checked, and the session's
/// bytes one link of the layer, which dials the target itself.
async fn open<S>(
    stream: &mut S,
    head: &Request,
    cfg: &Arc<Config>,
    keep: bool,
    layer: bool,
    from: Option<IpAddr>,
) -> Option<bool>
where
    S: AsyncWrite + Unpin,
{
    let at = if layer { OPEN_LAYER } else { OPEN };
    let (far, meter, of) = match reach(stream, head, cfg, at, keep, from).await {
        Ok(reached) => reached,
        Err(kept) => return kept,
    };
    let (session, key) = match Session::open(cfg.clone(), meter, of.clone()) {
        Ok(opened) => opened,
        Err(why) => return write(stream, refuse(503, &format!("http: {why}"), &[], keep), keep).await,
    };
    sessions::insert(session.clone());
    pumps::start(&session, far);
    cfg.event_of(&of, if layer { "http open layer" } else { "http open" });
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

/// The far side of a new session of the road, of either form, at the path
/// `path` (its prefix before `HOST/PORT`), once [`checked`]: the target
/// dialed as the forward road dials it; at a path of the layer, a new link
/// of the layer, which dials the target after its handshake, as a link of
/// `/v1/layer/` does. With the connection's [`Of`], which names its client
/// and target. A refusal is written, and `Err` holds what its write gave.
async fn reach<S>(
    stream: &mut S,
    head: &Request,
    cfg: &Arc<Config>,
    path: &str,
    keep: bool,
    from: Option<IpAddr>,
) -> Result<(Far, super::usage::Meter, Of), Option<bool>>
where
    S: AsyncWrite + Unpin,
{
    let (asked, plan, meter) = checked(stream, head, cfg, path, keep, from).await?;
    let target = shown(&asked.host, asked.port);
    let of = Of::client(from).to(&target);
    if path == OPEN_LAYER || path == ONE_LAYER {
        let (up, down) = tokio::io::split(super::layer::link(cfg, asked.host, plan, of.clone()));
        let far: Far = (Box::new(up), Box::new(down));
        return Ok((far, meter, of));
    }
    // As the forward road dials: through the host's proxy when one is set,
    // the owner told of the proxy's fault, and the unsent bytes bounded.
    let tcp = match egress::dial(&asked.host, &plan, &cfg.egress, &cfg.policy.ipv6, cfg.limits.connect).await {
        Ok((tcp, _)) => tcp,
        Err(Missed { said, line }) => {
            if let Some(line) = line {
                cfg.event(&format!("proxy: {line}"));
            }
            let reach = super::egress::cannot_reach(&target, &said);
            let why = format!("relay: {reach}");
            cfg.event_of(&of, &format!("refused 502 {reach}"));
            return Err(write(stream, refuse(502, &why, &[], keep), keep).await);
        }
    };
    super::sockets::bound_unsent(&tcp);
    let (up, down) = tcp.into_split();
    let far: Far = (Box::new(up), Box::new(down));
    Ok((far, meter, of))
}

/// The checks of a new session of the road at the path `path`: the token
/// and its budget, the target by the policy, the bound on sessions at once.
/// The target and the plan of its dial, and the meter of its token's key;
/// a refusal is written, and `Err` holds what its write gave. A link of the
/// layer is refused in the layer's words, as on `/v1/layer/`.
async fn checked<S>(
    stream: &mut S,
    head: &Request,
    cfg: &Arc<Config>,
    path: &str,
    keep: bool,
    from: Option<IpAddr>,
) -> Result<(Asked, Plan, super::usage::Meter), Option<bool>>
where
    S: AsyncWrite + Unpin,
{
    let who = if path == OPEN_LAYER || path == ONE_LAYER { "layer" } else { "http" };
    let token_ok = head.header("x-relay-token").is_some_and(|t| cfg.tokens.check(t, tokens::now_ms()));
    if !token_ok {
        let reply = refusal(Refusal::NotAllowed, &format!("{who}: missing or wrong token"), &[], keep);
        return Err(write(stream, reply, keep).await);
    }
    // The token's key, and its budget, before anything is dialed (T-636).
    let meter = match super::usage::meter_of(cfg, head) {
        Ok(meter) => meter,
        Err(why) => {
            let reply = refusal(Refusal::NotAllowed, &format!("{who}: {why}"), &[], keep);
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
    let plan = match cfg.policy.plan(&asked.host, asked.port, asked.family, &cfg.egress).await {
        Ok(plan) => plan,
        Err(refused) => {
            // Each refusal is a line, as on the other roads (T-1050).
            let of = Of::client(from).to(&shown(&asked.host, asked.port));
            cfg.say_refused(&of, refused.status(), &refused.answer(), refused.logged());
            // The policy's refusal is the role's `not allowed`; another
            // status (a target that cannot be reached) keeps its own words.
            let reply = match refused.status() {
                403 => refusal(Refusal::NotAllowed, &refused.answer(), &[], keep),
                status => refuse(status, &refused.answer(), &[], keep),
            };
            return Err(write(stream, reply, keep).await);
        }
    };
    Ok((asked, plan, meter))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_road_s_paths_are_its_own() {
        assert!(serves("/v1/http/open/github.com/22?family=4"));
        assert!(serves("/v1/http/s/0123456789abcdef0123456789abcdef/down?at=0"));
        assert!(serves("/v1/http/open-layer/github.com/22") && serves("/v1/http/one-layer/github.com/22"));
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
        assert_eq!(l["layer_paths"], json!(["/v1/http/open-layer/", "/v1/http/one-layer/"]));
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
