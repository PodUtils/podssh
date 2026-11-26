//! The role's one request on one surface (#225, T-764 and T-767): the
//! routes of the contract, the static site of a cover, the owner's local
//! socket, and the application-layer credential of an authenticated client.
//! Apart from `mod.rs` so that each file stays within 500 lines.

use std::net::IpAddr;
use std::sync::Arc;

use podssh_ws::http::request;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::cover;
#[cfg(feature = "derp")]
use super::derp;
use super::surface::{self};
use super::{answer, body, brake, docs, forward, head_of, http_road, layer, leg, mailbox, meet, mint, probe};
use super::{reverse, said, slow_down, strike, tokens, Config, MINT_BODY};

/// [`serve_named`] for a client at `from`, by whom the brake counts (T-454):
/// a listener's TCP peer; behind the quick tunnel, where the peer is
/// Cloudflare's edge, the visitor that the edge names
/// ([`brake::edge_visitor`]). Requests with none share one count.
pub async fn serve_from<S>(stream: S, cfg: Arc<Config>, sni: Option<String>, from: Option<IpAddr>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_surface(stream, cfg, sni, from, surface::Surface::Public, None, None).await
}

/// [`serve_from`] for a connection of TLS, whose exporter a delegated
/// credential binds (T-765): the same routes, with the exporter of that
/// handshake.
pub async fn serve_tls<S>(
    stream: S,
    cfg: Arc<Config>,
    sni: Option<String>,
    from: Option<IpAddr>,
    exporter: Option<[u8; 32]>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_surface(stream, cfg, sni, from, surface::Surface::Public, exporter, None).await
}

/// [`serve_from`] for a connection of the owner's control socket (T-767):
/// the documents and the probes are served here, never on the public
/// listener of a cover.
pub async fn serve_local<S>(stream: S, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_surface(stream, cfg, None, None, surface::Surface::Local, None, None).await
}

/// Serve one request of `stream` on `surface`. With a cover on the public
/// listener, a path that is not a public route, and each document or probe,
/// gets the site's own 404 (T-764, T-767); the token's roads stay, and the
/// mint takes a POST with a body.
async fn serve_surface<S>(
    mut stream: S,
    cfg: Arc<Config>,
    sni: Option<String>,
    from: Option<IpAddr>,
    surface: surface::Surface,
    exporter: Option<[u8; 32]>,
    // A request that another road read from the same connection, with its
    // pending bytes and its path (T-319); `None` reads the next one.
    read: Option<(request::Request, Vec<u8>, String)>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some((head, pending, first)) = (match read {
        Some(read) => Some(read),
        None => head_of(&mut stream).await,
    }) else {
        return;
    };
    let path = head.target.split('?').next().unwrap_or_default().to_string();
    let route = surface::classify(&head.method, &path);
    let cover = cfg.cover.clone();
    let covered = surface == surface::Surface::Public && cover.is_some();
    if covered {
        // The cover decides before any role route does (SURF-1, DELEG-2):
        // the site answers each path that is not the contract's, each
        // document and probe, and each token's road without its credential.
        // Nothing below this block sees a request that the cover refused.
        let Some(route) = route else {
            // The site's own page, asset, `robots.txt` or 404 (T-764).
            return answer(&mut stream, cover.as_ref().expect("a cover").respond(sni.as_deref(), &head)).await;
        };
        let refused = match route.reach {
            surface::Reach::Local => true,
            // A token road takes the cover credential. The delegate road is
            // the one that issues it, so it takes the token alone (T-765).
            surface::Reach::Token if route.id != surface::Id::Delegate => {
                !cover_credential_ok(&cfg, &head, exporter, sni.as_deref())
            }
            surface::Reach::Token => !token_ok(&cfg, &head),
            surface::Reach::Open => false,
        };
        if refused {
            return answer(&mut stream, cover.as_ref().expect("a cover").not_found(&head)).await;
        }
    }
    // A wrong token counts after the cover answered: a refusal here would
    // name the role to an observer (T-806, SURF-1).
    if let Err(braked) = strike(&cfg, &head, &first, from) {
        return slow_down(&mut stream, &head, pending, &first, braked, &cfg).await;
    }
    if brake::braked(&head.method, &path)
        && let Err(braked) = cfg.brake.take(brake::Who::of(from))
    {
        return slow_down(&mut stream, &head, pending, &path, braked, &cfg).await;
    }
    // The HTTP road keeps its connection for its next request, and gives
    // back a request of another path that came on it (T-319): that request
    // is served from the top, so the cover gates it too.
    if http_road::serves(&head.target) {
        if let Some((stream, next, bytes)) = http_road::serve(stream, head, pending, cfg.clone(), from).await {
            let path = next.target.split('?').next().unwrap_or_default().to_string();
            return Box::pin(serve_surface(stream, cfg, sni, from, surface, exporter, Some((next, bytes, path)))).await;
        }
        return;
    }
    let (mut stream, head, pending) = (stream, head, pending);
    match route.map(|route| route.id) {
        Some(surface::Id::Mint) if covered => {
            // SURF-2: a POST with a body alone, and each other method 405.
            if head.method != "POST" {
                let reply = request::refusal(405, "the mint takes a POST", &[("Allow", "POST")]);
                return answer(&mut stream, reply).await;
            }
            if head.header("content-length").and_then(|l| l.trim().parse::<usize>().ok()).unwrap_or(0) == 0 {
                let reply = request::refusal(400, "the mint takes a JSON body", &[]);
                return answer(&mut stream, reply).await;
            }
            mint(&mut stream, &head, pending, &cfg, sni.as_deref(), from).await
        }
        Some(surface::Id::Mint) if head.method == "POST" => {
            mint(&mut stream, &head, pending, &cfg, sni.as_deref(), from).await
        }
        Some(surface::Id::Connect) => forward::connect(stream, head, pending, cfg, from).await,
        // The forward road in the resumable layer (T-173), beside the contract.
        Some(surface::Id::Layer) => layer::connect(stream, head, pending, cfg, from).await,
        Some(surface::Id::Health) => answer(&mut stream, docs::json(&docs::health(&cfg))).await,
        Some(surface::Id::Relays) => {
            // A harness counts the reads of the document (T-173).
            cfg.event_of(&said::Of::client(from), "relays.json");
            answer(&mut stream, docs::json(&docs::relays(&cfg, &head))).await
        }
        Some(surface::Id::Trace) => {
            let reply = docs::trace(&cfg, &head).await;
            answer(&mut stream, reply).await
        }
        Some(surface::Id::Spec) => answer(&mut stream, docs::text(docs::SPEC)).await,
        // What a path does to a stream, for `podssh doctor --stream` (T-325).
        Some(surface::Id::Probe) => probe::request(stream, head, pending).await,
        // The application-layer credential of a cover name (T-765). A
        // client that keeps the connection open goes on to its upgrade on
        // this same TLS connection, whose exporter the credential bound.
        Some(surface::Id::Delegate) => {
            if delegate(&mut stream, &head, pending, &cfg, exporter, sni.as_deref()).await {
                Box::pin(serve_surface(stream, cfg, sni, from, surface, exporter, None)).await;
            }
        }
        // The meeting point of the pairing by a short code (T-086).
        Some(surface::Id::Mailbox) => mailbox::request(stream, head, pending, cfg).await,
        // A leg for a member of the net, by the node's key (T-434).
        Some(surface::Id::Leg) => leg::request(stream, head, pending, cfg, sni).await,
        Some(surface::Id::Reverse) => reverse::request(stream, head, pending, cfg, sni, from).await,
        // DERP for a node of `podssh ts`, where its owner named the keys (T-106).
        #[cfg(feature = "derp")]
        Some(surface::Id::Derp) => derp::request(stream, head, pending, cfg).await,
        // iroh's relay protocol and the probes of a meeting point (T-720).
        Some(surface::Id::Meet) => meet::request(stream, head, pending, cfg).await,
        // The HTTP road was served above, after the cover gated it; a
        // request of its path that comes back here has no answer of its own.
        Some(surface::Id::HttpRoad) => answer(&mut stream, request::refusal(404, "not found", &[])).await,
        _ => {
            let reply = match cover.as_ref() {
                Some(cover) => cover.not_found(&head),
                None => request::refusal(404, &format!("{path}: not found"), &[]),
            };
            answer(&mut stream, reply).await
        }
    }
}

/// Whether the upgrade carries a cover credential that this role's pinned
/// issuer signed, for this name, now, and bound to this connection's
/// exporter. One already spent is refused as a replay.
fn cover_credential_ok(cfg: &Config, head: &request::Request, exporter: Option<[u8; 32]>, sni: Option<&str>) -> bool {
    let (Some(cover), Some(exporter)) = (cfg.cover.as_ref(), exporter) else { return false };
    let Some(value) = head.header(cover::Cover::credential_header()) else { return false };
    let Ok(credential) = podssh_ws::delegated::decode_wire(value) else { return false };
    let now = i64::try_from(tokens::now_ms() / 1000).unwrap_or(0);
    cover.admit(&credential, &exporter, now, sni).is_ok()
}

/// Whether the request carries a token that this role minted and that is
/// still valid, without spending a token of one session.
pub(super) fn token_ok(cfg: &Config, head: &request::Request) -> bool {
    let now = tokens::now_ms();
    head.header("x-relay-token").is_some_and(|t| cfg.tokens.check(t, now) || cfg.tokens.is_once(t, now))
}

/// `POST /v1/delegate`: the application-layer credential of this cover name
/// for the subject key in the body, bound to the exporter of this connection
/// (T-765). It is no RFC 9345 credential and no TLS-level delegation: the
/// handshake still authenticates the certificate, and the credential is
/// signed and checked afterwards (`podssh_ws::delegated`).
async fn delegate<S>(
    stream: &mut S,
    head: &request::Request,
    pending: Vec<u8>,
    cfg: &Config,
    exporter: Option<[u8; 32]>,
    name: Option<&str>,
) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let kept = head.header("connection").is_some_and(|value| value.trim().eq_ignore_ascii_case("keep-alive"));
    let Some(cover) = cfg.cover.as_ref() else {
        return close(stream, request::refusal(404, "not found", &[])).await;
    };
    if head.method != "POST" {
        let reply = request::refusal(405, "the credential takes a POST", &[("Allow", "POST")]);
        return close(stream, reply).await;
    }
    let sent = match body(stream, head, pending, MINT_BODY, cover::DELEGATE).await {
        Ok(sent) => sent,
        Err(refusal) => return close(stream, refusal).await,
    };
    let subject = match podssh_ws::delegated::subject_key(&String::from_utf8_lossy(&sent)) {
        Ok(subject) => subject,
        Err(why) => return close(stream, request::refusal(400, &why, &[])).await,
    };
    let Some(exporter) = exporter else {
        let why = "the credential needs a TLS connection's exporter";
        return close(stream, request::refusal(503, why, &[])).await;
    };
    let now = i64::try_from(tokens::now_ms() / 1000).unwrap_or(0);
    match cover.issue(subject, now, &exporter, name) {
        Ok(credential) => {
            cfg.event(&format!("delegate {}", cover.name));
            let body = podssh_ws::delegated::encode_with_issuer(&credential, &cover.issuer().pinned());
            if kept {
                let reply = docs::text_kept_alive(&body);
                let _ = stream.write_all(&reply).await;
                let _ = stream.flush().await;
                true
            } else {
                close(stream, docs::text(&body)).await;
                false
            }
        }
        Err(why) => close(stream, request::refusal(503, &format!("the credential: {why}"), &[])).await,
    }
}

/// [`answer`], and whether the connection stayed open: `false`, so a caller
/// returns it as the answer's.
async fn close<S: AsyncWrite + Unpin>(stream: &mut S, reply: Vec<u8>) -> bool {
    answer(stream, reply).await;
    false
}
