//! The meeting points of a net on the role's one listener (T-720), beside
//! DERP at `/derp` ([`super::derp`], T-106): iroh's relay protocol at
//! `/relay` with its probe `/ping` (`meet_iroh.rs`, feature `iroh-serve`),
//! and `/generate_204`, the probe of a captive portal that iroh's and
//! Tailscale's reports of the network ask of a relay. Each is off until
//! `podssh relay serve --relay-roads` names its road. No listener of its
//! own (rule 2): each is a route of the role's, behind its TLS, its slots
//! and its log. The members of a net that lets only port 443 in meet here,
//! where they used n0's relays and Tailscale's DERP fleet.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_ws::http::request::{self, Request};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{answer, Config};

// iroh's relay protocol over the role's own upgrade (T-720).
#[cfg(feature = "iroh-serve")]
#[path = "meet_iroh.rs"]
pub mod protocol;

/// iroh's relay connection, as iroh-relay names it (`RELAY_PATH`).
pub const RELAY_PATH: &str = "/relay";
/// iroh's probe of latency: an empty 200 (`RELAY_PROBE_PATH`).
pub const PING_PATH: &str = "/ping";
/// The probe of a captive portal, which iroh and Tailscale both ask.
pub const NO_CONTENT_PATH: &str = "/generate_204";

/// Whether iroh's relay protocol is served, from [`enable_iroh`] on.
static IROH: AtomicBool = AtomicBool::new(false);

/// Serve iroh's relay protocol at `/relay` from now on; a process has one
/// role, so this holds for its whole life, as DERP's [`super::derp::enable`].
#[cfg(feature = "iroh-serve")]
pub fn enable_iroh() {
    IROH.store(true, Ordering::SeqCst);
}

/// Whether iroh's relay protocol is served.
pub fn iroh() -> bool {
    IROH.load(Ordering::SeqCst)
}

/// Whether DERP is served, where this build has it.
fn derp() -> bool {
    #[cfg(feature = "derp")]
    {
        super::derp::enabled()
    }
    #[cfg(not(feature = "derp"))]
    {
        false
    }
}

/// Whether `path` is one of these routes, as the roads that are on serve
/// them: a role with neither answers each with its 404, as before.
pub fn serves(path: &str) -> bool {
    (iroh() && matches!(path, RELAY_PATH | PING_PATH)) || ((iroh() || derp()) && path == NO_CONTENT_PATH)
}

/// Serve one request of these routes.
pub async fn request<S>(mut stream: S, head: Request, pending: Vec<u8>, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let path = head.target.split('?').next().unwrap_or_default().to_string();
    match path.as_str() {
        NO_CONTENT_PATH => answer(&mut stream, no_content(&head)).await,
        PING_PATH => answer(&mut stream, ping()).await,
        #[cfg(feature = "iroh-serve")]
        RELAY_PATH => protocol::request(stream, head, pending, cfg).await,
        _ => {
            // No byte of a body is read: these routes take none.
            let _ = (pending, cfg);
            answer(&mut stream, request::refusal(404, &format!("{path}: not found"), &[])).await
        }
    }
}

/// iroh's answer at `/ping`: an empty 200 that a page may read too, as
/// iroh-relay's `probe_handler` answers.
pub fn ping() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}

/// The 204 of `/generate_204`, with the answer to each challenge that it
/// holds: Tailscale's (`derpserver.ServeNoContent`, v1.104.4) and iroh's
/// (`serve_no_content_handler`, 1.4.1). A client checks the answer, so that
/// a captive portal that answers 204 to each URL is told apart.
pub fn no_content(head: &Request) -> Vec<u8> {
    let mut answers = String::new();
    for (asked, header, max, colon) in CHALLENGES {
        if let Some(challenge) = head.header(asked)
            && is_challenge(challenge, max, colon)
        {
            answers.push_str(&format!("{header}: response {challenge}\r\n"));
        }
    }
    format!(
        "HTTP/1.1 204 No Content\r\nCache-Control: no-cache, no-store, must-revalidate, no-transform, max-age=0\r\n\
         {answers}Connection: close\r\n\r\n"
    )
    .into_bytes()
}

/// Each challenge: the header asked, the header of its answer, its longest
/// length, and whether `:` is one of its characters. Tailscale takes 64
/// characters and `:`; iroh fewer than 64 and no `:`.
const CHALLENGES: [(&str, &str, usize, bool); 2] =
    [("x-tailscale-challenge", "X-Tailscale-Response", 64, true), ("x-iroh-challenge", "X-Iroh-Response", 63, false)];

/// Whether `challenge` may be echoed: a few safe characters, so that no
/// byte of a request can break the answer's head.
fn is_challenge(challenge: &str, max: usize, colon: bool) -> bool {
    let safe = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_') || (colon && b == b':');
    !challenge.is_empty() && challenge.len() <= max && challenge.bytes().all(safe)
}

/// What `/relays.json` says of these roads, so that a member lists this
/// host first: iroh's relay URL (iroh adds `/relay` itself), DERP's
/// `HOST:PORT` (as `podssh ts --ts-relay` takes it), and the probe; `null`
/// for a road that is off.
pub fn doc(authority: &str) -> Value {
    json!({
        "iroh": iroh().then(|| format!("https://{authority}/")),
        "derp": derp().then(|| authority.to_string()),
        "probe": (iroh() || derp()).then_some(NO_CONTENT_PATH),
    })
}

#[cfg(test)]
#[path = "meet_tests.rs"]
mod tests;
