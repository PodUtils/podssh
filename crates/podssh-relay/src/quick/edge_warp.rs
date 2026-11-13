//! The quick tunnel's edge inside WARP's tunnel (T-374), feature `warp`: a
//! node whose cage allows ports 443, 80 and 8443 alone reaches the edge's
//! TCP port 7844 as any target of WARP's road (T-352), over HTTP/2 to
//! Cloudflare's endpoint on 443. The road is a dial (pod-warp's `WarpNet`,
//! which podssh-cli opens): each region of the edge is a TCP stream of the
//! dial, its name asked inside the tunnel, then the edge's TLS of
//! [`super::edge`] over that stream, and the client of T-300 on it as it is.
//! The request for a tunnel to `api.trycloudflare.com` goes as before,
//! through the proxy.

use pod_core::{Dial, Target};
use podssh_ws::Trust;

// The edge's TLS on either road, as the node serves it: one trait for both.
pub use super::edge::EdgeIo;
use super::edge::{server_name, Edge, DIAL_LIMIT};

/// The road's words, as the node says how it registered.
pub const ROAD: &str = "HTTP/2 inside WARP's tunnel";

/// A TLS connection to `edge` through `warp`, the dial inside WARP's
/// tunnel, trusted as `trust` says (the node's: [`super::edge::trust`]):
/// each region in turn; the failure of each when none answers. It holds the
/// tunnel while it lasts.
pub async fn connect(warp: &dyn Dial, edge: &Edge, trust: &Trust) -> Result<Box<dyn EdgeIo>, String> {
    let (mut failed, port) = (Vec::new(), edge.port);
    for region in &edge.regions {
        let deadline = tokio::time::Instant::now() + DIAL_LIMIT;
        let stream = match warp.dial(&Target::new(region, port), deadline).await {
            Ok(connected) => connected.io,
            Err(e) => {
                failed.push(format!("{region}:{port}: {}", e.chain()));
                continue;
            }
        };
        match podssh_ws::tls::connect_over(stream, server_name(), trust, DIAL_LIMIT).await {
            Ok(tls) => return Ok(Box::new(tls)),
            Err(e) => failed.push(format!("{region}:{port}: {e}")),
        }
    }
    Err(format!("no region of the edge answered inside WARP's tunnel: {}", failed.join("; ")))
}
