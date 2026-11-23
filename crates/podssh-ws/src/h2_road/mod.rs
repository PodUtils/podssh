//! The WebSocket over HTTP/2's extended CONNECT (RFC 8441, T-321, GitHub
//! #51): `pod-ws` of PodUtils/podcrates, with one pool of connections for
//! the process ([`POOL`]) and podssh's way out for the proxy of each
//! configuration.

use std::sync::OnceLock;
use std::time::Duration;

pub use pod_ws::h2_road::{
    duplex, Fallback, Offered, Pool, Road, Shape, Stream, CONNECTION_WINDOW, H2, HTTP1, IDLE, REMEMBERED, STREAMS,
    STREAM_WINDOW,
};

use crate::client::{ConnectError, WsClientConfig};
use crate::dial::ProxyChoice;
use crate::session::RelaySession;
use crate::tls::Trust;

/// The connections of the road in this process, each host's apart.
pub static POOL: Pool = Pool::new();

/// The variable that chooses the shape of the HTTP/2 that this road sends.
pub const SHAPE_ENV: &str = "PODSSH_H2_SHAPE";

/// The shape that the command line chose, once, before the run.
static CHOSEN: OnceLock<Shape> = OnceLock::new();

/// Choose the shape for this process, as `--h2-shape` does: the flag wins
/// over [`SHAPE_ENV`]. A word that is not a shape is refused and nothing is
/// stored, so the caller refuses the run rather than sending the default.
pub fn choose(word: &str) -> Result<(), String> {
    if word.trim().is_empty() {
        return Err(format!("{SHAPE_ENV}: existing, browser or firefox, not an empty word"));
    }
    let shape = shape_of(Some(word))?;
    let _ = CHOSEN.set(shape);
    Ok(())
}

/// The shape chosen by [`choose`], or `None` when only the variable or the
/// default applies.
pub fn chosen() -> Option<Shape> {
    CHOSEN.get().cloned()
}

/// The shape that this road sends: the command line's, else [`SHAPE_ENV`]'s,
/// else the road's own.
fn current() -> Result<Shape, String> {
    match chosen() {
        Some(shape) => Ok(shape),
        None => shape_from_env(),
    }
}

/// Connect as [`crate::connect`] does, with `token` in a field and nowhere
/// else, on this road where the host takes it, else by the upgrade of
/// HTTP/1.1: the session, and how it is carried.
pub async fn connect(config: &WsClientConfig, token: &str) -> Result<(RelaySession, Road), ConnectError> {
    let shape = current().map_err(ConnectError::Config)?;
    connect_with_shape(config, token, &shape).await
}

/// [`connect`] with the shape of the HTTP/2 that a new connection sends:
/// its SETTINGS and their order, the connection's window, the order of the
/// request's fields, the PRIORITY frames and the padding of a large DATA
/// frame. `pod-ws` records the last two and sends neither through h2 0.4,
/// so a shape that names them claims only what the connection carries.
pub async fn connect_with_shape(
    config: &WsClientConfig,
    token: &str,
    shape: &Shape,
) -> Result<(RelaySession, Road), ConnectError> {
    connect_on(&POOL, config, token, shape).await
}

/// [`connect_with_shape`] on `pool`: a test keeps its own connections.
pub async fn connect_on(
    pool: &Pool,
    config: &WsClientConfig,
    token: &str,
    shape: &Shape,
) -> Result<(RelaySession, Road), ConnectError> {
    pod_ws::h2_road::connect_with(pool, &config.pod(), token, shape).await
}

/// The shape that [`SHAPE_ENV`] names: `existing` (the default), `browser`
/// or `firefox`; another word is refused with why.
pub fn shape_from_env() -> Result<Shape, String> {
    shape_of(std::env::var(SHAPE_ENV).ok().as_deref())
}

/// [`shape_from_env`] of `value`, which a test gives.
pub fn shape_of(value: Option<&str>) -> Result<Shape, String> {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(Shape::existing()),
        Some(word) => match word.to_ascii_lowercase().as_str() {
            "existing" => Ok(Shape::existing()),
            "browser" => Ok(Shape::browser()),
            "firefox" => Ok(Shape::firefox()),
            other => Err(format!("{SHAPE_ENV}: existing, browser or firefox, not {other}")),
        },
    }
}

/// What `host:port` offers the road, with nothing sent but HTTP/2's
/// preface, its SETTINGS and a PING, all within `limit` each: TLS checked
/// for `server_name` as each road checks it, through `proxy`.
pub async fn probe(
    host: &str,
    port: u16,
    server_name: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    limit: Duration,
) -> Result<Offered, ConnectError> {
    pod_ws::h2_road::probe(&crate::client::way(proxy), host, port, server_name, trust, limit).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H2-1: the shape is chosen by its name, the default is the road's own,
    /// and another word is refused with the variable's name.
    #[test]
    fn the_shape_is_chosen_by_its_name_and_another_word_is_refused() {
        assert_eq!(shape_of(None), Ok(Shape::existing()));
        assert_eq!(shape_of(Some(" browser ")), Ok(Shape::browser()));
        assert_eq!(shape_of(Some("FIREFOX")), Ok(Shape::firefox()));
        assert_eq!(shape_of(Some("existing")), Ok(Shape::existing()));
        let refused = shape_of(Some("chrome-58")).unwrap_err();
        assert!(refused.starts_with("PODSSH_H2_SHAPE: existing, browser or firefox"), "{refused}");
        assert!(choose("  ").is_err(), "an empty word is not the default");
        assert!(Shape::browser().words().contains("SETTINGS"));
    }
}
