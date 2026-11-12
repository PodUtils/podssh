//! A forward session in the resumable layer, whose far end is podssh's relay
//! role (T-173): `pod-relay` of PodUtils/podcrates (T-684). Its dialer takes
//! podssh's context (`crate::context`); the offers are kept in podssh's cache.

pub use pod_relay::forward_layer::*;

/// The offers of the layer that the cache keeps for each relay host.
pub mod kept {
    pub use pod_relay::forward_layer::kept::*;

    use super::Offer;
    use crate::relay::Relay;

    /// Keep `offered` for `relay`, read at `now_ms`.
    pub fn keep(relay: &Relay, offered: &Offer, now_ms: i64) {
        pod_relay::forward_layer::kept::keep(&crate::context::cache(), relay, offered, now_ms)
    }

    /// Keep `offered` for `relay`, read now.
    pub fn keep_now(relay: &Relay, offered: &Offer) {
        pod_relay::forward_layer::kept::keep_now(&crate::context::cache(), relay, offered)
    }

    /// The offer kept for `relay` that is younger than a day at `now_ms`.
    pub fn kept(relay: &Relay, now_ms: i64) -> Option<Offer> {
        pod_relay::forward_layer::kept::kept(&crate::context::cache(), relay, now_ms)
    }

    /// The offer kept for `relay` that is younger than a day now.
    pub fn kept_now(relay: &Relay) -> Option<Offer> {
        pod_relay::forward_layer::kept::kept_now(&crate::context::cache(), relay)
    }

    /// Forget the offer kept for `relay`.
    pub fn forget(relay: &Relay) {
        pod_relay::forward_layer::kept::forget(&crate::context::cache(), relay)
    }
}

/// The offer of the layer in a host's `/relays.json`.
pub mod offer {
    use std::time::Duration;

    pub use pod_relay::forward_layer::offer::*;
    use podssh_ws::{ProxyChoice, Trust};
    use tokio::io::{AsyncRead, AsyncWrite};

    use crate::relay::Relay;

    /// The offer of `relay`, read through `proxy` within `timeout`.
    pub async fn ask(relay: &Relay, trust: &Trust, proxy: &ProxyChoice, timeout: Duration) -> Result<Offer, String> {
        pod_relay::forward_layer::offer::ask(&crate::context::of(proxy), relay, trust, timeout).await
    }

    /// The offer of `asked` read over `stream`, whose requests name
    /// `host_header`, with podssh's user agent.
    pub async fn over<S>(stream: &mut S, host_header: &str, asked: &Relay) -> Result<Offer, String>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        pod_relay::forward_layer::offer::over(stream, &podssh_ws::dial::user_agent(), host_header, asked).await
    }
}
