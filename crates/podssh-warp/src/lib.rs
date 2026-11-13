//! podssh-warp — WARP's road (T-352) over `pod-warp` of PodUtils/podcrates:
//! Cloudflare's own network carries a TCP stream to any target, from a host
//! whose only way out is HTTPS on port 443, with no account. The operator
//! allowed it on 2026-10-31 (Q52, `docs/decisions.md`).
//!
//! The road is the crate's: the registration and the identity file, MASQUE
//! over HTTP/2 through the caller's dial or over HTTP/3 where UDP passes,
//! the front door's key pinned and the record read again when it shows
//! another, the doors in turn, the check that a packet crosses a new
//! session, and the userspace stack inside the tunnel. This crate gives it
//! podssh's parts:
//!
//! - [`api`]: WARP's API through podssh's HTTP client for a proxy, with the
//!   bases that go first and a team's token.
//! - [`settings`]: the way of a session (podssh's dial for the proxy, its
//!   TLS provider, the system's UDP for HTTP/3), the pinned endpoint of a
//!   run and its check.
//! - [`open`] and [`Warp`]: the tunnel, the words of its way, and a stream
//!   to `HOST:PORT` inside it, a name asked inside the tunnel first and of
//!   podssh's resolver after.
//!
//! Its rules are podssh's: one outbound connection, through `HTTPS_PROXY`
//! when one is set; no listener and no TUN device; no credential in output.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use pod_core::{BoxedIo, Class, Dial, Failure, Report, Stage, Target};
use pod_warp::{Api, Door, Settings, SystemUdp, WarpNet, Way};
use podssh_ws::ProxyChoice;

pub use {pod_core, pod_warp};

/// The device's record in the cache: pod-warp's identity file (the device,
/// its certificate and its key).
pub const FILE: &str = "warp-device.json";
/// The front door that opened last and the base of the API that answered
/// last: podssh's file, which `pod_warp::door::door_from` reads.
pub const DOOR_FILE: &str = "warp-door.json";

/// The Terms that a registration accepts, which the user accepts first.
pub fn terms_url() -> &'static str {
    pod_warp::service::terms_url()
}

/// What a run asks of the road.
#[derive(Debug, Clone)]
pub struct Road {
    /// The way out of the API and of a session over HTTP/2.
    pub proxy: ProxyChoice,
    /// One endpoint in place of the doors of the record
    /// (`PODSSH_WARP_ENDPOINT`).
    pub endpoint: Option<SocketAddr>,
    /// Check that a packet crosses a new session (`PODSSH_WARP_PROBE`).
    pub probe: bool,
    /// HTTP/3 on the system's UDP in place of HTTP/2 (`PODSSH_WARP_H3`).
    pub h3: bool,
    /// The time limit of each step.
    pub limit: Duration,
}

/// WARP's API through podssh's HTTP client for `proxy`: the bases of
/// `first` first, then the crate's; a registration sends `team`.
pub fn api(proxy: &ProxyChoice, first: &[String], team: Option<&str>) -> Api {
    let api = Api::new(podssh_ws::client::getter(proxy));
    let mut bases = first.to_vec();
    for base in api.bases() {
        if !bases.contains(base) {
            bases.push(base.clone());
        }
    }
    let api = api.with_bases(bases);
    match team {
        Some(team) => api.with_team(team),
        None => api,
    }
}

/// The settings of `road` over `api`, with the events and the decisions
/// of `report`.
pub fn settings(api: Api, road: &Road, report: Report) -> Settings {
    let dial: Arc<dyn Dial> = Arc::new(podssh_ws::dial::dialer(&road.proxy, false));
    let mut way = Way::new(dial, Arc::new(podssh_ws::crypto::provider()));
    way.timeout = road.limit;
    if road.h3 {
        way.h3 = true;
        way.udp = Some(Arc::new(SystemUdp));
    }
    let mut settings = Settings::new(api, way);
    if let Some(at) = road.endpoint {
        settings.door = Door::Pinned(Target::Addr(at));
    }
    if !road.probe {
        settings.net.check = None;
    }
    settings.report = report;
    settings
}

/// The proxy that carries a connection to `ip`, in the words of a line.
fn proxy_for(ip: &str, proxy: &ProxyChoice) -> Option<String> {
    match proxy {
        ProxyChoice::Direct => None,
        ProxyChoice::Via(p) => Some(p.to_string()),
        ProxyChoice::FromEnvironment => podssh_ws::dial::proxy_from_env(ip).ok().flatten().map(|p| p.to_string()),
    }
}

/// An open tunnel and its stack.
#[derive(Clone)]
pub struct Warp {
    net: WarpNet,
    /// The front door that opened, and the proxy that carries the tunnel.
    pub endpoint: Option<SocketAddr>,
    pub proxy: Option<String>,
    /// Over HTTP/3.
    pub h3: bool,
    /// The time of the answer of the check of the data path; none when the
    /// run skipped the check.
    pub checked: Option<Duration>,
}

/// The tunnel of `warp`, made with [`settings`] of `road`.
pub async fn open(warp: &pod_warp::Warp, road: &Road) -> Result<Warp, Failure> {
    let net = warp.connect().await?;
    let endpoint = warp.won_door();
    let proxy = match endpoint {
        Some(at) if !road.h3 => proxy_for(&at.ip().to_string(), &road.proxy),
        _ => None,
    };
    Ok(Warp { checked: net.checked(), net, endpoint, proxy, h3: road.h3 })
}

impl Warp {
    /// The road's words for `-v` and doctor: the endpoint, and its proxy.
    pub fn via(&self) -> String {
        let at = self.endpoint.map(|at| at.to_string()).unwrap_or_else(|| "?".into());
        match (&self.proxy, self.h3) {
            (_, true) => format!("WARP's endpoint {at} over HTTP/3"),
            (Some(proxy), false) => format!("WARP's endpoint {at} through the proxy {proxy}"),
            (None, false) => format!("WARP's endpoint {at}"),
        }
    }

    /// The network inside the tunnel, a [`Dial`] (names asked inside it).
    pub fn net(&self) -> &WarpNet {
        &self.net
    }

    /// Why the tunnel ended, once it has.
    pub fn ended(&self) -> Option<String> {
        self.net.is_closed().then(|| self.net.close_reason().unwrap_or_else(|| "the tunnel ended".into()))
    }

    /// The addresses of `host`: itself, when it is one; else the resolver
    /// inside the tunnel's; else, after a failure that is not NXDOMAIN,
    /// podssh's own resolver, which asks the system and DNS over HTTPS.
    pub async fn resolve(&self, host: &str, limit: Duration) -> Result<Vec<IpAddr>, String> {
        let inside = pod_warp::dns::lookup(&self.net, &pod_warp::dns::RESOLVERS, host, limit).await;
        match inside {
            Ok(ips) => Ok(ips),
            Err(e) if e.class == Class::NotFound => Err(e.chain()),
            Err(inside) => {
                let deadline = tokio::time::Instant::now() + limit;
                match podssh_ws::resolve::resolve(host, 0, deadline).await {
                    Ok(addrs) => Ok(addrs.into_iter().map(|a| a.ip()).collect()),
                    Err(own) => Err(format!("{host}: inside the tunnel: {}; on this host: {own}", inside.chain())),
                }
            }
        }
    }

    /// A TCP stream to `host:port` inside the tunnel: each address of
    /// `host` in turn, within `limit`.
    pub async fn connect(&self, host: &str, port: u16, limit: Duration) -> Result<BoxedIo, String> {
        let deadline = tokio::time::Instant::now() + limit;
        let ips = self.resolve(host, limit).await?;
        let addrs: Vec<SocketAddr> = ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
        let connected = self.net.dial_addrs(host, &addrs, deadline).await.map_err(|f| f.chain())?;
        Ok(connected.io)
    }
}

/// Whether the way out failed at a proxy (it refused the endpoint, or it
/// was not reached): the endpoint was not reached, whatever the class.
pub fn at_proxy(failure: &Failure) -> bool {
    let mut next: Option<&(dyn std::error::Error + 'static)> = Some(failure);
    while let Some(e) = next {
        if e.downcast_ref::<Failure>().is_some_and(|f| f.stage == Stage::Proxy) {
            return true;
        }
        next = e.source();
    }
    false
}

/// The class of a failure of the road that HTTP/3 may pass: the endpoint
/// not reached (a proxy that refused it too), cut or silent. A refused
/// device or a setting is the same over QUIC.
pub fn worth_h3(failure: &Failure) -> bool {
    at_proxy(failure)
        || !matches!(failure.class, Class::Refused | Class::Revoked | Class::Config | Class::Usage | Class::Unsupported)
}

/// A failure over HTTP/2, and the one over HTTP/3 after it, as one failure
/// of the first's class.
pub fn both(h2: Failure, h3: &Failure) -> Failure {
    let text = format!("{}; over HTTP/3: {}", h2.chain(), h3.chain());
    Failure::new(h2.stage, h2.class, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn road() -> Road {
        Road { proxy: ProxyChoice::Direct, endpoint: None, probe: true, h3: false, limit: Duration::from_secs(5) }
    }

    /// The bases of a run go first, once each, then the crate's; a team's
    /// token stays out of the `Debug` form.
    #[test]
    fn the_bases_of_a_run_go_first() {
        let second = pod_warp::service::api_second();
        let api = api(&ProxyChoice::Direct, std::slice::from_ref(&second), Some("a-token-of-the-test"));
        assert_eq!(api.bases(), [second, pod_warp::service::api_base()]);
        assert!(!format!("{api:?}").contains("a-token-of-the-test"));
    }

    /// The settings of a run: its endpoint pinned, no check with no probe,
    /// HTTP/3 on the system's UDP.
    #[test]
    fn the_settings_follow_the_run() {
        let api = api(&ProxyChoice::Direct, &[], None);
        let plain = settings(api.clone(), &road(), Report::default());
        assert_eq!(plain.door, Door::Record);
        assert!(plain.net.check.is_some() && !plain.way.h3 && plain.way.udp.is_none());
        let at: SocketAddr = "162.159.198.2:443".parse().unwrap();
        let run = Road { endpoint: Some(at), probe: false, h3: true, ..road() };
        let set = settings(api, &run, Report::default());
        assert_eq!(set.door, Door::Pinned(Target::Addr(at)));
        assert!(set.net.check.is_none() && set.way.h3 && set.way.udp.is_some());
        assert_eq!(set.way.timeout, Duration::from_secs(5));
    }

    /// A refused device is not tried again over QUIC; an endpoint that was
    /// not reached is, and the line keeps the first failure's class.
    #[test]
    fn http3_follows_a_failure_of_the_way_alone() {
        let refused = Failure::new(Stage::Warp, Class::Refused, "refused");
        let silent = Failure::new(Stage::Warp, Class::Unavailable, "carried nothing");
        assert!(!worth_h3(&refused) && worth_h3(&silent));
        // A proxy that refused the endpoint is the way's, not the device's.
        let proxy = Failure::new(Stage::Proxy, Class::Refused, "the proxy refused CONNECT");
        let wrapped = Failure::caused(Stage::Warp, Class::Refused, "the front door", proxy);
        assert!(at_proxy(&wrapped) && worth_h3(&wrapped) && !at_proxy(&refused));
        let line = both(silent, &Failure::new(Stage::Quic, Class::Timeout, "UDP does not pass"));
        assert_eq!(line.class, Class::Unavailable);
        assert!(line.text().contains("carried nothing; over HTTP/3: UDP does not pass"), "{}", line.text());
    }
}
