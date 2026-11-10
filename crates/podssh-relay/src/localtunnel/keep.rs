//! A node's tunnel at a localtunnel server, kept: asked for, then held by
//! its connections, each opened again at once when it ends, as
//! localtunnel's client opens a new one at each `dead` (`lib/Tunnel.js`);
//! the server forgets a tunnel 1 s after its last connection closed
//! (`lib/Client.js`, `graceTimeout`), so no wait comes between them. A
//! connection whose dial fails three times in a row, 1 s apart, finds the
//! tunnel gone (its port refuses, as the server closed it): the node asks
//! for its tunnel again, under the same name where it is free.
//!
//! Each connection is TCP to the port that the server named, directly or
//! by `HTTPS_PROXY`'s CONNECT, as podssh dials each host ([`tcp`]): the
//! server's OS chose the port, so a proxy that lets CONNECT reach port 443
//! alone refuses it, and the node needs an egress that reaches the port.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::ProxyChoice;
use tokio::sync::watch;
use tokio::task::JoinSet;

use super::api::{self, Dial, Failed, Tunnel};
use super::Service;
use crate::opentunnel::dial::{BoxIo, Dialing, CONNECT_LIMIT};
use crate::opentunnel::Say;

/// The tries of a connection's dial before the tunnel is taken as gone.
pub const DIAL_TRIES: u32 = 3;
/// The wait between those tries.
pub const DIAL_AGAIN: Duration = Duration::from_secs(1);
/// The waits between requests of a tunnel: doubling from the first to the most.
pub const ASK_FIRST: Duration = Duration::from_secs(1);
pub const ASK_MOST: Duration = Duration::from_secs(60);

/// How a node reaches a tunnel's port: [`tcp`], or a test's stream.
pub type Connect = Arc<dyn Fn(String, u16) -> Dialing + Send + Sync>;
/// The serving of one connection, until it ends.
pub type Serving = Pin<Box<dyn Future<Output = ()> + Send>>;
/// What serves one connection of the tunnel.
pub type Serve = Arc<dyn Fn(BoxIo, Arc<Tunnel>) -> Serving + Send + Sync>;

/// TCP to a tunnel's port through `proxy`.
pub fn tcp(proxy: ProxyChoice) -> Connect {
    Arc::new(move |host: String, port: u16| -> Dialing {
        let proxy = proxy.clone();
        Box::pin(async move {
            let tcp = podssh_ws::dial::dial(&host, port, &proxy, CONNECT_LIMIT).await;
            tcp.map(|tcp| Box::new(tcp) as BoxIo).map_err(|e| {
                let shown = podssh_ws::dial::authority(&host, port);
                format!("{shown}, the tunnel's port: {e} (the node's egress must reach that port)")
            })
        })
    })
}

/// What a node keeps.
#[derive(Clone)]
pub struct Keep {
    pub service: Service,
    pub api: Dial,
    pub connect: Connect,
    /// The name that the node asks for; a random one where it is none.
    pub asked: Option<String>,
    pub serve: Serve,
    pub say: Say,
}

/// The wait before request `attempt` of a tunnel, from 0.
pub fn ask_wait(attempt: u32) -> Duration {
    ASK_FIRST.saturating_mul(1u32 << attempt.min(16)).min(ASK_MOST)
}

/// A tunnel, asked for again after each passing failure, with a wait that
/// doubles; none once `stop` is true. A refusal of the request itself (a
/// name that the server does not take) ends it.
pub async fn asked(keep: &Keep, mut stop: watch::Receiver<bool>) -> Result<Option<Tunnel>, String> {
    let mut attempt = 0u32;
    loop {
        let asking = api::ask(&keep.service, &keep.api, keep.asked.as_deref());
        let failed = tokio::select! {
            asked = asking => match asked {
                Ok(tunnel) => return Ok(Some(tunnel)),
                Err(Failed::Refused(why)) => return Err(why),
                Err(Failed::ForNow(why)) => why,
            },
            _ = stop.wait_for(|stop| *stop) => return Ok(None),
        };
        let wait = ask_wait(attempt);
        attempt = attempt.saturating_add(1);
        (keep.say)(format!("no tunnel from {}: {failed}; asked again in {} s", keep.service, wait.as_secs()));
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            _ = stop.wait_for(|stop| *stop) => return Ok(None),
        }
    }
}

/// Keep `first`, then each tunnel after it, until `stop` is true; `made`
/// hears each new tunnel, which may have another name. The end of a refusal
/// of the request is its reason.
pub async fn run<M>(keep: Keep, first: Tunnel, mut made: M, stop: watch::Receiver<bool>) -> Result<(), String>
where
    M: FnMut(&Tunnel) + Send,
{
    let mut tunnel = first;
    loop {
        let lost = hold(&keep, Arc::new(tunnel.clone()), stop.clone()).await;
        let Some(why) = lost else { return Ok(()) };
        (keep.say)(format!("{why}; so the tunnel {} is gone, and the node asks for it again", tunnel.url()));
        tunnel = match asked(&keep, stop.clone()).await? {
            Some(next) => next,
            None => return Ok(()),
        };
        made(&tunnel);
    }
}

/// Hold `tunnel` by its connections: why it is gone, or none at the stop.
async fn hold(keep: &Keep, tunnel: Arc<Tunnel>, mut stop: watch::Receiver<bool>) -> Option<String> {
    let host = tunnel.dial_host(&keep.service);
    let mut set = JoinSet::new();
    for _ in 0..tunnel.connections {
        let (connect, serve, host, tunnel) = (keep.connect.clone(), keep.serve.clone(), host.clone(), tunnel.clone());
        set.spawn(connection(connect, serve, host, tunnel));
    }
    let gone = tokio::select! {
        gone = set.join_next() => Some(match gone {
            Some(Ok(why)) => why,
            Some(Err(e)) => format!("a connection of the tunnel failed: {e}"),
            None => "the tunnel has no connection".to_string(),
        }),
        _ = stop.wait_for(|stop| *stop) => None,
    };
    // The other connections, and each request that they serve, end with it.
    set.abort_all();
    gone
}

/// One connection of the tunnel, opened again after each end: why its port
/// was refused [`DIAL_TRIES`] times in a row.
async fn connection(connect: Connect, serve: Serve, host: String, tunnel: Arc<Tunnel>) -> String {
    let mut failed = 0u32;
    loop {
        match connect(host.clone(), tunnel.port).await {
            Ok(io) => {
                failed = 0;
                serve(io, tunnel.clone()).await;
            }
            Err(why) => {
                failed += 1;
                if failed >= DIAL_TRIES {
                    return why;
                }
                tokio::time::sleep(DIAL_AGAIN).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn the_waits_between_requests_double_from_1_s_to_60_s() {
        assert_eq!(ask_wait(0), Duration::from_secs(1));
        assert_eq!(ask_wait(3), Duration::from_secs(8));
        assert_eq!(ask_wait(30), ASK_MOST);
    }

    fn tunnel(connections: usize) -> Tunnel {
        let host = "abcd.lt.test".to_string();
        Tunnel { id: "abcd".into(), port: 9, connections, host, web_port: 443, ip: None }
    }

    /// A port that refuses each dial: the tunnel is gone after the tries of
    /// one connection, and no connection was served.
    #[tokio::test(start_paused = true)]
    async fn a_port_that_refuses_each_dial_is_a_tunnel_gone() {
        let dials = Arc::new(AtomicUsize::new(0));
        let counted = dials.clone();
        let connect: Connect = Arc::new(move |_: String, _: u16| -> Dialing {
            counted.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err("refused".to_string()) })
        });
        let serve: Serve = Arc::new(|_: BoxIo, _: Arc<Tunnel>| -> Serving { Box::pin(async { panic!("no visitor") }) });
        let service = super::super::Service::parse("https://lt.test").unwrap();
        let api: Dial = Arc::new(|_: &Service| -> Dialing { Box::pin(async { Err("no API here".to_string()) }) });
        let keep = Keep { service, api, connect, asked: None, serve, say: Arc::new(|_| {}) };
        let (_stop, stopped) = watch::channel(false);
        let gone = hold(&keep, Arc::new(tunnel(2)), stopped).await;
        assert_eq!(gone.as_deref(), Some("refused"));
        assert!(dials.load(Ordering::SeqCst) >= DIAL_TRIES as usize);
    }
}
