//! The serving of `podssh node --ssh-j` (T-570), apart from `node_sshj` for
//! the length of that file: TARGET probed first, then one leg to the server
//! at a time, each with the remote forward of the node's derived name,
//! opened again after its end (a lost connection, the server's restart)
//! with a wait that doubles from 1 s to 60 s; each visitor that the server
//! sends down the forward is a link of the resumable layer, served under the
//! node's keeper, so a session moves from one leg to the next.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::e2e::ends;
use podssh_relay::pinggy::far::{self, Visitor};
use podssh_relay::pinggy::trace::{Counts, Traced};
use podssh_relay::pinggy::Say;
use podssh_relay::reverse::{self, layered::NODE_BUDGET};
use podssh_relay::session::far as layer_far;
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::record::Role;
use podssh_ssh::russh::{self, client};
use podssh_ws::ProxyChoice;
use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, watch};

use crate::exitmap::Fault;
use crate::node_derp::Door;
use crate::node_sshj::{settings, Ready, UNASKED_LIMIT};
use crate::relay_settings::Refusal;
use crate::sshj::leg::{self, Leg, Visitors, CONNECT_LIMIT};
use crate::sshj::{self, JumpName, Service, NAME_PORT};

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);
/// The waits between legs.
const AGAIN_FIRST: Duration = Duration::from_secs(1);
const AGAIN_MOST: Duration = Duration::from_secs(60);
/// The visitors that wait for the layer, for each leg.
const WAITING: usize = 64;

/// The wait before leg `attempt`, from 0, with jitter.
fn again_wait(attempt: u32) -> Duration {
    let base = AGAIN_FIRST.saturating_mul(1u32 << attempt.min(16)).min(AGAIN_MOST);
    let ms = base.as_millis() as u64;
    Duration::from_millis(rand::rng().random_range(ms / 2..=ms))
}

/// A leg that holds the node's name: its session, and its host key.
struct Held {
    handle: client::Handle<Leg>,
    host_key: (String, bool),
}

impl Held {
    /// Wait until the leg's session ended: a lost connection, the server's
    /// end, or the keepalive's.
    async fn ended(&self) {
        while !self.handle.is_closed() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn close(&self) {
        let _ = self.handle.disconnect(russh::Disconnect::ByApplication, "the node stops", "en").await;
    }
}

/// A leg to `service` through `proxy`, logged in as `name`'s user, with the
/// remote forward of `name`'s address; each visitor goes to `queue`.
async fn hold(
    service: &Service,
    name: &JumpName,
    proxy: &ProxyChoice,
    queue: mpsc::Sender<Visitor>,
) -> Result<Held, String> {
    let tcp = podssh_ws::dial::dial(&service.host, service.port, proxy, CONNECT_LIMIT)
        .await
        .map_err(|e| format!("{service}: {e}"))?;
    let visitors = Visitors { address: name.address.clone(), queue };
    let opened = leg::open(tcp, service, &name.user, Some(visitors)).await?;
    let forward = opened.handle.tcpip_forward(name.address.as_str(), NAME_PORT);
    let forward = tokio::time::timeout(CONNECT_LIMIT, forward).await;
    match forward {
        Ok(Ok(_)) => Ok(Held { handle: opened.handle, host_key: opened.host_key }),
        // The server keeps a name for the session that holds it: a stranger
        // who took it first, or this node's last session, not yet ended there.
        Ok(Err(e)) => Err(format!(
            "{service} refused the forward of {name} ({e}): another session holds the name, a stranger's or this \
             node's last, which the server has not ended"
        )),
        Err(_) => Err(format!("{service}: no answer to the forward within {} s", CONNECT_LIMIT.as_secs())),
    }
}

/// Serve each visitor of `visitors` until its sender ends (the leg ended):
/// the layer's far end with `keeper`, whose sessions outlive this leg.
async fn visitors_served<A, O, F>(mut visitors: mpsc::Receiver<Visitor>, open: O, keeper: Arc<Keeper<A>>, say: Say)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: std::future::Future<Output = Result<A, String>> + Send + 'static,
{
    while let Some(Visitor { stream, peer }) = visitors.recv().await {
        let (keeper, open, say) = (keeper.clone(), open.clone(), say.clone());
        tokio::spawn(async move {
            // Each visitor's bytes, for its last line, as the Pinggy road says them.
            let counts = Counts::new();
            let link = Traced::new(stream, counts.clone());
            layer_far::serve(link, Role::NODE, settings(), &keeper, NODE_BUDGET, open).await;
            let why = counts.end().unwrap_or_else(|| "the layer ended its link".into());
            say(format!("a visitor from {peer} ended ({why}): {}", counts.line()));
        });
    }
}

pub(crate) async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, targets, roost, key, door, service, unasked, pair_left } = ready;
    // TARGET first: a node that cannot reach it would serve no session.
    let target = match crate::node::probe(&targets, roost).await {
        Ok(versions) => crate::node::serving(&targets, &versions),
        Err(refusal) => return refusal.report("node", err),
    };
    let say: Say = {
        let label = label.clone();
        Arc::new(move |line: String| {
            podssh_ssh::err_line!("podssh node: {label}: {line}");
            crate::detach::on_line("node", &line);
        })
    };
    let failed = |message: String| Refusal { message, code: Fault::RelayUnreachable.code() };
    let identity = Arc::new(key.identity);
    let public = identity.public();
    // The name is the key's: a client that holds the key derives it too.
    let name = JumpName::of_fingerprint(&public.fingerprint());
    let proxy = ProxyChoice::FromEnvironment;
    // The first leg before any line of serving: unasked, a node that cannot
    // reach the server ends soon, as it would with no road.
    let (queue, first_rx) = mpsc::channel(WAITING);
    let holding = hold(&service, &name, &proxy, queue);
    let held = match unasked {
        Some(_) => tokio::time::timeout(UNASKED_LIMIT, holding)
            .await
            .unwrap_or_else(|_| Err(format!("no leg within {} s", UNASKED_LIMIT.as_secs()))),
        None => holding.await,
    };
    let first = match held {
        Ok(held) => held,
        Err(why) => return failed(format!("no ssh-j road through {service}: {why}")).report("node", err),
    };
    let mut line = |words: String| {
        let _ = writeln!(err, "podssh node: {label}: {words}");
    };
    if let Some(why) = &unasked {
        line(format!("{why}; so the node serves the ssh-j road unasked, the last"));
    }
    line(sshj::third_party_line(&service));
    let by = match &door {
        Door::Allow(_) => String::new(),
        Door::Net(net) => format!("; with no --allow, the members of the net {net} are its door"),
    };
    line(format!("serving {target} over the ssh-j road alone until Ctrl-C{by}"));
    if let Some(pair) = &pair_left {
        line(format!("{pair} is not served beside the ssh-j road: run podssh node {label} TARGET for the pair's road"));
    }
    line(format!("key {public}"));
    line(leg::host_key_line(&service, &first.host_key));
    if let Door::Allow(allow) = &door {
        line(crate::channel::who_may(Some(allow.as_path())));
    }
    if let Some(admitted) = crate::net::admit::line(&public) {
        line(admitted);
    }
    // The channel of T-088, with this node's key and its door.
    let allow = match door {
        Door::Allow(path) => Some(path),
        Door::Net(_) => None,
    };
    // Grants used once (T-226), signed by the node's key or by its door's.
    let redeem = crate::grants::door(&label, public, allow.clone());
    let (admit, grant) = crate::net::admit::doors(allow, public, true);
    // The person of --ask (T-638), as on the node's other roads.
    let gate = crate::node_ask::gate();
    let channel =
        ends::Node { identity: identity.clone(), admit, say: say.clone(), redeem, leases: Default::default(), gate };
    let routes = crate::node::routes_of(&targets, grant, roost, Some(public));
    let first_target = crate::node_exit::first(&targets);
    let (host, port) = (first_target.host, first_target.port);
    let target = move || {
        let host = host.clone();
        async move { reverse::tcp::dial_target(&host, port, DIAL_LIMIT, roost).await }
    };
    // Each session is a pipe (T-164): the target is reached once the
    // operator's key is let in.
    let open = {
        let (channel, routes) = (Some(channel.clone()), routes.clone());
        move || {
            let (target, channel, routes) = (target.clone(), channel.clone(), routes.clone());
            async move { crate::channel::piped_by(channel, routes, target).await }
        }
    };
    // The upgrade's keeper (T-679), whose lost sessions a sweep ends.
    let keeper = crate::node_upgrade::channel_keeper(&channel, settings().resume_deadline);
    far::sweep(&keeper);
    crate::node_upgrade::lines(say.clone());
    let (stop, stopped) = watch::channel(false);
    let until_stopped = |mut stopped: watch::Receiver<bool>| async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };
    // One leg at a time, each opened again after its end; the first is open.
    let legs = async {
        let (mut held, mut visitors_rx, mut attempt) = (Some(first), Some(first_rx), 0u32);
        loop {
            if let (Some(this_leg), Some(rx)) = (held.take(), visitors_rx.take()) {
                attempt = 0;
                let key_line = public.fingerprint();
                say(format!("ssh-j name {name} at {service} (podssh ssh node://{label} --node-key {key_line})"));
                let serving = visitors_served(rx, open.clone(), keeper.clone(), say.clone());
                tokio::select! {
                    () = serving => {}
                    () = this_leg.ended() => {}
                    () = until_stopped(stopped.clone()) => {
                        this_leg.close().await;
                        return;
                    }
                }
                say(format!("the leg to {service} ended; a new one, under the same name"));
            }
            let wait = again_wait(attempt);
            attempt = attempt.saturating_add(1);
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = until_stopped(stopped.clone()) => return,
            }
            let (queue, rx) = mpsc::channel(WAITING);
            let opened = tokio::select! {
                opened = hold(&service, &name, &proxy, queue) => opened,
                () = until_stopped(stopped.clone()) => return,
            };
            match opened {
                Ok(opened) => (held, visitors_rx) = (Some(opened), Some(rx)),
                Err(why) => say(format!("no leg at {service}: {why}; again in a while")),
            }
        }
    };
    // Until Ctrl-C, or an upgrade (T-679): the legs go on by themselves.
    tokio::pin!(legs);
    tokio::select! {
        () = &mut legs => {}
        () = crate::node_upgrade::stop() => {
            let _ = stop.send(true);
            legs.await;
        }
    }
    // An upgrade's handover ends this binary; its successor holds the name
    // once the server ended this one's session. Else the stop's line.
    crate::node_upgrade::or_finish(|| {
        let _ = writeln!(err, "podssh node: {label}: stopped");
        0
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_waits_between_legs_double_from_1_s_to_60_s() {
        for attempt in 0..20 {
            let wait = again_wait(attempt);
            let base = AGAIN_FIRST.saturating_mul(1u32 << attempt.min(16)).min(AGAIN_MOST);
            assert!(wait >= base / 2 && wait <= base, "{attempt}: {wait:?}");
        }
    }
}
