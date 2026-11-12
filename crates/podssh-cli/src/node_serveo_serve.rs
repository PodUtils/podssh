//! The serving of `podssh node --serveo` (T-549), apart from `node_serveo`
//! for the length of that file, in the shape of the Pinggy road's
//! (`node_pinggy_serve`), whose waits, settings and far end it takes: TARGET
//! probed first, then a tunnel at Serveo at a time, under the first alias of
//! the node's key that Serveo grants, opened again after each end with a
//! wait that doubles from 1 s to 60 s; each client's channel served under the
//! node's keeper, with no TLS; and the pair's road beside it when the node
//! has a pair. Serveo's documents name no bound of an alias's tunnel (their
//! 10 minutes are of a public port of anonymous TCP), so the node keeps each
//! tunnel until it ends, and a session's layer moves it to the next.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::e2e::ends;
use podssh_relay::pinggy::{self, far};
use podssh_relay::reverse::{self, Layered, NodeConfig, Wire};
use podssh_relay::serveo;
use podssh_ws::ProxyChoice;
use tokio::sync::{mpsc, watch};

use crate::exitmap::Fault;
use crate::node_derp::Door;
use crate::node_pinggy::{settings, UNASKED_LIMIT};
use crate::node_pinggy_serve::again_wait;
use crate::node_serveo::Ready;
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);
/// The clients that wait for the layer, for each tunnel.
const WAITING: usize = 64;

pub(crate) async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, targets, roost, key, door, service, trust, pair, unasked } = ready;
    // TARGET first: a node that cannot reach it would serve no session.
    let target = match crate::node::probe(&targets, roost).await {
        Ok(versions) => crate::node::serving(&targets, &versions),
        Err(refusal) => return refusal.report("node", err),
    };
    let say: pinggy::Say = {
        let label = label.clone();
        Arc::new(move |line: String| {
            podssh_ssh::err_line!("podssh node: {label}: {line}");
            crate::detach::on_line("node", &line);
        })
    };
    let failed = |message: String| Refusal { message, code: Fault::RelayUnreachable.code() };
    let identity = Arc::new(key.identity);
    let public = identity.public();
    // The alias is of the key's fingerprint, as a client holds it.
    let fingerprint = public.fingerprint();
    let proxy = ProxyChoice::FromEnvironment;
    // The first tunnel before any line of serving: unasked, a node that
    // cannot reach Serveo ends soon, as it would with no road.
    let (visitors, first_rx) = mpsc::channel(WAITING);
    let opening = crate::serveo_leg::open(&service, &fingerprint, &proxy, visitors, &say);
    let opened = match unasked {
        Some(_) => tokio::time::timeout(UNASKED_LIMIT, opening)
            .await
            .unwrap_or_else(|_| Err(format!("no tunnel within {} s", UNASKED_LIMIT.as_secs()))),
        None => opening.await,
    };
    let first = match opened {
        Ok(tunnel) => tunnel,
        Err(why) => return failed(format!("no Serveo road through {service}: {why}")).report("node", err),
    };
    if let Some(why) = &unasked {
        let _ = writeln!(err, "podssh node: {label}: {why}; so the node serves the Serveo road unasked, the last");
    }
    let _ = writeln!(err, "podssh node: {label}: {}", serveo::third_party_line(&service));
    let roads = match &pair {
        Ok((pair, _)) => format!(
            "the Serveo road and the pair's road through {} (the pair expires {})",
            pair.relay.host,
            crate::pairs::utc(pair.expires_ms)
        ),
        Err(why) if unasked.is_none() => format!("the Serveo road alone ({why})"),
        Err(_) => "the Serveo road alone".to_string(),
    };
    let by = match &door {
        Door::Allow(_) => String::new(),
        Door::Net(net) => format!("; with no --allow, the members of the net {net} are its door"),
    };
    let _ = writeln!(err, "podssh node: {label}: serving {target} over {roads} until Ctrl-C{by}");
    let _ = writeln!(err, "podssh node: {label}: key {public}");
    let pinned = if first.host_key.1 { "pinned by pod-services" } else { "unpinned" };
    let (host_key, way) = (&first.host_key.0, first.way);
    let _ = writeln!(err, "podssh node: {label}: {service}'s host key {host_key} ({pinned}), over {way}");
    let _ = writeln!(
        err,
        "podssh node: {label}: each session goes inside SSH to {service}, with no TLS of the node's: {service} sees \
         the alias, the times and the sizes, and the end-to-end channel keeps the bytes"
    );
    if let Door::Allow(allow) = &door {
        let _ = writeln!(err, "podssh node: {label}: {}", crate::channel::who_may(Some(allow.as_path())));
    }
    if let Some(line) = crate::net::admit::line(&public) {
        let _ = writeln!(err, "podssh node: {label}: {line}");
    }
    // The channel of T-088 on both roads, with this node's key and its door.
    let allow = match door {
        Door::Allow(path) => Some(path),
        Door::Net(_) => None,
    };
    // Grants used once (T-226), signed by the node's key or by its door's.
    let redeem = crate::grants::door(&label, public, allow.clone());
    let (admit, grant) = crate::net::admit::doors(allow, public, true);
    // The person of --ask (T-638), as on the node's other roads.
    let gate = crate::node_ask::gate();
    let channel = ends::Node {
        identity: identity.clone(),
        admit,
        events: podssh_relay::e2e::events(say.clone()),
        redeem,
        leases: Default::default(),
        gate,
        docs: podssh_relay::e2e::net::process(),
        holds: podssh_relay::e2e::hold::holds(),
    };
    let routes = crate::node::routes_of(&targets, grant, roost, Some(public));
    let first_target = crate::node_exit::first(&targets);
    let (host, port) = (first_target.host, first_target.port);
    let handler = reverse::tcp::handler(host.clone(), port, DIAL_LIMIT, roost);
    let target = move || {
        let host = host.clone();
        async move { reverse::tcp::dial_target(&host, port, DIAL_LIMIT, roost).await }
    };
    // Each session of either road is a pipe (T-164): the target is reached
    // once the operator's key is let in.
    let open = {
        let (channel, routes) = (Some(channel.clone()), routes.clone());
        move || {
            let (target, channel, routes) = (target.clone(), channel.clone(), routes.clone());
            async move { crate::channel::piped_by(channel, routes, target).await }
        }
    };
    let budget = podssh_relay::reverse::layered::NODE_BUDGET;
    // The upgrade's keeper, for each road of the node (T-679).
    let keeper = crate::node_upgrade::channel_keeper(&channel, settings().resume_deadline);
    far::sweep(&keeper);
    crate::node_upgrade::lines(say.clone());
    let transit = match (&pair, crate::node_transit::url()) {
        (Ok((pair, stored)), Some(url)) => crate::node_transit::road(&label, pair, *stored, &trust, url, say.clone()),
        _ => None,
    };
    let transit_open = open.clone();
    let (stop, stopped) = watch::channel(false);
    let until_stopped = |mut stopped: watch::Receiver<bool>| async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };
    // One tunnel at a time, each opened again after its end; the first is open.
    let tunnel_road = async {
        let (mut tunnel, mut visitors_rx, mut attempt) = (Some(first), Some(first_rx), 0u32);
        loop {
            if let (Some(open_tunnel), Some(rx)) = (tunnel.take(), visitors_rx.take()) {
                attempt = 0;
                let alias = open_tunnel.name.clone();
                say(format!(
                    "alias {alias} of its key {fingerprint} (podssh ssh node://{label}, where the pins of {label}, \
                     --node-key or the net name the key)"
                ));
                let (open, keeper, say_far) = (open.clone(), keeper.clone(), say.clone());
                let serving = far::serve(rx, None, settings(), budget, open, keeper, say_far);
                tokio::select! {
                    () = serving => {}
                    () = open_tunnel.ended() => {}
                    () = until_stopped(stopped.clone()) => {
                        open_tunnel.close().await;
                        return;
                    }
                }
                say(format!("the tunnel of the alias {alias} ended; a new one"));
            }
            let wait = again_wait(attempt);
            attempt = attempt.saturating_add(1);
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = until_stopped(stopped.clone()) => return,
            }
            let (visitors, rx) = mpsc::channel(WAITING);
            let opening = crate::serveo_leg::open(&service, &fingerprint, &proxy, visitors, &say);
            let opened = tokio::select! {
                opened = opening => opened,
                () = until_stopped(stopped.clone()) => return,
            };
            match opened {
                Ok(opened) => (tunnel, visitors_rx) = (Some(opened), Some(rx)),
                Err(why) => say(format!("no tunnel at {service}: {why}; again in a while")),
            }
        }
    };
    let pair_road = async {
        let Ok((pair, stored)) = pair else { return };
        let channel_say = podssh_relay::e2e::say(&channel);
        let say_pair = |line: String| channel_say(line);
        let (repair, expiry) = crate::node_expiry::watch(&label, &pair, stored, channel_say.clone(), &trust);
        let mut config = NodeConfig {
            pair,
            label: stored.then(|| label.clone()),
            trust: &trust,
            ctx: &podssh_relay::context::of(&proxy),
            timeout: crate::pairs::REQUEST_LIMIT,
            settings: reverse::Settings { rejoin: crate::layered::settings().resume_deadline, ..reverse::settings() },
            repair,
            wire: Wire::Tls,
            say: Some(&say_pair),
        };
        let piped = crate::channel::Piped { inner: Arc::new(handler), channel: Some(channel.clone()), routes };
        let layered = Layered::with_keeper(piped, crate::layered::settings(), budget, keeper.clone());
        let pair_run = Box::pin(reverse::run(&mut config, Arc::new(layered), until_stopped(stopped.clone())));
        let exit = crate::node_transit::alongside(pair_run, transit, transit_open, keeper.clone()).await;
        expiry.abort();
        if let Some((_, why)) = crate::node::ended(&label, exit) {
            channel_say(format!("the pair's road ended: {why}; the Serveo road goes on"));
        }
    };
    // Until Ctrl-C, or an upgrade (T-679): the tunnels go on by themselves.
    let both = async { tokio::join!(tunnel_road, pair_road) };
    tokio::pin!(both);
    tokio::select! {
        _ = &mut both => {}
        () = crate::node_upgrade::stop() => {
            let _ = stop.send(true);
            both.await;
        }
    }
    // An upgrade's handover ends this binary; its successor asks the same
    // alias, which Serveo may hold a while, so it may take the next.
    crate::node_upgrade::or_finish(|| {
        let _ = writeln!(err, "podssh node: {label}: stopped");
        0
    })
    .await
}
