//! The serving of `podssh node --pinggy` (T-548), apart from `node_pinggy`
//! for the length of that file: TARGET probed first, then a tunnel of
//! Pinggy's at a time, each opened again after its end (a free tunnel's hour,
//! a lost connection) with a wait that doubles from 1 s to 60 s, each
//! visitor's TLS ended here and served under the node's keeper; each
//! tunnel's address put in the node's record of pkarr (T-445); and the
//! pair's road beside it when the node has a pair, as the OpenTunnel road's
//! node runs it.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::e2e::ends;
use podssh_relay::pinggy::{self, far};
use podssh_relay::reverse::{self, Layered, NodeConfig, TcpHandler, Wire};
use podssh_ws::ProxyChoice;
use rand::RngExt;
use tokio::sync::{mpsc, watch};

use crate::exitmap::Fault;
use crate::node_derp::Door;
use crate::node_pinggy::{settings, Ready, UNASKED_LIMIT};
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);
/// The waits between tunnels.
const AGAIN_FIRST: Duration = Duration::from_secs(1);
const AGAIN_MOST: Duration = Duration::from_secs(60);
/// The visitors that wait for the node's TLS, for each tunnel.
const WAITING: usize = 64;

/// The wait before tunnel `attempt`, from 0, with jitter.
fn again_wait(attempt: u32) -> Duration {
    let base = AGAIN_FIRST.saturating_mul(1u32 << attempt.min(16)).min(AGAIN_MOST);
    let ms = base.as_millis() as u64;
    Duration::from_millis(rand::rng().random_range(ms / 2..=ms))
}

pub(crate) async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, targets, roost, key, door, service, trust, pair, unasked, record } = ready;
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
    // One TLS key, beside the node's own, whose pin clients hold.
    let node_tls = match crate::pinggy_cert::load(key.path.as_deref()) {
        Ok(node_tls) => node_tls,
        Err(why) => return failed(why).report("node", err),
    };
    let acceptor = match far::served(&node_tls.cert_pem, &node_tls.key_pem).and_then(far::acceptor) {
        Ok(acceptor) => acceptor,
        Err(why) => return failed(why).report("node", err),
    };
    let pin = node_tls.pin;
    let proxy = ProxyChoice::FromEnvironment;
    // The first tunnel before any line of serving: unasked, a node that
    // cannot reach Pinggy ends soon, as it would with no road.
    let (visitors, first_rx) = mpsc::channel(WAITING);
    let opening = crate::pinggy_leg::open(&service, &trust, &proxy, visitors, &say);
    let opened = match unasked {
        Some(_) => tokio::time::timeout(UNASKED_LIMIT, opening)
            .await
            .unwrap_or_else(|_| Err(format!("no tunnel within {} s", UNASKED_LIMIT.as_secs()))),
        None => opening.await,
    };
    let first = match opened {
        Ok(tunnel) => tunnel,
        Err(why) => return failed(format!("no Pinggy road through {service}: {why}")).report("node", err),
    };
    if let Some(why) = &unasked {
        let _ = writeln!(err, "podssh node: {label}: {why}; so the node serves the Pinggy road unasked, the last");
    }
    let _ = writeln!(err, "podssh node: {label}: {}", pinggy::third_party_line(&service));
    let roads = match &pair {
        Ok((pair, _)) => format!(
            "the Pinggy road and the pair's road through {} (the pair expires {})",
            pair.relay.host,
            crate::pairs::utc(pair.expires_ms)
        ),
        Err(why) if unasked.is_none() => format!("the Pinggy road alone ({why})"),
        Err(_) => "the Pinggy road alone".to_string(),
    };
    let identity = Arc::new(key.identity);
    let public = identity.public();
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
        "podssh node: {label}: TLS ends at this host, with a certificate of its own key, pin {pin} ({}), which a \
         client gives after the name; {service} sees the name, the times and the sizes, and the end-to-end channel \
         keeps the bytes",
        node_tls.kept
    );
    if let Door::Allow(allow) = &door {
        let _ = writeln!(err, "podssh node: {label}: {}", crate::channel::who_may(Some(allow.as_path())));
    }
    if let Some(line) = crate::net::admit::line(&public) {
        let _ = writeln!(err, "podssh node: {label}: {line}");
    }
    // Its record names each tunnel's address, for as long as the node runs
    // (T-445): signed by the node's key, so a client that holds that key
    // trusts the pin in it as it would the node's own line.
    let line = |words: String| {
        let _ = writeln!(err, "podssh node: {label}: {words}");
    };
    let (_record, tell) = crate::node_record::alone(record, &identity, &trust, say.clone(), line);
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
    let channel =
        ends::Node { identity: identity.clone(), admit, say: say.clone(), redeem, leases: Default::default(), gate };
    let routes = crate::node::routes_of(&targets, grant, roost, Some(public));
    let first_target = crate::node_exit::first(&targets);
    let (host, port) = (first_target.host, first_target.port);
    let handler = TcpHandler { host: host.clone(), port, timeout: DIAL_LIMIT, sshd: roost };
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
                let name = open_tunnel.name.clone();
                say(format!("name {name} pin {pin} (podssh ssh node://{label} --pinggy-name {name}#{pin})"));
                // An address and a pin, not a credential; kept as the pins are.
                let file = crate::node_pinggy::name_file(&label);
                match podssh_relay::cache::store_file(&file, format!("{name}#{pin}\n").as_bytes()) {
                    Ok(path) => say(format!("the name is kept in {}", path.display())),
                    Err(why) => say(format!("the name could not be kept: {why}")),
                }
                // The record names the new tunnel in the place of the last; a
                // tunnel that ended stays named until the next, as a client
                // that dials it only finds no node there, or a stranger whose
                // key the pin refuses.
                let told = pinggy::Name::parse(&name).and_then(|name| tell.pinggy(&pinggy::Address { name, pin }));
                if let Err(why) = told {
                    say(format!("its record does not name this tunnel: {why}"));
                }
                let (acceptor, open, keeper, say_far) = (acceptor.clone(), open.clone(), keeper.clone(), say.clone());
                let serving = far::serve(rx, acceptor, settings(), budget, open, keeper, say_far);
                tokio::select! {
                    () = serving => {}
                    () = open_tunnel.ended() => {}
                    () = until_stopped(stopped.clone()) => {
                        open_tunnel.close().await;
                        return;
                    }
                }
                say(format!("the tunnel {name} ended (a free tunnel ends at 60 minutes); a new one, under a new name"));
            }
            let wait = again_wait(attempt);
            attempt = attempt.saturating_add(1);
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = until_stopped(stopped.clone()) => return,
            }
            let (visitors, rx) = mpsc::channel(WAITING);
            let opening = crate::pinggy_leg::open(&service, &trust, &proxy, visitors, &say);
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
        let say_pair = |line: String| (channel.say)(line);
        let (repair, expiry) = crate::node_expiry::watch(&label, &pair, stored, channel.say.clone(), &trust);
        let mut config = NodeConfig {
            pair,
            label: stored.then(|| label.clone()),
            trust: &trust,
            proxy: &proxy,
            timeout: crate::pairs::REQUEST_LIMIT,
            settings: reverse::Settings {
                rejoin: crate::layered::settings().resume_deadline,
                ..reverse::Settings::default()
            },
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
            (channel.say)(format!("the pair's road ended: {why}; the Pinggy road goes on"));
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
    // An upgrade's handover ends this binary; its successor opens a tunnel
    // of its own, under a new name. Else the stop's line.
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
    fn the_waits_between_tunnels_double_from_1_s_to_60_s() {
        for attempt in 0..20 {
            let wait = again_wait(attempt);
            let base = AGAIN_FIRST.saturating_mul(1u32 << attempt.min(16)).min(AGAIN_MOST);
            assert!(wait >= base / 2 && wait <= base, "{attempt}: {wait:?}");
        }
    }
}
