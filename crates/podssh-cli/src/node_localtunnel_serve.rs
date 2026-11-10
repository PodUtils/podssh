//! The serving of `podssh node --localtunnel` (T-568), apart from
//! `node_localtunnel` for the length of that file: TARGET probed first,
//! then the tunnel asked for under the name that the node's key gives, and
//! kept by its connections (`podssh_relay::localtunnel::keep`); each
//! connection goes to the relay role or to the node's links by its path
//! (`podssh_relay::localtunnel::route`). Each link is served under the
//! node's keeper, so a session moves from one link to the next, as on the
//! ssh-j road.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::e2e::ends;
use podssh_relay::localtunnel;
use podssh_relay::localtunnel::api::{self, Tunnel};
use podssh_relay::localtunnel::keep::{self, Keep, Serve, Serving};
use podssh_relay::localtunnel::route::{self, Router, Visit, Visiting};
use podssh_relay::opentunnel::dial::BoxIo;
use podssh_relay::opentunnel::Say;
use podssh_relay::pinggy::far;
use podssh_relay::reverse::{self, layered::NODE_BUDGET};
use podssh_relay::session::far as layer_far;
use podssh_relay::session::record::Role;
use podssh_ws::ProxyChoice;
use tokio::io::DuplexStream;
use tokio::sync::watch;

use crate::exitmap::Fault;
use crate::node_derp::Door;
use crate::node_localtunnel::{settings, Ready, UNASKED_LIMIT};
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);

/// The line of the tunnel's name: the one of the node's key, which a client
/// derives; or another's, as the server gave one where a stranger, or this
/// node's last run not yet forgotten, holds the key's.
pub(crate) fn name_line(tunnel: &Tunnel, name: &str, label: &str, fingerprint: &str) -> String {
    if tunnel.id == name {
        let client = format!("podssh ssh node://{label} --node-key {fingerprint}");
        return format!("localtunnel name {name}, of the node's key ({client})");
    }
    format!(
        "the name {name} of the node's key is another's at the server, which gave {}: a client that derives the \
         name reaches the other, which the end-to-end channel refuses; the node asks for its name again when it \
         asks for its tunnel again",
        tunnel.id
    )
}

/// The serving of one connection: the router's, with the tunnel's name.
fn served(router: Arc<Router>) -> Serve {
    Arc::new(move |io: BoxIo, tunnel: Arc<Tunnel>| -> Serving {
        Box::pin(route::serve(router.clone(), tunnel.host.clone(), io))
    })
}

pub(crate) async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, targets, roost, key, door, service, trust, unasked, pair_left, role } = ready;
    // TARGET first, when there is one: a node that cannot reach it would
    // serve no session. With none, the node is the relay alone.
    let target = match targets.is_empty() {
        true => None,
        false => match crate::node::probe(&targets, roost).await {
            Ok(versions) => Some(crate::node::serving(&targets, &versions)),
            Err(refusal) => return refusal.report("node", err),
        },
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
    let name = localtunnel::name_of(&public.fingerprint());
    if let Some(role) = &role {
        // Its list of keys at a URL, fetched again each TTL (T-646).
        role.keep_lists(&label);
    }
    // The channel of T-088, with this node's key and its door.
    let allow = match &door {
        Door::Allow(path) => Some(path.clone()),
        Door::Net(_) => None,
    };
    // Grants used once (T-226), signed by the node's key or by its door's.
    let redeem = crate::grants::door(&label, public, allow.clone());
    let (admit, grant) = crate::net::admit::doors(allow, public, true);
    // The person of --ask (T-638), as on the node's other roads.
    let gate = crate::node_ask::gate();
    let channel =
        ends::Node { identity: identity.clone(), admit, say: say.clone(), redeem, leases: Default::default(), gate };
    // The upgrade's keeper (T-679), whose lost sessions a sweep ends.
    let keeper = crate::node_upgrade::channel_keeper(&channel, settings().resume_deadline);
    far::sweep(&keeper);
    // Each visitor's WebSocket is a link of the layer: a pipe (T-164), whose
    // target is reached once the operator's key is let in.
    let visit: Option<Visit> = (!targets.is_empty()).then(|| {
        let routes = crate::node::routes_of(&targets, grant, roost, Some(public));
        let first = crate::node_exit::first(&targets);
        let (host, port) = (first.host, first.port);
        let dial = move || {
            let host = host.clone();
            async move { reverse::tcp::dial_target(&host, port, DIAL_LIMIT, roost).await }
        };
        let open = move || {
            let (dial, channel, routes) = (dial.clone(), Some(channel.clone()), routes.clone());
            async move { crate::channel::piped_by(channel, routes, dial).await }
        };
        let keeper = keeper.clone();
        Arc::new(move |link: DuplexStream| -> Visiting {
            let (keeper, open) = (keeper.clone(), open.clone());
            Box::pin(async move { layer_far::serve(link, Role::NODE, settings(), &keeper, NODE_BUDGET, open).await })
        }) as Visit
    });
    let role_cfg = role.as_ref().map(|role| role.cfg.clone());
    let router = Arc::new(Router { role: role_cfg.clone(), alone: targets.is_empty(), visit });
    let proxy = ProxyChoice::FromEnvironment;
    let kept = Keep {
        service: service.clone(),
        api: api::tls(trust, proxy.clone()),
        connect: keep::tcp(proxy),
        asked: Some(name.clone()),
        serve: served(router),
        say: say.clone(),
    };
    crate::node_upgrade::lines(say.clone());
    let (stop, stopped) = watch::channel(false);
    // With the role, Ctrl-C alone: its tokens and pairs live in this
    // process, so it takes no upgrade (T-679), as behind the quick tunnel.
    let stopper = tokio::spawn(async move {
        match role_cfg.is_none() {
            true => crate::node_upgrade::stop().await,
            false => crate::node::stop_signal().await,
        }
        // A planned stop closes each socket of the role's reverse road with 1012 first (T-255).
        if let Some(cfg) = role_cfg {
            let _ = cfg.pairs.restart(crate::relay_serve::STOP_WAIT).await;
        }
        let _ = stop.send(true);
    });
    // The first tunnel before any line of serving: unasked, a node that
    // cannot reach the server ends soon, as it would with no road.
    let asking = keep::asked(&kept, stopped.clone());
    let first = match unasked {
        Some(_) => tokio::time::timeout(UNASKED_LIMIT, asking)
            .await
            .unwrap_or_else(|_| Err(format!("no tunnel within {} s", UNASKED_LIMIT.as_secs()))),
        None => asking.await,
    };
    let first = match first {
        Ok(Some(tunnel)) => tunnel,
        Ok(None) => {
            return crate::node_upgrade::or_finish(|| {
                let _ = writeln!(err, "podssh node: {label}: stopped");
                0
            })
            .await
        }
        Err(why) => {
            stopper.abort();
            return failed(format!("no localtunnel road through {service}: {why}")).report("node", err);
        }
    };
    let url = first.url();
    if let Some(why) = &unasked {
        let _ = writeln!(err, "podssh node: {label}: {why}; so the node serves the localtunnel road unasked, the last");
    }
    let _ = writeln!(err, "podssh node: {label}: {}", localtunnel::third_party_line(&service));
    let serving = match &target {
        Some(target) => format!("serving {target} at {url} over the localtunnel road alone until Ctrl-C"),
        None => format!("serving the relay alone at {url} over the localtunnel road until Ctrl-C"),
    };
    let by = match &door {
        Door::Allow(_) => String::new(),
        Door::Net(net) => format!("; with no --allow, the members of the net {net} are its door"),
    };
    let _ = writeln!(err, "podssh node: {label}: {serving}{by}");
    let _ = writeln!(err, "podssh node: {label}: {}", name_line(&first, &name, &label, &public.fingerprint()));
    if let Some(role) = &role {
        let _ = writeln!(err, "podssh node: {label}: {}", role.shown(&first.host));
    }
    if let Some(pair) = &pair_left {
        let words = format!("{pair} is not served beside the localtunnel road: run podssh node {label} TARGET for it");
        let _ = writeln!(err, "podssh node: {label}: {words}");
    }
    let _ = writeln!(err, "podssh node: {label}: key {public}");
    if let Door::Allow(allow) = &door {
        let _ = writeln!(err, "podssh node: {label}: {}", crate::channel::who_may(Some(allow.as_path())));
    }
    if let Some(admitted) = crate::net::admit::line(&public) {
        let _ = writeln!(err, "podssh node: {label}: {admitted}");
    }
    // The URL is the node's answer: the one line on stdout, the relay host
    // of `--relay-host` for a node with the role.
    podssh_ssh::out_line!("{url}");
    // Said first; then a detached node goes on (T-380).
    crate::detach::ready("node");
    let made = {
        let (say, first_url) = (say.clone(), url.clone());
        move |tunnel: &Tunnel| match tunnel.url() == first_url {
            true => say(format!("the tunnel at {first_url} again")),
            false => say(format!("a new tunnel at {}, in the place of {first_url}", tunnel.url())),
        }
    };
    let ended = keep::run(kept, first, made, stopped).await;
    stopper.abort();
    match ended {
        // An upgrade's handover ends this binary; else the stop's line.
        Ok(()) => {
            crate::node_upgrade::or_finish(|| {
                let _ = writeln!(err, "podssh node: {label}: stopped");
                0
            })
            .await
        }
        Err(why) => failed(format!("the localtunnel road ended: {why}")).report("node", err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_s_line_says_whether_the_server_gave_the_key_s_name() {
        let tunnel = |id: &str| Tunnel {
            id: id.into(),
            port: 1,
            connections: 1,
            host: format!("{id}.lt.test"),
            web_port: 443,
            ip: None,
        };
        let ours = name_line(&tunnel("podssh-00"), "podssh-00", "lab", "SHA256:abc");
        assert!(ours.contains("of the node's key") && ours.contains("--node-key SHA256:abc"), "{ours}");
        let theirs = name_line(&tunnel("heavy-puma-9"), "podssh-00", "lab", "SHA256:abc");
        assert!(theirs.contains("another's") && theirs.contains("heavy-puma-9"), "{theirs}");
    }
}
