//! The serving of `podssh node --bore` (T-569), apart from `node_bore` for
//! the length of that file: TARGET probed first, then the first registration
//! at the server, at a port of the node's key, before any line of serving;
//! then `podssh_relay::bore::far`, which holds one registration at a time
//! and makes it again after its end (the server's restart, its 24 hours, a
//! lost connection), each visitor a link of the resumable layer under the
//! node's keeper, so a session moves from one registration to the next.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_relay::bore::{self, Node};
use podssh_relay::e2e::ends;
use podssh_relay::pinggy::Say;
use podssh_relay::reverse::{self, layered::NODE_BUDGET};
use podssh_ws::ProxyChoice;

use crate::exitmap::Fault;
use crate::node_bore::{settings, Ready};
use crate::node_derp::Door;
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);
/// The bound on a node's first registration when it serves the road unasked.
const UNASKED_LIMIT: Duration = Duration::from_secs(30);

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
    // The ports are the key's: a client that holds the key derives them too.
    let dial = bore::tcp(ProxyChoice::FromEnvironment);
    let node = Node::of_key(service.clone(), &public.fingerprint(), dial, say.clone());
    // The first registration before any line of serving: unasked, a node
    // that cannot reach the server ends soon, as it would with no road.
    let registering = node.register();
    let first = match unasked {
        Some(_) => tokio::time::timeout(UNASKED_LIMIT, registering)
            .await
            .unwrap_or_else(|_| Err(format!("no registration within {} s", UNASKED_LIMIT.as_secs()))),
        None => registering.await,
    };
    let first = match first {
        Ok(first) => first,
        Err(why) => return failed(format!("no bore road through {service}: {why}")).report("node", err),
    };
    let mut line = |words: String| {
        let _ = writeln!(err, "podssh node: {label}: {words}");
    };
    if let Some(why) = &unasked {
        line(format!("{why}; so the node serves the bore road unasked, the last"));
    }
    line(bore::third_party_line(&service));
    let by = match &door {
        Door::Allow(_) => String::new(),
        Door::Net(net) => format!("; with no --allow, the members of the net {net} are its door"),
    };
    line(format!("serving {target} over the bore road alone until Ctrl-C{by}"));
    if let Some(pair) = &pair_left {
        line(format!("{pair} is not served beside the bore road: run podssh node {label} TARGET for the pair's road"));
    }
    line(format!("key {public}"));
    let key_line = public.fingerprint();
    line(format!("{} (podssh ssh node://{label} --node-key {key_line})", node.line(&first)));
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
    // The upgrade's keeper (T-679), whose lost sessions the road's sweep ends.
    let keeper = crate::node_upgrade::channel_keeper(&channel, settings().resume_deadline);
    crate::node_upgrade::lines(say.clone());
    let serving = bore::far::serve_kept(node, Some(first), settings(), NODE_BUDGET, open, keeper);
    // Until Ctrl-C, or an upgrade (T-679): the registrations go on by
    // themselves, and end with the node; a new binary registers anew.
    tokio::select! {
        () = serving => {}
        () = crate::node_upgrade::stop() => {}
    }
    crate::node_upgrade::or_finish(|| {
        let _ = writeln!(err, "podssh node: {label}: stopped");
        0
    })
    .await
}
