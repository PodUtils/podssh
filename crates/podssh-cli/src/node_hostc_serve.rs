//! The serving of `podssh node --hostc` (T-742), apart from `node_hostc` for
//! the length of that file: TARGET probed first, when there is one; then the
//! tunnel asked for and kept by its socket (`podssh_relay::hostc::keep`),
//! whose streams come as visitors of plain HTTP/1.1; each is served as a
//! visitor of a tunnel of `ssh -R` (`node_ssh_http_serve::visitors_served`):
//! a WebSocket at `/` is a link of the resumable layer under the node's
//! keeper, so a session moves from one socket to the next; a path of the
//! relay role goes to the role, with `--relay`. Each name of the tunnel, the
//! first and each new one, is said, kept under NAME in the cache and put in
//! the node's record (T-445), as the name of a tunnel of `ssh -R` is: a
//! client takes it the same way.

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use podssh_relay::e2e::ends;
use podssh_relay::hostc;
use podssh_relay::hostc::api::{self, Failed, Tunnel};
use podssh_relay::hostc::keep::{self, Keep};
use podssh_relay::hostc::link::Beat;
use podssh_relay::pinggy::far;
use podssh_relay::pinggy::Say;
use podssh_relay::reverse;
use podssh_ws::ProxyChoice;
use tokio::sync::{mpsc, watch};

use crate::exitmap::Fault;
use crate::node_derp::Door;
use crate::node_hostc::Ready;
use crate::node_pinggy::UNASKED_LIMIT;
use crate::node_ssh_http_serve::{named, visitors_served, Behind};
use crate::node_sshj::settings;
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);
/// The visitors that wait for their first request: the server's own bound
/// of streams at once for a tunnel.
const WAITING: usize = hostc::MAX_STREAMS;

pub(crate) async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, targets, roost, key, door, service, trust, unasked, pair_left, relay, record } = ready;
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
    // Each failure to reach the service is the road's, so an unasked node
    // goes on to the next road (Q78); a 426 is one, with its own words.
    let failed = |message: String| Refusal { message, code: Fault::RelayUnreachable.code() };
    let identity = Arc::new(key.identity);
    let public = identity.public();
    let kept = Keep {
        service: service.clone(),
        dial: api::tls(trust, ProxyChoice::FromEnvironment),
        say: say.clone(),
        beat: Beat::default(),
    };
    // The first tunnel before any line of serving: unasked, a node that
    // cannot reach the service ends soon, as it would with no road.
    let asking = keep::first(&kept);
    let first = match unasked {
        Some(_) => tokio::time::timeout(UNASKED_LIMIT, asking)
            .await
            .unwrap_or_else(|_| Err(Failed::ForNow(format!("no tunnel within {} s", UNASKED_LIMIT.as_secs())))),
        None => asking.await,
    };
    let first = match first {
        Ok(tunnel) => tunnel,
        Err(Failed::Version(why)) => return failed(why).report("node", err),
        Err(why) => return failed(format!("no hostc road through {service}: {why}")).report("node", err),
    };
    let url = first.url();
    let mut line = |words: String| {
        let _ = writeln!(err, "podssh node: {label}: {words}");
    };
    if let Some(why) = &unasked {
        line(format!("{why}; so the node serves the hostc road unasked, before localtunnel's"));
    }
    line(hostc::third_party_line(&service));
    let by = match &door {
        Door::Allow(_) => String::new(),
        Door::Net(net) => format!("; with no --allow, the members of the net {net} are its door"),
    };
    match &target {
        Some(target) => line(format!("serving {target} at {url} over the hostc road alone until Ctrl-C{by}")),
        None => line(format!("serving the relay alone at {url} over the hostc road until Ctrl-C{by}")),
    }
    if let Some(pair) = &pair_left {
        line(format!("{pair} is not served beside the hostc road: podssh node {label} TARGET serves the pair's road"));
    }
    line(format!("key {public}"));
    line(format!(
        "each visitor's TLS ends at hostc's edge, which sends its request down the tunnel's socket: {service} sees \
         the name, the times and the sizes, and the end-to-end channel keeps the bytes"
    ));
    if let Door::Allow(allow) = &door {
        line(crate::channel::who_may(Some(allow.as_path())));
    }
    if let Some(admitted) = crate::net::admit::line(&public) {
        line(admitted);
    }
    // Its record names the tunnel, for as long as the node runs (T-445).
    let (_record, tell) =
        crate::node_record::alone(record, &identity, &crate::pairs::trust(None), say.clone(), &mut line);
    let relay = relay.map(Arc::new);
    if let Some(relay) = &relay {
        // Its list of keys at a URL, fetched again each TTL (T-646).
        relay.keep_lists(&label);
        line(relay.shown(&first.host));
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
    let dial = move || {
        let host = host.clone();
        async move { reverse::tcp::dial_target(&host, port, DIAL_LIMIT, roost).await }
    };
    // Each session is a pipe (T-164): the target is reached once the
    // operator's key is let in.
    let open = {
        let (channel, routes) = (Some(channel.clone()), routes.clone());
        move || {
            let (dial, channel, routes) = (dial.clone(), channel.clone(), routes.clone());
            async move { crate::channel::piped_by(channel, routes, dial).await }
        }
    };
    // The upgrade's keeper (T-679), whose lost sessions a sweep ends.
    let keeper = crate::node_upgrade::channel_keeper(&channel, settings().resume_deadline);
    far::sweep(&keeper);
    crate::node_upgrade::lines(say.clone());
    // The URL is the node's answer: the one line on stdout, the relay host
    // of `--relay-host` for a node with the role.
    podssh_ssh::out_line!("{url}");
    // Said first; then a detached node goes on (T-380).
    crate::detach::ready("node");
    let behind =
        Behind { role: relay.clone(), name: Arc::new(Mutex::new(first.host.clone())), alone: targets.is_empty() };
    named(&first.host, &label, &tell, &say);
    // The streams of each socket of the tunnel, served one by one.
    let (queue, visitors) = mpsc::channel(WAITING);
    let serving = tokio::spawn(visitors_served(visitors, behind.clone(), open, keeper, say.clone()));
    let (stop, stopped) = watch::channel(false);
    // With the role, Ctrl-C alone: its tokens and pairs live in this
    // process, so it takes no upgrade (T-679), as behind the quick tunnel.
    let role_cfg = relay.as_ref().map(|relay| relay.cfg.clone());
    let stopper = tokio::spawn(async move {
        match &role_cfg {
            None => crate::node_upgrade::stop().await,
            Some(cfg) => {
                crate::node::stop_signal().await;
                // A planned stop closes each socket of the role's reverse road with 1012 first (T-255).
                let _ = cfg.pairs.restart(crate::relay_serve::STOP_WAIT).await;
            }
        }
        let _ = stop.send(true);
    });
    // A new tunnel, where the server forgot the last: its name in the
    // place of the last, for the role's mint and for clients.
    let made = |tunnel: &Tunnel| {
        say(format!("a new tunnel at {}, in the place of the last; its name is new", tunnel.url()));
        *behind.name.lock().unwrap_or_else(PoisonError::into_inner) = tunnel.host.clone();
        named(&tunnel.host, &label, &tell, &say);
    };
    let ended = keep::run(kept, first, queue, made, stopped).await;
    stopper.abort();
    serving.abort();
    match ended {
        // An upgrade's handover ends this binary; else the stop's line.
        Ok(()) => {
            crate::node_upgrade::or_finish(|| {
                let _ = writeln!(err, "podssh node: {label}: stopped");
                0
            })
            .await
        }
        Err(why) => failed(format!("the hostc road ended: {why}")).report("node", err),
    }
}
