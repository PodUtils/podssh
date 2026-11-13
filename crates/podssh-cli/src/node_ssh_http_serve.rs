//! The serving of `podssh node --localhost-run` (T-565), and of the other
//! words of its module (`--sandhole`, `--srv-us`), apart from
//! `node_ssh_http` for the length of that file, in the shape of the ssh-j
//! road's (`node_sshj_serve`): TARGET probed first, when there is one; then
//! one tunnel at a time, opened again after its end (a lost connection, the
//! service's end of a free tunnel) with a wait that doubles from 1 s to
//! 60 s; each visitor's first request served (`podssh_relay::ssh_http::
//! visit`): a WebSocket at `/` is a link of the resumable layer, served under
//! the node's keeper, so a session moves from one tunnel to the next; a path
//! of the relay role goes to the role, with `--relay`. Each name of the
//! tunnel, the first and each new one, is said, kept under NAME in the cache
//! and put in the node's record (T-445): a free name changes after a few
//! hours, so the client finds the new one there.

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use podssh_relay::e2e::ends;
use podssh_relay::pinggy::far::{self, Visitor};
use podssh_relay::pinggy::trace::{Counts, Traced};
use podssh_relay::pinggy::Say;
use podssh_relay::reverse::{self, layered::NODE_BUDGET};
use podssh_relay::session::far as layer_far;
use podssh_relay::session::keep::Keeper;
use podssh_relay::session::record::Role;
use podssh_relay::ssh_http;
use podssh_relay::ssh_http::visit::{self, Visited};
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, watch};

use crate::exitmap::Fault;
use crate::node_derp::Door;
use crate::node_pinggy::UNASKED_LIMIT;
use crate::node_pinggy_serve::again_wait;
use crate::node_quick_relay::Role as RelayRole;
use crate::node_ssh_http::Ready;
use crate::node_sshj::settings;
use crate::relay_settings::Refusal;
use crate::ssh_http_leg::{self, Opened};

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);
/// The visitors that wait for their first request, for each tunnel.
const WAITING: usize = 64;

/// The relay role behind the tunnel, and the tunnel's name now, whose
/// origin takes the role's paths (T-428); `alone` with no TARGET. The hostc
/// road serves its streams so too (T-742, `node_hostc_serve`).
#[derive(Clone)]
pub(crate) struct Behind {
    pub(crate) role: Option<Arc<RelayRole>>,
    pub(crate) name: Arc<Mutex<String>>,
    pub(crate) alone: bool,
}

impl Behind {
    fn origin(&self) -> Option<Arc<dyn podssh_relay::quick::origin::Origin>> {
        let name = self.name.lock().unwrap_or_else(PoisonError::into_inner).clone();
        self.role.as_ref().map(|role| role.origin(&name, self.alone))
    }
}

/// Serve each visitor of `visitors` until its sender ends (the tunnel
/// ended): its first request, then, for a WebSocket, the layer's far end
/// with `keeper`, whose sessions outlive this tunnel.
pub(crate) async fn visitors_served<A, O, F>(
    mut visitors: mpsc::Receiver<Visitor>,
    behind: Behind,
    open: O,
    keeper: Arc<Keeper<A>>,
    say: Say,
) where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: std::future::Future<Output = Result<A, String>> + Send + 'static,
{
    while let Some(Visitor { stream, peer }) = visitors.recv().await {
        let (origin, keeper, open, say) = (behind.origin(), keeper.clone(), open.clone(), say.clone());
        tokio::spawn(async move {
            match visit::serve(stream, origin).await {
                Visited::Layer(link) => {
                    // Each visitor's bytes, for its last line, as the Pinggy road says them.
                    let counts = Counts::new();
                    let link = Traced::new(link, counts.clone());
                    layer_far::serve(link, Role::NODE, settings(), &keeper, NODE_BUDGET, open).await;
                    let why = counts.end().unwrap_or_else(|| "the layer ended its link".into());
                    say(format!("a visitor from {peer} ended ({why}): {}", counts.line()));
                }
                // The role says its own lines of each request.
                Visited::Role(_) => {}
                Visited::Refused(status) => say(format!("a visitor from {peer} was answered {status}")),
                Visited::Gone(why) => say(format!("a visitor from {peer} ended: {why}")),
            }
        });
    }
}

/// The node's lines of a new name: said, kept under the label in the cache
/// for a client of this host, and put in the record in the place of the
/// last.
pub(crate) fn named(name: &str, label: &str, tell: &crate::node_record::Tell, say: &Say) {
    say(format!("tunnel https://{name} (podssh ssh node://{label} --tunnel-url https://{name})"));
    let file = crate::node_ssh_http::name_file(label);
    match podssh_relay::cache::store_file(&file, format!("https://{name}\n").as_bytes()) {
        Ok(path) => say(format!("the name is kept in {}", path.display())),
        Err(why) => say(format!("the name could not be kept: {why}")),
    }
    tell.tunnel(name);
}

pub(crate) async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, targets, roost, key, door, service, unasked, pair_left, relay, record } = ready;
    let road = service.word.name;
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
    let proxy = ProxyChoice::FromEnvironment;
    // The first tunnel before any line of serving: unasked, a node that
    // cannot reach the service ends soon, as it would with no road.
    let (queue, first_rx) = mpsc::channel(WAITING);
    let opening = ssh_http_leg::open(&service, &proxy, queue, &say, &identity);
    let opened = match unasked {
        Some(_) => tokio::time::timeout(UNASKED_LIMIT, opening)
            .await
            .unwrap_or_else(|_| Err(format!("no tunnel within {} s", UNASKED_LIMIT.as_secs()))),
        None => opening.await,
    };
    let first = match opened {
        Ok(opened) => opened,
        Err(why) => return failed(format!("no {road} road through {service}: {why}")).report("node", err),
    };
    let mut line = |words: String| {
        let _ = writeln!(err, "podssh node: {label}: {words}");
    };
    if let Some(why) = &unasked {
        line(format!("{why}; so the node serves the {road} road unasked, the last"));
    }
    line(ssh_http::third_party_line(&service));
    let by = match &door {
        Door::Allow(_) => String::new(),
        Door::Net(net) => format!("; with no --allow, the members of the net {net} are its door"),
    };
    match &target {
        Some(target) => line(format!("serving {target} over the {road} road alone until Ctrl-C{by}")),
        None => line(format!("serving the relay alone over the {road} road until Ctrl-C{by}")),
    }
    if let Some(pair) = &pair_left {
        line(format!("{pair} is not served beside the {road} road: podssh node {label} TARGET serves the pair's road"));
    }
    line(format!("key {public}"));
    let pinned = if first.tunnel.host_key.1 { "pinned by pod-services" } else { "unpinned" };
    line(format!("{service}'s host key {} ({pinned}), over {}", first.tunnel.host_key.0, first.tunnel.way));
    line(format!(
        "each visitor's TLS ends at {service}, which sends its HTTP down the tunnel: {service} sees the name, the \
         times and the sizes, and the end-to-end channel keeps the bytes"
    ));
    if let Door::Allow(allow) = &door {
        line(crate::channel::who_may(Some(allow.as_path())));
    }
    if let Some(admitted) = crate::net::admit::line(&public) {
        line(admitted);
    }
    // Its record names the tunnel, for as long as the node runs (T-445).
    let trust = crate::pairs::trust(None);
    let (_record, tell) = crate::node_record::alone(record, &identity, &trust, say.clone(), &mut line);
    let relay = relay.map(Arc::new);
    if let Some(relay) = &relay {
        relay.keep_lists(&label);
        line(relay.shown(&first.tunnel.name));
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
    // The upgrade's keeper (T-679), whose lost sessions a sweep ends.
    let keeper = crate::node_upgrade::channel_keeper(&channel, settings().resume_deadline);
    far::sweep(&keeper);
    crate::node_upgrade::lines(say.clone());
    // The key of a leg that logs in by it (srv.us, T-566), for each tunnel.
    let leg_key = identity.clone();
    let name = Arc::new(Mutex::new(first.tunnel.name.clone()));
    let behind = Behind { role: relay.clone(), name, alone: targets.is_empty() };
    let (stop, stopped) = watch::channel(false);
    let until_stopped = |mut stopped: watch::Receiver<bool>| async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };
    // One tunnel at a time, each opened again after its end; the first is open.
    let tunnels = async {
        let (mut held, mut visitors_rx, mut attempt) = (Some(first), Some(first_rx), 0u32);
        loop {
            if let (Some(Opened { tunnel, mut names }), Some(rx)) = (held.take(), visitors_rx.take()) {
                attempt = 0;
                let mut now = tunnel.name.clone();
                *behind.name.lock().unwrap_or_else(PoisonError::into_inner) = now.clone();
                named(&now, &label, &tell, &say);
                let serving = visitors_served(rx, behind.clone(), open.clone(), keeper.clone(), say.clone());
                tokio::pin!(serving);
                loop {
                    tokio::select! {
                        () = &mut serving => break,
                        () = tunnel.ended() => break,
                        renamed = ssh_http_leg::renamed(&mut names, &now) => {
                            say(format!("{service} gave the tunnel a new name, {renamed}, in the place of {now}"));
                            *behind.name.lock().unwrap_or_else(PoisonError::into_inner) = renamed.clone();
                            named(&renamed, &label, &tell, &say);
                            now = renamed;
                        }
                        () = until_stopped(stopped.clone()) => {
                            tunnel.close().await;
                            return;
                        }
                    }
                }
                say(format!("the tunnel {now} at {service} ended; a new one, whose name may be another"));
            }
            let wait = again_wait(attempt);
            attempt = attempt.saturating_add(1);
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = until_stopped(stopped.clone()) => return,
            }
            let (queue, rx) = mpsc::channel(WAITING);
            let opened = tokio::select! {
                opened = ssh_http_leg::open(&service, &proxy, queue, &say, &leg_key) => opened,
                () = until_stopped(stopped.clone()) => return,
            };
            match opened {
                Ok(opened) => (held, visitors_rx) = (Some(opened), Some(rx)),
                Err(why) => say(format!("no tunnel at {service}: {why}; again in a while")),
            }
        }
    };
    tokio::pin!(tunnels);
    // With the role behind the tunnel, Ctrl-C alone: the role's tokens and
    // pairs live in this process, so it takes no upgrade (T-679), as behind
    // a quick tunnel.
    let role_cfg = relay.as_ref().map(|relay| relay.cfg.clone());
    let stopping = async {
        match &role_cfg {
            None => crate::node_upgrade::stop().await,
            Some(cfg) => {
                crate::node::stop_signal().await;
                let _ = cfg.pairs.restart(crate::relay_serve::STOP_WAIT).await;
            }
        }
    };
    tokio::select! {
        () = &mut tunnels => {}
        () = stopping => {
            let _ = stop.send(true);
            tunnels.await;
        }
    }
    // An upgrade's handover ends this binary; its successor opens a tunnel
    // of its own, whose name the record and the cache then give. Else the
    // stop's line.
    crate::node_upgrade::or_finish(|| {
        let _ = writeln!(err, "podssh node: {label}: stopped");
        0
    })
    .await
}
