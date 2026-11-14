//! The serving of `podssh node --gsr` (T-707), apart from `node_gsr` for
//! the length of that file, in a build with the feature `gsr`: TARGET
//! probed first, then the first registration at the relay of gsocket, under
//! the address of the secret, before any line of serving; then one
//! registration at a time, made again at once when a client paired with it
//! or the wait ended, and after a pause that grows to 30 s when the relay
//! or the way to it failed. Each client is a visitor of the resumable
//! layer's far end under the node's keeper (`podssh_relay::pinggy::far`),
//! so a session moves from one pairing to the next.

use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use podssh_gsr::{Dial, Failure, Role, Settings, Stream};
use podssh_relay::e2e::ends;
use podssh_relay::pinggy::far::{self, Visitor};
use podssh_relay::pinggy::Say;
use podssh_relay::reverse::{self, layered::NODE_BUDGET};
use podssh_ws::ProxyChoice;
use tokio::sync::mpsc;

use crate::exitmap::Fault;
use crate::gsr::Secret;
use crate::node_derp::Door;
use crate::node_gsr::{settings, Ready};
use crate::relay_settings::Refusal;

/// Bound on each dial of TARGET, under the node's 10 s to open a session.
const DIAL_LIMIT: Duration = Duration::from_secs(8);
/// How long one registration waits for a client before it is made again;
/// the pings keep it alive at the relay meanwhile.
const WAIT: Duration = Duration::from_secs(3600);
/// A first registration that failed in this time says why, and ends the
/// node (69); one that still waits is taken as held.
const FIRST: Duration = Duration::from_secs(10);
/// The pause after a failed registration, doubled up to the longest.
const PAUSE: Duration = Duration::from_secs(1);
const PAUSE_MOST: Duration = Duration::from_secs(30);

/// One registration's wait for a client.
type Opening = Pin<Box<dyn Future<Output = Result<Stream, Failure>> + Send>>;

/// The maker of each registration.
type Opener = Arc<dyn Fn() -> Opening + Send + Sync>;

fn opener(dial: Arc<dyn Dial>, gsr: Settings, secret: Secret) -> Opener {
    let (gsr, secret) = (Arc::new(gsr), Arc::new(secret));
    Arc::new(move || {
        let (dial, gsr, secret) = (dial.clone(), gsr.clone(), secret.clone());
        Box::pin(async move { podssh_gsr::open(&*dial, &gsr, Role::Listen, secret.expose(), WAIT).await }) as Opening
    })
}

/// The registrations, one at a time, from `first` on: each client goes to
/// `queue`, until the node ends it.
async fn registrations(first: Opening, open: Opener, queue: mpsc::Sender<Visitor>, host: String, say: Say) {
    let (mut pending, mut pause) = (Some(first), PAUSE);
    loop {
        let opening = pending.take().unwrap_or_else(|| open());
        match opening.await {
            Ok(stream) => {
                pause = PAUSE;
                let peer = format!("the GSRN relay {host}");
                if queue.send(Visitor { stream: Box::new(stream), peer }).await.is_err() {
                    return;
                }
            }
            // The wait ended with no client: register again at once.
            Err(failure) if podssh_gsr::no_peer_yet(&failure) => {}
            Err(failure) => {
                say(format!("the GSRN relay {host}: {}; registering again in {} s", failure.chain(), pause.as_secs()));
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(PAUSE_MOST);
            }
        }
    }
}

pub(crate) async fn serve(ready: Ready, err: &mut dyn Write) -> i32 {
    let Ready { label, targets, roost, key, door, secret, pair_left } = ready;
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
    // `prepare` read the settings and checked the secret against them.
    let gsr = match podssh_gsr::settings() {
        Ok(gsr) => gsr,
        Err(why) => return Refusal::config(format!("--gsr: {why}")).report("node", err),
    };
    let host = podssh_gsr::host_of(&gsr, secret.expose());
    let open = opener(podssh_gsr::dialer(&ProxyChoice::FromEnvironment), gsr, secret);
    // The first registration before any line of serving: a relay that the
    // node cannot reach ends it soon, as it would with no road.
    let mut first = open();
    // Bound apart from the match, whose arms take `first` back.
    let early = tokio::time::timeout(FIRST, &mut first).await;
    let first = match early {
        Err(_) => first,
        Ok(Ok(stream)) => Box::pin(std::future::ready(Ok(stream))) as Opening,
        Ok(Err(failure)) if podssh_gsr::no_peer_yet(&failure) => open(),
        Ok(Err(failure)) => {
            return failed(format!("no GSRN road through {host}: {}", failure.chain())).report("node", err);
        }
    };
    let identity = Arc::new(key.identity);
    let public = identity.public();
    let mut line = |words: String| {
        let _ = writeln!(err, "podssh node: {label}: {words}");
    };
    line(format!(
        "the GSRN relay {host} of {} carries the sessions of this road: a third party that nobody vouches for, \
         which sees their sizes and times; TLS with SRP of the shared secret and the end-to-end channel keep \
         their bytes",
        podssh_gsr::party()
    ));
    let by = match &door {
        Door::Allow(_) => String::new(),
        Door::Net(net) => format!("; with no --allow, the members of the net {net} are its door"),
    };
    line(format!("serving {target} over the GSRN road alone until Ctrl-C{by}"));
    if let Some(pair) = &pair_left {
        line(format!("{pair} is not served beside the GSRN road: run podssh node {label} TARGET for the pair's road"));
    }
    line(format!("key {public}"));
    let fingerprint = public.fingerprint();
    line(format!(
        "registered at {host} (podssh ssh node://{label} --node-key {fingerprint} --gsr-secret-file FILE, with \
         the same secret)"
    ));
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
    let (target_host, port) = (first_target.host, first_target.port);
    let target = move || {
        let host = target_host.clone();
        async move { reverse::tcp::dial_target(&host, port, DIAL_LIMIT, roost).await }
    };
    // Each session is a pipe (T-164): the target is reached once the
    // operator's key is let in.
    let open_session = {
        let (channel, routes) = (Some(channel.clone()), routes.clone());
        move || {
            let (target, channel, routes) = (target.clone(), channel.clone(), routes.clone());
            async move { crate::channel::piped_by(channel, routes, target).await }
        }
    };
    // The upgrade's keeper (T-679), whose lost sessions the sweep ends.
    let keeper = crate::node_upgrade::channel_keeper(&channel, settings().resume_deadline);
    crate::node_upgrade::lines(say.clone());
    far::sweep(&keeper);
    let (queue, visitors) = mpsc::channel::<Visitor>(16);
    let registering = tokio::spawn(registrations(first, open, queue, host, say.clone()));
    let serving = far::serve(visitors, None, settings(), NODE_BUDGET, open_session, keeper, say);
    // Until Ctrl-C, or an upgrade (T-679); a new binary registers anew.
    tokio::select! {
        () = serving => {}
        () = crate::node_upgrade::stop() => {}
    }
    registering.abort();
    crate::node_upgrade::or_finish(|| {
        let _ = writeln!(err, "podssh node: {label}: stopped");
        0
    })
    .await
}
