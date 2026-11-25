//! A client's `-R` under `podssh serve` (T-123, GitHub #18): each forward is
//! a pair made at the relay's control host, whose node runs in serve's
//! process; each session that an operator opens on it opens a
//! `forwarded-tcpip` channel to the client, through the server's
//! [`Opener`]. serve binds nothing for it (rule 2 of `AGENTS.md`): the
//! pair's requests and its node's socket go out, through `HTTPS_PROXY`
//! where it is set, as `podssh relay pair` and `podssh node` would make
//! them by hand; a connection holds 8 forwards at most.
//!
//! The pair is kept in the cache under a label of its own
//! (`rPORT-XXXXXX`), as `podssh relay pair` keeps one, so that `podssh
//! operator LABEL` on this host reaches the forward; no line holds a token.
//! Each session runs the resumable layer and the end-to-end channel, with a
//! key for this forward alone, which an operator pins under the label at
//! first sight. The forward's end (a cancel, the connection's end, serve's
//! stop) stops the node, then the pair by `POST /v1/stop`, and forgets the
//! stored copy; a relay that did not answer leaves the copy, and the line
//! names `podssh relay revoke LABEL`.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use podssh_relay::identity::file;
use podssh_relay::pair::{self, Pair, PairContext, PairError};
use podssh_relay::relay::{self, Relay};
use podssh_relay::reverse::{self, E2e, Exit, Handler, Layered, NodeConfig, Opening, SessionId, Wire};
use podssh_relay::session::keep::Keeper;
use podssh_ssh::russh::server::Msg;
use podssh_ssh::russh::ChannelStream;
use podssh_ssh::server::remote_forward::{Asked, Opener, Publish, Published, Publisher, Publishing, Stop};
use podssh_ws::Trust;
use tokio::io::DuplexStream;
use tokio::sync::{oneshot, watch};

/// Bound on a publish: the pair, then its node online. The client's whole
/// connection waits on it, as russh reads its next message after.
const PUBLISH_LIMIT: Duration = Duration::from_secs(20);
/// Bound on the pair's stop at the relay.
pub(crate) const STOP_LIMIT: Duration = Duration::from_secs(10);
/// Bound on the open of the client's channel: under the node's 10 s.
const OPEN_LIMIT: Duration = Duration::from_secs(8);
/// The origin that each channel names: serve's own host, as the operator's
/// address is the relay's to know.
const ORIGIN: &str = "127.0.0.1";
/// The first port that a request of port 0 may be told: the dynamic range,
/// as no port is bound.
const ANY_FROM: u32 = 49_152;
/// How many labels are drawn before a publish gives up on a free one.
const DRAWS: usize = 4;

/// The publisher of serve's settings.
pub(crate) fn publisher() -> Publisher {
    Publisher(Arc::new(Relayed))
}

/// Publishes each forward as a pair of the relay.
struct Relayed;

impl Publish for Relayed {
    fn publish(&self, asked: Asked, opener: Opener) -> Publishing {
        Box::pin(publish(asked, opener))
    }
}

/// The relay's control host and the trust store, read at the first forward:
/// a serve that is asked none reads neither.
struct Way {
    control: Relay,
    trust: Trust,
}

static WAY: OnceLock<Result<Way, String>> = OnceLock::new();

fn way() -> Result<&'static Way, String> {
    let found = WAY.get_or_init(|| {
        // The pins of PODSSH_RELAY_ADDR and the settings file, as a node's.
        crate::pins::apply(None).map_err(|r| r.message)?;
        let relays =
            crate::relay_settings::relays(None, std::env::var(relay::RELAY_ENV).ok()).map_err(|r| r.message)?;
        Ok(Way { control: relays.primary().clone(), trust: crate::pairs::trust(None) })
    });
    found.as_ref().map_err(Clone::clone)
}

async fn publish(asked: Asked, opener: Opener) -> Result<Published, String> {
    crate::pairs::online().map_err(|r| r.message)?;
    let way = way()?;
    let port = if asked.port == 0 { ANY_FROM + u32::from(rand::random::<u16>() % 16_384) } else { asked.port };
    let label = free_label(port)?;
    let (ready, told) = oneshot::channel();
    let (stop, stopping) = oneshot::channel::<()>();
    let (control, trust) = (way.control.clone(), way.trust.clone());
    let forward = Forward { label: label.clone(), asked, port, opener, control, trust };
    tokio::spawn(forward.run(ready, stopping, Live::enter()));
    // Each early return drops `stop`: the task then stops what it made.
    match tokio::time::timeout(PUBLISH_LIMIT, told).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(why))) => return Err(why),
        Ok(Err(_)) => return Err("the forward's node ended before the relay took it".into()),
        Err(_) => {
            return Err(format!("the relay did not take the forward's node within {} s", PUBLISH_LIMIT.as_secs()))
        }
    }
    let reach = format!("podssh operator {label} reaches it on serve's host, which keeps its pair");
    let stop = Stop::new(move || {
        let _ = stop.send(());
    });
    Ok(Published { name: label, port, reach: Some(reach), stop })
}

/// A label that no stored pair holds, for the forward of `port`.
fn free_label(port: u32) -> Result<String, String> {
    for _ in 0..DRAWS {
        let label = format!("r{port}-{:06x}", rand::random::<u32>() & 0x00ff_ffff);
        if matches!(pair::load(&label), Ok(None)) {
            return Ok(label);
        }
    }
    Err("no free label for the forward's pair in the cache".into())
}

/// One forward's pair and node, run on a task of its own.
struct Forward {
    label: String,
    asked: Asked,
    /// The port that the client is told: the asked one, or one chosen.
    port: u32,
    opener: Opener,
    control: Relay,
    trust: Trust,
}

impl Forward {
    /// Make the pair, keep it, run its node until the forward stops, then
    /// stop the pair. `ready` hears the node online, or why not.
    async fn run(self, ready: oneshot::Sender<Result<(), String>>, stop: oneshot::Receiver<()>, _live: Live) {
        let Forward { label, asked, port, opener, control, trust } = self;
        let context = podssh_relay::context::process();
        let ctx = crate::pairs::context(&control, &trust, &context);
        let mut stop = Box::pin(stopped(stop));
        let made = tokio::select! {
            made = pair::create(&ctx) => made,
            () = &mut stop => return,
        };
        let made = match made {
            Ok(made) => made,
            Err(e) => {
                let _ = ready.send(Err(format!("the relay made no pair: {}", crate::pairs::refusal(&e).message)));
                return;
            }
        };
        if let Err(e) = pair::store(&label, &made) {
            let _ = ready.send(Err(format!("the forward's pair could not be kept: {e}")));
            end(&ctx, &made, &label).await;
            return;
        }
        // A key for this forward alone: the operator pins it under the label.
        let key = match crate::channel::load_node_key(&file::Place::Ephemeral) {
            Ok(key) => key,
            Err(refusal) => {
                let _ = ready.send(Err(refusal.message));
                end(&ctx, &made, &label).await;
                return;
            }
        };
        let me = key.identity.public();
        let shown = format!("-R {}:{port} of key {}", asked.address, asked.who);
        podssh_ssh::err_line!(
            "podssh serve: {label}: {shown} is the pair {} at {}, key {me} (this forward alone)",
            made.name,
            control.host
        );
        // Whoever holds the pair's connect token reaches the client's
        // service, as with `podssh node` and no --allow: the token is in
        // this user's cache alone.
        let node = crate::channel::node_end(&label, key.identity, crate::channel::admit_of(None));
        let settings = crate::layered::settings();
        let keeper: Arc<Keeper<DuplexStream>> =
            Arc::new(Keeper::new(settings.resume_deadline).with_tell(podssh_relay::session::budget::told()));
        let budget = reverse::layered::NODE_BUDGET;
        let handler = Arc::new(Layered::with_keeper(E2e::new(ToClient { opener }, node), settings, budget, keeper));
        let ready = Mutex::new(Some(ready));
        let say = |line: String| {
            // The relay takes the pair's sessions from this line on.
            if line.starts_with("online") {
                if let Some(ready) = ready.lock().ok().and_then(|mut r| r.take()) {
                    let _ = ready.send(Ok(()));
                }
            }
            podssh_ssh::err_line!("podssh serve: {label}: {line}");
        };
        let mut config = NodeConfig {
            pair: made,
            label: Some(label.clone()),
            trust: &trust,
            ctx: &context,
            timeout: crate::pairs::REQUEST_LIMIT,
            settings: reverse::Settings { rejoin: settings.resume_deadline, ..reverse::settings() },
            repair: None,
            wire: Wire::Tls,
            say: Some(&say),
        };
        let exit = reverse::run(&mut config, handler, &mut stop).await;
        let why = ended(&exit);
        match ready.lock().ok().and_then(|mut r| r.take()) {
            Some(ready) => {
                let _ = ready.send(Err(why.unwrap_or_else(|| "the forward stopped".into())));
            }
            None => {
                if let Some(why) = why {
                    podssh_ssh::err_line!("podssh serve: {label}: {shown} reaches nothing now: {why}");
                }
            }
        }
        end(&ctx, &config.pair, &label).await;
    }
}

/// Why a forward's node ended on its own, in words of serve's log; None
/// for its stop.
fn ended(exit: &Exit) -> Option<String> {
    let again = "the client's next -R makes a new pair";
    Some(match exit {
        Exit::Stopped => return None,
        Exit::NameInUse => format!("another node took the pair's name (409); {again}"),
        Exit::PairStopped => format!("the pair was stopped on the relay; {again}"),
        Exit::PairExpired => format!("the pair expired (72 h at most); {again}"),
        Exit::Forbidden => format!("the relay refused the pair (403); {again}"),
        Exit::Unusable(why) => why.clone(),
    })
}

/// Stop the pair at the relay and forget its stored copy. A relay that did
/// not answer has not ended it: the copy stays, as its stop token is the
/// only way to end the pair before it expires.
async fn end(ctx: &PairContext<'_>, made: &Pair, label: &str) {
    let stopped = tokio::time::timeout(STOP_LIMIT, pair::stop(ctx, made)).await;
    let answered = !matches!(stopped, Err(_) | Ok(Err(PairError::Connect(_))));
    if !answered {
        podssh_ssh::err_line!(
            "podssh serve: {label}: the relay did not answer the pair's stop; `podssh relay revoke {label}` stops it"
        );
        return;
    }
    // The relay ends its tokens whatever it answered.
    if matches!(pair::load(label), Ok(Some(kept)) if kept.name == made.name) {
        let _ = pair::remove(label);
    }
}

/// Each session of the forward: a channel to the client, toward the
/// address and port of its `-R`.
struct ToClient {
    opener: Opener,
}

impl Handler for ToClient {
    type Stream = ChannelStream<Msg>;

    fn open(&self, _id: SessionId) -> Opening<ChannelStream<Msg>> {
        let opener = self.opener.clone();
        Box::pin(async move {
            let within = OPEN_LIMIT.as_secs();
            match tokio::time::timeout(OPEN_LIMIT, opener.open(ORIGIN, 0)).await {
                Ok(opened) => opened,
                Err(_) => Err(format!("the client did not open the forwarded channel within {within} s")),
            }
        })
    }
}

/// The forward tasks of this process that still run, and serve's end.
struct Tasks {
    live: watch::Sender<usize>,
    end: watch::Sender<bool>,
}

static TASKS: OnceLock<Tasks> = OnceLock::new();

fn tasks() -> &'static Tasks {
    TASKS.get_or_init(|| Tasks { live: watch::Sender::new(0), end: watch::Sender::new(false) })
}

/// One forward's task, counted while it runs.
struct Live;

impl Live {
    fn enter() -> Live {
        tasks().live.send_modify(|n| *n += 1);
        Live
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        tasks().live.send_modify(|n| *n = n.saturating_sub(1));
    }
}

/// Until the forward's [`Stop`] runs (or is dropped), or serve ends.
async fn stopped(stop: oneshot::Receiver<()>) {
    let mut end = tasks().end.subscribe();
    tokio::select! {
        _ = stop => {}
        _ = end.wait_for(|ended| *ended) => {}
    }
}

/// serve's end, before its runtime goes: each forward stops its node and
/// its pair, and this waits for them, a bounded time. Nothing to wait for
/// where no client asked a `-R`.
pub(crate) async fn end_all() {
    let tasks = tasks();
    tasks.end.send_replace(true);
    let mut live = tasks.live.subscribe();
    let _ = tokio::time::timeout(STOP_LIMIT + Duration::from_secs(2), live.wait_for(|n| *n == 0)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each way a forward's node ends on its own has its words, and the
    /// client's next -R as the remedy; a stop has none.
    #[test]
    fn a_node_that_ends_on_its_own_says_why() {
        assert_eq!(ended(&Exit::Stopped), None);
        for exit in [Exit::NameInUse, Exit::PairStopped, Exit::PairExpired, Exit::Forbidden] {
            let why = ended(&exit).unwrap_or_default();
            assert!(why.contains("next -R"), "{exit:?}: {why}");
        }
        assert_eq!(ended(&Exit::Unusable("the proxy refused".into())).as_deref(), Some("the proxy refused"));
    }

    /// A label is a name that the pair store takes, and names its port.
    #[test]
    fn a_label_names_its_port_and_the_store_takes_it() {
        let label = format!("r{}-{:06x}", 2201, 0x00ab_cdefu32);
        assert!(pair::file_name(&label).is_ok(), "{label}");
        assert!(label.starts_with("r2201-"));
    }

    /// serve's end with no forward waits for nothing.
    #[tokio::test]
    async fn the_end_with_no_forward_is_at_once() {
        let started = std::time::Instant::now();
        end_all().await;
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
