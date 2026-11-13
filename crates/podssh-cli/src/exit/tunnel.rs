//! An exit behind a quick tunnel (`--exit cf://HOST`, T-459): the node of
//! `podssh node NAME --exit --quick-tunnel` serves each visitor's WebSocket
//! as a link of the resumable layer, with the end-to-end channel above it,
//! as `podssh ssh --exit cf://HOST` reaches it (`crate::ssh::cloudflare`).
//! `podssh exit`, `proxy --exit` and `pipe --exit` carry each session so
//! (`super::open`): the tunnel's WebSocket in place of a relay's legs, a new
//! one after each lost one, and the channel's word naming the target. No
//! relay is between the ends, so no pair, no expiry and no leg's close: the
//! layer and the channel judge the end.

use std::future::Future;

use podssh_relay::session::client::{self, Greeted};
use podssh_relay::session::resume::{self, Next, Note};
use podssh_relay::session::{Ask, Ended, OsEntropy};
use podssh_ws::cloudflare::Access;
use podssh_ws::Trust;
use tokio::io::DuplexStream;

use crate::exitmap::{sysexits, Fault};
use crate::layered::{self, Carried, Line};
use crate::relay_settings::Refusal;
use crate::ssh::cloudflare::{self, SCHEME};

/// The quick tunnel of an exit: its host, and how its edge lets a visitor
/// in.
pub struct Tunnel {
    pub host: String,
    access: Access,
    trust: Trust,
}

impl Tunnel {
    /// The tunnel of `--exit NAME` when NAME is a `cf://HOST`; none for each
    /// other exit. A flag of another road is refused (64), and a credential
    /// of Cloudflare Access that is not one (78), before anything connects.
    pub fn of(
        name: &str,
        pair_file: Option<&str>,
        carrier: Option<&str>,
        ca_file: Option<&str>,
    ) -> Result<Option<Tunnel>, Refusal> {
        let Some(host) = host_of(name, pair_file, carrier)? else { return Ok(None) };
        // A quick tunnel has no Access; a named tunnel of the user's may.
        let access = cloudflare::access_from(&|var| std::env::var(var).ok()).map_err(Refusal::config)?;
        Ok(Some(Tunnel { host, access, trust: crate::pairs::trust(ca_file) }))
    }
}

/// The host of `--exit cf://HOST`, checked with the flags of the exit beside
/// it, in the words of `podssh ssh --exit cf://HOST`; none for another name.
pub fn host_of(name: &str, pair_file: Option<&str>, carrier: Option<&str>) -> Result<Option<String>, Refusal> {
    let host = match cloudflare::destination(name) {
        Ok(None) => return Ok(None),
        Ok(Some((None, host))) => host,
        Ok(Some((Some(_), _))) => return Err(Refusal::usage(format!("--exit {name}: an exit takes no user name"))),
        Err(why) => return Err(Refusal::usage(format!("--exit {why}"))),
    };
    let why = if carrier.is_some() {
        Some("--carrier is another road: the quick tunnel's name is the exit's one road")
    } else if pair_file.is_some() {
        Some("--pair-file names a pair's road: a quick tunnel's node has no pair")
    } else {
        None
    };
    match why {
        Some(why) => Err(Refusal::usage(format!("--exit {name}: {why}"))),
        None => Ok(Some(host)),
    }
}

/// Carry `app` to the exit behind `tunnel`, with `channel` above the layer:
/// how the session ended; or why none began, the edge's refusal or a far
/// end that is no podssh node. `pin_say` gets the line of the node's key
/// pinned at its first sight.
pub async fn carry<A: crate::channel::Bytes + 'static>(
    tunnel: &Tunnel,
    app: A,
    channel: Option<crate::channel::Operator>,
    say: &(dyn Fn(Line) + Sync),
    pin_say: impl Fn(String) + Send + 'static,
) -> Result<Carried, Refusal> {
    let Tunnel { host, access, trust } = tunnel;
    let link = cloudflare::open(host, access, trust).await.map_err(|(message, code)| Refusal { message, code })?;
    let greeted = client::greeted(link)
        .await
        .map_err(|e| Refusal { message: format!("{SCHEME}{host}: {e}"), code: sysexits::EX_UNAVAILABLE })?;
    // The exit's word goes in the channel, which a podssh node alone runs: a
    // service of cloudflared would take the bytes with no exit, and no rule.
    if !greeted.layer() {
        let message = format!(
            "{SCHEME}{host}: the far end greets with no layer: not a podssh node (podssh node NAME --exit \
             --quick-tunnel)"
        );
        return Err(Refusal { message, code: sysexits::EX_NOPERM });
    }
    Ok(through(greeted, cloudflare::redial(host, access, trust), app, channel, say, pin_say).await)
}

/// The session on `greeted`, the first link, whose far end said `GREETING`:
/// the layer, the channel around `app`, and a new link of `dial` after each
/// lost one, until the session ends. Apart from the edge, for the tests.
pub(crate) async fn through<A, D, F>(
    greeted: Greeted<DuplexStream>,
    mut dial: D,
    app: A,
    channel: Option<crate::channel::Operator>,
    say: &(dyn Fn(Line) + Sync),
    pin_say: impl Fn(String) + Send + 'static,
) -> Carried
where
    A: crate::channel::Bytes + 'static,
    D: FnMut() -> F + Send,
    F: Future<Output = Next<DuplexStream>> + Send,
{
    // The edge keeps no bound of the pair's relay (T-443), and an exit's
    // session names no shell.
    let started = greeted.start(Ask::New, layered::settings().off_the_pair(), &mut OsEntropy).await;
    let client = match started {
        Ok(client) => client,
        Err(e) => {
            let why = format!("the far end greets with the resumable layer, but its handshake failed: {e}");
            return Carried { why: Some(why), leg: None, channel: None, signalled: false };
        }
    };
    crate::no_resume::found_lines(client.found()).into_iter().for_each(|line| say(Line::Verbose(line)));
    let me = channel.as_ref().map(|c| c.identity.clone());
    let (stream, session, told) = crate::channel::around_told(app, channel, pin_say);
    // A signal that the command took (T-586) ends the bytes, and the layer
    // sends CLOSE, as on a relay's legs.
    let hangup = crate::hangup::taken();
    let stream = crate::hangup::ending(stream, hangup.as_ref());
    let connect = |_: &Ended| dial();
    let note = |note: Note| say(layered::line_of(note));
    let mut entropy = OsEntropy;
    let run = resume::run(client, stream, connect, note, &mut entropy);
    let channel_end = async move {
        match session {
            Some(session) => session.await.err(),
            None => None,
        }
    };
    // The handshake's line at -v, once the node let this end in (T-643).
    let told = async {
        if let Ok(line) = told.await {
            say(Line::Verbose(line));
        }
    };
    let joined = Box::pin(async { tokio::join!(run, channel_end, told) });
    let Some((outcome, failed, ())) = crate::hangup::bounded(hangup.as_ref(), joined).await else {
        return Carried { why: None, leg: None, channel: None, signalled: true };
    };
    // The channel says more than the layer: a refused key, a refused target.
    let channel = failed.as_ref().and_then(|e| crate::channel::judged(e, me.as_deref()));
    Carried { why: layered::why_ended(outcome), leg: None, channel, signalled: false }
}

/// The code and the line of a session to an exit behind a quick tunnel that
/// did not end well; none for a good end. The channel's verdict first, as
/// for a relay's legs (`crate::operator::judged`); no leg's close follows.
pub fn judged(carried: &Carried) -> Option<(i32, String)> {
    if let Some((fault, why)) = &carried.channel {
        return Some((fault.code(), why.clone()));
    }
    carried.why.clone().map(|why| (Fault::SessionFault.code(), why))
}

#[cfg(test)]
#[path = "tunnel_tests.rs"]
mod tests;
