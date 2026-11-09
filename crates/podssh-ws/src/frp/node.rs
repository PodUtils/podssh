//! The node's side of the frp road: a connection to frps, the login, the
//! STCP service of the node's name, a heartbeat each 30 s as frpc sends one,
//! and a work connection each time frps asks for one, handed to the caller
//! once a visitor took it. A lost connection is made again, after 1 s and up
//! to 30 s between tries, from 1 s again after a connection that lasted a
//! minute; a refused token ends the road, as no try again would pass. And
//! the visitor's side: a visit on a connection of its own, logged in as its
//! user when the road names one, as frps checks a service's `allowUsers`.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::DuplexStream;
use zeroize::Zeroizing;

use super::control::Session;
use super::dial::{self, Server};
use super::msg;
use super::mux::Mux;
use super::FrpError;
use crate::dial::ProxyChoice;
use crate::tls::Trust;

/// frpc's heartbeat (`transport.heartbeatInterval`'s default).
pub const HEARTBEAT: Duration = Duration::from_secs(30);
/// frps ends a client that sent no heartbeat for this long (frpc's own
/// timeout of a pong, `heartbeatTimeout`'s default).
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);
/// The bound of the connection and its TLS.
pub const DIAL_LIMIT: Duration = Duration::from_secs(20);
const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(30);
const STEADY: Duration = Duration::from_secs(60);

/// The road of a node through frps.
#[derive(Clone)]
pub struct Road {
    pub server: Server,
    pub token: Arc<Zeroizing<String>>,
    pub secret: Arc<Zeroizing<String>>,
    pub trust: Trust,
    /// frpc's `user`: the user that the road logs in as, which frps checks
    /// against a service's `allowUsers` and which frpc puts before the
    /// names of its services; empty for none, as frpc's default.
    pub user: String,
    /// frpc's visitor's `serverUser`: the user of the frpc whose service a
    /// visitor reaches, where it is not the road's own; empty for none.
    pub owner: String,
}

impl Road {
    /// The name of a node's service on frps, as frpc names its proxies:
    /// `USER.NAME` with a user, else NAME.
    pub fn registered(&self, name: &str) -> String {
        prefixed(&self.user, name)
    }

    /// The name that a visitor asks frps for, as frpc's visitor names it:
    /// `OWNER.NAME` with an owner, else [`Road::registered`]'s, so that a
    /// node and a visitor of one file meet.
    pub fn visited(&self, name: &str) -> String {
        if self.owner.is_empty() {
            self.registered(name)
        } else {
            prefixed(&self.owner, name)
        }
    }
}

fn prefixed(user: &str, name: &str) -> String {
    if user.is_empty() {
        name.to_string()
    } else {
        format!("{user}.{name}")
    }
}

/// A line of the road, as the caller says it.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// Serve the STCP service `name` on `road` until frps refuses its token:
/// why. Each work connection that a visitor took goes to `work`.
pub async fn serve<W, F>(road: Road, name: String, say: Say, work: W) -> String
where
    W: Fn(DuplexStream) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let mut wait = RETRY_FIRST;
    loop {
        let started = Instant::now();
        match once(&road, &name, &say, work.clone()).await {
            Err(e) if e.is_bad_token() => return e.to_string(),
            Err(e) => say(format!("the road through {} ended: {e}; trying again", road.server.shown())),
            Ok(()) => {}
        }
        if started.elapsed() >= STEADY {
            wait = RETRY_FIRST;
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(RETRY_MAX);
    }
}

/// One connection's life: until it ends.
async fn once<W, F>(road: &Road, name: &str, say: &Say, work: W) -> Result<(), FrpError>
where
    W: Fn(DuplexStream) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let proxy = ProxyChoice::FromEnvironment;
    let conn = dial::connect(&road.server, &road.trust, &proxy, DIAL_LIMIT).await.map_err(FrpError::Ended)?;
    let mux = Mux::client(conn);
    let mut session = Session::login(mux.clone(), &road.token, &road.user).await?;
    let service = road.registered(name);
    session.write.lock().await.send(msg::NEW_PROXY, &msg::new_stcp(&service, &road.secret)).await?;
    let heartbeat = {
        let (write, token) = (session.write.clone(), road.token.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(HEARTBEAT).await;
                if write.lock().await.send(msg::PING, &msg::ping(&token, msg::now())).await.is_err() {
                    return;
                }
            }
        })
    };
    let result = control_loop(&mut session, road, &service, say, work).await;
    heartbeat.abort();
    mux.close();
    result
}

/// Read frps's control messages: the service's answer, frps's asks for work
/// connections and its pongs.
async fn control_loop<W, F>(session: &mut Session, road: &Road, name: &str, say: &Say, work: W) -> Result<(), FrpError>
where
    W: Fn(DuplexStream) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let mut last_pong = Instant::now();
    loop {
        let next = tokio::time::timeout(HEARTBEAT_TIMEOUT, session.read.recv()).await;
        let m = match next {
            Ok(m) => m?,
            Err(_) => {
                return Err(FrpError::Ended(format!(
                    "frps said nothing for {} s, its pong neither",
                    HEARTBEAT_TIMEOUT.as_secs()
                )))
            }
        };
        match m.kind {
            msg::NEW_PROXY_RESP => match m.error() {
                Some(words) => return Err(FrpError::Refused { step: "the service", words: words.into() }),
                None => say(format!("waiting for visitors at {} as the STCP service {name}", road.server.shown())),
            },
            msg::REQ_WORK_CONN => {
                let (mux, token, run_id) = (session.mux.clone(), road.token.clone(), session.run_id.clone());
                let (work, say) = (work.clone(), say.clone());
                tokio::spawn(async move {
                    match Session::work_conn(&mux, &token, &run_id).await {
                        Ok((stream, _start)) => work(stream).await,
                        Err(e) => say(format!("a work connection failed: {e}")),
                    }
                });
            }
            msg::PONG => {
                if let Some(words) = m.error() {
                    return Err(FrpError::Refused { step: "the heartbeat", words: words.into() });
                }
                last_pong = Instant::now();
            }
            // Messages of frp's other services, which podssh registers none of.
            _ => {}
        }
        if last_pong.elapsed() > HEARTBEAT_TIMEOUT {
            return Err(FrpError::Ended("frps answered no heartbeat in time".into()));
        }
    }
}

/// A visitor's stream to `name`: a connection of its own and the visit; the
/// connection ends with the stream, so that each visit costs one.
pub async fn visit(road: &Road, name: &str) -> Result<DuplexStream, FrpError> {
    let proxy = ProxyChoice::FromEnvironment;
    let conn = dial::connect(&road.server, &road.trust, &proxy, DIAL_LIMIT).await.map_err(FrpError::Ended)?;
    visit_on(Mux::client(conn), road, name).await
}

/// [`visit`] on the connection of `mux`, which ends with the visit. With a
/// user, the visitor logs in first and names its run id, as frpc's visitor
/// does, so that frps checks that user against the service's `allowUsers`;
/// the login is held while the visit lasts. With none, no login: frps
/// admits a visitor with no run id as the user "", whom a service of an
/// empty user allows.
pub async fn visit_on(mux: Mux, road: &Road, name: &str) -> Result<DuplexStream, FrpError> {
    let service = road.visited(name);
    let login = if road.user.is_empty() {
        None
    } else {
        match Session::login_visitor(mux.clone(), &road.token, &road.user).await {
            Ok(session) => Some(session),
            Err(e) => {
                mux.close();
                return Err(e);
            }
        }
    };
    let run_id = login.as_ref().map(|session| session.run_id.clone()).unwrap_or_default();
    let mut stream = match super::control::visit(&mux, &service, &road.secret, &run_id).await {
        Ok(stream) => stream,
        Err(e) => {
            mux.close();
            return Err(e);
        }
    };
    let (user, mut ours) = tokio::io::duplex(VISIT_PIPE);
    tokio::spawn(async move {
        let copy = tokio::io::copy_bidirectional(&mut ours, &mut stream);
        tokio::pin!(copy);
        match login {
            None => {
                let _ = copy.await;
            }
            // A login that frps ended ends no visit: the visit's stream is
            // its own.
            Some(session) => tokio::select! {
                _ = &mut copy => {}
                () = session.keep(HEARTBEAT) => {
                    let _ = copy.await;
                }
            },
        }
        mux.close();
    });
    Ok(user)
}

/// The pipe between a visitor's user and its stream.
const VISIT_PIPE: usize = 64 * 1024;
