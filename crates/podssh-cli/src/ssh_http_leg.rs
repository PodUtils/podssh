//! The node's leg of a tunnel of HTTP made by `ssh -R` (T-565,
//! `podssh_relay::ssh_http`): SSH to the service's server, raw, on each of
//! its ports in turn, directly or by `HTTPS_PROXY`'s CONNECT, as `ssh -R
//! 80:localhost:PORT nokey@localhost.run` reaches it. localhost.run's
//! documents name no SSH inside TLS (read 2026-11-10), so a proxy that
//! passes TLS alone leaves this road out. The handshake, the check of the
//! host key and the login with no account are the Pinggy road's
//! (`pinggy_leg`), as the word's user; one remote forward, the word's, whose
//! `forwarded-tcpip` channels Pinggy's handler hands on as visitors. The
//! session channel takes a shell with no terminal, as `ssh -T` does, whose
//! lines name the tunnel, then each new name, for as long as the session
//! lives (`podssh_relay::ssh_http::name`): the service logs a line for each
//! request there too, so the text is read to its end, line by line, and
//! never kept whole.

use podssh_relay::pinggy::far::Visitor;
use podssh_relay::pinggy::Say;
use podssh_relay::ssh_http::{name, Service};
use podssh_ssh::russh::client::{self, Msg};
use podssh_ssh::russh::{self, Channel, ChannelMsg};
use podssh_ws::ProxyChoice;
use tokio::sync::{mpsc, watch};

use crate::pinggy_leg::{self, Leg, Tunnel, CONNECT_LIMIT, NAME_LIMIT};

/// A tunnel at the service: its session, and the name that its lines say
/// now, which changes when the service gives the tunnel another.
pub(crate) struct Opened {
    pub tunnel: Tunnel,
    pub names: watch::Receiver<Option<String>>,
}

/// A tunnel at `service`, through `proxy`; each visitor goes to `visitors`.
/// Else why there is none.
pub(crate) async fn open(
    service: &Service,
    proxy: &ProxyChoice,
    visitors: mpsc::Sender<Visitor>,
    say: &Say,
) -> Result<Opened, String> {
    let mut failed = Vec::new();
    for &port in &service.ports {
        let at = service.at(port);
        let tcp = match podssh_ws::dial::dial(&at.host, port, proxy, CONNECT_LIMIT).await {
            Ok(tcp) => tcp,
            Err(e) => {
                failed.push(format!("port {port}: {e}"));
                continue;
            }
        };
        // Raw SSH alone: no version line to wait for before a TLS that the
        // service does not take.
        let (mut handle, key) = match pinggy_leg::handshake(tcp, &at, visitors.clone(), None).await {
            Ok(done) => done,
            Err(failed_ssh) => {
                failed.push(format!("port {port}: {}", failed_ssh.why));
                continue;
            }
        };
        let user = service.word.user;
        pinggy_leg::login(&mut handle, user).await.map_err(|why| format!("{service} on port {port}: {why}"))?;
        say(format!("the leg to {service} is raw SSH on port {port}, as {user}, a user with no account"));
        if service.host_key.is_none() {
            say(format!("{service}'s host key {key} is taken unpinned: the end-to-end channel keeps the bytes"));
        }
        let host_key = (key, service.host_key.is_some());
        return forwarded(handle, host_key, service).await;
    }
    Err(format!("{service}: {}", failed.join("; ")))
}

/// The word's forward on `handle`, and the session whose lines name it.
async fn forwarded(
    mut handle: client::Handle<Leg>,
    host_key: (String, bool),
    service: &Service,
) -> Result<Opened, String> {
    let (address, port) = service.word.forward;
    if let Err(e) = handle.tcpip_forward(address, port).await {
        return give_up(handle, format!("{service} refused the tunnel's forward of port {port}: {e}")).await;
    }
    let session = match handle.channel_open_session().await {
        Ok(session) => session,
        Err(e) => return give_up(handle, format!("{service}: a session: {e}")).await,
    };
    if let Err(e) = session.request_shell(false).await {
        return give_up(handle, format!("{service}: a shell: {e}")).await;
    }
    let (said, mut names) = watch::channel(None);
    tokio::spawn(read_names(session, said, service.clone()));
    let named = match tokio::time::timeout(NAME_LIMIT, names.wait_for(Option::is_some)).await {
        Ok(Ok(named)) => named.clone(),
        _ => None,
    };
    let Some(name) = named else {
        return give_up(handle, format!("{service} named no tunnel within {} s", NAME_LIMIT.as_secs())).await;
    };
    Ok(Opened { tunnel: Tunnel { name, host_key, way: "raw SSH", handle }, names })
}

/// End the session of a leg that holds no tunnel, and say why.
async fn give_up(handle: client::Handle<Leg>, why: String) -> Result<Opened, String> {
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "no tunnel", "en").await;
    Err(why)
}

/// Read the session's channel to its end, so that it never holds the
/// session back, and say each name of the tunnel that a line gives.
async fn read_names(mut session: Channel<Msg>, said: watch::Sender<Option<String>>, service: Service) {
    let mut lines = name::Lines::default();
    while let Some(msg) = session.wait().await {
        let data = match msg {
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => data,
            _ => continue,
        };
        for line in lines.push(&data) {
            let Some(found) = name::of_line(&line, &service.word, &|host| service.own(host)) else { continue };
            said.send_if_modified(|now| {
                let new = now.as_deref() != Some(found.as_str());
                if new {
                    *now = Some(found.clone());
                }
                new
            });
        }
    }
}

/// The next name that the session's lines give after `now`; none, for
/// ever, once the session ended: the tunnel's own end says that.
pub(crate) async fn renamed(names: &mut watch::Receiver<Option<String>>, now: &str) -> String {
    loop {
        if names.changed().await.is_err() {
            return std::future::pending().await;
        }
        if let Some(name) = names.borrow_and_update().clone().filter(|name| name != now) {
            return name;
        }
    }
}
