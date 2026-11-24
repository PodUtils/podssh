//! `tcpip-forward` from a stock `ssh -R` (T-123, GitHub #18), with no bind:
//! serve hands each forward to a [`Publish`] of its settings, the relay's
//! pair in the CLI (a name whose operator sessions reach the client) and a
//! stand-in in the tests. Each session that comes on the published name
//! opens a `forwarded-tcpip` channel to the client, toward the address and
//! port of the request, through an [`Opener`]. serve binds no socket for
//! `-R`; without a [`Publish`], each request is refused, as russh's default
//! refused it.
//!
//! One teardown for each way a forward ends (a `cancel-tcpip-forward`, the
//! connection's end, a failed publish): its [`Stop`] runs once, when the
//! forward leaves the table of its connection. A connection holds at most
//! [`MAX_REMOTE_FORWARDS`]; the same address and port twice is refused, as
//! a second publish of one forward would part its sessions between two
//! names.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use russh::server::{Handle, Msg};
use russh::ChannelStream;

use super::{Rules, Settings};

/// The forwards of `-R` open at once on one connection.
pub const MAX_REMOTE_FORWARDS: usize = 8;

/// A forward to publish: the address and the port that the client named
/// (the far end of its channels), and the key that asked, for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    pub address: String,
    pub port: u32,
    pub who: String,
}

/// A forward published: the name that reaches it, the port that the client
/// is told (the asked one, or one chosen for port 0), and its teardown.
pub struct Published {
    pub name: String,
    pub port: u32,
    pub stop: Stop,
}

/// What a forward's teardown does, once: the pair stopped at the relay, a
/// stand-in's row removed. It runs when its holder drops it.
pub struct Stop(Option<Box<dyn FnOnce() + Send>>);

impl Stop {
    pub fn new(stop: impl FnOnce() + Send + 'static) -> Stop {
        Stop(Some(Box::new(stop)))
    }

    /// A forward whose end needs nothing.
    pub fn nothing() -> Stop {
        Stop(None)
    }
}

impl Drop for Stop {
    fn drop(&mut self) {
        if let Some(stop) = self.0.take() {
            stop();
        }
    }
}

/// The answer of a publish, when it is ready.
pub type Publishing = Pin<Box<dyn Future<Output = Result<Published, String>> + Send>>;

/// What publishes a forward of `-R` with no bind.
pub trait Publish: Send + Sync {
    /// Publish `asked`; each session on its name opens its channel with
    /// `opener`. `Err` is why not, in words for serve's log.
    fn publish(&self, asked: Asked, opener: Opener) -> Publishing;
}

/// The publisher of the settings, beside its words for `Debug`.
#[derive(Clone)]
pub struct Publisher(pub Arc<dyn Publish>);

impl std::fmt::Debug for Publisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Publisher")
    }
}

/// Opens a `forwarded-tcpip` channel to the client for one forward.
#[derive(Clone)]
pub struct Opener {
    handle: Handle,
    address: String,
    port: u32,
}

impl Opener {
    /// A channel toward the forward's address and port, from `from`
    /// (the session's own end, as the operator's side names it).
    pub async fn open(&self, from: &str, from_port: u32) -> Result<ChannelStream<Msg>, String> {
        let opened = self.handle.channel_open_forwarded_tcpip(self.address.clone(), self.port, from, from_port);
        match opened.await {
            Ok(channel) => Ok(channel.into_stream()),
            Err(e) => Err(format!("the client did not open the forwarded channel: {e}")),
        }
    }
}

/// The forwards of one connection, each stopped as it leaves.
#[derive(Default)]
pub(super) struct Forwards {
    live: HashMap<(String, u32), Published>,
}

impl Forwards {
    /// Answer a `tcpip-forward`: true with `port` set to the port
    /// published, false with a line of serve's log that says why.
    pub(super) async fn ask(
        &mut self,
        settings: &Settings,
        rules: Result<Arc<Rules>, String>,
        who: &str,
        address: &str,
        port: &mut u32,
        handle: Handle,
    ) -> bool {
        let shown = format!("-R {address}:{port}");
        let refused = |why: &str| {
            settings.say(&format!("key {who}: {shown} refused: {why}"));
            false
        };
        if let Some(why) = refusal(settings, rules.as_deref(), address, *port, self.live.len()) {
            return refused(&why);
        }
        if *port != 0 && self.live.contains_key(&(address.to_string(), *port)) {
            return refused("that address and port are forwarded already on this connection");
        }
        let Some(Publisher(publish)) = settings.remote.as_ref() else {
            return refused("serve binds no socket for -R, and no relay publishes it here");
        };
        let asked = Asked { address: address.to_string(), port: *port, who: who.to_string() };
        let opener = Opener { handle, address: address.to_string(), port: *port };
        match publish.publish(asked, opener).await {
            Ok(published) => {
                settings.say(&format!("key {who}: {shown} published as {}", published.name));
                *port = published.port;
                // A forward of the same key here replaces none: the check
                // above refused it, and a port of 0 gets its own.
                self.live.insert((address.to_string(), published.port), published);
                true
            }
            Err(why) => refused(&why),
        }
    }

    /// Answer a `cancel-tcpip-forward`: its forward stops, once.
    pub(super) fn cancel(&mut self, address: &str, port: u32) -> bool {
        self.live.remove(&(address.to_string(), port)).is_some()
    }

    /// The forwards open now.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.live.len()
    }
}

/// Why a forward is refused before any publish: forwarding turned off, the
/// key's rules, a port out of range, or the connection's cap.
fn refusal(
    settings: &Settings,
    rules: Result<&Rules, &String>,
    address: &str,
    port: u32,
    open: usize,
) -> Option<String> {
    if settings.no_forwarding {
        return Some("--no-forwarding".into());
    }
    match rules {
        Err(why) => return Some(why.clone()),
        Ok(rules) if rules.no_port_forwarding => return Some("the key's no-port-forwarding (or restrict)".into()),
        Ok(_) => {}
    }
    if port > u32::from(u16::MAX) {
        return Some(format!("port {port} is past 65535"));
    }
    if address.len() > 255 || address.chars().any(char::is_control) {
        return Some("the address is no host name or address".into());
    }
    if open >= MAX_REMOTE_FORWARDS {
        return Some(format!("{MAX_REMOTE_FORWARDS} forwards are open on this connection already"));
    }
    None
}

#[cfg(test)]
#[path = "remote_forward_tests.rs"]
mod tests;
