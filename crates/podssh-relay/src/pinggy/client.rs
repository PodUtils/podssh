//! The client of the Pinggy road: for each link, a TCP stream to the node's
//! tunnel name on port 443 through `HTTPS_PROXY`, then TLS by that name:
//! Pinggy reads the SNI, sends the bytes down the node's SSH session, and the
//! node ends the TLS with its own certificate, whose key the client pins
//! ([`super::tls`]): the node says the pin with its name, and the two go
//! together as an [`Address`]. No upgrade and no account, so a proxy that
//! refuses the WebSocket upgrade passes it. The end-to-end channel above the
//! layer checks the node's own key too. After each lost link, a new one; a
//! node whose free tunnel ended has a new name, which a later link takes
//! from the node's record or the user (the node says it).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use podssh_ws::Trust;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::tls;
use super::Say;
use crate::opentunnel::dial::{BoxIo, Visit, CONNECT_LIMIT};
use crate::session::client::{self, Outcome};
use crate::session::resume::{self, Next, Note};
use crate::session::{Ask, Ended, Hearing, OsEntropy, Settings};

/// A node's name at Pinggy: the name of its tunnel, as the node says it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Name(String);

impl Name {
    /// A DNS name of two labels or more, each of `[a-z0-9-]`; case does not
    /// matter, and a scheme or a port of 443 is taken off, as the node may
    /// say its tunnel's address with them.
    pub fn parse(text: &str) -> Result<Name, String> {
        let text = text.trim();
        let port_ok = match text.split_once("://").map_or(text, |(_, rest)| rest).rsplit_once(':') {
            Some((_, port)) => port.trim_end_matches('/') == "443",
            None => true,
        };
        match super::urls::host_of(text) {
            Some(host) if port_ok => Ok(Name(host)),
            _ => Err("a node's name at Pinggy is its tunnel's name, as the node says it, such as \
                      NAME.a.free.pinggy.link"
                .into()),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A node's name at Pinggy and the pin of its certificate's key, as the node
/// says them and a client gives them: `NAME#SHA256:...`. A name with no pin
/// is no address: TLS would then prove nothing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    pub name: Name,
    pub pin: tls::Pin,
}

impl Address {
    /// `NAME#PIN`; the refusal says which half is wrong, never with its text.
    pub fn parse(text: &str) -> Result<Address, String> {
        let Some((name, pin)) = text.trim().split_once('#') else {
            return Err(format!(
                "a node's address at Pinggy is NAME#{}..., as the node's line name says it: the pin of the node's \
                 certificate goes with its tunnel's name",
                tls::PIN_PREFIX
            ));
        };
        Ok(Address { name: Name::parse(name)?, pin: tls::Pin::parse(pin)? })
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}", self.name, self.pin)
    }
}

/// A link to the node: TLS by its name, over Pinggy.
pub struct Link(BoxIo);

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("pinggy::Link(..)")
    }
}

/// The links of one client to one node.
pub struct Dialer {
    address: Address,
    visit: Visit,
    say: Say,
}

impl Dialer {
    /// The dialer of the node at `address`, through `visit`.
    pub fn new(address: Address, visit: Visit, say: Say) -> Dialer {
        Dialer { address, visit, say }
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    /// A new link to the node, once its TLS passed with the pinned key; else
    /// why there is none.
    pub async fn link(&self) -> Result<Link, String> {
        let (name, pin) = (self.address.name.to_string(), self.address.pin);
        // A verifier for each link, so that its refusal is this link's.
        let (trust, verifier): (Trust, _) = tls::trust(pin)?;
        let tcp = (self.visit)(&name).await?;
        match podssh_ws::tls_over(tcp, &name, &trust, CONNECT_LIMIT).await {
            Ok(tls) => Ok(Link(Box::new(tls))),
            // Another key at the name: a stranger holds it now, or a proxy
            // ended TLS; either way, not the node.
            Err(podssh_ws::ConnectError::Tls(_)) if verifier.refused().is_some() => {
                let seen = verifier.refused().unwrap_or_default();
                (self.say)(format!("TLS with {name} refused: its certificate's key is {seen}, not the pin {pin}"));
                Err(format!(
                    "{name} showed a certificate of the key {seen}, not the node's pin {pin}: refused, as a stranger \
                     holds the name now (a free tunnel's name goes to another after its hour) or a proxy ended TLS"
                ))
            }
            // Pinggy closes a visitor whose name no tunnel holds: the node's
            // free tunnel ended, and its next one has another name.
            Err(podssh_ws::ConnectError::Tls(why)) => {
                (self.say)(format!("TLS with {name} failed: {why}"));
                Err(format!(
                    "TLS with {name} failed ({why}): no node holds the name at Pinggy now (a free tunnel ends at \
                     60 minutes, and the next has a new name), or a proxy ended it"
                ))
            }
            Err(e) => Err(format!("{name}: {e}")),
        }
    }
}

/// Carry `app` to the node of `dialer`: the first link and the layer's
/// handshake on it, then a new link after each lost one, until the session
/// ends. `note` hears each step of the session across links.
pub async fn carry<A, N>(dialer: &Dialer, app: A, settings: Settings, note: N) -> Result<Outcome, String>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    carry_heard(dialer, app, settings, note, Arc::default()).await
}

/// [`carry`], with the session's `hearing`, which a notice of the far end's
/// silence reads.
pub async fn carry_heard<A, N>(
    dialer: &Dialer,
    app: A,
    settings: Settings,
    note: N,
    hearing: Arc<Hearing>,
) -> Result<Outcome, String>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    let first = dialer.link().await?;
    let client = client::start(first, Ask::New, settings, &mut OsEntropy).await.map_err(|e| e.to_string())?;
    let client = client.with_hearing(hearing);
    let connect = |_: &Ended| async move {
        match dialer.link().await {
            Ok(link) => Next::Link(link),
            Err(why) => Next::Retry(why),
        }
    };
    // On the heap: the layer's future is larger than a small thread's stack
    // in a debug build.
    Ok(Box::pin(resume::run(client, app, connect, note, &mut OsEntropy)).await)
}

impl AsyncRead for Link {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Link {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_the_tunnel_s_host_with_no_other_port() {
        let name = Name::parse("tls://Xyzzy-12.A.Free.Pinggy.Link:443").unwrap();
        assert_eq!(name.as_str(), "xyzzy-12.a.free.pinggy.link");
        assert_eq!(Name::parse("xyzzy-12.a.free.pinggy.link.").unwrap(), name);
        for bad in ["xyzzy:8443", "tls://a.b.c:8443", "127.0.0.1", "a_b.pinggy.link", "pinggy", ""] {
            assert!(Name::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_address_is_the_name_and_the_pin_and_a_name_alone_is_none() {
        let pin = tls::Pin::of_spki(b"a key");
        let address = Address::parse(&format!(" Xyzzy-12.A.Free.Pinggy.Link#{pin} ")).unwrap();
        assert_eq!(address.name.as_str(), "xyzzy-12.a.free.pinggy.link");
        assert_eq!(address.pin, pin);
        assert_eq!(Address::parse(&address.to_string()), Ok(address.clone()));
        let why = Address::parse("xyzzy-12.a.free.pinggy.link").unwrap_err();
        assert!(why.contains("NAME#SHA256:"), "{why}");
        assert!(Address::parse("xyzzy-12.a.free.pinggy.link#SHA256:SECRET").unwrap_err().starts_with("a pin is"));
        assert!(Address::parse(&format!("bad_name#{pin}")).is_err());
    }
}
