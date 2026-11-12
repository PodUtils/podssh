//! VMess in its AEAD form (T-739, the operator's ruling Q78): the third line
//! form of the public proxy nodes (T-574), as most nodes of the lists on 443
//! over a WebSocket and TLS speak it. The server takes the target from a
//! header sealed under keys from the user's ID and the time ([`header`],
//! [`kdf`]), dials it, and carries the bytes in sealed chunks ([`body`]). The
//! MD5 form (`aid` above 0) and a body in clear are never sent ([`link`]).
//!
//! The auth ID holds this host's clock: a server takes it within 120 s of
//! its own, so a node that ends the session at once may hold a clock that
//! differs, which the failure's line says. The settings of a dial are
//! VLESS's ([`crate::vless::Dial`]), as each road of the nodes dials alike.

mod body;
mod header;
mod kdf;
pub mod link;
mod ws;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::dial::DialError;
use crate::via::Duplex;

pub use crate::vless::{AtEnd, Dial};
pub use body::Cipher;
pub use link::Server;

/// How long a session whose server speaks first waits for its first bytes:
/// Xray's server sends its answer with the target's first bytes.
pub const ANSWER_WAIT: Duration = Duration::from_secs(10);
/// How long a pipe waits before it takes the stream.
pub const EARLY_WAIT: Duration = Duration::from_secs(3);

/// Why a VMess server carried no session.
#[derive(Debug)]
pub enum VmessError {
    /// The target cannot go in VMess's header.
    Target(String),
    /// TCP, or the host's proxy.
    Dial(DialError),
    /// TLS or the upgrade failed, or the pump could not start: what failed.
    Carry(String),
    /// The WebSocket's upgrade was refused: its status, and what it refused.
    Refused { status: u16, why: String },
    /// The server ended the session before its answer.
    Ended,
    /// The answer's header was not the session's: what was wrong.
    Wrong(&'static str),
    /// No answer within the wait.
    Silent(Duration),
}

/// The words on a refusal that a wrong clock gives as well as a wrong ID.
const CLOCK: &str = "the link's ID is not the server's, or this host's clock is more than 2 minutes off the \
                     server's (VMess's request holds the time)";

impl VmessError {
    /// The line that says it, for the server `shown` and the target. No line
    /// holds the ID.
    pub fn line(&self, shown: &str, target: &str) -> String {
        match self {
            VmessError::Target(why) => format!("{target} cannot go to the VMess server {shown}: {why}"),
            VmessError::Dial(e) => format!("the VMess server {shown}: {e}"),
            VmessError::Carry(why) => format!("the VMess server {shown}: {why}"),
            VmessError::Refused { status, why } => format!("the VMess server {shown} refused {why}: HTTP {status}"),
            VmessError::Ended => format!(
                "the VMess server {shown}, for {target}: the server ended the session before its answer: {CLOCK}, \
                 or the server could not reach the target"
            ),
            VmessError::Wrong(why) => format!(
                "the VMess server {shown}, for {target}: its answer was not this session's ({why}): the node is \
                 not a VMess server of the AEAD form, or something between changed the bytes"
            ),
            VmessError::Silent(after) => format!(
                "the VMess server {shown} gave nothing for {target} within {} s: {CLOCK}, the target said nothing, \
                 or a proxy or a front end between holds the bytes",
                after.as_secs()
            ),
        }
    }
}

/// A session to the target.
pub struct Opened {
    pub stream: Box<dyn Duplex>,
    /// What carried it: "a WebSocket over TLS", "a WebSocket".
    pub how: &'static str,
    /// The server's answer came within the wait.
    pub answered: bool,
}

/// A session to `host:port` through `server`, at this host's clock.
pub async fn open(server: &Server, host: &str, port: u16, dial: &Dial<'_>) -> Result<Opened, VmessError> {
    let unix = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    open_at(server, host, port, dial, unix).await
}

/// [`open`] with the time that the auth ID holds: the tests set a clock off.
pub async fn open_at(server: &Server, host: &str, port: u16, dial: &Dial<'_>, unix: u64) -> Result<Opened, VmessError> {
    // 33 bytes of the body's keys and the answer's byte, 4 of the auth ID,
    // 8 of the connection's nonce, 1 of the padding's length, 15 of padding.
    let mut random = [0u8; 61];
    fill(&mut random)?;
    let keys = header::Keys::new(random[..33].try_into().unwrap_or(&[0u8; 33]));
    let auth_random: [u8; 4] = random[33..37].try_into().unwrap_or_default();
    let nonce: [u8; 8] = random[37..45].try_into().unwrap_or_default();
    // Xray's client pads with 0 to 15 bytes, as `dice.Roll(16)` draws them.
    let pad = usize::from(random[45] % 16);
    let plain = header::request(&keys, server.cipher, host, port, &random[46..46 + pad]).map_err(VmessError::Target)?;
    let sealed = header::seal(&kdf::cmd_key(server.id.bytes()), &plain, unix, auth_random, nonce)
        .ok_or_else(|| VmessError::Carry("VMess's header could not be sealed".into()))?;
    let raw = ws::open(server, dial).await?;
    let (stream, told) = body::spawn(raw, &keys, server.cipher, sealed)
        .ok_or_else(|| VmessError::Carry("the body's cipher could not be keyed".into()))?;
    let answered = match tokio::time::timeout(dial.answer, told).await {
        Ok(Ok(Ok(()))) => true,
        Ok(Ok(Err(body::Answer::Ended))) => return Err(VmessError::Ended),
        Ok(Ok(Err(body::Answer::Wrong(why)))) => return Err(VmessError::Wrong(why)),
        Ok(Ok(Err(body::Answer::Io(e)))) => return Err(VmessError::Carry(format!("before the answer: {e}"))),
        Ok(Err(_)) => return Err(VmessError::Ended),
        Err(_) if dial.silence_is_ready => false,
        Err(_) => return Err(VmessError::Silent(dial.answer)),
    };
    let how = if server.tls { "a WebSocket over TLS" } else { "a WebSocket" };
    Ok(Opened { stream: Box::new(stream), how, answered })
}

/// Random bytes from the system's source.
fn fill(out: &mut [u8]) -> Result<(), VmessError> {
    use rustls::crypto::SecureRandom as _;
    crate::crypto::random::OsRandom.fill(out).map_err(|_| VmessError::Carry("no random bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_names_the_server_and_the_clock_where_it_may_be_the_cause() {
        let shown = "vmess://v.example:443/vm";
        let ended = VmessError::Ended.line(shown, "h.example:22");
        assert!(ended.contains("before its answer") && ended.contains("clock"), "{ended}");
        assert!(VmessError::Silent(ANSWER_WAIT).line(shown, "h:22").contains("within 10 s"));
        let wrong = VmessError::Wrong("it did not open").line(shown, "h:22");
        assert!(wrong.contains("(it did not open)") && !wrong.contains("clock"), "{wrong}");
        let refused = VmessError::Refused { status: 404, why: "the WebSocket upgrade at /vm".into() };
        assert_eq!(
            refused.line(shown, "h:22"),
            "the VMess server vmess://v.example:443/vm refused the WebSocket upgrade at /vm: HTTP 404"
        );
    }
}
