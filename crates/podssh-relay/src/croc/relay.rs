//! A client's handshake with croc's relay (schollz/croc:src/tcp/tcp.go at
//! v11.6.4, `HandshakeTCPServerCapability`, and the relay's side in
//! `clientHandshake` and `clientCommunication`), each message one frame:
//!
//! 1. this end's PAKE message (role 0, `super::pake`), and the relay's;
//! 2. a salt of 8 random bytes, and the key of `super::crypt` from it;
//! 3. the relay's password, then the room, each sealed, sent at once, as
//!    croc's own client sends them;
//! 4. the relay's banner and this end's address, `BANNER|||ADDRESS`, sealed,
//!    or `bad password`;
//! 5. the room's answer, sealed: `ok` for a room made or joined, `room full`,
//!    or `rate limited`.
//!
//! Then a member that made the room gets a frame of the one byte 1 each
//! second while it waits, and the relay pipes the raw bytes of both members
//! once the second came (`super::meet` reads past those frames).

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use super::crypt;
use super::pake::{Pake, MESSAGE_MOST, WEAK_KEY};
use super::wire::{Cut, Wire};
use crate::session::secret::Entropy;

/// croc's password of its public relays (src/models/constants.go at
/// v11.6.4, `DEFAULT_PASSPHRASE`), which croc-web's bridge names too.
pub const PASSWORD: &str = "pass123";
/// The bound of the whole handshake: the relay's own is 5 minutes, and its
/// first frame's 60 s.
pub const HANDSHAKE_LIMIT: Duration = Duration::from_secs(30);
/// The longest sealed answer that is read: a banner and an address.
const ANSWER_MOST: usize = 4096;

/// What the relay answered for the room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// The room is this end's, made or joined.
    In,
    /// Two members are in the room already.
    Full,
    /// The relay limits joins of this source or this room.
    Limited,
}

/// Why the handshake gave no room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The relay took another password.
    Password,
    /// Words that are not the relay's, or a key that does not open them.
    Words(String),
    /// The connection.
    Cut(Cut),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Password => f.write_str("croc's relay refused the password (bad password)"),
            Refused::Words(why) => f.write_str(why),
            Refused::Cut(cut) => cut.fmt(f),
        }
    }
}

impl From<Cut> for Refused {
    fn from(cut: Cut) -> Refused {
        Refused::Cut(cut)
    }
}

/// The handshake for `room` with `password`, within [`HANDSHAKE_LIMIT`].
pub async fn admit<S>(
    wire: &mut Wire<'_, S>,
    password: &str,
    room: &str,
    entropy: &mut (dyn Entropy + Send),
) -> Result<Admission, Refused>
where
    S: AsyncRead + AsyncWrite + Send,
{
    let late =
        || Refused::Cut(Cut::Broken(format!("croc's relay did not admit within {} s", HANDSHAKE_LIMIT.as_secs())));
    tokio::time::timeout(HANDSHAKE_LIMIT, steps(wire, password, room, entropy)).await.map_err(|_| late())?
}

async fn steps<S>(
    wire: &mut Wire<'_, S>,
    password: &str,
    room: &str,
    entropy: &mut (dyn Entropy + Send),
) -> Result<Admission, Refused>
where
    S: AsyncRead + AsyncWrite + Send,
{
    let no_random = |e: crate::session::secret::NoRandom| Refused::Words(e.to_string());
    let mut pake = Pake::new(WEAK_KEY, 0, entropy).map_err(no_random)?;
    wire.send(&pake.bytes()).await?;
    let theirs = wire.frame(MESSAGE_MOST).await?;
    pake.update(&theirs).map_err(|why| Refused::Words(format!("croc's relay's PAKE: {why}")))?;
    let pake_key = pake.session_key().ok_or_else(|| Refused::Words("the PAKE gave no key".into()))?;
    let mut salt = [0u8; crypt::SALT_BYTES];
    entropy.fill(&mut salt).map_err(no_random)?;
    let key = crypt::key(&pake_key[..], &salt);
    wire.send(&salt).await?;
    // The room goes with the password, as croc's client pipelines it: a
    // relay reads it after the password is checked.
    wire.send(&crypt::seal(&key, password.as_bytes(), entropy).map_err(no_random)?).await?;
    wire.send(&crypt::seal(&key, room.as_bytes(), entropy).map_err(no_random)?).await?;
    let banner = opened(&key, &wire.frame(ANSWER_MOST).await?)?;
    if !banner.contains("|||") {
        return Err(match banner.as_str() {
            "bad password" => Refused::Password,
            _ => Refused::Words("croc's relay answered words that are not its banner".into()),
        });
    }
    match opened(&key, &wire.frame(ANSWER_MOST).await?)?.as_str() {
        "ok" => Ok(Admission::In),
        "room full" => Ok(Admission::Full),
        "rate limited" => Ok(Admission::Limited),
        other => {
            let shown: String = podssh_ws::text::one_line(other).chars().take(60).collect();
            Err(Refused::Words(format!("croc's relay answered {shown:?} for the room")))
        }
    }
}

/// A sealed answer, as text.
fn opened(key: &[u8; 32], sealed: &[u8]) -> Result<String, Refused> {
    let plain = crypt::open(key, sealed).ok_or_else(|| Refused::Words("croc's relay's answer does not open".into()))?;
    Ok(String::from_utf8_lossy(&plain).into_owned())
}
