//! A meeting in a room of croc's relay (T-694): the relay's handshake for
//! the room (`super::relay`), then podssh's own words each way through the
//! relay's pipe, each one frame of croc's: a hello with this end's part and
//! a nonce, then a proof of the pair's secret over both nonces, as the
//! transit road's (`crate::transit::meet`). Each end sends its hello at
//! once: a member that made the room waits with it unread at the relay,
//! which pipes it to the second once it came (tcp.go's comment on the
//! frames that a waiting peer buffered). Until then the relay sends the
//! first member a frame of the one byte 1 each second, which is read past.
//! The relay pairs any two members of a room, so two clients of one pair
//! can meet each other: their parts tell them apart. The relay sees the
//! room; a peer that knows it alone, as the relay does, proves nothing, so
//! the node's door stays the pair's.

use std::fmt;
use std::time::Duration;

use podssh_ws::RelaySession;
use tokio::io::{AsyncRead, AsyncWrite};

use super::relay::{admit, Admission, Refused};
use super::rooms::{Rooms, PROOF_BYTES};
use super::wire::{Cut, Wire, FRAME_MOST};
use crate::session::secret::Entropy;
use crate::transit::Part;

/// The version of podssh's words after the relay's handshake.
pub const VERSION: u8 = 1;
/// The bytes of a nonce.
pub const NONCE: usize = 32;
/// A hello: the version, the part, the nonce; never one byte long, so it is
/// never taken for the relay's frame of a waiting member.
pub const HELLO: usize = 2 + NONCE;
/// The relay's frame to a member that waits for the second.
pub const WAITING: &[u8] = &[1];
/// How long the hello and the proof of a peer that met this end may take.
pub const PROOF_LIMIT: Duration = Duration::from_secs(10);

/// Why a meeting gave no link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Missed {
    /// No peer came to the room within the wait.
    Alone(Duration),
    /// Two members are in the room already.
    Full,
    /// The relay limits joins of this source or room.
    Limited,
    /// The relay or the bridge ended the connection before a peer spoke.
    Dropped(String),
    /// The relay refused the handshake, or answered words that are not its.
    Refused(String),
    /// A peer of this end's own part met it: two clients of one pair.
    SamePart,
    /// The peer did not prove the pair: one that knows the room alone, or
    /// the end of another pair.
    NotProven(String),
    /// The connection failed, or the peer said nothing in time.
    Broken(String),
}

impl fmt::Display for Missed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Missed::Alone(wait) => write!(f, "no peer came to the room within {} s", wait.as_secs()),
            Missed::Full => f.write_str("the room is taken by two members"),
            Missed::Limited => f.write_str("croc's relay limits the joins of this source (rate limited)"),
            Missed::Dropped(why) => write!(f, "croc's relay ended the connection: {why}"),
            Missed::Refused(why) | Missed::Broken(why) => f.write_str(why),
            Missed::SamePart => f.write_str("another client of the pair met this one"),
            Missed::NotProven(why) => write!(f, "the peer did not prove the pair: {why}"),
        }
    }
}

impl From<Cut> for Missed {
    fn from(cut: Cut) -> Missed {
        match cut {
            Cut::Dropped(why) => Missed::Dropped(why),
            Cut::Broken(why) => Missed::Broken(why),
        }
    }
}

/// Meet the other end in the room `slot` of `rooms` over `session`, as
/// `part`, waiting at most `wait` for a peer once in the room (`None`: as
/// long as the connection lives): the bytes that came after the peer's
/// proof, which are the first of the link.
pub async fn meet<S>(
    session: &RelaySession<S>,
    password: &str,
    rooms: &Rooms,
    slot: usize,
    part: Part,
    wait: Option<Duration>,
    entropy: &mut (dyn Entropy + Send),
) -> Result<Vec<u8>, Missed>
where
    S: AsyncRead + AsyncWrite + Send,
{
    let mut wire = Wire::new(session);
    match admit(&mut wire, password, &rooms.room(slot), entropy).await {
        Ok(Admission::In) => {}
        Ok(Admission::Full) => return Err(Missed::Full),
        Ok(Admission::Limited) => return Err(Missed::Limited),
        Err(Refused::Cut(cut)) => return Err(cut.into()),
        Err(refused) => return Err(Missed::Refused(refused.to_string())),
    }
    greet(wire, rooms, part, wait, entropy).await
}

/// The hello and the proof each way, once in the room.
pub async fn greet<S>(
    mut wire: Wire<'_, S>,
    rooms: &Rooms,
    part: Part,
    wait: Option<Duration>,
    entropy: &mut (dyn Entropy + Send),
) -> Result<Vec<u8>, Missed>
where
    S: AsyncRead + AsyncWrite + Send,
{
    let mut nonce = [0u8; NONCE];
    entropy.fill(&mut nonce).map_err(|e| Missed::Broken(e.to_string()))?;
    let mut hello = Vec::with_capacity(HELLO);
    hello.extend_from_slice(&[VERSION, part.byte()]);
    hello.extend_from_slice(&nonce);
    wire.send(&hello).await?;
    let theirs = match wait {
        Some(wait) => tokio::time::timeout(wait, peer_hello(&mut wire)).await.map_err(|_| Missed::Alone(wait))??,
        None => peer_hello(&mut wire).await?,
    };
    if theirs.len() != HELLO || theirs[0] != VERSION {
        let why = match theirs.first() {
            Some(&v) if theirs.len() == HELLO => {
                format!("its words are of version {v}, and this podssh's of {VERSION}")
            }
            _ => "its hello is not podssh's".to_string(),
        };
        return Err(Missed::NotProven(why));
    }
    if theirs[1] == part.byte() {
        return Err(Missed::SamePart);
    }
    if theirs[1] != part.other().byte() {
        return Err(Missed::NotProven("its hello is not podssh's".into()));
    }
    let peer = &theirs[2..];
    wire.send(&rooms.prove(part.byte(), &nonce, peer)).await?;
    let late = || Missed::Broken(format!("the peer said too little within {} s", PROOF_LIMIT.as_secs()));
    let proof = tokio::time::timeout(PROOF_LIMIT, wire.frame(PROOF_BYTES)).await.map_err(|_| late())??;
    if !rooms.verify(part.other().byte(), peer, &nonce, &proof) {
        return Err(Missed::NotProven("its proof is not of this pair's secret".into()));
    }
    Ok(wire.rest())
}

/// The peer's hello: the first frame that is not the relay's to a member
/// that waits.
async fn peer_hello<S>(wire: &mut Wire<'_, S>) -> Result<Vec<u8>, Missed>
where
    S: AsyncRead + AsyncWrite + Send,
{
    loop {
        let frame = wire.frame(FRAME_MOST).await?;
        if frame != WAITING {
            return Ok(frame);
        }
    }
}
