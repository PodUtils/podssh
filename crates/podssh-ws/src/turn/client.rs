//! A TURN client's transactions on one TCP or TLS connection to the server:
//! STUN over a stream, each message framed by its own header (RFC 8489,
//! 6.2.2), the long-term credential learned from the server's first 401
//! and kept for each later request, and a stale nonce (438) answered once
//! with the new one.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use super::msg::{self, ERROR, INDICATION, MESSAGE_INTEGRITY, NONCE, REALM, SOFTWARE, SUCCESS, USERNAME};
use super::{Credentials, TurnError};
use crate::stun::{self, TransactionId, HEADER, MAGIC};

/// The largest message taken: a TURN answer is a few hundred bytes, and a
/// header that says more is no TURN server's.
const LARGEST: usize = 4096;

/// What the server asked of the credential, and the key made of it.
pub struct Auth {
    pub user: String,
    pub realm: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key: Zeroizing<[u8; 16]>,
}

impl Auth {
    /// The credential for the realm and nonce of a 401.
    pub fn of(credentials: &Credentials, realm: &[u8], nonce: &[u8]) -> Auth {
        let (user, password) = credentials.pair();
        let realm_text = String::from_utf8_lossy(realm);
        let key = Zeroizing::new(msg::long_term_key(&user, &realm_text, &password));
        Auth { user, realm: realm.to_vec(), nonce: nonce.to_vec(), key }
    }

    /// `attributes`, then USERNAME, REALM and NONCE, signed with the key.
    pub fn sign(&self, kind: u16, id: &TransactionId, attributes: &[(u16, &[u8])]) -> Vec<u8> {
        let mut all: Vec<(u16, &[u8])> = attributes.to_vec();
        all.push((USERNAME, self.user.as_bytes()));
        all.push((REALM, &self.realm));
        all.push((NONCE, &self.nonce));
        msg::signed(kind, id, &all, Some(&self.key[..]))
    }
}

/// A fresh transaction's id, from the system's random source.
pub fn transaction_id() -> Result<TransactionId, TurnError> {
    use rustls::crypto::SecureRandom as _;
    let mut id = [0u8; 12];
    crate::crypto::random::OsRandom
        .fill(&mut id)
        .map_err(|_| TurnError::Protocol("no bytes from the system's random source".into()))?;
    Ok(id)
}

/// One message from `stream`: its header, then the length that it names,
/// and nothing past it, as the bytes after a ConnectionBind's answer are the
/// target's.
pub async fn read_message<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, TurnError> {
    let mut out = vec![0u8; HEADER];
    stream.read_exact(&mut out).await.map_err(|e| closed(&e))?;
    if u32::from_be_bytes([out[4], out[5], out[6], out[7]]) != MAGIC || out[0] & 0xc0 != 0 {
        return Err(TurnError::Protocol("it answered with bytes that are not STUN's".into()));
    }
    let length = usize::from(u16::from_be_bytes([out[2], out[3]]));
    if length > LARGEST || length % 4 != 0 {
        return Err(TurnError::Protocol(format!("it sent a STUN message of {length} bytes")));
    }
    out.resize(HEADER + length, 0);
    stream.read_exact(&mut out[HEADER..]).await.map_err(|e| closed(&e))?;
    stun::parse(&out).map_err(|why| TurnError::Protocol(format!("a STUN message that does not read: {why}")))?;
    Ok(out)
}

fn closed(e: &std::io::Error) -> TurnError {
    match e.kind() {
        std::io::ErrorKind::UnexpectedEof => TurnError::Protocol("it closed the connection".into()),
        _ => TurnError::Protocol(format!("the connection failed: {e}")),
    }
}

/// The answer of a transaction, read.
pub struct Answer {
    pub bytes: Vec<u8>,
}

impl Answer {
    pub fn message(&self) -> stun::Message<'_> {
        stun::parse(&self.bytes).expect("read_message parsed it")
    }

    pub fn is_success(&self) -> bool {
        self.message().kind & ERROR == SUCCESS
    }

    /// The error's code and reason; 0 and words of their own where the
    /// answer has no ERROR-CODE that reads.
    pub fn error(&self) -> (u16, String) {
        match self.message().error() {
            Some(Ok((code, reason))) => (code, crate::text::one_line(&reason)),
            Some(Err(why)) => (0, why),
            None => (0, "an error with no ERROR-CODE".into()),
        }
    }

    pub fn attribute(&self, kind: u16) -> Option<Vec<u8>> {
        self.message().attribute(kind).map(<[u8]>::to_vec)
    }

    /// The server's software, where it says it.
    pub fn software(&self) -> Option<String> {
        self.attribute(SOFTWARE).map(|v| crate::text::one_line(&String::from_utf8_lossy(&v)))
    }
}

/// Send `request` and read until the answer of its id: indications
/// (a ConnectionAttempt of a peer that dialed in) and answers of other
/// transactions are passed over. Bounded by `wait`.
pub async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &[u8],
    wait: Duration,
    step: &'static str,
) -> Result<Answer, TurnError> {
    let id: TransactionId = request[8..HEADER].try_into().expect("a request has a header");
    let work = async {
        stream.write_all(request).await.map_err(|e| closed(&e))?;
        stream.flush().await.map_err(|e| closed(&e))?;
        loop {
            let bytes = read_message(stream).await?;
            let kind = u16::from_be_bytes([bytes[0], bytes[1]]);
            if bytes[8..HEADER] == id && kind & ERROR != INDICATION && kind & ERROR != 0 {
                return Ok(Answer { bytes });
            }
        }
    };
    tokio::time::timeout(wait, work).await.map_err(|_| TurnError::Timeout { step, after: wait })?
}

/// A request of `method` with `attributes`, signed with `auth`, its answer
/// checked: a stale nonce (438) is tried again once with the server's new
/// nonce, and an answer that carries MESSAGE-INTEGRITY must carry the
/// credential's (RFC 8489, 9.2.4), else it is no answer of this server.
pub async fn signed<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    auth: &mut Auth,
    method: u16,
    attributes: &[(u16, &[u8])],
    wait: Duration,
    step: &'static str,
) -> Result<Answer, TurnError> {
    for round in 0..2 {
        let id = transaction_id()?;
        let answer = exchange(stream, &auth.sign(method, &id, attributes), wait, step).await?;
        if !answer.is_success() && answer.error().0 == 438 && round == 0 {
            if let Some(nonce) = answer.attribute(NONCE) {
                auth.nonce = nonce;
                continue;
            }
        }
        return checked(answer, &auth.key[..]);
    }
    unreachable!("the second round returns")
}

/// `answer`, unless its MESSAGE-INTEGRITY is not the key's. An error
/// response of 401 may carry none, and a server may sign none.
pub fn checked(answer: Answer, key: &[u8]) -> Result<Answer, TurnError> {
    let has = answer.message().attribute(MESSAGE_INTEGRITY).is_some();
    if has && msg::integrity(&answer.bytes, key) != Some(true) {
        return Err(TurnError::Protocol("an answer whose MESSAGE-INTEGRITY is not of this credential".into()));
    }
    Ok(answer)
}
