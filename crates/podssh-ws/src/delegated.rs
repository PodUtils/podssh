//! The application-layer delegated credential of a cover name (#225,
//! T-765 and T-766): the server issues it after a client authenticated, and
//! both ends check it against the operator's pinned key, the same name, its
//! window and the TLS exporter of the connection.
//!
//! It is not RFC 9345 and it is not a TLS delegated credential. There is no
//! CertificateVerify, no certificate extension and no wire format of a TLS
//! handshake: the credential travels as JSON after the handshake, and the TLS
//! stack still authenticates the certificate of the name.
//!
//! The issuer key is Ed25519 and operator-held: the relay is configured with
//! its public half, pinned, and an attacker who holds only the certificate
//! cannot mint a credential the relay accepts. The relay checks each
//! credential on the live upgrade, against the pinned key, the name, the
//! window, the exporter and the set of signatures it has already spent. A
//! wrong key, a wrong name, an expired credential and a replayed one are each
//! refused by name. The certificate alone proves nothing about the credential:
//! the exporter binding ties it to the one connection.

use std::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use pod_cover::{Credential, CredentialError};
use rustls::{ClientConnection, ServerConnection};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::client::TlsStream;

/// The header that carries an encoded credential on the live upgrade.
pub const CREDENTIAL_HEADER: &str = "X-Cover-Credential";

/// The field of the encoded credential that names the issuer's public key.
const ISSUER_KEY: &str = "issuer_key";

/// The label of the TLS exporter that both ends export.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-podssh-cover";

/// The context of the TLS exporter that both ends export.
pub const EXPORTER_CONTEXT: &[u8] = b"delegated credential";

/// The exporter of the server's handshake, 32 bytes.
pub fn server_exporter(conn: &ServerConnection) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, Some(EXPORTER_CONTEXT)).ok()?;
    Some(out)
}

/// The exporter of the client's handshake, 32 bytes.
pub fn client_exporter(conn: &ClientConnection) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, Some(EXPORTER_CONTEXT)).ok()?;
    Some(out)
}

/// The Ed25519 signing key of the operator, from its 32-byte seed. The seed
/// is the operator's secret; no certificate and no public value derives it.
pub fn issuer_signing_key(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// The public half that the relay pins, from the operator's signing key.
pub fn issuer_verifying_key(signing: &SigningKey) -> VerifyingKey {
    signing.verifying_key()
}

/// The operator's signing key from a secret file's contents: 64 hexadecimal
/// digits of the 32-byte seed, with the whitespace that a file ends with.
pub fn parse_issuer_seed(text: &str) -> Result<SigningKey, String> {
    let word = text.trim();
    let raw = hex::decode(word).map_err(|_| "the issuer secret is no hexadecimal")?;
    let seed: [u8; 32] =
        raw.try_into().map_err(|raw: Vec<u8>| format!("the issuer secret is {} bytes, not 32", raw.len()))?;
    Ok(issuer_signing_key(&seed))
}

/// The public key that the relay pins, from its hexadecimal form.
pub fn parse_verifying_key(text: &str) -> Result<VerifyingKey, String> {
    let word = text.trim();
    let raw = hex::decode(word).map_err(|_| "the issuer public key is no hexadecimal")?;
    let bytes: [u8; 32] =
        raw.try_into().map_err(|raw: Vec<u8>| format!("the issuer public key is {} bytes, not 32", raw.len()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "the issuer public key is not an Ed25519 key".into())
}

/// Check `credential` against the pinned operator key `key`, the name
/// `chain_name`, the instant `now` and the exporter of the connection.
/// A different issuer or name, a window that does not hold `now`, another
/// exporter and another key are each refused by name.
pub fn verify(
    credential: &Credential,
    chain_name: &str,
    key: &VerifyingKey,
    exporter: &[u8],
    now: i64,
) -> Result<(), CredentialError> {
    credential.verify(chain_name, now, Some(exporter), key)
}

/// `credential` as one JSON object, its keys in hexadecimal.
pub fn encode(credential: &Credential) -> String {
    serde_json::json!({
        "issuer": credential.issuer,
        "name": credential.name,
        "not_before": credential.not_before,
        "not_after": credential.not_after,
        "subject_key": hex::encode(credential.subject_key),
        "exporter": credential.exporter.map(hex::encode),
        "signature": hex::encode(credential.signature),
    })
    .to_string()
}

/// [`encode`] as one header value: the JSON in hexadecimal, so that no
/// control character of it reaches a header line.
pub fn encode_wire(credential: &Credential) -> String {
    hex::encode(encode(credential))
}

/// [`decode`] from one header value written by [`encode_wire`].
pub fn decode_wire(text: &str) -> Result<Credential, String> {
    let raw = hex::decode(text.trim()).map_err(|_| "the credential header is no hexadecimal")?;
    let json = String::from_utf8(raw).map_err(|_| "the credential header is no UTF-8")?;
    decode(&json)
}

/// [`encode`] with the issuer's public key, so that a client can verify the
/// signature against the key that the authenticated connection delivered.
pub fn encode_with_issuer(credential: &Credential, issuer: &VerifyingKey) -> String {
    let mut value: serde_json::Value =
        serde_json::from_str(&encode(credential)).expect("an encoded credential is JSON");
    value[ISSUER_KEY] = serde_json::json!(hex::encode(issuer.as_bytes()));
    value.to_string()
}

/// [`decode`], and the issuer public key that the encoded credential names.
/// A missing or malformed key is a refusal that names the field.
pub fn decode_with_issuer(text: &str) -> Result<(Credential, VerifyingKey), String> {
    let credential = decode(text)?;
    let value: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("the credential: {e}"))?;
    let hexed = value
        .get(ISSUER_KEY)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("the credential has no {ISSUER_KEY}"))?;
    let raw = hex::decode(hexed).map_err(|_| format!("the credential's {ISSUER_KEY} is no hexadecimal"))?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|raw: Vec<u8>| format!("the credential's {ISSUER_KEY} is {} bytes, not 32", raw.len()))?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| format!("the credential's {ISSUER_KEY} is not a key"))?;
    Ok((credential, key))
}

/// The credential of one JSON object written by [`encode`]. A missing field,
/// a key that is no hexadecimal of the right length, and a field of the wrong
/// type are each a refusal that names the field.
pub fn decode(text: &str) -> Result<Credential, String> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("the credential: {e}"))?;
    let string = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("the credential has no {key}"))
    };
    let number = |key: &str| {
        value.get(key).and_then(serde_json::Value::as_i64).ok_or_else(|| format!("the credential has no {key}"))
    };
    let bytes = |key: &str, len: usize| {
        let text = string(key)?;
        let raw = hex::decode(&text).map_err(|_| format!("the credential's {key} is no hexadecimal"))?;
        if raw.len() != len {
            return Err(format!("the credential's {key} is {} bytes, not {len}", raw.len()));
        }
        let mut out = vec![0u8; len];
        out.copy_from_slice(&raw);
        Ok(out)
    };
    let subject: [u8; 32] = bytes("subject_key", 32)?.try_into().expect("32 bytes");
    let signature: [u8; 64] = bytes("signature", 64)?.try_into().expect("64 bytes");
    let exporter = match value.get("exporter") {
        None | Some(serde_json::Value::Null) => None,
        Some(_) => Some(bytes("exporter", 32)?.try_into().expect("32 bytes")),
    };
    Ok(Credential {
        issuer: string("issuer")?,
        name: string("name")?,
        not_before: number("not_before")?,
        not_after: number("not_after")?,
        subject_key: subject,
        exporter,
        signature,
    })
}

/// Why a client did not get a verified credential.
#[derive(Debug)]
pub enum DelegatedError {
    /// The handshake has no exporter to bind the credential to.
    NoExporter,
    /// The server presented no leaf certificate.
    NoLeaf,
    /// The request or its answer did not cross the connection.
    Io(std::io::Error),
    /// The answer is no HTTP response of one head and one body.
    Http(String),
    /// The server refused the request with `status`.
    Refused { status: u16, body: String },
    /// The answer is not a credential.
    Decode(String),
    /// The credential did not verify against this chain, name, window and
    /// exporter. The text is pod-cover's, and names the field that failed.
    Verify(CredentialError),
}

impl fmt::Display for DelegatedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DelegatedError::NoExporter => f.write_str("the connection has no TLS exporter to bind a credential to"),
            DelegatedError::NoLeaf => f.write_str("the server presented no certificate"),
            DelegatedError::Io(error) => write!(f, "the delegate request: {}", crate::text::said(&error)),
            DelegatedError::Http(why) => write!(f, "the delegate answer: {why}"),
            DelegatedError::Refused { status, body } => {
                write!(f, "the delegate request was refused with {status}: {body}")
            }
            DelegatedError::Decode(why) => f.write_str(why),
            DelegatedError::Verify(why) => f.write_str(&why.to_string()),
        }
    }
}

impl std::error::Error for DelegatedError {}

/// The most bytes of a delegate answer: a credential is a few hundred.
const MOST_ANSWER: usize = 64 * 1024;

/// Ask `tls`, an authenticated connection to the cover `name`, for a
/// credential of `subject_key`, and verify it against the issuer key that the
/// answer carries over that authenticated connection, the `name`, `now` and
/// the connection's exporter. The leaf is only required to exist: it
/// authenticates the name, and no credential key is derived from it.
/// `token` goes in `X-Relay-Token` and nowhere else: no error quotes it.
pub async fn request_and_verify<S>(
    tls: &mut TlsStream<S>,
    token: &str,
    subject_key: [u8; 32],
    name: &str,
    now: i64,
) -> Result<(Credential, VerifyingKey), DelegatedError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (exporter, _leaf) = {
        let (_, connection) = tls.get_ref();
        let exporter = client_exporter(connection).ok_or(DelegatedError::NoExporter)?;
        let leaf = connection
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|leaf| leaf.as_ref().to_vec())
            .ok_or(DelegatedError::NoLeaf)?;
        (exporter, leaf)
    };
    let body = serde_json::json!({ "subject_key": hex::encode(subject_key) }).to_string();
    // Keep-alive: the connection's exporter is what the credential binds,
    // so the upgrade that uses it must follow on this same connection
    // (T-765). A caller that is finished drops `tls` after the answer.
    let request = format!(
        "POST /v1/delegate HTTP/1.1\r\nHost: {name}\r\nX-Relay-Token: {token}\r\nContent-Type: \
         application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(request.as_bytes()).await.map_err(DelegatedError::Io)?;
    tls.flush().await.map_err(DelegatedError::Io)?;
    let (status, _head, body) = read_answer(&mut *tls).await?;
    if status != 200 {
        // A refusal's body is the server's, and a broken or hostile server
        // could echo the header: never put the token in an error's words.
        return Err(DelegatedError::Refused { status, body: body.replace(token, "<redacted>") });
    }
    let (credential, issuer) = decode_with_issuer(&body).map_err(DelegatedError::Decode)?;
    // The connection authenticated the name's certificate; the issuer key
    // arrived over it, and the signature covers the fields. A no-op here
    // would accept a credential of any key, which the server-side check in
    // `podssh-relay` refuses before any tunnel opens.
    verify(&credential, name, &issuer, &exporter, now).map_err(DelegatedError::Verify)?;
    Ok((credential, issuer))
}

/// One HTTP/1.1 answer: its status, its head, and the body of the length
/// that the head names. Reading stops at that length, so the connection is
/// left for the caller's next request (T-765).
async fn read_answer<S>(tls: &mut S) -> Result<(u16, String, String), DelegatedError>
where
    S: AsyncRead + Unpin,
{
    let mut answer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(split) = answer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&answer[..split]).into_owned();
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.trim().eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().ok())?
                })
                .ok_or_else(|| DelegatedError::Http("the answer names no length".into()))?;
            if length > MOST_ANSWER {
                return Err(DelegatedError::Http("the body is longer than a credential's answer".into()));
            }
            while answer.len() < split + 4 + length {
                let n = tls.read(&mut chunk).await.map_err(DelegatedError::Io)?;
                if n == 0 {
                    return Err(DelegatedError::Http("the answer ended before its body".into()));
                }
                answer.extend_from_slice(&chunk[..n]);
            }
            let status = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|code| code.parse::<u16>().ok())
                .ok_or_else(|| DelegatedError::Http("no status line".into()))?;
            let body = String::from_utf8_lossy(&answer[split + 4..split + 4 + length]).into_owned();
            return Ok((status, head, body));
        }
        if answer.len() > MOST_ANSWER {
            return Err(DelegatedError::Http("the head is longer than a credential's answer".into()));
        }
        let n = tls.read(&mut chunk).await.map_err(DelegatedError::Io)?;
        if n == 0 {
            return Err(DelegatedError::Http("no end of the head".into()));
        }
        answer.extend_from_slice(&chunk[..n]);
    }
}

/// The subject key of a request's one JSON object, `{"subject_key": HEX}`.
/// A missing field, a key that is no hexadecimal of 32 bytes, and a body that
/// is no JSON are each a refusal that says why.
pub fn subject_key(text: &str) -> Result<[u8; 32], String> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("the request: {e}"))?;
    let hex = value.get("subject_key").and_then(serde_json::Value::as_str).ok_or("the request has no subject_key")?;
    let raw = hex::decode(hex).map_err(|_| "the subject_key is no hexadecimal")?;
    raw.try_into().map_err(|raw: Vec<u8>| format!("the subject_key is {} bytes, not 32", raw.len()))
}

#[cfg(test)]
#[path = "delegated_tests.rs"]
mod tests;
