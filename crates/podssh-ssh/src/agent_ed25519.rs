//! Ed25519 signatures of plain bytes by the SSH agent: a bearer of podssh
//! (`--bearer agent`) is signed so, for a person whose key lives in an agent
//! alone. The request is SSH_AGENTC_SIGN_REQUEST with flags 0, as an Ed25519
//! key takes none; the answer is an SSH signature blob, `ssh-ed25519` and
//! the 64 bytes. Each request has a time limit, as an agent that asks its
//! person to confirm may never answer.

use std::time::Duration;

use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_key::public::{Ed25519PublicKey, KeyData};
use russh::keys::ssh_key::Signature;
use russh::keys::{Algorithm, PublicKey};

use crate::keys::connect_agent;
use crate::options::Agent;

/// The limit of each request to the agent: within the far end's wait for
/// the proof that carries the signature.
pub const WAIT: Duration = Duration::from_secs(20);

/// The Ed25519 keys that the agent of `choice` holds as plain keys, in its
/// order; `None` when no agent runs. A key held only in a certificate is
/// left out: the request names the plain key.
pub async fn ed25519_keys(choice: &Agent) -> Result<Option<Vec<[u8; 32]>>, String> {
    match tokio::time::timeout(WAIT, listed(choice)).await {
        Ok(listed) => listed,
        Err(_) => Err(format!("the SSH agent gave no list of its keys within {} s", WAIT.as_secs())),
    }
}

/// [`ed25519_keys`] with no time limit.
async fn listed(choice: &Agent) -> Result<Option<Vec<[u8; 32]>>, String> {
    let Some(mut agent) = connect_agent(choice).await? else { return Ok(None) };
    let held = agent.request_identities().await.map_err(|e| format!("the SSH agent gave no list of its keys: {e}"))?;
    let plain = held.iter().filter_map(|id| match id {
        AgentIdentity::PublicKey { key, .. } => raw_ed25519(key),
        AgentIdentity::Certificate { .. } => None,
    });
    Ok(Some(plain.collect()))
}

/// The 32 bytes of an Ed25519 key; `None` for each other kind.
pub fn raw_ed25519(key: &PublicKey) -> Option<[u8; 32]> {
    match key.key_data() {
        KeyData::Ed25519(key) => Some(key.0),
        _ => None,
    }
}

/// The agent of `choice` signs `data` with its Ed25519 key `key`: the 64
/// bytes of the signature, or why not in one line.
pub async fn sign_ed25519(choice: &Agent, key: &[u8; 32], data: &[u8]) -> Result<[u8; 64], String> {
    let signature = match tokio::time::timeout(WAIT, signed(choice, key, data)).await {
        Ok(signed) => signed?,
        Err(_) => return Err(format!("the SSH agent did not sign within {} s", WAIT.as_secs())),
    };
    ed25519_bytes(&signature)
}

/// [`sign_ed25519`]'s request, with no time limit.
async fn signed(choice: &Agent, key: &[u8; 32], data: &[u8]) -> Result<Signature, String> {
    let public = PublicKey::from(Ed25519PublicKey(*key));
    let Some(mut agent) = connect_agent(choice).await? else {
        return Err("no SSH agent runs now: SSH_AUTH_SOCK names none".to_string());
    };
    // No hash algorithm: an Ed25519 key's request carries flags 0.
    agent.sign_request_signature(&public, None, data).await.map_err(|e| format!("the SSH agent did not sign: {e}"))
}

/// The 64 bytes of an Ed25519 signature; an agent that answered with
/// another kind is refused, as its bytes would not verify.
pub fn ed25519_bytes(signature: &Signature) -> Result<[u8; 64], String> {
    if signature.algorithm() != Algorithm::Ed25519 {
        return Err(format!("the SSH agent signed with {}, not ssh-ed25519", signature.algorithm()));
    }
    signature.as_bytes().try_into().map_err(|_| "the SSH agent's Ed25519 signature is not 64 bytes".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An SSH string: its length, then its bytes.
    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    /// The agent's answer, `string "ssh-ed25519", string SIG`, read from
    /// fixed bytes: the 64 bytes come back as they were.
    #[test]
    fn an_ed25519_signature_blob_gives_its_64_bytes() {
        let sig: Vec<u8> = (0u8..64).collect();
        let mut blob = string(b"ssh-ed25519");
        blob.extend(string(&sig));
        assert_eq!(&blob[..15], b"\0\0\0\x0bssh-ed25519", "the form of the blob");
        let read = Signature::try_from(&blob[..]).expect("an SSH signature blob");
        assert_eq!(ed25519_bytes(&read).unwrap().to_vec(), sig);
    }

    /// A signature of another kind, or of another length, is no Ed25519
    /// signature, whatever its bytes.
    #[test]
    fn a_signature_of_another_kind_is_refused() {
        let other = Signature::new(Algorithm::Rsa { hash: None }, vec![1u8; 256]).expect("an RSA signature");
        assert!(ed25519_bytes(&other).unwrap_err().contains("not ssh-ed25519"));
        let mut blob = string(b"ssh-ed25519");
        blob.extend(string(&[7u8; 63]));
        let refused = match Signature::try_from(&blob[..]) {
            Ok(read) => ed25519_bytes(&read).is_err(),
            Err(_) => true,
        };
        assert!(refused, "63 bytes are no Ed25519 signature");
    }

    /// An Ed25519 key gives its 32 bytes, which the request names.
    #[test]
    fn an_ed25519_key_is_its_32_bytes() {
        let key = PublicKey::from(Ed25519PublicKey([9u8; 32]));
        assert_eq!(raw_ed25519(&key), Some([9u8; 32]));
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
    }
}
