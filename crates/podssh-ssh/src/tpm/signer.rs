//! The login's signer of a key sealed to the machine (T-839): the key
//! file's, which signs in the TPM once the server took the key. russh asks
//! a signer only after the server's answer to the query, so a key that the
//! server does not take sends nothing to the TPM.

use std::sync::Arc;

use russh::keys::agent::AgentIdentity;
use russh::keys::HashAlg;

use super::KeyFile;
use crate::log::Log;

/// Why the TPM did not sign.
#[derive(Debug)]
pub(crate) struct TpmError(pub String);

impl From<russh::SendError> for TpmError {
    fn from(_: russh::SendError) -> Self {
        TpmError("the session ended".into())
    }
}

impl std::fmt::Display for TpmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The key of a key file of a TPM.
pub(crate) struct TpmSigner {
    pub file: KeyFile,
    pub log: Arc<Log>,
}

impl russh::Signer for TpmSigner {
    type Error = TpmError;

    /// `to_sign`, then its signature as an agent gives it: the length, then
    /// the signature of SSH. The TPM works on a thread of its own, as each
    /// command can take a second.
    async fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, TpmError> {
        let (file, log) = (self.file.clone(), self.log.clone());
        let data = to_sign.clone();
        let blob = tokio::task::spawn_blocking(move || {
            log.debug("signing in the TPM");
            super::sign_blob(&file, &data)
        })
        .await
        .map_err(|_| TpmError("the thread of the TPM failed".into()))?
        .map_err(TpmError)?;
        to_sign.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        to_sign.extend_from_slice(&blob);
        Ok(to_sign)
    }
}
