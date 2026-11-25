//! `podssh serve`'s host key in a TPM (T-839). russh's server takes its
//! host keys as `PrivateKey`s, and asks the server's own signer first for
//! each one (`Config::host_key_signer`, podssh's patch 0015 of russh). So a
//! key file of a TPM becomes a stand-in: the TPM's public key with a private
//! scalar of zeros, which no ECDSA signs with (p256 refuses a zero scalar,
//! so a path that missed the signer fails and never signs wrong). The
//! stand-in is kept here with its key file; serve's signer finds it by its
//! public key, and the TPM signs each exchange hash. Neither russh nor
//! podssh holds the private key.

use std::sync::{Arc, Mutex, MutexGuard};

use russh::keys::ssh_key::private::{EcdsaKeypair, EcdsaPrivateKey, KeypairData};
use russh::keys::ssh_key::public::{EcdsaPublicKey, KeyData};
use russh::keys::{PrivateKey, PublicKey};

use super::{Device, KeyFile, Opener};

/// A host key of a TPM: its file, the way to its TPM, and one signature at
/// a time, as a TPM in software serves one connection.
pub struct HostTpm {
    file: KeyFile,
    open: Opener,
    turn: Mutex<()>,
}

impl HostTpm {
    /// The SSH signature (`ecdsa-sha2-nistp256`) of `data`, an exchange
    /// hash: the TPM signs its SHA-256. It waits for the TPM, each command
    /// for 30 s at most.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let _turn = self.turn.lock().unwrap_or_else(|e| e.into_inner());
        let mut transport = (self.open)()?;
        super::sign_with(&mut *transport, &self.file, data)
    }
}

/// The host keys of a TPM of this process, by their public keys.
static HELD: Mutex<Vec<(KeyData, Arc<HostTpm>)>> = Mutex::new(Vec::new());

fn held() -> MutexGuard<'static, Vec<(KeyData, Arc<HostTpm>)>> {
    HELD.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether `text`, a file's, is a key file of a TPM.
pub fn is_key_text(text: &str) -> bool {
    super::keyfile::is_pem(text.as_bytes())
}

/// The stand-in of the host key in `text`, a key file of a TPM, on the TPM
/// that the probe finds. The TPM must answer and the key must sign a fresh
/// challenge now, else why not ("no TPM: ..." where there is none): a host
/// key that cannot sign is never served.
pub fn stand_in(text: &str) -> Result<PrivateKey, String> {
    stand_in_on(super::probe(None)?, text)
}

/// [`stand_in`] on the TPM of `device`.
pub fn stand_in_on(device: Device, text: &str) -> Result<PrivateKey, String> {
    stand_in_with(super::opener_of(device), text)
}

/// [`stand_in`] on the TPM that `open` reaches.
pub(crate) fn stand_in_with(open: Opener, text: &str) -> Result<PrivateKey, String> {
    let file = KeyFile::from_pem(text)?;
    let public = super::public_key(&file)?;
    {
        let mut transport = open()?;
        super::signs_now(&mut *transport, &file, &public).map_err(|e| format!("the key of the TPM {e}"))?;
    }
    let key = stand_in_key(&public, file.description.clone().unwrap_or_default())?;
    let tpm = Arc::new(HostTpm { file, open, turn: Mutex::new(()) });
    let mut held = held();
    held.retain(|(data, _)| data != public.key_data());
    held.push((public.key_data().clone(), tpm));
    Ok(key)
}

/// A private key of `public` whose scalar is zeros.
fn stand_in_key(public: &PublicKey, comment: String) -> Result<PrivateKey, String> {
    let KeyData::Ecdsa(EcdsaPublicKey::NistP256(point)) = public.key_data() else {
        return Err("a key of a TPM that is not ECDSA P-256, which podssh does not make".into());
    };
    let pair = EcdsaKeypair::NistP256 { public: *point, private: EcdsaPrivateKey::from([0u8; 32]) };
    PrivateKey::new(KeypairData::Ecdsa(pair), comment).map_err(|e| format!("the host key of the TPM: {e}"))
}

/// The TPM of `key`, when [`stand_in`] made it.
pub fn of(key: &PrivateKey) -> Option<Arc<HostTpm>> {
    held().iter().find(|(data, _)| data == key.public_key().key_data()).map(|(_, tpm)| tpm.clone())
}

/// Whether `key` is a stand-in: an ECDSA P-256 key whose scalar is zeros,
/// for which only a TPM signs.
pub fn is_stand_in(key: &PrivateKey) -> bool {
    match key.key_data() {
        KeypairData::Ecdsa(EcdsaKeypair::NistP256 { private, .. }) => private.as_slice().iter().all(|b| *b == 0),
        _ => false,
    }
}

#[cfg(test)]
#[path = "host_tests.rs"]
mod tests;
