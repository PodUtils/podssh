//! A key file sealed to a TPM (T-839), offered as [`PublicKeys`] offers a
//! key file of a security key: the probe first, and with no TPM the key is
//! skipped with the reason before the server sees it. Else the TPM signs
//! once the server took the key; its time does not count against the
//! server's limit, and a refusal (the boot state changed, the file is of
//! another TPM) lets the next key go on.

use std::path::Path;
use std::sync::{Arc, Mutex};

use russh::client::Handle;

use super::PublicKeys;
use crate::answer::{within_signing, AgentTime, Timed};
use crate::auth::Step;
use crate::handler::Client;
use crate::tpm::signer::TpmSigner;

impl PublicKeys {
    pub(crate) async fn try_tpm_key(
        &mut self,
        handle: &mut Handle<Client>,
        user: &str,
        path: &Path,
    ) -> Result<Option<Step>, String> {
        let read = crate::tpm::read_key_file(path).and_then(|file| Ok((crate::tpm::public_key(&file)?, file)));
        let (public, file) = match read {
            Ok(read) => read,
            Err(why) => {
                self.log.info(&format!("could not use the key file {}: {why}", path.display()));
                return Ok(None);
            }
        };
        if self.offered.iter().any(|k| k.key_data() == public.key_data()) {
            return Ok(None);
        }
        if let Some(why) = self.accepted.refuses(&public) {
            self.log.verbose(&format!("skipped the key file {}: {why}", path.display()));
            return Ok(None);
        }
        if let Err(why) = crate::tpm::probe(None) {
            self.log.verbose(&format!("skipped the key file {}: {why}", path.display()));
            self.skipped_tpm.push(format!("{}: {why}", path.display()));
            return Ok(None);
        }
        let shown = crate::known_hosts::fingerprint(&public);
        self.log.debug(&format!("offering ecdsa key {shown} sealed to the TPM, {}", path.display()));
        let mut signer = TpmSigner { file, log: self.log.clone() };
        let time = Arc::new(Mutex::new(AgentTime::default()));
        let mut timed = Timed { inner: &mut signer, time: time.clone(), failed: None };
        let call = handle.authenticate_publickey_with(user, public.clone(), None, &mut timed);
        let answer = within_signing(self.limit, &self.host, "the publickey request", &time, call).await?;
        if let Some(why) = timed.failed.take() {
            self.log.info(&format!("the TPM did not sign with {}: {why}", path.display()));
        }
        self.offered.push(public);
        match answer {
            Ok(result) => Ok(Some(Step::from(result))),
            Err(e) => Err(format!("public key authentication failed: {e}")),
        }
    }
}
