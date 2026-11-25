//! The key that signs for `podssh keygen -Y sign`, `-s` and `podssh net`
//! (T-020, T-289): the agent's when it holds the key of `-f`, else the
//! private key of the file, its passphrase asked. With `-U`, the agent's
//! alone, and a refusal that says whether no agent runs or it lacks the key
//! (T-971). Each file is read within its bound (T-966).

use std::path::Path;

use podssh_ssh::options::Agent;
use podssh_ssh::russh::keys::ssh_key::{Certificate, HashAlg, SshSig};
use podssh_ssh::russh::keys::{PrivateKey, PublicKey};
use podssh_ssh::sshsig;

use crate::keygen_sign::Signing;

/// The key that signs for `-f KEY`: the agent when it holds the public key
/// of KEY (and only the agent with `-U`), else the private key in KEY. A
/// certificate in `-f` is the key of the signature (T-289).
pub(crate) fn signer(path: &Path, agent_only: bool) -> Result<(Signing, Option<Certificate>), String> {
    let shown = path.display();
    let text = podssh_ssh::key_text::text_of(path)?;
    if let Some(certificate) = certificate_line(&text) {
        return certified(path, &certificate, agent_only).map(|signing| (signing, Some(certificate)));
    }
    let public = public_key(path, &text);
    let held = public.as_ref().map(agent_holds);
    if let (Some(public), Some(Ok(true))) = (&public, &held) {
        return Ok((Signing::Agent(public.clone()), None));
    }
    if agent_only {
        return Err(match held {
            Some(held) => not_held(held),
            None => format!("{shown} holds no public key for the agent to sign with"),
        });
    }
    if public.is_some() && public_line(&text).is_some() {
        return Err(format!("{shown} is a public key, and no agent holds its private key"));
    }
    open_private(path, &text).map(|key| (Signing::Key(Box::new(key)), None))
}

/// The certificate in `-f`, when its first line is one.
fn certificate_line(text: &str) -> Option<Certificate> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#'))?;
    Certificate::from_openssh(line).ok()
}

/// The key that signs for `-f KEY-cert.pub`, as OpenSSH's `load_sign_key`
/// finds it: the agent when it holds the certificate's key, else the
/// private key at the path without `-cert.pub` (or `.pub`), which must be
/// the certificate's key.
fn certified(path: &Path, certificate: &Certificate, agent_only: bool) -> Result<Signing, String> {
    let public = PublicKey::new(certificate.public_key().clone(), "");
    let held = agent_holds(&public);
    if held == Ok(true) {
        return Ok(Signing::Agent(public));
    }
    if agent_only {
        return Err(not_held(held));
    }
    let shown = path.to_string_lossy();
    let private = ["-cert.pub", ".pub"].iter().find_map(|suffix| shown.strip_suffix(suffix)).unwrap_or(&shown);
    let private = Path::new(private);
    if !private.exists() {
        return Err(format!("No private key found for public key \"{shown}\""));
    }
    let text = podssh_ssh::key_text::text_of(private)?;
    let key = open_private(private, &text)?;
    if key.public_key().key_data() != certificate.public_key() {
        return Err(format!("Public key {shown} doesn't match private {}", private.display()));
    }
    Ok(Signing::Key(Box::new(key)))
}

/// The public key of `-f`: the file's when it is one, else `FILE.pub`, else
/// the half of a private key that needs no passphrase to read.
pub(crate) fn public_key(path: &Path, text: &str) -> Option<PublicKey> {
    if let Some(key) = public_line(text) {
        return Some(key);
    }
    let pub_path = podssh_ssh::keygen::public_path(path);
    if let Some(key) = podssh_ssh::key_text::read_text(&pub_path).ok().as_deref().and_then(|text| public_line(text)) {
        return Some(key);
    }
    PrivateKey::from_openssh(text.trim_start()).ok().map(|key| PublicKey::new(key.public_key().key_data().clone(), ""))
}

pub(crate) fn public_line(text: &str) -> Option<PublicKey> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#'))?;
    PublicKey::from_openssh(line).ok()
}

/// The private key of `-f`, its passphrase asked when it has one.
pub(crate) fn open_private(path: &Path, text: &str) -> Result<PrivateKey, String> {
    let shown = path.display();
    match podssh_ssh::key_file::decode(text, None) {
        Ok(key) => return Ok(key),
        Err(podssh_ssh::russh::keys::Error::KeyIsEncrypted) => {}
        Err(e) => {
            return Err(format!("{shown}: not a private key that podssh reads: {}", podssh_ssh::key_text::why(&e)))
        }
    }
    if !podssh_ssh::prompt::can_ask() {
        return Err(format!(
            "{shown} is encrypted, and there is no terminal and no SSH_ASKPASS to ask for its passphrase"
        ));
    }
    let question = format!("Enter passphrase for \"{shown}\": ");
    let passphrase = podssh_ssh::prompt::ask(&question, false).map_err(|e| format!("{shown}: {e}"))?;
    podssh_ssh::key_file::decode(text, Some(passphrase.as_str())).map_err(|_| format!("{shown}: incorrect passphrase"))
}

/// Whether the agent of the environment holds `public`.
pub(crate) fn agent_has(public: &PublicKey) -> bool {
    agent_holds(public) == Ok(true)
}

/// Whether the agent of the environment holds `public`; why not, when no
/// agent runs or none answers (T-971).
fn agent_holds(public: &PublicKey) -> Result<bool, String> {
    block_on(async {
        match podssh_ssh::keys::held_keys(&Agent::FromEnvironment).await {
            Ok(Some(keys)) => Ok(keys.iter().any(|k| k.key_data() == public.key_data())),
            Ok(None) => Err("no agent runs: SSH_AUTH_SOCK names none".into()),
            // The client's own words name its library; the socket says it all.
            Err(_) => Err(match std::env::var_os("SSH_AUTH_SOCK") {
                Some(sock) => format!("no agent answers at SSH_AUTH_SOCK ({})", sock.to_string_lossy()),
                None => "no agent answers".into(),
            }),
        }
    })
}

/// The refusal of `-U` for a key that the agent does not sign with: it
/// lacks the key, or no agent runs (as `-s -U` says).
fn not_held(held: Result<bool, String>) -> String {
    match held {
        Err(why) => format!("-U signs with the agent alone, and {why}"),
        Ok(_) => "the agent does not hold the key of -f (-U signs with the agent alone)".into(),
    }
}

pub(crate) fn with_agent(public: &PublicKey, namespace: &str, hash: HashAlg, prehash: &[u8]) -> Result<SshSig, String> {
    block_on(sshsig::sign_with_agent(&Agent::FromEnvironment, public, namespace, hash, prehash))
}

pub(crate) fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime").block_on(future)
}
