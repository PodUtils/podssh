//! The commands that talk to an agent (T-034): `add`, `list`, `remove`,
//! `lock` and `unlock`, to the agent of `SSH_AUTH_SOCK`, podssh's or
//! OpenSSH's, with the words of `ssh-add`. A passphrase or a lock password
//! is asked on the terminal or through `SSH_ASKPASS`, and lives in memory
//! that is wiped. A key file of a TPM goes to the agent whole: its private
//! part is of use only in that TPM (T-839). Each failure has the code of
//! its kind (T-969): 65 data that is no key, 66 a file or an answer that did
//! not come, 69 an agent that refused or did not answer, 77 a wrong
//! passphrase or password, 78 no terminal and no `SSH_ASKPASS` to ask on.

use std::io::Write;
use std::path::Path;

use podssh_ssh::prompt::{self, PromptError};
use podssh_ssh::russh::keys::agent::client::{AgentClient, AgentStream};
use podssh_ssh::russh::keys::agent::{AgentIdentity, Constraint};
use podssh_ssh::russh::keys::{HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use super::AgentArgs;
use crate::exitmap::sysexits::{EX_CONFIG, EX_DATAERR, EX_NOINPUT, EX_NOPERM, EX_UNAVAILABLE};

type Agent = AgentClient<Box<dyn AgentStream + Send + Unpin + 'static>>;

/// What a refused list, removal or lock can mean: russh's agent, podssh's,
/// refuses each while it is locked; OpenSSH's lists no key then.
const MAYBE_LOCKED: &str = "it may be locked (podssh agent unlock)";

/// The agent of `SSH_AUTH_SOCK`; on Windows, else OpenSSH's named pipe.
pub(super) async fn connect(err: &mut dyn Write) -> Result<Agent, i32> {
    let named = std::env::var("SSH_AUTH_SOCK").ok().filter(|v| !v.is_empty());
    #[cfg(unix)]
    let Some(place) = named
    else {
        let _ = writeln!(err, "podssh agent: SSH_AUTH_SOCK is not set: start podssh agent, and set it as it says");
        return Err(EX_UNAVAILABLE);
    };
    #[cfg(unix)]
    let reached = AgentClient::connect_uds(&place).await.map(|agent| agent.dynamic());
    #[cfg(windows)]
    let place = named.unwrap_or_else(|| r"\\.\pipe\openssh-ssh-agent".to_string());
    #[cfg(windows)]
    let reached = AgentClient::connect_named_pipe(&place).await.map(|agent| agent.dynamic());
    reached.map_err(|e| {
        let _ = writeln!(err, "podssh agent: no agent answers at {place}: {}", podssh_ws::text::said(&e));
        EX_UNAVAILABLE
    })
}

/// `add FILE...`: each key to the agent, for `--lifetime` seconds when given.
pub async fn add(args: &AgentArgs, _out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut agent = match connect(err).await {
        Ok(agent) => agent,
        Err(code) => return code,
    };
    let lifetime: Option<u32> = args.lifetime.as_deref().and_then(|s| s.parse().ok());
    for file in &args.args {
        // A key file of a TPM goes as ssh-tpm-agent's ssh-tpm-add gives one
        // (T-839): only podssh agent and ssh-tpm-agent keep it.
        if podssh_ssh::tpm::is_key_file(Path::new(file)) {
            match add_tpm(Path::new(file), lifetime, err).await {
                0 => continue,
                code => return code,
            }
        }
        let key = match load(Path::new(file), err).await {
            Ok(key) => key,
            Err(code) => return code,
        };
        let mut constraints: Vec<Constraint> =
            lifetime.map(|seconds| vec![Constraint::KeyLifetime { seconds }]).unwrap_or_default();
        // A key of a security key goes as ssh-add sends one, with the helper
        // that signs with it: OpenSSH's own, which podssh agent stands in
        // for (T-229).
        if podssh_ssh::sk::is_sk(key.public_key()) {
            constraints.push(Constraint::Extensions {
                name: podssh_ssh::sk::agent::SK_PROVIDER.as_bytes().to_vec(),
                details: b"internal".to_vec(),
            });
        }
        match agent.add_identity(&key, &constraints).await {
            Ok(()) => {}
            Err(podssh_ssh::russh::keys::Error::AgentFailure) => {
                let why = refused_why(key.algorithm().is_rsa());
                let _ = writeln!(err, "podssh agent: the agent refused {file}{why}");
                return EX_UNAVAILABLE;
            }
            Err(e) => {
                let _ = writeln!(err, "podssh agent: {file} did not reach the agent: {}", podssh_ws::text::said(&e));
                return EX_UNAVAILABLE;
            }
        }
        let _ = writeln!(err, "Identity added: {file} ({})", key.comment());
        if let Some(seconds) = lifetime {
            let _ = writeln!(err, "Lifetime set to {seconds} seconds");
        }
    }
    0
}

/// Why an agent may refuse a key: podssh's keeps no RSA key (T-257), as its
/// signer of RSA is not constant-time; another agent may keep one.
fn refused_why(rsa: bool) -> String {
    if rsa {
        "; podssh agent keeps no RSA key, as its RSA signing is not constant-time: use an Ed25519 key, or OpenSSH's \
         ssh-agent"
            .into()
    } else {
        format!("; {MAYBE_LOCKED}")
    }
}

/// The key file of a TPM at `path`, to the agent of `SSH_AUTH_SOCK` on a
/// connection of its own. The agent signs once in the TPM before it keeps
/// the key, so the answer can take seconds.
async fn add_tpm(path: &Path, lifetime: Option<u32>, err: &mut dyn Write) -> i32 {
    let file = match podssh_ssh::tpm::read_key_file(path) {
        Ok(file) => file,
        Err(why) => {
            let _ = writeln!(err, "podssh agent: {why}");
            return EX_NOINPUT;
        }
    };
    let mut stream = match connect(err).await {
        Ok(agent) => agent.into_inner(),
        Err(code) => return code,
    };
    if let Err(why) = podssh_ssh::tpm::agent::add(&mut stream, &file, lifetime).await {
        let _ = writeln!(err, "podssh agent: the agent refused {}: {why}", path.display());
        return EX_UNAVAILABLE;
    }
    let comment = file.description.as_deref().unwrap_or("sealed to the TPM");
    let _ = writeln!(err, "Identity added: {} ({comment})", path.display());
    if let Some(seconds) = lifetime {
        let _ = writeln!(err, "Lifetime set to {seconds} seconds");
    }
    0
}

/// The agent's keys, or the line of a refusal and its code.
async fn identities(agent: &mut Agent, err: &mut dyn Write) -> Result<Vec<AgentIdentity>, i32> {
    agent.request_identities().await.map_err(|e| {
        let why = match e {
            podssh_ssh::russh::keys::Error::AgentFailure => MAYBE_LOCKED.to_string(),
            other => podssh_ws::text::said(&other),
        };
        let _ = writeln!(err, "podssh agent: the agent did not list its keys: {why}");
        EX_UNAVAILABLE
    })
}

/// `list`: a line for each key, as `ssh-add -l` writes it; 1, as there,
/// when the agent holds none.
pub async fn list(out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut agent = match connect(err).await {
        Ok(agent) => agent,
        Err(code) => return code,
    };
    let identities = match identities(&mut agent, err).await {
        Ok(identities) => identities,
        Err(code) => return code,
    };
    if identities.is_empty() {
        let _ = writeln!(out, "The agent has no identities.");
        return 1;
    }
    for identity in &identities {
        let _ = writeln!(out, "{}", line(identity));
    }
    0
}

/// One line of `list`: the size, the fingerprint, the comment and the type,
/// `-CERT` after the type of a certificate, as `ssh-add -l` writes it.
fn line(identity: &AgentIdentity) -> String {
    let key = identity.public_key();
    let mut kind = podssh_ssh::known_hosts::key_type(&key);
    if matches!(identity, AgentIdentity::Certificate { .. }) {
        kind.push_str("-CERT");
    }
    format!("{} {} {} ({kind})", bits(&key), key.fingerprint(HashAlg::Sha256), identity.comment())
}

/// `remove FILE...` or `remove --all`.
pub async fn remove(args: &AgentArgs, _out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut agent = match connect(err).await {
        Ok(agent) => agent,
        Err(code) => return code,
    };
    if args.all {
        // One request, as ssh-add -D sends it: an agent that is locked
        // refuses it, where a list of no keys would read as done.
        if agent.remove_all_identities().await.is_err() {
            let _ = writeln!(err, "podssh agent: the agent did not remove its keys: {MAYBE_LOCKED}");
            return EX_UNAVAILABLE;
        }
        let _ = writeln!(err, "All identities removed.");
        return 0;
    }
    for file in &args.args {
        let public = match public_of(Path::new(file), err).await {
            Ok(public) => public,
            Err(code) => return code,
        };
        if agent.remove_identity(&public).await.is_err() {
            let why = format!("it does not hold it, or {MAYBE_LOCKED}");
            let _ = writeln!(err, "podssh agent: the agent did not remove {file}: {why}");
            return EX_UNAVAILABLE;
        }
        let _ = writeln!(err, "Identity removed: {file}");
    }
    0
}

/// `lock` (the password asked twice) or `unlock`.
pub async fn lock(locking: bool, _out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut agent = match connect(err).await {
        Ok(agent) => agent,
        Err(code) => return code,
    };
    let password = match ask("Enter lock password: ".into()).await {
        Ok(password) => password,
        Err(e) => return no_answer("no password", &e, err),
    };
    if locking {
        match ask("Again: ".into()).await {
            Ok(again) if again.as_str() == password.as_str() => {}
            Ok(_) => {
                let _ = writeln!(err, "podssh agent: the passwords do not match");
                return EX_DATAERR;
            }
            Err(e) => return no_answer("no password", &e, err),
        }
    }
    let done = if locking { agent.lock(password.as_bytes()).await } else { agent.unlock(password.as_bytes()).await };
    match (done, locking) {
        (Ok(()), true) => {
            let _ = writeln!(err, "Agent locked.");
            0
        }
        (Ok(()), false) => {
            let _ = writeln!(err, "Agent unlocked.");
            0
        }
        (Err(_), true) => {
            let _ = writeln!(err, "podssh agent: the agent refused to lock: it may be locked already");
            EX_UNAVAILABLE
        }
        (Err(_), false) => {
            let _ = writeln!(err, "podssh agent: the agent refused to unlock: a wrong password, or it is not locked");
            EX_NOPERM
        }
    }
}

/// A prompt that gave nothing: 78 where nothing can ask (no terminal and no
/// `SSH_ASKPASS` that runs), else 66, as no answer came.
fn no_answer(what: &str, e: &PromptError, err: &mut dyn Write) -> i32 {
    let _ = writeln!(err, "podssh agent: {what}: {}", podssh_ws::text::said(&e));
    match e {
        PromptError::NoTerminal | PromptError::Failed(_) => EX_CONFIG,
        _ => EX_NOINPUT,
    }
}

/// A key file, opened with its passphrase when it asks for one.
async fn load(path: &Path, err: &mut dyn Write) -> Result<PrivateKey, i32> {
    let shown = path.display();
    match podssh_ssh::key_file::load(path, None) {
        Ok(key) => Ok(key),
        Err(podssh_ssh::russh::keys::Error::KeyIsEncrypted) => {
            let passphrase = match ask(format!("Enter passphrase for {shown}: ")).await {
                Ok(passphrase) => passphrase,
                Err(e) => return Err(no_answer(&format!("{shown} is encrypted, and no passphrase came"), &e, err)),
            };
            podssh_ssh::key_file::load(path, Some(passphrase.as_str())).map_err(|_| {
                let _ = writeln!(err, "podssh agent: bad passphrase for {shown}");
                EX_NOPERM
            })
        }
        // A file that is not there or cannot be read: 66; one that is no key
        // (too large, not text, another format): 65.
        Err(podssh_ssh::russh::keys::Error::IO(e)) if e.kind() != std::io::ErrorKind::InvalidData => {
            let _ = writeln!(err, "podssh agent: {shown}: {}", podssh_ws::text::said(&e));
            Err(EX_NOINPUT)
        }
        Err(e) => {
            let _ = writeln!(err, "podssh agent: {shown}: not a key that podssh reads: {}", podssh_ws::text::said(&e));
            Err(EX_DATAERR)
        }
    }
}

/// The public key of a key file: the file itself, or `FILE.pub`, else the
/// private key's half.
async fn public_of(path: &Path, err: &mut dyn Write) -> Result<PublicKey, i32> {
    if let Ok(public) = podssh_ssh::russh::keys::load_public_key(path) {
        return Ok(public);
    }
    let mut pub_file = path.as_os_str().to_owned();
    pub_file.push(".pub");
    if let Ok(public) = podssh_ssh::russh::keys::load_public_key(&pub_file) {
        return Ok(public);
    }
    // A key file of a TPM holds its public key in the clear.
    if podssh_ssh::tpm::is_key_file(path) {
        return podssh_ssh::tpm::read_key_file(path).and_then(|file| podssh_ssh::tpm::public_key(&file)).map_err(
            |why| {
                let _ = writeln!(err, "podssh agent: {why}");
                EX_NOINPUT
            },
        );
    }
    load(path, err).await.map(|key| key.public_key().clone())
}

/// A prompt on its own thread, as it may block on the terminal.
async fn ask(text: String) -> Result<Zeroizing<String>, PromptError> {
    tokio::task::spawn_blocking(move || prompt::ask(&text, false))
        .await
        .unwrap_or(Err(PromptError::Failed("the prompt's thread failed".into())))
}

/// The size of a key, as `ssh-add -l` shows it.
fn bits(key: &PublicKey) -> usize {
    use podssh_ssh::russh::keys::ssh_key::public::KeyData;
    match key.key_data() {
        KeyData::Ed25519(_) | KeyData::SkEd25519(_) | KeyData::SkEcdsaSha2NistP256(_) => 256,
        KeyData::Ecdsa(ecdsa) => match ecdsa.curve().as_str() {
            "nistp384" => 384,
            "nistp521" => 521,
            _ => 256,
        },
        KeyData::Rsa(rsa) => rsa.n().as_positive_bytes().map_or(0, |n| n.len() * 8),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use podssh_ssh::russh::keys::ssh_key::{certificate, Algorithm};

    /// A certificate's line names its type with `-CERT`, as `ssh-add -l`
    /// writes `(ECDSA-CERT)`; the key's line names the type alone (T-963).
    #[test]
    fn a_certificate_is_listed_with_its_type_and_cert() {
        let mut rng = rand::rng();
        for (algorithm, kind) in [
            (Algorithm::Ecdsa { curve: podssh_ssh::russh::keys::EcdsaCurve::NistP256 }, "ECDSA"),
            (Algorithm::Ed25519, "ED25519"),
        ] {
            let key = PrivateKey::random(&mut rng, algorithm).unwrap();
            let ca = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
            let mut builder =
                certificate::Builder::new_with_random_nonce(&mut rng, key.public_key(), 0, u64::MAX).unwrap();
            builder.key_id("k").unwrap();
            builder.valid_principal("someone").unwrap();
            let cert = builder.sign(&ca).unwrap();
            let plain = AgentIdentity::PublicKey { key: key.public_key().clone(), comment: "k_ecdsa".into() };
            let certified = AgentIdentity::Certificate { certificate: cert, comment: "k_ecdsa".into() };
            assert!(line(&plain).ends_with(&format!(" k_ecdsa ({kind})")), "{}", line(&plain));
            assert!(line(&certified).ends_with(&format!(" k_ecdsa ({kind}-CERT)")), "{}", line(&certified));
            let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
            assert!(line(&certified).starts_with(&format!("256 {fingerprint} ")), "{}", line(&certified));
        }
    }

    /// An RSA key's refusal is a sentence of the user's, with what to use,
    /// and names no library (T-969); another key's names the lock.
    #[test]
    fn the_refusal_of_an_rsa_key_names_no_library() {
        let rsa = refused_why(true);
        assert!(rsa.contains("keeps no RSA key") && rsa.contains("Ed25519"), "{rsa}");
        assert!(!rsa.contains("russh") && !rsa.contains("crate"), "{rsa}");
        assert!(refused_why(false).contains(MAYBE_LOCKED));
    }
}
