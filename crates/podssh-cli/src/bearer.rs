//! A bearer (T-834) at each end of `podssh`: a token of 30 s that a key of
//! the user signs, bound to one end-to-end channel, for a person with no key
//! that a node's door names. A client's `--bearer SIGNER` (`operator`,
//! `proxy` and `ssh` to `node://`, and `pipe`'s `node:`) is a podssh key
//! file, or `agent` (the first Ed25519 key of the SSH agent, or
//! `agent:FINGERPRINT`), each checked before anything connects. The bearer
//! is minted once the node's key was checked, for the binding of that
//! channel alone, and only the run's first channel carries one, as a grant.
//! A node takes it in its door for grants ([`redeem`]): its signer must be a
//! key that may grant what was asked, so a bearer reaches no more than its
//! signer, and each one is taken once.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use podssh_relay::e2e::{ends, Ask, Binding};
use podssh_relay::grant::bearer::{self, Bearers};
use podssh_relay::grant::{self, Door};
use podssh_relay::identity::{file, Identity, KeyName, PublicKey};
use podssh_relay::reverse::exit_caller;
use podssh_relay::session::{Entropy, OsEntropy};
use podssh_ssh::agent_ed25519;
use podssh_ssh::options::Agent;

use crate::relay_settings::Refusal;

/// Who signs this run's bearer.
#[derive(Clone)]
pub enum Signer {
    /// A podssh key file, read once.
    File(Arc<Identity>),
    /// An Ed25519 key of the SSH agent, which signs each bearer.
    Agent(PublicKey),
}

impl Signer {
    /// The signer's public key, which the node's door must name.
    pub fn key(&self) -> PublicKey {
        match self {
            Signer::File(identity) => identity.public(),
            Signer::Agent(key) => *key,
        }
    }
}

/// The signer of this run's first channel, as `--bearer` gave it.
static ASKED: Mutex<Option<Signer>> = Mutex::new(None);

/// Whether this run's channel carried a bearer: the node's refusal of it
/// comes in the words of a grant's (T-942).
static SENT: AtomicBool = AtomicBool::new(false);

/// The record of this process's nodes: a bearer is taken once, by any.
static BEARERS: LazyLock<Bearers> = LazyLock::new(Bearers::default);

/// The future of the proof that a channel carries: a grant, a bearer, or
/// none.
pub type Minted = Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>>;

/// A line for the user that each task of the session may say.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// `--bearer SIGNER` of a client, read and kept for the run's first
/// channel: beside `--no-e2e` or `--grant`, or a URL, it is a usage error
/// (64); a signer that cannot be used is a configuration error (78). Each
/// is said before anything connects.
pub fn ask(word: Option<&str>, granted: bool, no_e2e: bool) -> Result<(), Refusal> {
    let Some(word) = word else { return Ok(()) };
    check(word, granted, no_e2e)?;
    let signer = read(word)?;
    *ASKED.lock().unwrap_or_else(PoisonError::into_inner) = Some(signer);
    Ok(())
}

/// The refusals of `--bearer WORD` that read nothing: `granted` is whether
/// `--grant` was given too.
fn check(word: &str, granted: bool, no_e2e: bool) -> Result<(), Refusal> {
    if no_e2e {
        return Err(Refusal::usage("--bearer travels in the end-to-end channel, which --no-e2e turns off"));
    }
    if granted {
        return Err(Refusal::usage("--bearer and --grant are two proofs for one channel: give one of them"));
    }
    if word.is_empty() {
        return Err(Refusal::usage("--bearer takes a key file, agent, or agent:FINGERPRINT"));
    }
    if grant::looks_like_url(word) {
        return Err(Refusal::usage(format!("--bearer {word}: a signer is a key file or agent, never a URL")));
    }
    Ok(())
}

/// The signer that `word` names: `agent`, `agent:FINGERPRINT`, else a
/// podssh key file, read and never made.
fn read(word: &str) -> Result<Signer, Refusal> {
    if word == "agent" {
        return from_agent(None);
    }
    if let Some(named) = word.strip_prefix("agent:") {
        let name = KeyName::parse(named).ok_or_else(|| {
            Refusal::usage(format!("--bearer {word}: agent:FINGERPRINT takes SHA256:... or an Ed25519 key"))
        })?;
        return from_agent(Some(name));
    }
    match file::existing(&file::Place::File(word.into())) {
        Ok(Some(identity)) => Ok(Signer::File(Arc::new(identity))),
        Ok(None) => Err(Refusal::config(format!("--bearer {word}: no such key file (a podssh key, or agent)"))),
        // The reader's words of a bad key say that a new one is made, which a
        // signer never is.
        Err(why) if why.contains("not a key") => {
            Err(Refusal::config(format!("--bearer {word}: not a podssh key file (64 hex digits)")))
        }
        Err(why) => Err(Refusal::config(format!("--bearer: {why}"))),
    }
}

/// The agent's key that `named` names, else its first Ed25519 key.
fn from_agent(named: Option<KeyName>) -> Result<Signer, Refusal> {
    let keys = agent_list().map_err(|why| Refusal::config(format!("--bearer agent: {why}")))?;
    choose(&keys, named.as_ref()).map(Signer::Agent).map_err(|why| Refusal::config(format!("--bearer agent: {why}")))
}

/// The agent's Ed25519 keys, asked on a thread of its own: this check runs
/// before anything connects, whether a runtime runs on this thread or not.
fn agent_list() -> Result<Vec<[u8; 32]>, String> {
    let asked = std::thread::spawn(|| -> Result<Option<Vec<[u8; 32]>>, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("no runtime to ask the SSH agent: {}", podssh_ws::text::said(&e)))?;
        runtime.block_on(agent_ed25519::ed25519_keys(&Agent::FromEnvironment))
    });
    match asked.join() {
        Ok(Ok(Some(keys))) => Ok(keys),
        Ok(Ok(None)) => Err("no SSH agent runs: SSH_AUTH_SOCK names none".into()),
        Ok(Err(why)) => Err(why),
        Err(_) => Err("the question to the SSH agent ended with no answer".into()),
    }
}

/// The key of `keys` (the agent's, in its order) that `named` names, else
/// the first.
pub fn choose(keys: &[[u8; 32]], named: Option<&KeyName>) -> Result<PublicKey, String> {
    let mut keys = keys.iter().map(|raw| PublicKey(*raw));
    match named {
        None => keys.next().ok_or_else(|| "the SSH agent holds no Ed25519 key: ssh-add one, or give a key file".into()),
        Some(name) => {
            keys.find(|key| name.matches(key)).ok_or_else(|| format!("the SSH agent holds no Ed25519 key {name}"))
        }
    }
}

/// The signer for the channel that starts now, once: the first takes it.
fn take() -> Option<Signer> {
    ASKED.lock().unwrap_or_else(PoisonError::into_inner).take()
}

/// `say`, shared by the tasks of a session.
pub fn shared(say: impl Fn(String) + Send + 'static) -> Say {
    let say = Mutex::new(say);
    Arc::new(move |line: String| (say.lock().unwrap_or_else(PoisonError::into_inner))(line))
}

/// The maker of the proof of the channel of the operator key `holder`, for
/// `ends::operator_bound`: `grant`, else a bearer of this run's signer for
/// that channel's binding, else none. A bearer that cannot be made is said,
/// and the channel carries none: the node's door alone decides.
pub fn proof(
    grant: Option<Vec<u8>>,
    holder: PublicKey,
    say: Say,
) -> impl FnOnce(PublicKey, Binding) -> Minted + Send + 'static {
    let signer = if grant.is_none() { take() } else { None };
    proof_of(signer, grant, holder, say)
}

/// [`proof`] with its signer named, not taken from the run (for tests).
pub fn proof_of(
    signer: Option<Signer>,
    grant: Option<Vec<u8>>,
    holder: PublicKey,
    say: Say,
) -> impl FnOnce(PublicKey, Binding) -> Minted + Send + 'static {
    move |_node: PublicKey, binding: Binding| -> Minted {
        // A grant goes as it is: `ask` refused the two together.
        let signer = match (signer, grant) {
            (Some(signer), None) => signer,
            (_, grant) => return Box::pin(std::future::ready(grant)),
        };
        Box::pin(async move {
            match make(&signer, holder, &binding, now()).await {
                Ok(blob) => {
                    SENT.store(true, Ordering::Relaxed);
                    Some(blob)
                }
                Err(why) => {
                    say(format!("--bearer: {why}; this channel carries no bearer, so the node's door alone decides"));
                    None
                }
            }
        })
    }
}

/// A bearer of `signer` for `holder` on the channel of `binding`, made at
/// `iat` with a fresh nonce.
pub async fn make(signer: &Signer, holder: PublicKey, binding: &Binding, iat: u64) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; 32];
    OsEntropy.fill(&mut nonce).map_err(|_| "the OS gave no random bytes for a bearer".to_string())?;
    match signer {
        Signer::File(identity) => Ok(bearer::mint(identity, holder, binding, iat, nonce)),
        Signer::Agent(key) => {
            let unsigned = bearer::Unsigned::new(*key, holder, binding, iat, nonce);
            let signature = agent_ed25519::sign_ed25519(&Agent::FromEnvironment, &key.0, unsigned.message()).await?;
            Ok(unsigned.signed(&signature))
        }
    }
}

/// The operator's line of the node's refusal of its proof: a node on
/// podcrates v0.86.0+ sends [`ends::BEARER_REFUSED`] for a bearer and
/// [`ends::GRANT_REFUSED`] for a grant; an older node sends `GRANT_REFUSED`
/// for both, so a run that sent a bearer names it in `BEARER_REFUSED`'s
/// words (T-942).
pub fn refused_line(why: &str) -> String {
    refused_line_of(SENT.load(Ordering::Relaxed), why)
}

/// [`refused_line`] with whether a bearer was sent named (for tests).
pub fn refused_line_of(sent: bool, why: &str) -> String {
    if why == ends::BEARER_REFUSED || !sent {
        return format!("the node refused: {why}");
    }
    format!("the node refused: {}", ends::BEARER_REFUSED)
}

/// Whether `blob` is a bearer, never a certificate: the door tells them
/// apart by its first bytes.
pub fn is_bearer(blob: &[u8]) -> bool {
    bearer::is_bearer(blob)
}

/// A node's check of the bearer `blob` of `peer`, which the channel proved,
/// for `ask`, at its door `door` (and its exit's, `exit`), at `now`: the
/// line of the node's event, or why not, which names the check that failed.
pub fn redeem(
    door: &Door,
    exit: Option<&Door>,
    peer: &PublicKey,
    ask: &Ask,
    blob: &[u8],
    now: u64,
) -> Result<String, String> {
    redeem_in(&BEARERS, ends::binding().as_ref(), door, exit, peer, ask, blob, now)
}

/// [`redeem`] with its record and its channel's binding named (for tests).
#[allow(clippy::too_many_arguments)]
pub fn redeem_in(
    bearers: &Bearers,
    binding: Option<&Binding>,
    door: &Door,
    exit: Option<&Door>,
    peer: &PublicKey,
    ask: &Ask,
    blob: &[u8],
    now: u64,
) -> Result<String, String> {
    let may = |signer: &PublicKey| signs(door, exit, signer, ask);
    bearers
        .verify(blob, binding, peer, may, now)
        .map(|verified| verified.to_string())
        .map_err(|refused| refused.to_string())
}

/// Whether `signer` may grant `ask` at `door`, as a grant's issuer may: the
/// node's own key, or an issuer of the door for what it may reach itself;
/// an exit's target at the exit's door, as `exit_caller::redeem` routes a
/// grant, and never the route that names an exit.
pub fn signs(door: &Door, exit: Option<&Door>, signer: &PublicKey, ask: &Ask) -> bool {
    let (door, ask) = match ask {
        Ask::Exit { .. } => match exit {
            Some(exit) => (exit, Ask::Route(exit_caller::GRANT_ROUTE.into())),
            None => return false,
        },
        Ask::Route(route) if route == exit_caller::GRANT_ROUTE => return false,
        other => (door, other.clone()),
    };
    *signer == door.node || (door.issuers)(signer, &ask).is_ok()
}

/// Seconds since the epoch, as a bearer's life counts them.
fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
#[path = "bearer_tests.rs"]
mod tests;
