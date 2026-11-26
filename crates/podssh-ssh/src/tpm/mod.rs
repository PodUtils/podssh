//! Keys sealed to the machine (T-839): an ECDSA P-256 key that a TPM 2.0
//! makes and keeps, which signs only while chosen PCRs hold the values that
//! they held when the key was made. A copy of its file is useless in
//! another TPM, and after a boot that measured something else (another
//! boot loader, Secure Boot turned off) the TPM refuses the key.
//!
//! The key's `authPolicy` is the digest of one `TPM2_PolicyPCR`, and it has
//! no `userWithAuth`: the TPM takes no password for it, only a policy
//! session that ran that command while the PCRs held those values. Or it is
//! the digest of one `TPM2_PolicyAuthorize`: the key then takes each policy
//! that a [`PolicyKey`], kept off the host, signed, and a new boot state
//! needs a new signature, not a new key (the offline update). The file
//! is the `TSS2 PRIVATE KEY` of the draft that openssl_tpm2_engine and
//! ssh-tpm-agent read ([`KeyFile`]).
//!
//! The codec, the key file, the sequences and the transport of a Unix
//! device or socket are PodUtils/podcrates' `pod-tpm` (PodUtils/podssh#351).
//! podssh keeps the probe of the device ([`DEVICE_VARIABLE`]), the way to
//! the TPM Base Services on Windows (`windows.rs`: tbs.dll loaded at run
//! time, each command bounded and cancelled), the storage key kept at
//! [`PERSISTENT_SRK`] where the owner's hierarchy has a password, the forms
//! of SSH (the public key and the signature), the policy key of an SSH key,
//! and the signer of a login. Beside a login, `podssh agent` holds such keys
//! ([`agent`]) and `podssh serve` takes one as its host key ([`host`]).
//! Each use probes first (AGENTS.md, section 5, rule 1): with no TPM that
//! podssh may reach, it says why, before it writes or sends anything.

#[cfg(unix)]
#[path = "unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "windows.rs"]
mod platform;
#[cfg(not(any(unix, windows)))]
#[path = "other.rs"]
mod platform;
mod policy_key;
mod ssh;
// Windows' codes and the bound of a command, built on each system so
// that each system's tests check them.
#[cfg_attr(not(windows), allow(dead_code))]
mod tbs;

pub mod agent;
pub mod host;
pub(crate) mod signer;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pod_core::entropy::Entropy;
use pod_tpm::flow::{self, pcr, sign};
use pod_tpm::rc::Code;
use pod_tpm::wire::RH_OWNER;
use pod_tpm::{Authorize, Policy, Statement, Transport};
use russh::keys::ssh_key::Signature;
use russh::keys::PublicKey;
use signature::Verifier;

pub use pod_tpm::{AuthPolicy, KeyFile, PcrSelection as Pcrs};
pub use policy_key::PolicyKey;

/// The variable that names the TPM: a device, or a socket of a TPM in
/// software; `none` turns TPM keys off.
pub const DEVICE_VARIABLE: &str = "PODSSH_TPM_DEVICE";

/// The time of one command, on a device, a socket (pod-tpm's `Limits`) or
/// Windows' TPM Base Services (which set no limit of their own); a TPM's
/// slowest, the making of a key, takes a second or two.
pub const COMMAND_LIMIT: Duration = Duration::from_secs(30);

/// The storage key that a TPM keeps, at the handle that the TCG's
/// provisioning guidance gives it. Windows makes one, and keeps no password
/// of the owner's hierarchy (Windows 10 1607 and later), so the owner's
/// storage key cannot be made there.
pub const PERSISTENT_SRK: u32 = 0x8100_0001;

/// The line of an owner's hierarchy with a password.
const OWNER_PASSWORD: &str = "the TPM's owner hierarchy has a password, and podssh uses the empty one, the default";

/// The PCRs of a new key when none are named: PCR 7, the state of Secure
/// Boot (its keys and whether it is on), which a kernel's update leaves
/// alone.
pub const DEFAULT_PCRS: &str = "7";

/// The nonces of the sessions and the policyRef of a new key: the thread
/// generator of rand, seeded from the operating system.
struct Random;

impl Entropy for Random {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), pod_core::entropy::NoRandom> {
        rand::fill(buf);
        Ok(())
    }
}

/// A TPM that the probe found, and that answered.
pub struct Device {
    place: platform::Place,
    maker: String,
}

impl Device {
    /// What the probe found, for `-v`.
    pub fn describe(&self) -> String {
        format!("the TPM of {} ({})", self.place.describe(), self.maker)
    }

    fn open(&self) -> Result<Box<dyn Transport>, String> {
        platform::open(&self.place)
    }
}

/// A way to the TPM for one operation, opened where it runs (a thread that
/// may wait): the probe's, or a test's TPM in software.
pub(crate) type Opener = Arc<dyn Fn() -> Result<Box<dyn Transport>, String> + Send + Sync>;

/// The TPM that the probe finds at each use, as [`sign_blob`] reaches it.
pub(crate) fn probing() -> Opener {
    Arc::new(|| probe(None)?.open())
}

/// The TPM of `device`, which a probe found.
pub(crate) fn opener_of(device: Device) -> Opener {
    let device = Arc::new(device);
    Arc::new(move || device.open())
}

/// The TPM here, or why there is none: a message that starts "no TPM: ".
/// `named` is the one that the user named; else [`DEVICE_VARIABLE`] names
/// one, or turns them off. The TPM must answer a question of TPM 2.0.
pub fn probe(named: Option<&Path>) -> Result<Device, String> {
    let variable = std::env::var_os(DEVICE_VARIABLE).filter(|v| !v.is_empty());
    if named.is_none() && variable.as_deref().is_some_and(|v| v == "none") {
        return Err(format!("no TPM: {DEVICE_VARIABLE} is none"));
    }
    let from_variable = variable.map(PathBuf::from);
    let place = platform::find(named.or(from_variable.as_deref()))?;
    let mut transport = platform::open(&place)?;
    let no_answer = |why: String| format!("no TPM: {} gave no answer of a TPM 2.0: {why}", place.describe());
    let facts = pcr::capabilities(&mut *transport).map_err(|e| no_answer(podssh_ws::text::said(&e)))?;
    let maker = facts.manufacturer.ok_or_else(|| no_answer("it names no manufacturer".into()))?;
    Ok(Device { place, maker })
}

/// A new key, sealed to `pcrs`, and its public key. Before it is given,
/// it signs a fresh challenge and the signature is checked: a key that
/// cannot sign now is never written.
pub fn make(device: &Device, pcrs: Pcrs, comment: &str) -> Result<(KeyFile, PublicKey), String> {
    make_with(device, pcrs, comment, None)
}

/// [`make`]; with `policy_key`, the key takes each policy that it signs,
/// and the file holds the first: `pcrs` as they are now.
pub fn make_with(
    device: &Device,
    pcrs: Pcrs,
    comment: &str,
    policy_key: Option<&PolicyKey>,
) -> Result<(KeyFile, PublicKey), String> {
    let mut transport = device.open()?;
    make_on(&mut *transport, pcrs, comment, policy_key)
}

/// [`make_with`] over a transport that the caller opened.
pub(crate) fn make_on(
    t: &mut dyn Transport,
    pcrs: Pcrs,
    comment: &str,
    policy_key: Option<&PolicyKey>,
) -> Result<(KeyFile, PublicKey), String> {
    let (mut file, area) = match policy_key {
        None => {
            let statement = pcr::policy_pcr_now(t, &pcrs).map_err(text)?;
            create_signing(t, &Policy::new(vec![statement]))?
        }
        Some(key) => {
            let policy_ref: [u8; 32] = rand::random();
            let head = key.head(&policy_ref)?;
            let own = Policy::new(vec![Statement::authorize(&head).map_err(text)?]);
            // The first policy is signed before the key exists: a signer
            // that fails leaves nothing in the TPM.
            let first = key.signed_now(t, &pcrs, &policy_ref, None)?;
            let (file, area) = create_signing(t, &own)?;
            (sign::add_signed_policy(&file, first).map_err(text)?, area)
        }
    };
    file.description = (!comment.is_empty()).then(|| comment.to_string());
    let public = ssh::public_key(&area.point)?;
    signs_now(t, &file, &public)
        .map_err(|e| format!("the new key {}, so it is not kept", podssh_ws::text::said(&e)))?;
    Ok((file, public))
}

/// A new signing key of `policy` under the owner's storage key, made again
/// from its template; where the owner's hierarchy has a password (Windows
/// keeps one that nobody knows), under the storage key kept at
/// [`PERSISTENT_SRK`], and the file names that parent. `pod-tpm` takes the
/// parent that it is given; the choice is podssh's.
fn create_signing(t: &mut dyn Transport, policy: &Policy) -> Result<(KeyFile, pod_tpm::EccPublic), String> {
    match flow::create_signing(t, &mut Random, RH_OWNER, policy) {
        Err(e) if matches!(e.code().map(|c| c.code()), Some(Code::BadAuth | Code::AuthFail)) => {
            flow::create_signing(t, &mut Random, PERSISTENT_SRK, policy).map_err(|e| {
                format!(
                    "{OWNER_PASSWORD}, and no storage key kept at {PERSISTENT_SRK:#010x} takes the key: {}",
                    podssh_ws::text::said(&e)
                )
            })
        }
        other => other.map_err(text),
    }
}

/// `file` with a new signed policy, tried first: the PCRs of `pcrs` (else
/// those of the file's newest signed policy, else [`DEFAULT_PCRS`]) as they
/// are now on `device`, signed by `policy_key`. Before it is given, the key
/// signs with it. Sign only a boot state whose change you know the reason
/// of: the key then signs in it, a tampered one too.
pub fn add_policy(
    device: &Device,
    file: &KeyFile,
    pcrs: Option<Pcrs>,
    policy_key: &PolicyKey,
    name: Option<String>,
) -> Result<KeyFile, String> {
    let pcrs = match pcrs.or_else(|| signed_pcrs(file)) {
        Some(pcrs) => pcrs,
        None => Pcrs::parse(DEFAULT_PCRS).map_err(text)?,
    };
    let Some(head) = head(file) else {
        return Err("the key is sealed to its PCRs alone, with no policy key: a new boot state needs a new key \
                    (podssh keygen -t ecdsa-tpm -O policy-key=FILE makes one that takes signed policies)"
            .into());
    };
    if head.public != policy_key.public {
        return Err("the policy key is not the one that the key file names".into());
    }
    let mut transport = device.open()?;
    let signed = policy_key.signed_now(&mut *transport, &pcrs, &head.policy_ref, name)?;
    let new = sign::add_signed_policy(file, signed).map_err(text)?;
    signs_now(&mut *transport, &new, &public_key(&new)?)
        .map_err(|e| format!("with the new policy, the key {}", podssh_ws::text::said(&e)))?;
    Ok(new)
}

/// The key's own `TPM2_PolicyAuthorize`, when its policy begins with one.
fn head(file: &KeyFile) -> Option<Authorize> {
    let first = file.policy.statements.first()?;
    (first.code == pod_tpm::cmd::CC_POLICY_AUTHORIZE).then(|| Authorize::parse(&first.body).ok()).flatten()
}

/// The PCRs of the newest signed policy of `file`, if it has one.
pub fn signed_pcrs(file: &KeyFile) -> Option<Pcrs> {
    let newest = file.auth_policy.first()?;
    let statement = newest.policy.statements.iter().find(|s| s.code == pod_tpm::cmd::CC_POLICY_PCR)?;
    statement.read_pcr().ok().map(|(selection, _)| selection)
}

/// Whether the key of `file` takes signed policies (its policy begins
/// with `TPM2_PolicyAuthorize`).
pub fn takes_signed_policies(file: &KeyFile) -> bool {
    head(file).is_some()
}

/// That the key of `file` signs a fresh challenge now, and ssh-key verifies
/// the signature; else why not, as the end of a sentence.
fn signs_now(transport: &mut dyn Transport, file: &KeyFile, public: &PublicKey) -> Result<(), String> {
    let challenge: [u8; 32] = rand::random();
    let blob =
        sign_with(transport, file, &challenge).map_err(|e| format!("did not sign: {}", podssh_ws::text::said(&e)))?;
    check(public, &challenge, &blob)
        .map_err(|e| format!("gave a signature that failed its check: {}", podssh_ws::text::said(&e)))
}

/// The signature of `data` with the key of `file`, as SSH carries it
/// (`ecdsa-sha2-nistp256`), from the TPM that the probe finds.
pub fn sign_blob(file: &KeyFile, data: &[u8]) -> Result<Vec<u8>, String> {
    sign_on(&probe(None)?, file, data)
}

/// [`sign_blob`] on the TPM of `device`.
pub fn sign_on(device: &Device, file: &KeyFile, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut transport = device.open()?;
    sign_with(&mut *transport, file, data)
}

/// [`sign_blob`] over a transport that the caller opened.
pub fn sign_with(transport: &mut dyn Transport, file: &KeyFile, data: &[u8]) -> Result<Vec<u8>, String> {
    let digest = ssh::sha256(data);
    check_parent(file)?;
    let mut key = flow::load(transport, file).map_err(text)?;
    let signature = sign::sign(&mut key, &mut Random, file, &digest).map_err(text)?;
    key.finish().map_err(text)?;
    Ok(ssh::signature_blob(&signature))
}

/// A key file's parent that podssh loads under, else why not, before
/// anything is sent: the owner's P-256 storage key, made again from its
/// template, or a storage key that the TPM keeps.
fn check_parent(file: &KeyFile) -> Result<(), String> {
    match file.parent {
        RH_OWNER if !file.rsa_parent => Ok(()),
        handle if handle >> 24 == 0x81 && !file.rsa_parent => Ok(()),
        other => Err(format!(
            "the key file's parent is {other:#010x}{}; podssh loads keys under the owner's P-256 storage key \
             (0x40000001) or a storage key that the TPM keeps (0x81000000 to 0x81FFFFFF)",
            if file.rsa_parent { " of RSA" } else { "" }
        )),
    }
}

/// Whether `blob` is a valid signature of `data` by `public`, checked by
/// ssh-key, as a server checks it.
pub fn check(public: &PublicKey, data: &[u8], blob: &[u8]) -> Result<(), String> {
    let signature = Signature::try_from(blob).map_err(|e| podssh_ws::text::said(&e))?;
    public.key_data().verify(data, &signature).map_err(|e| podssh_ws::text::said(&e))
}

/// The public key of a key file of a TPM.
pub fn public_key(file: &KeyFile) -> Result<PublicKey, String> {
    ssh::public_key(&flow::public_point(file).map_err(text)?)
}

/// Whether the file at `path` is a key file of a TPM: its first line.
pub fn is_key_file(path: &Path) -> bool {
    let mut head = [0u8; 128];
    let Ok(mut file) = std::fs::File::open(path) else { return false };
    let n = file.read(&mut head).unwrap_or(0);
    pod_tpm::keyfile::is_pem(&head[..n])
}

/// The key file of a TPM at `path`, read with a bound on its size.
pub fn read_key_file(path: &Path) -> Result<KeyFile, String> {
    let max = pod_tpm::keyfile::MAX_PEM;
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {}", path.display(), podssh_ws::text::said(&e)))?;
    let mut text = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut text)
        .map_err(|e| format!("{}: {}", path.display(), podssh_ws::text::said(&e)))?;
    if text.len() > max {
        return Err(format!("{}: more than {max} bytes, which no key file of a TPM has", path.display()));
    }
    let text = String::from_utf8(text).map_err(|_| format!("{}: not text", path.display()))?;
    KeyFile::from_pem(&text).map_err(|e| format!("{}: {}", path.display(), podssh_ws::text::said(&e)))
}

/// The line of an error of `pod-tpm`.
fn text(e: pod_tpm::Error) -> String {
    podssh_ws::text::said(&e)
}

/// What the tests of a real TPM need beside a user's operations: a change
/// of the boot state, and a signer that ignores the policy, which a sealed
/// key must refuse.
#[doc(hidden)]
pub mod testing {
    use super::*;

    /// Extend PCR `index` of the SHA-256 bank with `digest`.
    pub fn extend_pcr(device: &Device, index: u8, digest: &[u8; 32]) -> Result<(), String> {
        let mut t = device.open()?;
        pcr::pcr_extend(&mut *t, u32::from(index), digest).map_err(text)
    }

    /// Load the key of `file` and sign by the empty password, with no
    /// policy session: the planted signer.
    pub fn sign_ignoring_policy(device: &Device, file: &KeyFile, data: &[u8]) -> Result<(), String> {
        let mut t = device.open()?;
        check_parent(file)?;
        let mut key = flow::load(&mut *t, file).map_err(text)?;
        let command = pod_tpm::cmd::sign(key.handle(), &pod_tpm::wire::Auth::EMPTY_PASSWORD, &ssh::sha256(data));
        let answer = command.and_then(|c| pod_tpm::transact(key.transport(), &c));
        key.finish().map_err(text)?;
        answer.map(drop).map_err(text)
    }
}

#[cfg(test)]
mod tests;
