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
//! Each use probes first (AGENTS.md, section 5, rule 1): with no TPM that
//! podssh may reach, it says why, before it writes or sends anything. The
//! commands are bytes in and bytes out ([`Transport`]), tested
//! against a TPM in software that the tests script. The way to the TPM is
//! the kernel's device on Unix and the TPM Base Services on Windows. Beside
//! a login, `podssh agent` holds such keys ([`agent`]) and `podssh serve`
//! takes one as its host key ([`host`]).

mod authorize;
mod cmd;
mod flow;
mod flow_signed;
mod keyfile;
#[cfg(unix)]
#[path = "unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "windows.rs"]
mod platform;
#[cfg(not(any(unix, windows)))]
#[path = "other.rs"]
mod platform;
mod policy;
mod public;
mod rc;
// Windows' codes and the bound of a command, built on each system so
// that each system's tests check them.
#[cfg_attr(not(windows), allow(dead_code))]
mod tbs;
mod wire;

pub mod agent;
pub mod host;
pub(crate) mod signer;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use russh::keys::ssh_key::Signature;
use russh::keys::PublicKey;
use signature::Verifier;

pub use authorize::PolicyKey;
pub use flow::Transport;
pub use keyfile::{AuthPolicy, KeyFile};
pub use policy::Pcrs;
pub use public::EccPublic;

/// The variable that names the TPM: a device, or a socket of a TPM in
/// software; `none` turns TPM keys off.
pub const DEVICE_VARIABLE: &str = "PODSSH_TPM_DEVICE";

/// The time of one command; a TPM's slowest, the making of a key, takes a
/// second or two.
pub const COMMAND_LIMIT: Duration = Duration::from_secs(30);

/// The PCRs of a new key when none are named: PCR 7, the state of Secure
/// Boot (its keys and whether it is on), which a kernel's update leaves
/// alone.
pub const DEFAULT_PCRS: &str = "7";

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
    let maker = flow::manufacturer(&mut *transport)
        .map_err(|e| format!("no TPM: {} gave no answer of a TPM 2.0: {e}", place.describe()))?;
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
    let (file, area) = match policy_key {
        None => flow::make(&mut *transport, pcrs, comment, &rand::random())?,
        Some(key) => flow_signed::make(&mut *transport, pcrs, comment, &rand::random(), key, &rand::random())?,
    };
    let public = area.public_key()?;
    signs_now(&mut *transport, &file, &public).map_err(|e| format!("the new key {e}, so it is not kept"))?;
    Ok((file, public))
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
    let pcrs = match pcrs.or_else(|| flow_signed::newest_pcrs(file)) {
        Some(pcrs) => pcrs,
        None => Pcrs::parse(DEFAULT_PCRS)?,
    };
    let mut transport = device.open()?;
    let new = flow_signed::add_policy(&mut *transport, file, pcrs, policy_key, name)?;
    signs_now(&mut *transport, &new, &public_key(&new)?).map_err(|e| format!("with the new policy, the key {e}"))?;
    Ok(new)
}

/// The PCRs of the newest signed policy of `file`, if it has one.
pub fn signed_pcrs(file: &KeyFile) -> Option<Pcrs> {
    flow_signed::newest_pcrs(file)
}

/// Whether the key of `file` takes signed policies (its policy begins
/// with `TPM2_PolicyAuthorize`).
pub fn takes_signed_policies(file: &KeyFile) -> bool {
    matches!(flow_signed::head(file), Ok(Some(_)))
}

/// That the key of `file` signs a fresh challenge now, and ssh-key verifies
/// the signature; else why not, as the end of a sentence.
fn signs_now(transport: &mut dyn Transport, file: &KeyFile, public: &PublicKey) -> Result<(), String> {
    let challenge: [u8; 32] = rand::random();
    let blob = sign_with(transport, file, &challenge).map_err(|e| format!("did not sign: {e}"))?;
    check(public, &challenge, &blob).map_err(|e| format!("gave a signature that failed its check: {e}"))
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
    let digest = policy::sha256(data);
    flow::sign(transport, file, &digest, [&rand::random(), &rand::random()])
}

/// Whether `blob` is a valid signature of `data` by `public`, checked by
/// ssh-key, as a server checks it.
pub fn check(public: &PublicKey, data: &[u8], blob: &[u8]) -> Result<(), String> {
    let signature = Signature::try_from(blob).map_err(|e| e.to_string())?;
    public.key_data().verify(data, &signature).map_err(|e| e.to_string())
}

/// The public key of a key file of a TPM.
pub fn public_key(file: &KeyFile) -> Result<PublicKey, String> {
    EccPublic::parse(&file.public)?.public_key()
}

/// Whether the file at `path` is a key file of a TPM: its first line.
pub fn is_key_file(path: &Path) -> bool {
    let mut head = [0u8; 128];
    let Ok(mut file) = std::fs::File::open(path) else { return false };
    let n = file.read(&mut head).unwrap_or(0);
    keyfile::is_pem(&head[..n])
}

/// The key file of a TPM at `path`, read with a bound on its size.
pub fn read_key_file(path: &Path) -> Result<KeyFile, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut text = Vec::new();
    file.take(keyfile::MAX_FILE as u64 + 1).read_to_end(&mut text).map_err(|e| format!("{}: {e}", path.display()))?;
    if text.len() > keyfile::MAX_FILE {
        return Err(format!(
            "{}: more than {} bytes, which no key file of a TPM has",
            path.display(),
            keyfile::MAX_FILE
        ));
    }
    let text = String::from_utf8(text).map_err(|_| format!("{}: not text", path.display()))?;
    KeyFile::from_pem(&text).map_err(|e| format!("{}: {e}", path.display()))
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
        let bytes = t.transact(&cmd::pcr_extend(index, digest)?)?;
        wire::response(&bytes, 0).map(|_| ()).map_err(|e| e.to_string())
    }

    /// Load the key of `file` and sign by the empty password, with no
    /// policy session: the planted signer.
    pub fn sign_ignoring_policy(device: &Device, file: &KeyFile, data: &[u8]) -> Result<(), String> {
        let mut t = device.open()?;
        let key = flow::load(&mut *t, file)?;
        let digest = policy::sha256(data);
        let bytes = t.transact(&cmd::sign_by_password(key, &digest)?);
        let _ = t.transact(&cmd::flush(key)?);
        wire::response(&bytes?, 0).map(|_| ()).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
#[path = "codec_tests.rs"]
mod codec_tests;
#[cfg(test)]
#[path = "flow_tests.rs"]
mod flow_tests;
#[cfg(test)]
#[path = "signed_tests.rs"]
mod signed_tests;
#[cfg(test)]
mod soft;
