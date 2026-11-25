//! The sequences of commands: the probe's question, the making of a sealed
//! key, and a signature with one. Each runs over a [`Transport`], a device
//! or a test's script of answers, and flushes each handle that it made on
//! each path, so a failure leaves the TPM as it found it.

use super::cmd;
use super::keyfile::KeyFile;
use super::policy::{self, Pcrs, ALG_SHA256, CC_POLICY_PCR};
use super::public::{self, EccPublic};
use super::rc;
use super::wire::{response, Fault, In, RH_OWNER};

/// A way to a TPM: one command out, its whole response back.
pub trait Transport {
    fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>, String>;
}

/// A command's response, read with `handles` handles: its handles and its
/// parameters, or the fault.
pub(super) fn run<T: Transport + ?Sized>(
    t: &mut T,
    command: &[u8],
    handles: usize,
) -> Result<(Vec<u32>, Vec<u8>), Fault> {
    let bytes = t.transact(command).map_err(Fault::Malformed)?;
    let answer = response(&bytes, handles)?;
    Ok((answer.handles, answer.params.rest().to_vec()))
}

/// Flush a handle; a failure is passed over, as the resource manager
/// flushes each handle of a closed connection too.
pub(super) fn flush<T: Transport + ?Sized>(t: &mut T, handle: u32) {
    if let Ok(command) = cmd::flush(handle) {
        let _ = run(t, &command, 0);
    }
}

/// The manufacturer of the TPM: the probe's one question.
pub(super) fn manufacturer<T: Transport + ?Sized>(t: &mut T) -> Result<String, String> {
    let command = cmd::get_manufacturer()?;
    let (_, params) = run(t, &command, 0).map_err(|e| e.to_string())?;
    cmd::manufacturer(&mut In::new(&params)).map_err(|e| format!("the TPM's answer cannot be read: {e}"))
}

/// The values of `pcrs` in the SHA-256 bank, in the order of their
/// numbers. A TPM reads 8 at most at once; a reading whose counter of
/// updates moved between two reads is begun again, three times at most.
pub(super) fn read_pcrs<T: Transport + ?Sized>(t: &mut T, pcrs: Pcrs) -> Result<Vec<[u8; 32]>, String> {
    'again: for _ in 0..3 {
        let mut values: Vec<(u8, [u8; 32])> = Vec::new();
        let mut left = pcrs;
        let mut counter = None;
        while !left.is_empty() {
            let command = cmd::pcr_read(left)?;
            let (_, params) = run(t, &command, 0).map_err(|e| format!("the TPM did not read its PCRs: {e}"))?;
            let bad = |why: String| format!("the TPM's reading of its PCRs cannot be read: {why}");
            let (count, read, digests) = cmd::pcr_values(&mut In::new(&params)).map_err(bad)?;
            if counter.is_some_and(|c| c != count) {
                continue 'again;
            }
            counter = Some(count);
            if read.is_empty() {
                return Err(format!(
                    "the TPM reads none of the PCRs {} in its SHA-256 bank: the bank is not allocated here",
                    left.text()
                ));
            }
            if !left.contains(read) || read.numbers().len() != digests.len() {
                return Err(bad("other PCRs than those asked".into()));
            }
            for (n, d) in read.numbers().into_iter().zip(digests) {
                let d: [u8; 32] = d.try_into().map_err(|_| bad(format!("PCR {n} is not 32 bytes")))?;
                values.push((n, d));
            }
            left = left.without(read);
        }
        values.sort_by_key(|(n, _)| *n);
        return Ok(values.into_iter().map(|(_, d)| d).collect());
    }
    Err(format!("the PCRs {} changed three times while podssh read them", pcrs.text()))
}

/// The storage key that a TPM keeps, at the handle that the TCG's
/// provisioning guidance gives it. Windows makes one, and keeps no password
/// of the owner's hierarchy (Windows 10 1607 and later), so the owner's
/// storage key cannot be made there.
pub(super) const PERSISTENT_SRK: u32 = 0x8100_0001;

/// The line of an owner's hierarchy with a password.
const OWNER_PASSWORD: &str = "the TPM's owner hierarchy has a password, and podssh uses the empty one, the default";

/// Why the owner's storage key was not made.
enum NoStorage {
    Password,
    Other(String),
}

impl NoStorage {
    fn line(self) -> String {
        match self {
            NoStorage::Password => OWNER_PASSWORD.to_string(),
            NoStorage::Other(why) => why,
        }
    }
}

/// The storage key, made again from its template: a handle to flush.
fn storage_key<T: Transport + ?Sized>(t: &mut T) -> Result<u32, NoStorage> {
    let template = public::storage_template().map_err(NoStorage::Other)?;
    let command = cmd::create_primary(&template).map_err(NoStorage::Other)?;
    let (handles, _) = run(t, &command, 1).map_err(|e| match e {
        Fault::Tpm(code) if matches!(rc::base(code), rc::BAD_AUTH | rc::AUTH_FAIL) => NoStorage::Password,
        other => NoStorage::Other(format!("the TPM did not make its storage key: {other}")),
    })?;
    handles.first().copied().ok_or_else(|| NoStorage::Other("the TPM gave no handle of its storage key".into()))
}

/// The parent of a key: its handle, and whether podssh made it (and
/// flushes it). The owner's storage key, made again; else, where the owner's
/// hierarchy has a password, the one kept at [`PERSISTENT_SRK`].
fn parent_for_new<T: Transport + ?Sized>(t: &mut T) -> Result<(u32, bool), String> {
    match storage_key(t) {
        Ok(handle) => Ok((handle, true)),
        Err(NoStorage::Password) => Ok((PERSISTENT_SRK, false)),
        Err(other) => Err(other.line()),
    }
}

/// The parent of `file`'s key, as [`parent_for_new`] gives it: the owner's
/// storage key, made again, or a storage key that the TPM keeps.
fn parent_of<T: Transport + ?Sized>(t: &mut T, file: &KeyFile) -> Result<(u32, bool), String> {
    match file.parent {
        RH_OWNER if !file.rsa_parent => storage_key(t).map(|handle| (handle, true)).map_err(NoStorage::line),
        handle if handle >> 24 == 0x81 => Ok((handle, false)),
        other => Err(format!(
            "the key file's parent is {other:#010x}{}; podssh loads keys under the owner's P-256 storage key \
             (0x40000001) or a storage key that the TPM keeps (0x81000000 to 0x81FFFFFF)",
            if file.rsa_parent { " of RSA" } else { "" }
        )),
    }
}

/// A new key, sealed to `pcrs` as they are now: its file, and its public
/// area as read. The TPM's own reading of the policy, in a trial session,
/// must be podssh's, and the public area that it made must carry it and
/// the attributes asked.
pub(super) fn make<T: Transport + ?Sized>(
    t: &mut T,
    pcrs: Pcrs,
    description: &str,
    nonce: &[u8; 32],
) -> Result<(KeyFile, EccPublic), String> {
    let values = read_pcrs(t, pcrs)?;
    let body = policy::pcr_body(pcrs, &values);
    let (selection, _, digest) = policy::split_pcr_body(&body)?;
    let steps = vec![(CC_POLICY_PCR, body)];
    let wanted = policy::digest(ALG_SHA256, &steps)?;
    let trial = trial_digest(t, nonce, |session| cmd::policy_pcr(session, &digest, &selection))?;
    if trial != wanted {
        return Err("the TPM's digest of the policy is not podssh's: no key is made".into());
    }
    let (private, public_area, area, parent) = create_sealed(t, &wanted)?;
    Ok((sealed_file(steps, description, public_area, private, parent), area))
}

/// The key file of a key that podssh made under `parent`.
pub(super) fn sealed_file(
    policy: Vec<(u32, Vec<u8>)>,
    description: &str,
    public: Vec<u8>,
    private: Vec<u8>,
    parent: u32,
) -> KeyFile {
    KeyFile {
        empty_auth: true,
        policy,
        auth_policies: Vec::new(),
        rsa_parent: false,
        description: (!description.is_empty()).then(|| description.to_string()),
        parent,
        public,
        private,
    }
}

/// A new sealed key of the policy digest `wanted`: its private and public
/// parts as a key file keeps them, its public area as read, which must
/// carry that digest and the attributes asked, and the parent that the file
/// names.
pub(super) fn create_sealed<T: Transport + ?Sized>(
    t: &mut T,
    wanted: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, EccPublic, u32), String> {
    let template = public::sealed_template(wanted)?;
    let (storage, made_here) = parent_for_new(t)?;
    let made = cmd::create(storage, &template).map_err(Fault::Malformed).and_then(|command| run(t, &command, 0));
    if made_here {
        flush(t, storage);
    }
    let (_, params) = made.map_err(|e| match made_here {
        true => format!("the TPM did not make the key: {e}"),
        false => format!("{OWNER_PASSWORD}, and no storage key kept at {PERSISTENT_SRK:#010x} takes the key: {e}"),
    })?;
    let (private, public_area) =
        cmd::created(&mut In::new(&params)).map_err(|e| format!("the TPM's new key cannot be read: {e}"))?;
    let area = EccPublic::parse(&public_area)?;
    if area.auth_policy != wanted || area.attributes != public::SEALED {
        return Err("the TPM made a key of another policy or other attributes than asked".into());
    }
    let parent = if made_here { RH_OWNER } else { PERSISTENT_SRK };
    Ok((private, public_area, area, parent))
}

/// The digest that the TPM reaches in a trial session for the one policy
/// command that `policy_command` makes for the session's handle.
pub(super) fn trial_digest<T: Transport + ?Sized>(
    t: &mut T,
    nonce: &[u8; 32],
    policy_command: impl FnOnce(u32) -> Result<Vec<u8>, String>,
) -> Result<Vec<u8>, String> {
    let session = start_session(t, cmd::SE_TRIAL, nonce)?;
    let digest = (|| -> Result<Vec<u8>, String> {
        let command = policy_command(session)?;
        run(t, &command, 0).map_err(|e| format!("the TPM's trial of the policy failed: {e}"))?;
        let command = cmd::policy_get_digest(session)?;
        let (_, params) = run(t, &command, 0).map_err(|e| format!("the TPM gave no digest of the policy: {e}"))?;
        Ok(In::new(&params).sized()?.to_vec())
    })();
    flush(t, session);
    digest
}

pub(super) fn start_session<T: Transport + ?Sized>(t: &mut T, kind: u8, nonce: &[u8; 32]) -> Result<u32, String> {
    let command = cmd::start_session(kind, nonce)?;
    let (handles, _) = run(t, &command, 1).map_err(|e| format!("the TPM did not start a session: {e}"))?;
    handles.first().copied().ok_or_else(|| "the TPM gave no handle of its session".into())
}

/// Load `file` under its parent: the key's handle, to flush.
pub(super) fn load<T: Transport + ?Sized>(t: &mut T, file: &KeyFile) -> Result<u32, String> {
    let (storage, made_here) = parent_of(t, file)?;
    let loaded = cmd::load(storage, &file.private, &file.public)
        .map_err(Fault::Malformed)
        .and_then(|command| run(t, &command, 1));
    if made_here {
        flush(t, storage);
    }
    let (handles, _) = loaded.map_err(|e| match e {
        Fault::Tpm(code) if rc::base(code) == rc::INTEGRITY => {
            "this TPM cannot load the key: it was made in another TPM, or its owner's seed changed (a clear of the TPM)"
                .to_string()
        }
        other => format!("the TPM did not load the key: {other}"),
    })?;
    handles.first().copied().ok_or_else(|| "the TPM gave no handle of the key".into())
}

/// The signature of `digest` (SHA-256) with the key of `file`, as SSH
/// carries it: the policy of the file runs in a fresh session, which the
/// signature then uses.
pub(super) fn sign<T: Transport + ?Sized>(
    t: &mut T,
    file: &KeyFile,
    digest: &[u8; 32],
    nonces: [&[u8; 32]; 2],
) -> Result<Vec<u8>, String> {
    if !file.empty_auth {
        return Err("the key needs a password, which podssh does not give".into());
    }
    if file.policy.is_empty() {
        return Err("the key file has no policy: podssh signs with sealed keys only".into());
    }
    if let Some(head) = super::flow_signed::head(file)? {
        return super::flow_signed::sign(t, file, &head, digest, nonces);
    }
    let key = load(t, file)?;
    let session = match start_session(t, cmd::SE_POLICY, nonces[0]) {
        Ok(session) => session,
        Err(why) => {
            flush(t, key);
            return Err(why);
        }
    };
    let signed = (|| -> Result<Vec<u8>, String> {
        for (code, body) in &file.policy {
            run_step(t, session, *code, body).map_err(Unmet::line)?;
        }
        sign_in(t, key, session, nonces[1], digest)
    })();
    // A session used with continueSession clear ended with a signature
    // that succeeded; after a failure it is still there.
    if signed.is_err() {
        flush(t, session);
    }
    flush(t, key);
    signed
}

/// TPM2_Sign of `digest` with the loaded `key` in the policy `session`,
/// whose policy ran: the signature as SSH carries it.
pub(super) fn sign_in<T: Transport + ?Sized>(
    t: &mut T,
    key: u32,
    session: u32,
    nonce: &[u8; 32],
    digest: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let command = cmd::sign(key, session, nonce, digest)?;
    let (_, params) = run(t, &command, 0).map_err(|e| refused(e, "the TPM did not sign"))?;
    public::signature_blob(&mut In::new(&params)).map_err(|e| format!("the TPM's signature cannot be read: {e}"))
}

/// Why a policy was not met: the PCRs that it names moved, or another
/// fault, in its line.
#[derive(Debug)]
pub(super) enum Unmet {
    Changed(Pcrs),
    Other(String),
}

impl Unmet {
    pub fn line(self) -> String {
        match self {
            Unmet::Changed(pcrs) => changed(pcrs),
            Unmet::Other(why) => why,
        }
    }
}

/// One policy command of the file, in `session`.
pub(super) fn run_step<T: Transport + ?Sized>(t: &mut T, session: u32, code: u32, body: &[u8]) -> Result<(), Unmet> {
    if code != CC_POLICY_PCR {
        return Err(Unmet::Other(format!("the key's policy has the command {code:#010x}, which podssh does not run")));
    }
    let (selection, pcrs, values) = policy::split_pcr_body(body).map_err(Unmet::Other)?;
    let command = cmd::policy_pcr(session, &values, &selection).map_err(Unmet::Other)?;
    run(t, &command, 0).map(|_| ()).map_err(|e| match e {
        Fault::Tpm(code) if rc::base(code) == rc::VALUE => Unmet::Changed(pcrs),
        other => Unmet::Other(refused(other, "the TPM did not run the key's policy")),
    })
}

/// The line of a key whose PCRs moved.
fn changed(pcrs: Pcrs) -> String {
    format!(
        "the PCRs {} hold other values than when the key was made: the boot state changed, and the TPM refuses the key",
        pcrs.text()
    )
}

/// The line of a fault, with a word for the codes that a sealed key gives.
pub(super) fn refused(fault: Fault, what: &str) -> String {
    match fault {
        Fault::Tpm(code) => match rc::base(code) {
            rc::POLICY_FAIL => format!("{what}: the key's policy was not met ({fault})"),
            rc::PCR_CHANGED => format!("{what}: a PCR changed while the policy ran; try again"),
            rc::AUTH_UNAVAILABLE => format!("{what}: the key takes its policy alone, no password ({fault})"),
            rc::LOCKOUT => format!("{what}: the TPM is locked out after failed authorizations ({fault})"),
            _ => format!("{what}: {fault}"),
        },
        Fault::Malformed(_) => format!("{what}: {fault}"),
    }
}
