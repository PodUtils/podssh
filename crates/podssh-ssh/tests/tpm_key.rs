//! A key sealed to the machine against a TPM that podssh did not write:
//! swtpm (libtpms), two of them, each on a Unix socket. A key sealed to
//! PCR 7 signs, and OpenSSH's `ssh-keygen` verifies the signature; after
//! the PCR is extended the same file is refused in one line; a signer that
//! authorizes by the password and ignores the policy is refused; a copy of
//! the file on the second swtpm does not load. The offline update: a key
//! of a policy key, refused after PCR 7 moved, signs again after a signed
//! policy of the new value; a policy signature that the file's writer
//! changed is refused by the TPM's own check (`TPM2_VerifySignature`).
//! serve's host key sealed to swtpm signs the key exchange that russh's
//! client takes, and `podssh agent`'s front signs with a key sealed to it.
//! On Windows, the TPM Base Services answer, or say "no TPM: " in one line.
//!
//! Ignored: it needs `swtpm` on the PATH (Debian's and Alpine's package
//! `swtpm`), and `ssh-keygen` for the check of OpenSSH.
//!
//! ```sh
//! CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test tpm_key -- --ignored
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use podssh_ssh::keygen::{generate, KeyKind};
use podssh_ssh::tpm::{self, testing, Pcrs, PolicyKey};
use russh::keys::ssh_key::{HashAlg, Signature, SshSig};
use russh::keys::EcdsaCurve;

/// One swtpm, stopped and its state removed at the end.
struct Swtpm {
    child: Child,
    dir: PathBuf,
}

impl Swtpm {
    fn start(name: &str) -> Swtpm {
        let dir = std::env::temp_dir().join(format!("podssh-swtpm-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let server = format!("type=unixio,path={}", dir.join("tpm.sock").display());
        let ctrl = format!("type=unixio,path={}", dir.join("ctrl.sock").display());
        let state = format!("dir={}", dir.display());
        let child = Command::new("swtpm")
            .args(["socket", "--tpm2", "--tpmstate", &state, "--server", &server, "--ctrl", &ctrl])
            .args(["--flags", "not-need-init,startup-clear"])
            .stdin(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("swtpm does not start ({e}): this test needs swtpm on the PATH"));
        let swtpm = Swtpm { child, dir };
        let until = Instant::now() + Duration::from_secs(10);
        while !swtpm.socket().exists() {
            assert!(Instant::now() < until, "swtpm made no socket within 10 s");
            std::thread::sleep(Duration::from_millis(50));
        }
        swtpm
    }

    fn socket(&self) -> PathBuf {
        self.dir.join("tpm.sock")
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// OpenSSH's verdict on an SSH signature (namespace `file`) of `data` by
/// `public`, whose signature over the signed data the TPM gave; `None`
/// where there is no `ssh-keygen`.
fn openssh_verifies(dir: &Path, public: &russh::keys::PublicKey, data: &[u8], blob: &[u8]) -> Option<bool> {
    let signature = Signature::try_from(blob).unwrap();
    let sig = SshSig::new(public.key_data().clone(), "file", HashAlg::Sha512, signature).unwrap();
    let path = dir.join("data.sig");
    std::fs::write(&path, podssh_ssh::sshsig::armour(&sig, None).unwrap()).unwrap();
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "check-novalidate", "-n", "file", "-s"])
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take().unwrap().write_all(data).unwrap();
    Some(child.wait().unwrap().success())
}

#[test]
#[ignore = "needs swtpm"]
fn a_key_sealed_to_pcr_7_signs_until_the_boot_state_changes() {
    let first = Swtpm::start("a");
    let device = tpm::probe(Some(&first.socket())).unwrap();
    let pcrs = Pcrs::parse("7").unwrap();
    let (file, public) = tpm::make(&device, pcrs, "test@lab").unwrap();

    // It signs; ssh-key and OpenSSH verify the signature of the data that
    // SSHSIG signs.
    let prehash = podssh_ssh::sshsig::digest(&mut &b"a login"[..], HashAlg::Sha512).unwrap();
    let signed = SshSig::signed_data_for_prehash("file", HashAlg::Sha512, &prehash).unwrap();
    let blob = tpm::sign_on(&device, &file, &signed).unwrap();
    tpm::check(&public, &signed, &blob).unwrap();
    match openssh_verifies(&first.dir, &public, b"a login", &blob) {
        Some(good) => assert!(good, "OpenSSH refused the TPM's signature"),
        None => eprintln!("no ssh-keygen here: OpenSSH's check is not run"),
    }

    // The planted signer: the password session, no policy.
    let why = testing::sign_ignoring_policy(&device, &file, b"a login").unwrap_err();
    assert!(why.contains("TPM_RC_AUTH_UNAVAILABLE"), "{why}");

    // A copy of the file on another TPM does not load.
    let second = Swtpm::start("b");
    let other = tpm::probe(Some(&second.socket())).unwrap();
    let why = tpm::sign_on(&other, &file, b"a login").unwrap_err();
    assert!(why.contains("this TPM cannot load the key"), "{why}");

    // The boot state changes: the same file is refused, in one line.
    testing::extend_pcr(&device, 7, &[0x5A; 32]).unwrap();
    let why = tpm::sign_on(&device, &file, b"a login").unwrap_err();
    assert!(why.contains("the PCRs 7 hold other values"), "{why}");
    assert!(!why.contains('\n'), "{why}");
}

/// A new policy key, as `podssh keygen -t ecdsa` makes it.
fn policy_key() -> PolicyKey {
    PolicyKey::new(generate(KeyKind::Ecdsa(EcdsaCurve::NistP256), "policy").unwrap()).unwrap()
}

#[test]
#[ignore = "needs swtpm"]
fn after_a_signed_policy_for_the_new_boot_state_the_key_signs_again() {
    let swtpm = Swtpm::start("signed");
    let device = tpm::probe(Some(&swtpm.socket())).unwrap();
    let key = policy_key();
    let (file, public) = tpm::make_with(&device, Pcrs::parse("7").unwrap(), "test@lab", Some(&key)).unwrap();
    assert!(tpm::takes_signed_policies(&file));
    assert_eq!(file.auth_policies.len(), 1);
    tpm::check(&public, b"a login", &tpm::sign_on(&device, &file, b"a login").unwrap()).unwrap();

    // The boot state changes: no signed policy of the file is met.
    testing::extend_pcr(&device, 7, &[0x5A; 32]).unwrap();
    let why = tpm::sign_on(&device, &file, b"a login").unwrap_err();
    assert!(why.contains("the PCRs 7 hold other values than each signed policy"), "{why}");
    assert!(!why.contains('\n'), "{why}");

    // Another key cannot sign a policy for it; the policy key can, and the
    // same file's key signs again, as OpenSSH verifies.
    let why = tpm::add_policy(&device, &file, None, &policy_key(), None).unwrap_err();
    assert!(why.contains("not the one that the key file names"), "{why}");
    let new = tpm::add_policy(&device, &file, None, &key, Some("after the update".into())).unwrap();
    assert_eq!(new.auth_policies.len(), 2);
    assert_eq!(tpm::signed_pcrs(&new), Some(Pcrs::parse("7").unwrap()));
    let prehash = podssh_ssh::sshsig::digest(&mut &b"a login"[..], HashAlg::Sha512).unwrap();
    let signed = SshSig::signed_data_for_prehash("file", HashAlg::Sha512, &prehash).unwrap();
    let blob = tpm::sign_on(&device, &new, &signed).unwrap();
    tpm::check(&public, &signed, &blob).unwrap();
    match openssh_verifies(&swtpm.dir, &public, b"a login", &blob) {
        Some(good) => assert!(good, "OpenSSH refused the TPM's signature"),
        None => eprintln!("no ssh-keygen here: OpenSSH's check is not run"),
    }

    // The planted change: one bit of the policy's signature. The TPM's
    // check of it refuses the policy.
    let mut changed = new.clone();
    let last = changed.auth_policies[0].policy.last_mut().unwrap();
    let end = last.1.len() - 1;
    last.1[end] ^= 1;
    let why = tpm::sign_on(&device, &changed, b"a login").unwrap_err();
    assert!(why.contains("not the policy key's"), "{why}");
}

/// A server that lets nobody in: the exchange needs the key exchange alone.
struct Nobody;

impl russh::server::Handler for Nobody {
    type Error = russh::Error;
}

/// A client that keeps the host key that the server showed.
struct Seen(std::sync::Arc<std::sync::Mutex<Option<russh::keys::PublicKey>>>);

impl russh::client::Handler for Seen {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        if let russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } = key {
            *self.0.lock().unwrap() = Some(key.clone());
        }
        Ok(true)
    }
}

/// The host key that russh's client met in an exchange with serve's config
/// of `host_key`, or `None` when the exchange failed.
fn exchange(host_key: russh::keys::PrivateKey) -> Option<russh::keys::PublicKey> {
    use std::sync::{Arc, Mutex};
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    runtime.block_on(async {
        let config = Arc::new(podssh_ssh::server::config(host_key));
        let (near, far) = tokio::io::duplex(1 << 20);
        let served = tokio::spawn(async move {
            match russh::server::run_stream(config, far, Nobody).await {
                Ok(running) => running.await,
                Err(e) => Err(e),
            }
        });
        let seen = Arc::new(Mutex::new(None));
        let client = russh::client::connect_stream(Arc::new(Default::default()), near, Seen(seen.clone()));
        let took = tokio::time::timeout(Duration::from_secs(60), client).await;
        served.abort();
        let key = seen.lock().unwrap().take();
        if matches!(took, Ok(Ok(_))) {
            key
        } else {
            None
        }
    })
}

/// serve's host key sealed to swtpm: russh's client meets the TPM's public
/// key, and takes the exchange that the TPM signed. After PCR 7 moved, the
/// key is refused at the start, in one line.
#[test]
#[ignore = "needs swtpm"]
fn a_host_key_sealed_to_the_tpm_signs_the_key_exchange() {
    let swtpm = Swtpm::start("host");
    let device = tpm::probe(Some(&swtpm.socket())).unwrap();
    let (file, public) = tpm::make(&device, Pcrs::parse("7").unwrap(), "host@lab").unwrap();
    let key = tpm::host::stand_in_on(device, &file.to_pem()).unwrap();
    assert!(tpm::host::is_stand_in(&key));
    let met = exchange(key).expect("russh's client took the exchange that the TPM signed");
    assert_eq!(met.key_data(), public.key_data());

    let device = tpm::probe(Some(&swtpm.socket())).unwrap();
    testing::extend_pcr(&device, 7, &[0x5A; 32]).unwrap();
    let why = tpm::host::stand_in_on(device, &file.to_pem()).unwrap_err();
    assert!(why.contains("the PCRs 7 hold other values") && !why.contains('\n'), "{why}");
}

/// `podssh agent`'s front holds a key sealed to swtpm: `tpm::agent::add`
/// gives it, and russh's agent client gets a signature that ssh-key and
/// OpenSSH's `ssh-keygen` verify.
#[test]
#[ignore = "needs swtpm"]
fn the_agent_signs_with_a_key_sealed_to_the_tpm() {
    let swtpm = Swtpm::start("agent");
    let device = tpm::probe(Some(&swtpm.socket())).unwrap();
    let (file, public) = tpm::make(&device, Pcrs::parse("7").unwrap(), "agent@lab").unwrap();
    drop(device);
    // The agent reaches the TPM as each use does, through PODSSH_TPM_DEVICE.
    // SAFETY: the other tests of this file read the environment through
    // std alone, which takes the lock that this write takes; no C code of
    // these tests reads it. The other tests name their device.
    unsafe { std::env::set_var(tpm::DEVICE_VARIABLE, swtpm.socket()) };
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (signed, blob) = runtime.block_on(async {
        let store = std::sync::Arc::new(podssh_ssh::credential_store::Store::default());
        let (mut near, far) = tokio::io::duplex(podssh_ssh::credential_store::MAX_FRAME);
        let (russh_end, _russh_far) = tokio::io::duplex(1024);
        let front = store.clone();
        tokio::spawn(async move { podssh_ssh::credential_store::serve_client(far, russh_end, &front).await });
        tpm::agent::add(&mut near, &file, None).await.unwrap();
        assert_eq!(store.tpm_keys.count(), 1);
        let prehash = podssh_ssh::sshsig::digest(&mut &b"a login"[..], HashAlg::Sha512).unwrap();
        let signed = SshSig::signed_data_for_prehash("file", HashAlg::Sha512, &prehash).unwrap();
        let mut agent = russh::keys::agent::client::AgentClient::connect(near);
        let identities = agent.request_identities().await.unwrap();
        assert!(identities.iter().any(|i| i.public_key().key_data() == public.key_data()));
        let signature = agent.sign_request_signature(&public, None, &signed).await.unwrap();
        (signed, russh::keys::ssh_encoding::Encode::encode_vec(&signature).unwrap())
    });
    tpm::check(&public, &signed, &blob).unwrap();
    match openssh_verifies(&swtpm.dir, &public, b"a login", &blob) {
        Some(good) => assert!(good, "OpenSSH refused the agent's signature"),
        None => eprintln!("no ssh-keygen here: OpenSSH's check is not run"),
    }
}

/// Windows' TPM Base Services: a TPM 2.0 answers, or the probe says why in
/// one line that starts "no TPM: " (a runner of CI may have none). A device
/// named on Windows is refused the same way. It runs in the gate's windows
/// job.
#[cfg(windows)]
#[test]
fn on_windows_tbs_answers_or_says_there_is_no_tpm() {
    match tpm::probe(None) {
        Ok(device) => assert!(device.describe().contains("TPM Base Services"), "{}", device.describe()),
        Err(why) => {
            assert!(why.starts_with("no TPM: "), "{why}");
            assert!(!why.contains('\n'), "{why}");
        }
    }
    let why = tpm::probe(Some(Path::new(r"C:\tpm0"))).err().expect("a device is refused on Windows");
    assert!(why.starts_with("no TPM: ") && !why.contains('\n'), "{why}");
}
