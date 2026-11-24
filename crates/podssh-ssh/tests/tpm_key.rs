//! A key sealed to the machine against a TPM that podssh did not write:
//! swtpm (libtpms), two of them, each on a Unix socket. A key sealed to
//! PCR 7 signs, and OpenSSH's `ssh-keygen` verifies the signature; after
//! the PCR is extended the same file is refused in one line; a signer that
//! authorizes by the password and ignores the policy is refused; a copy of
//! the file on the second swtpm does not load.
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

use podssh_ssh::tpm::{self, testing, Pcrs};
use russh::keys::ssh_key::{HashAlg, Signature, SshSig};

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
