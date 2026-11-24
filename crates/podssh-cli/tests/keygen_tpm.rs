//! Keys sealed to a TPM (T-839) as processes. With no TPM, `podssh keygen
//! -t ecdsa-tpm` refuses with the probe's reason (69) and writes nothing;
//! a usage error comes first (64); `-y` and `-l` read the public key of a
//! key file that go-tpm-keyfiles wrote; a login with such a file and no TPM
//! skips the key and says why. PODSSH_TPM_DEVICE set to none stands in for
//! a host with no TPM, which this test's host may not be. With swtpm, an
//! ignored test makes a key through the binary and logs in with it; and
//! another logs in to OpenSSH's sshd with a key that takes signed policies,
//! is refused after PCR 7 moved, and logs in again after `-O add-policy`.

mod cleanup;
mod keygen_support;
mod live_harness;
mod ssh_harness;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use keygen_support::*;

const NO_TPM: [(&str, &str); 1] = [("PODSSH_TPM_DEVICE", "none")];

/// A key file of go-tpm-keyfiles' tests, its body as podssh-ssh keeps it.
fn foreign_key_file(path: &Path) {
    let body = include_str!("../../podssh-ssh/src/tpm/testdata/p256-authvalue.b64").replace("\r\n", "\n");
    let text = format!("-----BEGIN TSS2 PRIVATE KEY-----\n{body}-----END TSS2 PRIVATE KEY-----\n");
    std::fs::write(path, text).unwrap();
}

#[test]
fn keygen_of_a_sealed_key_with_no_tpm_refuses_and_writes_nothing() {
    let dir = scratch();
    let key = file(&dir, "id_ecdsa_tpm");
    let run = podssh_with(&["keygen", "-t", "ecdsa-tpm", "-f", &key], &NO_TPM);
    assert_eq!(run.code, 69, "{}", run.err);
    assert!(run.err.contains("no TPM: PODSSH_TPM_DEVICE is none"), "{}", run.err);
    assert_eq!(run.err.lines().count(), 1, "one line: {}", run.err);
    assert!(run.out.is_empty() && !run.err.contains("passphrase"), "asked: {}{}", run.out, run.err);
    assert!(!Path::new(&key).exists() && !Path::new(&format!("{key}.pub")).exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn keygen_of_a_sealed_key_checks_its_options_first() {
    let dir = scratch();
    let key = file(&dir, "id_ecdsa_tpm");
    let cases: [&[&str]; 7] = [
        &["-O", "pcr=24"],
        &["-O", "pcr="],
        &["-O", "resident"],
        &["-m", "PEM"],
        &["-b", "384"],
        &["-O", "add-policy"],
        &["-O", "policy-key="],
    ];
    for args in cases {
        let mut all = vec!["keygen", "-t", "ecdsa-tpm", "-f", key.as_str()];
        all.extend_from_slice(args);
        let run = podssh_with(&all, &NO_TPM);
        assert_eq!(run.code, 64, "{args:?}: {}", run.err);
        assert!(!Path::new(&key).exists());
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `-O add-policy` with no TPM: the probe's reason (69), and the key file
/// as it was; with no key file of a TPM at -f, one line and 1.
#[test]
fn add_policy_with_no_tpm_refuses_and_leaves_the_file() {
    let dir = scratch();
    let key = dir.join("foreign.tpm");
    foreign_key_file(&key);
    let before = std::fs::read(&key).unwrap();
    let key = key.display().to_string();
    let args = ["keygen", "-t", "ecdsa-tpm", "-O", "add-policy", "-O", "policy-key=absent", "-f", key.as_str()];
    let run = podssh_with(&args, &NO_TPM);
    assert_eq!(run.code, 69, "{}", run.err);
    assert!(run.err.contains("no TPM: PODSSH_TPM_DEVICE is none"), "{}", run.err);
    assert_eq!(std::fs::read(&key).unwrap(), before, "the file is unchanged");
    let missing = file(&dir, "missing");
    let args = ["keygen", "-t", "ecdsa-tpm", "-O", "add-policy", "-O", "policy-key=absent", "-f", missing.as_str()];
    let run = podssh_with(&args, &NO_TPM);
    assert_eq!(run.code, 1, "{}", run.err);
    assert!(run.err.contains("no key file of a TPM") && run.err.lines().count() == 1, "{}", run.err);
    assert!(!Path::new(&missing).exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn y_and_l_read_the_public_key_of_a_key_file_of_a_tpm() {
    let dir = scratch();
    let key = dir.join("foreign.tpm");
    foreign_key_file(&key);
    let key = key.display().to_string();
    let printed = podssh(&["keygen", "-y", "-f", &key]);
    assert_eq!(printed.code, 0, "{}", printed.err);
    assert!(printed.out.starts_with("ecdsa-sha2-nistp256 AAAA"), "{}", printed.out);
    let listed = podssh(&["keygen", "-l", "-f", &key]);
    assert_eq!(listed.code, 0, "{}", listed.err);
    assert!(listed.out.starts_with("256 SHA256:") && listed.out.trim_end().ends_with("(ECDSA)"), "{}", listed.out);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The `ssh` that logs in to the harness with `key` as `user`.
fn login(dir: &Path, port: u16, key: &Path, user: &str, vars: &[(&str, &str)]) -> std::process::Output {
    let known = dir.join("known_hosts");
    Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["ssh", "--direct", "-p", &port.to_string(), "-v", "-o", "BatchMode=yes", "-o", "IdentityAgent=none"])
        .args(["-o", "StrictHostKeyChecking=accept-new", "-o"])
        .arg(format!("UserKnownHostsFile={}", known.display()))
        .arg("-i")
        .arg(key)
        .arg(format!("{user}@127.0.0.1"))
        .arg("greet")
        .envs(vars.iter().copied())
        .env("PODSSH_SSH_CONFIG", "none")
        .env("HOME", dir)
        .env("USERPROFILE", dir)
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_ASKPASS")
        .env_remove("PODSSH_OFFLINE")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn a_login_with_a_sealed_key_and_no_tpm_says_why() {
    let dir = scratch();
    let key = dir.join("id_ecdsa_tpm");
    foreign_key_file(&key);
    let host_key = file(&dir, "host_key");
    assert_eq!(podssh(&["keygen", "-q", "-N", "", "-f", &host_key]).code, 0);
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(Path::new(&host_key)));
    let output = login(&dir, port, &key, "key-tpm", &NO_TPM);
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(255), "{err}");
    assert!(err.contains("no TPM: PODSSH_TPM_DEVICE is none"), "{err}");
    assert!(err.contains("id_ecdsa_tpm"), "the key file is named: {err}");
    drop(runtime);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A swtpm on a Unix socket, stopped at the end.
struct Swtpm(Child, PathBuf);

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn swtpm(dir: &Path) -> Swtpm {
    let state = dir.join("swtpm");
    std::fs::create_dir_all(&state).unwrap();
    let socket = state.join("tpm.sock");
    let child = Command::new("swtpm")
        .args(["socket", "--tpm2", "--flags", "not-need-init,startup-clear"])
        .arg("--tpmstate")
        .arg(format!("dir={}", state.display()))
        .arg("--server")
        .arg(format!("type=unixio,path={}", socket.display()))
        .arg("--ctrl")
        .arg(format!("type=unixio,path={}", state.join("ctrl.sock").display()))
        .stdin(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("swtpm does not start ({e}): this test needs swtpm on the PATH"));
    let until = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < until, "swtpm made no socket within 10 s");
        std::thread::sleep(Duration::from_millis(50));
    }
    Swtpm(child, socket)
}

#[test]
#[ignore = "needs swtpm"]
fn a_key_made_in_swtpm_logs_in() {
    let dir = scratch();
    let tpm = swtpm(&dir);
    let socket = tpm.1.display().to_string();
    let vars = [("PODSSH_TPM_DEVICE", socket.as_str())];
    let key = file(&dir, "id_ecdsa_tpm");
    let made = podssh_with(&["keygen", "-t", "ecdsa-tpm", "-O", "pcr=7", "-C", "test@lab", "-f", &key], &vars);
    assert_eq!(made.code, 0, "{}", made.err);
    let text = std::fs::read_to_string(&key).unwrap();
    assert!(text.starts_with("-----BEGIN TSS2 PRIVATE KEY-----"), "{text}");
    let public = std::fs::read_to_string(format!("{key}.pub")).unwrap();
    assert!(public.starts_with("ecdsa-sha2-nistp256 ") && public.trim_end().ends_with(" test@lab"), "{public}");
    let host_key = file(&dir, "host_key");
    assert_eq!(podssh(&["keygen", "-q", "-N", "", "-f", &host_key]).code, 0);
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(Path::new(&host_key)));
    let output = login(&dir, port, Path::new(&key), "key-tpm", &vars);
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{err}");
    drop(runtime);
    drop(tpm);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `podssh ssh -i KEY` to this user at OpenSSH's sshd on `port`, which runs
/// `echo sealed`.
fn openssh_login(dir: &Path, port: u16, key: &str, vars: &[(&str, &str)]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["ssh", "--direct", "-p", &port.to_string(), "-i", key])
        .args(["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none"])
        .args(["-o", "StrictHostKeyChecking=accept-new", "-o"])
        .arg(format!("UserKnownHostsFile={}", dir.join("known_hosts").display()))
        .arg(format!("{}@127.0.0.1", live_harness::this_user()))
        .args(["echo", "sealed"])
        .envs(vars.iter().copied())
        .env("PODSSH_SSH_CONFIG", "none")
        .env("PODSSH_SETTINGS", "none")
        .env("HOME", dir)
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_ASKPASS")
        .env_remove("PODSSH_OFFLINE")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// The interop of T-839: OpenSSH's sshd takes the TPM's signature for a
/// login. The key takes signed policies: after PCR 7 moves, the login fails
/// and says why; after `-O add-policy` with the policy key, it logs in
/// again. Ignored: it needs swtpm; where no sshd runs, it says so and ends.
#[test]
#[ignore = "needs swtpm and OpenSSH's sshd"]
fn a_sealed_key_logs_in_to_openssh_and_again_after_a_signed_policy() {
    let dir = scratch();
    let tpm = swtpm(&dir);
    let socket = tpm.1.display().to_string();
    let vars = [("PODSSH_TPM_DEVICE", socket.as_str())];
    let policy = file(&dir, "policy_key");
    assert_eq!(podssh(&["keygen", "-q", "-t", "ecdsa", "-N", "", "-f", &policy]).code, 0);
    let with_policy = format!("policy-key={policy}");
    let key = file(&dir, "id_ecdsa_tpm");
    let made = podssh_with(&["keygen", "-t", "ecdsa-tpm", "-O", &with_policy, "-C", "test@lab", "-f", &key], &vars);
    assert_eq!(made.code, 0, "{}", made.err);
    let sshd = match live_harness::sshd::start(&dir, Path::new(&format!("{key}.pub"))) {
        Ok(sshd) => sshd,
        Err(why) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let first = openssh_login(&dir, sshd.port, &key, &vars);
    assert_eq!(first.status.code(), Some(0), "{}", String::from_utf8_lossy(&first.stderr));
    assert_eq!(String::from_utf8_lossy(&first.stdout).trim(), "sealed");

    let device = podssh_ssh::tpm::probe(Some(&tpm.1)).unwrap();
    podssh_ssh::tpm::testing::extend_pcr(&device, 7, &[0x5A; 32]).unwrap();
    let refused = openssh_login(&dir, sshd.port, &key, &vars);
    let err = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(refused.status.code(), Some(255), "{err}");
    assert!(err.contains("hold other values than each signed policy"), "{err}");

    let args = ["keygen", "-t", "ecdsa-tpm", "-O", "add-policy", "-O", with_policy.as_str(), "-f", key.as_str()];
    let signed = podssh_with(&args, &vars);
    assert_eq!(signed.code, 0, "{}", signed.err);
    assert!(signed.out.contains("The file holds 2 signed policies"), "{}", signed.out);
    let again = openssh_login(&dir, sshd.port, &key, &vars);
    assert_eq!(again.status.code(), Some(0), "{}", String::from_utf8_lossy(&again.stderr));
    drop(sshd);
    drop(tpm);
    std::fs::remove_dir_all(&dir).unwrap();
}
