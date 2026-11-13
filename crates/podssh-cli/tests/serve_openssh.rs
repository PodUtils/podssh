//! A command and a shell of `podssh serve --stdio` (T-108) against software
//! that podssh did not write: OpenSSH's client, with the server as its
//! ProxyCommand. The exit statuses 3, 0, 1 and 127; a command killed by
//! TERM; stdout and stderr apart; 5,000,000 bytes up and back whole;
//! `SetEnv LANG=C.UTF-8` arrives and `SetEnv LD_PRELOAD=x` does not; a
//! credential in serve's environment is not in the child's; `-tt` gets its
//! pty refused and the command runs. The shell (T-222): a `--shell` that is
//! missing, or a copy of `/bin/sh` on a noexec mount, refuses the start
//! with 78 and names why. Unix's, as `serve_stdio.rs`; a host with no
//! OpenSSH client says that the test did not run.

#![cfg(unix)]

mod serve_kit;

use std::path::Path;
use std::process::{Command, Stdio};

use serve_kit::{finish, have_openssh, keygen, openssh, openssh_with, podssh_env, run, scratch, Scratch, BIN};

/// A scratch home with the key `id` (listed) made, or None where this host
/// has no OpenSSH client.
fn home(tag: &str) -> Option<Scratch> {
    if !have_openssh() {
        eprintln!("did not run: no OpenSSH client here");
        return None;
    }
    let dir = scratch(tag);
    keygen(&dir.0, &dir.0.join("id"));
    Some(dir)
}

#[test]
fn each_exit_status_comes_back_and_a_signal_is_255() {
    let Some(dir) = home("status") else { return };
    let (home, key) = (&dir.0, dir.0.join("id"));
    for (command, code) in [("exit 3", 3), ("true", 0), ("false", 1), ("podssh-no-such-command-here", 127)] {
        let (got, err) = finish(openssh(home, &key, "accept-new", &[command]));
        assert_eq!(got, Some(code), "{command}: {err}");
        assert!(!err.contains("exec request failed"), "{command}: {err}");
    }
    // OpenSSH's client keeps no status of exit-signal, and exits 255.
    let (got, err) = finish(openssh(home, &key, "accept-new", &["kill -TERM $$"]));
    assert_eq!(got, Some(255), "{err}");
}

#[test]
fn stdout_and_stderr_come_apart() {
    let Some(dir) = home("apart") else { return };
    let mut cmd = openssh(&dir.0, &dir.0.join("id"), "accept-new", &["echo out; echo err >&2"]);
    cmd.stdout(Stdio::piped());
    let (code, out, err) = run(cmd, None);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(String::from_utf8_lossy(&out), "out\n");
    assert!(err.lines().any(|l| l == "err"), "{err}");
    assert!(!String::from_utf8_lossy(&out).contains("err"));
}

#[test]
fn five_million_bytes_go_up_and_come_back_whole() {
    let Some(dir) = home("bytes") else { return };
    let sent: Vec<u8> = (0..5_000_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
    let cmd = openssh(&dir.0, &dir.0.join("id"), "accept-new", &["cat"]);
    let (code, back, err) = run(cmd, Some(sent.clone()));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(back.len(), sent.len(), "{err}");
    assert!(back == sent, "the bytes came back changed");
}

#[test]
fn setenv_takes_the_locale_and_never_a_preload_or_a_credential() {
    let Some(dir) = home("env") else { return };
    let options = ["-o", "SetEnv=LANG=C.UTF-8 LD_PRELOAD=/planted.so"];
    let mut cmd = openssh_with(&dir.0, &dir.0.join("id"), "accept-new", "", &options, &["env"]);
    // serve's own environment: the ProxyCommand inherits ssh's.
    cmd.env("PODSSH_RELAY_TOKEN", "planted-token-of-serve").env("SERVE_OWN", "kept");
    cmd.stdout(Stdio::piped());
    let (code, out, err) = run(cmd, None);
    assert_eq!(code, Some(0), "{err}");
    let env = String::from_utf8_lossy(&out);
    assert!(env.lines().any(|l| l == "LANG=C.UTF-8"), "{env}");
    assert!(env.lines().any(|l| l == "SERVE_OWN=kept"), "serve's own environment stays: {env}");
    assert!(!env.contains("LD_PRELOAD"), "{env}");
    assert!(!env.contains("PODSSH_RELAY_TOKEN") && !env.contains("planted-token-of-serve"), "{env}");
}

/// The pty is refused with an answer. OpenSSH's client makes that refusal
/// fatal where the pty was forced (`-tt`; `client_status_confirm` closes
/// the channel), so its session ends with 255 after its own line and the
/// command never runs; serve's run of a command without a pty is
/// `serve_exec`'s `a_pty_request_is_refused_and_the_command_runs_without_one`.
#[test]
fn a_forced_pty_is_refused_with_an_answer() {
    let Some(dir) = home("pty") else { return };
    let mut cmd = openssh_with(&dir.0, &dir.0.join("id"), "accept-new", "", &["-tt"], &["test -t 0 || echo no-tty"]);
    cmd.stdout(Stdio::piped());
    let (code, out, err) = run(cmd, None);
    assert!(err.contains("PTY allocation request failed"), "{err}");
    assert_eq!(code, Some(255), "OpenSSH ends a session whose forced pty was refused: {err}");
    assert!(!String::from_utf8_lossy(&out).contains("no-tty"), "the command did not run: {err}");
}

#[test]
fn a_missing_shell_refuses_the_start_with_78_and_names_it() {
    let Some(dir) = home("noshell") else { return };
    let (code, err) = finish(serve_alone(&dir.0, "/nonexistent"));
    assert_eq!(code, Some(78), "{err}");
    assert!(err.contains("--shell /nonexistent: no such file"), "{err}");
    // No host key for a start that cannot serve.
    assert!(!dir.0.join("cache").join("serve_host_ed25519_key").exists());
    // Through OpenSSH, the client meets the same line and no login.
    let cmd = openssh_with(&dir.0, &dir.0.join("id"), "accept-new", " --shell /nonexistent", &[], &["true"]);
    let (code, err) = finish(cmd);
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("--shell /nonexistent: no such file"), "{err}");
}

#[test]
fn a_shell_on_a_noexec_mount_refuses_the_start() {
    let Some(dir) = home("noexec") else { return };
    let shm = Path::new("/dev/shm");
    let options = Command::new("findmnt").args(["-n", "-o", "OPTIONS", "--target"]).arg(shm).output();
    let noexec = options.is_ok_and(|o| String::from_utf8_lossy(&o.stdout).split(',').any(|f| f.trim() == "noexec"));
    if !noexec {
        eprintln!("did not run: /dev/shm is not a noexec mount here (or findmnt is missing)");
        return;
    }
    let copy = shm.join(format!("podssh-serve-sh-{}", std::process::id()));
    if std::fs::copy("/bin/sh", &copy).is_err() {
        eprintln!("did not run: /dev/shm takes no copy here");
        return;
    }
    let (code, err) = finish(serve_alone(&dir.0, &copy.display().to_string()));
    let _ = std::fs::remove_file(&copy);
    assert_eq!(code, Some(78), "{err}");
    assert!(err.contains("noexec"), "{err}");
}

/// `podssh serve --stdio --shell SHELL` with stdin the null device, as the
/// Prove of T-222 runs the static binary.
fn serve_alone(home: &Path, shell: &str) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.args(["serve", "--stdio", "--authorized-keys"]).arg(home.join("id.pub")).args(["--shell", shell]);
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    podssh_env(&mut cmd, home);
    cmd
}
