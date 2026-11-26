//! A command whose answer is its stdout says when that stdout cannot take
//! it (T-965): `/dev/full` (ENOSPC) gives one line on stderr and exit 74,
//! where the command would exit 0.
//! A closed pipe (`| head`) stays no failure. Linux has `/dev/full`.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-output-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn podssh(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("HOME", home).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_OFFLINE", "1");
    cmd.env_remove("SSH_AUTH_SOCK").env_remove("SSH_ASKPASS").stdin(Stdio::null());
    cmd
}

fn to_full(mut cmd: Command) -> Output {
    let full = std::fs::OpenOptions::new().write(true).open("/dev/full").unwrap();
    cmd.stdout(full).stderr(Stdio::piped()).output().unwrap()
}

#[test]
fn each_command_says_that_its_output_could_not_be_written() {
    let home = scratch("full");
    let key = home.join("k");
    let made = podssh(&home, &["keygen", "-q", "-t", "ed25519", "-N", "", "-f", key.to_str().unwrap()]).output();
    let made = made.unwrap();
    assert_eq!(made.status.code(), Some(0), "{}", String::from_utf8_lossy(&made.stderr));
    let key = key.to_str().unwrap();
    let cases: [(&str, Vec<&str>); 5] = [
        ("man", vec!["man", "doctor"]),
        ("node", vec!["node", "lab", "127.0.0.1:22", "--print-unit"]),
        ("serve", vec!["serve", "lab", "--no-forwarding", "--authorized-keys", "keys", "--print-unit"]),
        ("keygen", vec!["keygen", "-l", "-f", key]),
        ("keygen", vec!["keygen", "-y", "-f", key]),
    ];
    for (verb, args) in cases {
        let out = to_full(podssh(&home, &args));
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(74), "{args:?}: {err}");
        let line = format!("podssh {verb}: the output could not be written: No space left on device");
        assert!(err.contains(&line), "{args:?}: {err}");
        assert!(!err.contains("os error"), "{args:?}: {err}");
    }
    // A reader that went away (`| head`) is no failure: the whole manual
    // is more than a pipe holds, and the reader takes one byte.
    let mut man = podssh(&home, &["man", "--no-pager"]);
    let mut child = man.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut first = [0u8; 1];
    std::io::Read::read_exact(child.stdout.as_mut().unwrap(), &mut first).unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.is_empty(), "{err}");
    let _ = std::fs::remove_dir_all(&home);
}
