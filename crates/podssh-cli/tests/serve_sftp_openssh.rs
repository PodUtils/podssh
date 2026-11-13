//! The SFTP server of `podssh serve --stdio` (T-112) against software that
//! podssh did not write: OpenSSH's `sftp -b` and `scp`, with the server as
//! their ProxyCommand. 5,000,000 bytes put and got back with equal SHA-256
//! digests, a relative path landing in serve's HOME, mkdir, rename, ls, rm
//! and rmdir; then `scp` up and down (SFTP is its mode since OpenSSH 9.0)
//! with equal digests. Unix's, as `serve_openssh.rs`; a host with no
//! OpenSSH `sftp` or `scp` says that the test did not run.

#![cfg(unix)]

mod serve_kit;

use std::path::Path;
use std::process::{Command, Stdio};

use serve_kit::{have_openssh, keygen, podssh_env, run, scratch, Scratch, BIN};
use sha2::{Digest, Sha256};

/// Whether `program` is a file on PATH.
fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

/// A scratch home with the key `id` (listed) made, or None where this host
/// has no OpenSSH client or no `program`.
fn home(tag: &str, program: &str) -> Option<Scratch> {
    if !have_openssh() || !on_path(program) {
        eprintln!("did not run: no OpenSSH {program} here");
        return None;
    }
    let dir = scratch(tag);
    keygen(&dir.0, &dir.0.join("id"));
    std::fs::create_dir_all(dir.0.join("local")).unwrap();
    Some(dir)
}

/// `program` (OpenSSH's `sftp` or `scp`) with `podssh serve --stdio` as its
/// ProxyCommand, logging in with the key `id`; `args` after the options.
fn openssh_tool(home: &Path, program: &str, args: &[&str]) -> Command {
    let proxy = format!("'{BIN}' serve --stdio --authorized-keys '{}'", home.join("id.pub").display());
    let mut cmd = Command::new(program);
    cmd.args(["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "LogLevel=VERBOSE"])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", home.join("known_hosts").display()))
        .args(["-o", "StrictHostKeyChecking=accept-new", "-o", "HostKeyAlias=podssh-serve-test"])
        .args(["-o", "ConnectTimeout=30"])
        .arg("-i")
        .arg(home.join("id"))
        .arg("-o")
        .arg(format!("ProxyCommand={proxy}"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // serve's HOME is the scratch home: the server's relative paths start there.
    podssh_env(&mut cmd, home);
    cmd
}

fn sent() -> Vec<u8> {
    (0..5_000_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect()
}

fn digest(path: &Path) -> Vec<u8> {
    Sha256::digest(std::fs::read(path).unwrap()).to_vec()
}

#[test]
fn sftp_puts_and_gets_a_file_whole_and_each_step_works() {
    let Some(dir) = home("sftp", "sftp") else { return };
    let home = &dir.0;
    let local = home.join("local");
    std::fs::write(local.join("src.bin"), sent()).unwrap();
    let batch = format!(
        "put {src} up.bin\nget up.bin {down}\nmkdir d\nrename up.bin d/moved.bin\nls -l d\nrm d/moved.bin\nrmdir d\nls\n",
        src = local.join("src.bin").display(),
        down = local.join("down.bin").display(),
    );
    std::fs::write(home.join("batch"), batch).unwrap();
    let batch = home.join("batch");
    let cmd = openssh_tool(home, "sftp", &["-b", &batch.to_string_lossy(), "anyone@box"]);
    let (code, out, err) = run(cmd, None);
    let out = String::from_utf8_lossy(&out);
    assert_eq!(code, Some(0), "{out}\n{err}");
    assert_eq!(digest(&local.join("down.bin")), digest(&local.join("src.bin")), "{err}");
    // ls -l of the directory showed the file that rename moved there.
    assert!(out.lines().any(|l| l.contains("moved.bin") && l.starts_with("-rw")), "{out}");
    // The relative names were under serve's HOME, and rm and rmdir left none.
    assert!(!home.join("up.bin").exists() && !home.join("d").exists(), "{out}");
}

#[test]
fn sftp_says_why_a_missing_directory_fails_and_exits_1() {
    let Some(dir) = home("sftp-missing", "sftp") else { return };
    let home = &dir.0;
    // rmdir names no glob: OpenSSH's sftp prints the server's status for it.
    std::fs::write(home.join("batch"), "rmdir absent\n").unwrap();
    let batch = home.join("batch");
    let cmd = openssh_tool(home, "sftp", &["-b", &batch.to_string_lossy(), "anyone@box"]);
    let (code, out, err) = run(cmd, None);
    assert_eq!(code, Some(1), "{}\n{err}", String::from_utf8_lossy(&out));
    assert!(err.contains("No such file"), "{err}");
}

#[test]
fn scp_copies_up_and_down_whole() {
    let Some(dir) = home("scp", "scp") else { return };
    let home = &dir.0;
    let local = home.join("local");
    std::fs::write(local.join("src.bin"), sent()).unwrap();
    let src = local.join("src.bin").to_string_lossy().into_owned();
    let (code, _, err) = run(openssh_tool(home, "scp", &[&src, "anyone@box:scp.bin"]), None);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(digest(&home.join("scp.bin")), digest(&local.join("src.bin")));
    let down = local.join("down.bin").to_string_lossy().into_owned();
    let (code, _, err) = run(openssh_tool(home, "scp", &["anyone@box:scp.bin", &down]), None);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(digest(&local.join("down.bin")), digest(&local.join("src.bin")));
}
