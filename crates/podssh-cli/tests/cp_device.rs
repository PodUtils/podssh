//! `podssh cp` into a destination that is no regular file (T-1038), against
//! the test's SSH server on the loopback, whose subsystem `sftp` is
//! OpenSSH's `sftp-server` (`ssh_harness::sftp`): a device and a FIFO, here
//! and there, take the bytes into themselves and stay what they were; no
//! rename ever replaces them. A regular file, a missing name and a
//! directory keep their rule. `mv` within one server refuses to rename onto
//! a FIFO (73), and the source stays.

#![cfg(unix)]

mod cleanup;
mod ssh_harness;

use std::io::Read;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-cp-device-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

fn server(home: &Path) -> (tokio::runtime::Runtime, u16) {
    let key = home.join("host_key");
    let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let port = runtime.block_on(ssh_harness::start(&key));
    (runtime, port)
}

/// `podssh VERB` with `args` against the server on `port`, in `home`: its
/// code and stderr.
fn podssh(home: &Path, port: u16, verb: &str, args: &[&str]) -> (i32, String) {
    let known = home.join("known_hosts").display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args([verb, "--timeout", "120s", "--direct", "-P", &port.to_string()])
        .args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"])
        .arg(format!("UserKnownHostsFile={known}"))
        .args(args)
        .current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", home).env("USERPROFILE", home);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let out = cmd.output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn fifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: a path that this test owns, as a C string.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0, "mkfifo {}", path.display());
}

/// What a destination is before the copy.
#[derive(Clone, Copy, Debug)]
enum Dest {
    Regular,
    Missing,
    Directory,
    Fifo,
    Null,
}

/// Each kind of destination, down and up: the copy ends 0, the bytes are
/// where the kind puts them, and a device or a FIFO is still one.
#[test]
fn a_device_or_a_fifo_takes_the_bytes_and_stays_what_it_was() {
    if ssh_harness::sftp::server_path().is_none() {
        eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return;
    }
    let home = scratch("kinds");
    let (_runtime, port) = server(&home);
    let body = b"the bytes of the source\n".repeat(4096);
    let source = home.join("src.bin");
    std::fs::write(&source, &body).unwrap();
    for up in [false, true] {
        for kind in [Dest::Regular, Dest::Missing, Dest::Directory, Dest::Fifo, Dest::Null] {
            let case = format!("{}-{kind:?}", if up { "up" } else { "down" });
            let dest = match kind {
                Dest::Null => PathBuf::from("/dev/null"),
                _ => home.join(&case),
            };
            // A FIFO's reader: open to read and write, so that neither end
            // waits for the other to open.
            let mut reader = None;
            match kind {
                Dest::Regular => std::fs::write(&dest, b"old").unwrap(),
                Dest::Directory => std::fs::create_dir(&dest).unwrap(),
                Dest::Fifo => {
                    fifo(&dest);
                    reader = Some(std::fs::OpenOptions::new().read(true).write(true).open(&dest).unwrap());
                }
                Dest::Missing | Dest::Null => {}
            }
            let reading = reader.map(|mut r| {
                let len = body.len();
                std::thread::spawn(move || {
                    let mut got = vec![0u8; len];
                    r.read_exact(&mut got).map(|()| got)
                })
            });
            let (from, to) = match up {
                true => (source.display().to_string(), format!("u@127.0.0.1:{}", dest.display())),
                false => (format!("u@127.0.0.1:{}", source.display()), dest.display().to_string()),
            };
            let (rc, err) = podssh(&home, port, "cp", &[&from, &to]);
            // OpenSSH's sftp-server seeks before each write, which a FIFO
            // cannot do: a far FIFO is refused in its own words, and stays one.
            if up && matches!(kind, Dest::Fifo) {
                assert_eq!(rc, 73, "{case}: {err}");
                assert!(
                    err.contains("a FIFO on the server, which its SFTP server does not write into"),
                    "{case}: {err}"
                );
                assert!(
                    std::fs::symlink_metadata(&dest).unwrap().file_type().is_fifo(),
                    "{case}: replaced by a rename"
                );
                continue;
            }
            assert_eq!(rc, 0, "{case}: {err}");
            let meta = std::fs::symlink_metadata(&dest).unwrap();
            match kind {
                Dest::Regular | Dest::Missing => assert_eq!(std::fs::read(&dest).unwrap(), body, "{case}"),
                Dest::Directory => assert_eq!(std::fs::read(dest.join("src.bin")).unwrap(), body, "{case}"),
                Dest::Fifo => {
                    assert!(meta.file_type().is_fifo(), "{case}: replaced by a rename");
                    let got = reading.unwrap().join().unwrap().expect("the reader got each byte");
                    assert_eq!(got, body, "{case}");
                }
                Dest::Null => assert!(meta.file_type().is_char_device(), "{case}: /dev/null replaced"),
            }
        }
    }
    // No temporary name stays beside any of them.
    let left: Vec<_> = std::fs::read_dir(&home).unwrap().flatten().collect();
    assert!(!left.iter().any(|e| e.file_name().to_string_lossy().contains(".podssh-")), "{left:?}");
}

/// `mv` within one server would rename onto the FIFO: refused (73), and
/// both stay.
#[test]
fn a_move_within_one_server_onto_a_fifo_is_refused() {
    if ssh_harness::sftp::server_path().is_none() {
        eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return;
    }
    let home = scratch("mv");
    let (_runtime, port) = server(&home);
    std::fs::write(home.join("src.bin"), b"moved?").unwrap();
    fifo(&home.join("fifo"));
    let from = format!("u@127.0.0.1:{}", home.join("src.bin").display());
    let to = format!("u@127.0.0.1:{}", home.join("fifo").display());
    let (rc, err) = podssh(&home, port, "mv", &[&from, &to]);
    assert_eq!(rc, 73, "{err}");
    assert!(err.contains("a FIFO, which a rename would replace"), "{err}");
    assert!(std::fs::symlink_metadata(home.join("fifo")).unwrap().file_type().is_fifo());
    assert_eq!(std::fs::read(home.join("src.bin")).unwrap(), b"moved?");
}
