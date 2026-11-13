//! A far end that reads nothing above the socket (T-598): `podssh ssh
//! --direct` sends 4 MiB to `sleep 600` on `podssh serve`, which opens a
//! channel's window only as its child reads (T-118), so the window stays
//! shut while the host's buffers took each byte that it let go, and no
//! write of the socket waits. The session ends with 255 within 90 s, and
//! says that a write made no progress; the keepalives alone took 240 s.
//! The test serves one connection itself: its socket is serve's stdin and
//! stdout. Unix's.

#![cfg(unix)]

use std::net::TcpListener;
use std::os::fd::OwnedFd;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_podssh");

#[test]
fn a_window_that_stays_shut_ends_the_session_within_90_s_and_says_so() {
    let dir = std::env::temp_dir().join(format!("podssh-stuck-window-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("id");
    let made = Command::new(BIN).args(["keygen", "-t", "ed25519", "-N", "", "-f"]).arg(&key).output().unwrap();
    assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
    std::fs::write(dir.join("four"), vec![0u8; 4 << 20]).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let pubkey = key.with_extension("pub");
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let input = OwnedFd::from(stream.try_clone().unwrap());
        let output = OwnedFd::from(stream);
        let mut serve = Command::new(BIN)
            .args(["serve", "--stdio", "--authorized-keys"])
            .arg(&pubkey)
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(output))
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let _ = serve.wait();
    });

    let started = Instant::now();
    let mut ssh = Command::new(BIN)
        .env("HOME", &dir)
        .args(["ssh", "--direct", "-p", &port.to_string(), "-o", "StrictHostKeyChecking=accept-new"])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", dir.join("kh").display()))
        .args(["-o", "IdentitiesOnly=yes", "-i"])
        .arg(&key)
        .args(["127.0.0.1", "sleep 600"])
        .stdin(Stdio::from(std::fs::File::open(dir.join("four")).unwrap()))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let bound = Duration::from_secs(150);
    let status = loop {
        if let Some(status) = ssh.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > bound {
            let _ = ssh.kill();
            let _ = ssh.wait();
            panic!("podssh ssh did not end within {bound:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let took = started.elapsed();
    let mut err = String::new();
    std::io::Read::read_to_string(&mut ssh.stderr.take().unwrap(), &mut err).unwrap();
    let _ = server.join();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(status.code(), Some(255), "{err}");
    assert!(err.contains("no progress"), "the stall is named: {err}");
    assert!(took >= Duration::from_secs(55) && took <= Duration::from_secs(90), "ended after {took:?}: {err}");
}
