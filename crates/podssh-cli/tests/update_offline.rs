//! `PODSSH_OFFLINE` holds for `podssh update` too (T-810, found by the
//! black-box pass of T-809): `update --check` with the variable set ends
//! with 69 and its words, and connects to nothing. Each connection of the
//! run would go through `HTTPS_PROXY`, which a listener of this test stands
//! in for and counts; the planted defect (no check of the variable) reaches
//! it. Unix and Windows alike.

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(30);

#[test]
fn update_check_connects_to_nothing_when_offline() {
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = proxy.local_addr().unwrap().port();
    let reached = Arc::new(AtomicUsize::new(0));
    let counted = reached.clone();
    std::thread::spawn(move || {
        for stream in proxy.incoming() {
            counted.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    let home = std::env::temp_dir().join(format!("podssh-update-offline-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["update", "--check"])
        .env("PODSSH_OFFLINE", "1")
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{port}"))
        .env("https_proxy", format!("http://127.0.0.1:{port}"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CACHE_HOME", home.join("cache"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podssh runs");
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("podssh update --check did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let out = child.wait_with_output().unwrap();
    let _ = std::fs::remove_dir_all(&home);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(status.code(), Some(69), "{err}");
    assert!(err.contains("PODSSH_OFFLINE is set"), "{err}");
    assert_eq!(err.lines().count(), 1, "one line: {err}");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "a connection went out: {err}");
}
