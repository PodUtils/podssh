//! A session through a node goes on across the node's upgrade on Windows
//! (T-678), its bytes whole: the node's named event in the middle of 32 MiB
//! down, and the node starts its binary again (the test's own, which its
//! probe takes) as its child, hands it the session's socket and state, and
//! waits for it; the client resumes as after any loss, and the test's
//! server takes no new connection for the session, only the new binary's
//! look at TARGET as it starts. A session through a route to a Unix socket
//! (an AF_UNIX one of WinSock) goes on the same way (T-852). Each check says
//! that it did not run when this host has no Python or no openssl for the
//! stand-in.
#![cfg(windows)]

mod ssh_harness;
mod throughput_harness;
mod unix_sock;
mod upgrade_support;

use std::process::Stdio;
use std::time::Duration;

use throughput_harness::{lines_of, wait_for, Cell, Session};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{OpenEventW, SetEvent, EVENT_MODIFY_STATE};

/// The stand-in relay's name, on the loopback.
const PINS: [&str; 2] = ["--relay-addr", "relay-a.test=127.0.0.1"];

/// Set the event that asks the node of root `pid` to upgrade, as `podssh
/// update` does; within a few seconds of its start, the node makes it.
fn ask(pid: u32) {
    let name: Vec<u16> = format!("podssh-node-upgrade-{pid}").encode_utf16().chain(Some(0)).collect();
    for _ in 0..100 {
        // SAFETY: a NUL-terminated name; the handle is closed below.
        let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) };
        if !event.is_null() {
            // SAFETY: the event opened above.
            let set = unsafe { SetEvent(event) };
            // SAFETY: as above.
            unsafe { CloseHandle(event) };
            assert_ne!(set, 0, "the event was set");
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the node made no event of an upgrade within 10 s");
}

#[test]
fn a_session_through_a_node_goes_on_across_the_node_s_upgrade_on_windows() {
    const DOWN: u64 = 32 << 20;
    let session = Session::start("node-upgrade-windows");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    let mut pair = session.stand_in(&words(&["relay"]), &ca);
    let out = pair.args(["pair", "lab", "--relay-host", &relay]).args(PINS).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    let target = format!("127.0.0.1:{}", session.port);
    let mut node = session.stand_in(&words(&["node"]), &ca);
    node.args(["lab", target.as_str()]).args(PINS);
    let mut node = node.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let pid = node.id();
    let lines = lines_of(&mut node);
    session.keep(node);
    wait_for(&lines, "online").expect("the node is online");

    let mut args = words(&["ssh", "-v"]);
    args.extend(session.common());
    args.extend(words(&["node://tester@lab", &format!("source {DOWN}")]));
    let mut ssh = session.stand_in(&args[..1], &ca);
    ssh.args(PINS).args(&args[1..]);
    let mut client = ssh.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut before = 0;
    let came = upgrade_support::across(&mut client, DOWN, Duration::from_secs(180), || {
        before = session.connections.load(std::sync::atomic::Ordering::SeqCst);
        ask(pid);
        let went = wait_for(&lines, "sessions go to").expect("the node hands its sessions over");
        assert!(went.contains("1 of 1 sessions go to"), "{went}");
        let took = wait_for(&lines, "sessions over from").expect("the new binary takes them");
        assert!(took.contains("took 1 of 1 sessions over"), "{took}");
    });
    assert_eq!(came.code, Some(0), "{}", came.err);
    assert_eq!(came.total, DOWN, "{}", came.err);
    let after = session.connections.load(std::sync::atomic::Ordering::SeqCst);
    assert!(after <= before + 1, "the session took no new connection to the server: {before} then {after}");
}

/// A session through a node's route to a Unix socket goes on across the
/// node's upgrade on Windows (T-852): the route's socket is an AF_UNIX one
/// of WinSock, which the node hands to its child by WinSock's duplicate as
/// it hands a TCP target's. Where that duplicate fails, the node names the
/// socket before its count, and this test fails with that line.
#[test]
fn a_unix_route_s_session_goes_on_across_the_node_s_upgrade_on_windows() {
    use std::io::Write;

    const DOWN: u64 = 32 << 20;
    let session = Session::start("unix-route-upgrade-windows");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    let mut pair = session.stand_in(&words(&["relay"]), &ca);
    let out = pair.args(["pair", "lab", "--relay-host", &relay]).args(PINS).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    // A short directory of its own, removed also when an assertion fails: a
    // socket's address holds about 100 bytes.
    struct Gone(std::path::PathBuf);
    impl Drop for Gone {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = Gone(std::env::temp_dir().join(format!("pt852-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&dir.0);
    std::fs::create_dir_all(&dir.0).unwrap();
    let sock = dir.0.join("src.sock").display().to_string();
    // The service: DOWN bytes to each connection, then the end.
    let listener = unix_sock::Listener::bind(&sock);
    std::thread::spawn(move || {
        while let Some(mut stream) = listener.accept() {
            let chunk = vec![0x5au8; 1 << 16];
            let mut left = DOWN;
            while left > 0 {
                let n = left.min(chunk.len() as u64) as usize;
                if stream.write_all(&chunk[..n]).is_err() {
                    break;
                }
                left -= n as u64;
            }
        }
    });
    let route = format!("src=unix-connect:{sock}");
    let mut node = session.stand_in(&words(&["node"]), &ca);
    node.args(["lab", route.as_str()]).args(PINS);
    let mut node = node.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let pid = node.id();
    let lines = lines_of(&mut node);
    session.keep(node);
    wait_for(&lines, "online").expect("the node is online");

    let mut operator = session.stand_in(&words(&["operator"]), &ca);
    operator.args(PINS).arg("lab/src");
    let mut client = operator.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let came = upgrade_support::across(&mut client, DOWN, Duration::from_secs(180), || {
        ask(pid);
        // The first line that says where a session goes: a socket that did
        // not go is named before the count.
        let went = wait_for(&lines, "go to").expect("the node hands its sessions over");
        assert!(went.contains("1 of 1 sessions go to"), "{went}");
        let took = wait_for(&lines, "sessions over from").expect("the new binary takes them");
        assert!(took.contains("took 1 of 1 sessions over"), "{took}");
    });
    assert_eq!(came.code, Some(0), "{}", came.err);
    assert_eq!(came.total, DOWN, "{}", came.err);
}
