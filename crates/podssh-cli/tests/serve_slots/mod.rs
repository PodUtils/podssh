//! The listener's open connections, bounded (T-748): with
//! `--max-connections 2`, two idle TCP connections stay open, a third is
//! closed at once and said in the role's log, and a new one is taken once
//! one of the two ends. The test's connections come from the loopback, which
//! counts in all alone (a proxy in front of a role is on the loopback), so
//! the cap of each address is the unit tests' (`serve::slots`). And with its
//! descriptors limited to 64 and 200 idle clients, `accept` fails at each
//! turn: the role pauses after each failure, and its CPU over 3 s stays under
//! a tenth of a core, where a loop with no pause takes the whole core.

#![cfg(unix)]

use std::io::Read;
use std::net::TcpStream;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::role;
use crate::throughput_harness::Session;

/// Whether the role closed `tcp` within `wait`: an end or a reset, where an
/// open connection waits for TLS and gives nothing.
fn closed_within(tcp: &mut TcpStream, wait: Duration) -> bool {
    tcp.set_read_timeout(Some(wait)).unwrap();
    let mut byte = [0u8; 1];
    match tcp.read(&mut byte) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
    }
}

#[test]
fn a_connection_over_the_cap_is_closed_at_once_and_a_freed_place_is_taken_again() {
    let s = Session::start("serve-slots");
    let Some(cell) = role(&s, &["--max-connections", "2"]) else { return };
    let at = cell.args.iter().position(|a| a == "--relay-host").map(|i| cell.args[i + 1].clone()).unwrap();
    let port: u16 = at.rsplit(':').next().unwrap().parse().unwrap();
    let connect = || TcpStream::connect(("127.0.0.1", port)).expect("the listener takes a connection");
    // The role's own start may still hold a connection of its harness.
    std::thread::sleep(Duration::from_millis(500));
    let (mut one, mut two) = (connect(), connect());
    assert!(!closed_within(&mut one, Duration::from_millis(500)), "the first waits for TLS");
    assert!(!closed_within(&mut two, Duration::from_millis(500)), "the second waits for TLS");
    let started = Instant::now();
    let mut third = connect();
    assert!(closed_within(&mut third, Duration::from_secs(3)), "the third is over the cap");
    assert!(started.elapsed() < Duration::from_secs(2), "closed at once, before TLS");
    drop(one);
    std::thread::sleep(Duration::from_millis(300));
    let mut again = connect();
    assert!(!closed_within(&mut again, Duration::from_millis(800)), "a freed place is taken again");
    let log = std::fs::read_to_string(s.home.join("fake-relay-normal-role.log")).unwrap_or_default();
    assert!(log.contains("refused a connection from 127.0.0.1: 2 connections are open, the cap"), "{log}");
}

/// The CPU ticks (user and system) that the process `pid` used so far.
fn ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("the role's stat");
    // The fields after the command's closing parenthesis: utime and stime are
    // the 12th and 13th of them.
    let after = &stat[stat.rfind(')').unwrap() + 2..];
    let fields: Vec<&str> = after.split_whitespace().collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

#[test]
fn with_its_descriptors_spent_the_role_pauses_after_each_failed_accept() {
    let s = Session::start("serve-slots-fds");
    let Some(cell) = role(&s, &["--max-connections-per-address", "0"]) else { return };
    let at = cell.args.iter().position(|a| a == "--relay-host").map(|i| cell.args[i + 1].clone()).unwrap();
    let port: u16 = at.rsplit(':').next().unwrap().parse().unwrap();
    let pid = *s.pids().last().expect("the role's process");
    let limited = Command::new("prlimit").args(["--pid", &pid.to_string(), "--nofile=64:64"]).status();
    if !limited.is_ok_and(|status| status.success()) {
        eprintln!("did not run: prlimit could not lower the role's descriptors");
        return;
    }
    let clients: Vec<TcpStream> = (0..200).filter_map(|_| TcpStream::connect(("127.0.0.1", port)).ok()).collect();
    assert!(clients.len() > 64, "the kernel queues more than the role can accept: {}", clients.len());
    std::thread::sleep(Duration::from_millis(500));
    let before = ticks(pid);
    std::thread::sleep(Duration::from_secs(3));
    let used = ticks(pid) - before;
    // 100 ticks a second on Linux: a tenth of a core over 3 s is 30.
    assert!(used < 30, "the role used {used} ticks of CPU in 3 s with its descriptors spent");
    let log = std::fs::read_to_string(s.home.join("fake-relay-normal-role.log")).unwrap_or_default();
    assert!(log.contains("the listener could not accept") && log.contains("pauses 100 ms"), "{log}");
    drop(clients);
}
