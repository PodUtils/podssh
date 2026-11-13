//! A client that stops reading, against `podssh serve --stdio` (T-118), with
//! OpenSSH's client: `yes` runs through serve, and the test reads none of
//! ssh's stdout for 20 s. serve's own resident memory grows by less than
//! 8 MiB, the output goes on when the test reads again, and a killed client
//! ends `yes` within 5 s. Linux's (serve's memory is read in `/proc`); a host
//! with no OpenSSH client says that the test did not run.

#![cfg(target_os = "linux")]

mod serve_kit;

use std::io::Read;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serve_kit::{
    ends_within, have_openssh, keygen, number_in, openssh_proxy, resident_kib, runs, scratch, wrapped_serve,
};

/// How long the client's reader stops.
const STALL: Duration = Duration::from_secs(20);
/// The growth of serve's resident memory allowed while it stops.
const BOUND_KIB: u64 = 8 * 1024;

#[test]
fn yes_with_a_reader_that_stops_holds_serve_s_memory_and_a_killed_client_ends_it() {
    if !have_openssh() {
        eprintln!("did not run: no OpenSSH client here");
        return;
    }
    let dir = scratch("pressure");
    let (home, key) = (&dir.0, dir.0.join("id"));
    keygen(home, &key);
    let child_file = home.join("child.pid");
    let remote = format!("echo $$ > '{}'; exec yes", child_file.display());
    let mut cmd = openssh_proxy(home, &key, "accept-new", &wrapped_serve(home), &[], &[&remote]);
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut client = cmd.spawn().expect("ssh runs");
    let mut out = client.stdout.take().expect("stdout");
    let yes = number_in(&child_file);
    let serve = number_in(&home.join("serve.pid"));

    // A first read, then none: each buffer on the way fills, and `yes`
    // waits in its write.
    let mut buf = vec![0u8; 1 << 16];
    out.read_exact(&mut buf).expect("the first of yes's output");
    let before = resident_kib(serve).expect("serve's memory in /proc");
    let mut most = before;
    let started = Instant::now();
    while started.elapsed() < STALL {
        std::thread::sleep(Duration::from_secs(1));
        most = most.max(resident_kib(serve).unwrap_or(most));
    }
    let grew = most.saturating_sub(before);
    assert!(grew < BOUND_KIB, "serve's memory grew by {grew} KiB while the client read nothing");
    assert!(runs(yes), "yes waits on its full output; it is not ended");

    // The session goes on.
    let mut more = 0usize;
    let reading = Instant::now();
    while more < 4 << 20 && reading.elapsed() < Duration::from_secs(10) {
        more += out.read(&mut buf).expect("yes's output again");
    }
    assert!(more >= 4 << 20, "{more} bytes after the stall");

    // A client that is gone ends the session, and `yes` with it.
    client.kill().expect("kill ssh");
    let _ = client.wait();
    assert!(ends_within(yes, Duration::from_secs(5)), "yes runs on after its client was killed");
    assert!(ends_within(serve, Duration::from_secs(5)), "serve runs on after its client was killed");
}
