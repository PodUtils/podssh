//! A signal ends `podssh pipe` with a program (T-913): SIGINT, SIGTERM and
//! SIGHUP go on to the program, and podssh exits 128 + N with one line.
//! A program that ignores the signal is killed after 10 s. Either way no
//! program is left running once podssh has exited. Unix: Windows has no
//! signal to send to one process.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// `podssh pipe A B` with stdin at its end, and the pid that the program
/// printed first: podssh has started it and listens for signals then.
fn started(a: &str, b: &str) -> (Child, i32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["pipe", a, b])
        .env("PODSSH_SSH_CONFIG", "none")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podssh runs");
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(line);
    });
    let line = rx.recv_timeout(Duration::from_secs(20)).expect("the program printed its pid");
    let pid = line.trim().parse().unwrap_or_else(|_| panic!("a pid: {line:?}"));
    (child, pid)
}

/// The exit code and stderr of `child`, which must end within `limit`.
fn ended(mut child: Child, limit: Duration) -> (Option<i32>, String) {
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > limit {
            let _ = child.kill();
            panic!("podssh did not exit within {limit:?} of the signal");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// Whether `pid` is still a process.
fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 checks the pid and sends nothing.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[test]
fn each_signal_ends_the_pipe_and_its_program_with_128_and_its_number() {
    // The program's pid on stdout, then a wait that only a signal ends.
    let program = "exec:sh -c 'echo $$; exec sleep 60'";
    let signals = [(libc::SIGINT, 130, "SIGINT"), (libc::SIGTERM, 143, "SIGTERM"), (libc::SIGHUP, 129, "SIGHUP")];
    for (signal, code, name) in signals {
        for (a, b) in [("stdio", program), (program, "stdio")] {
            let (child, pid) = started(a, b);
            // SAFETY: a signal to the podssh that this test started.
            unsafe { libc::kill(child.id() as libc::pid_t, signal) };
            // A runner that ignores a signal (nohup) hands that on to the
            // program, which then is killed after 10 s: the same end.
            let (status, err) = ended(child, Duration::from_secs(20));
            assert_eq!(status, Some(code), "{name}, {a} {b}: {err}");
            assert!(err.contains(&format!("{name} ended the pipe")), "{name}, {a} {b}: {err}");
            assert!(!alive(pid), "{name}, {a} {b}: the program {pid} still runs");
        }
    }
}

#[test]
fn a_program_that_ignores_the_signal_is_killed_after_10_s() {
    // Ignored dispositions stay ignored across exec.
    let program = "exec:sh -c 'trap \"\" TERM INT HUP; echo $$; exec sleep 60'";
    let (child, pid) = started("stdio", program);
    // SAFETY: a signal to the podssh that this test started.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    let (status, err) = ended(child, Duration::from_secs(20));
    assert_eq!(status, Some(143), "{err}");
    assert!(err.contains("was killed"), "{err}");
    assert!(!alive(pid), "the program {pid} still runs");
}
