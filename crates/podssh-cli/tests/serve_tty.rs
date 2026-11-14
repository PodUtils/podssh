//! `podssh serve --stdio --pty notify` (T-776) against OpenSSH's client
//! with `-tt`: serve answers the program's tty calls by seccomp's user
//! notification, with no pty, as on a host with no `/dev/ptmx`. bash, as
//! the login shell, sees a tty: `test -t 0` and `stty size` answer, Ctrl-C
//! ends `sleep 30` with 130 and the shell goes on, less draws its screen
//! and reads its `q` from `/dev/tty`, vi takes `:q!`, top draws one frame,
//! and `exit 9` ends the session. The
//! keys come one after another, as typed. Linux's, on x86_64 and aarch64; a
//! host with no OpenSSH client, or whose kernel refuses the notification
//! (podssh doctor's line `pty notify`), says that the test did not run.
//! Where a filter with a listener already stands (a Python wrapper sets one,
//! as a sandbox may), user notification is refused (EBUSY), and serve
//! answers by ptrace (T-777): the same shell, with less's `/dev/tty`.

#![cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]

mod serve_kit;

use std::io::{Read, Write};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serve_kit::{have_openssh, keygen, openssh_proxy, openssh_with, scratch, serve_command};

/// The bound of the whole session.
const BOUND: Duration = Duration::from_secs(45);

/// The keys, each after its pause in ms, through `ssh -tt` to `serve`;
/// the session's output and its exit code.
fn session(serve: &str, keys: &[(u64, &[u8])]) -> (String, Option<i32>) {
    session_in(serve, keys, None).0
}

/// [`session`], with serve behind `wrapper`, a program that execs it, when
/// one is given: the output, the code and ssh's stderr, where the
/// ProxyCommand's lines go.
fn session_in(serve: &str, keys: &[(u64, &[u8])], wrapper: Option<&str>) -> ((String, Option<i32>), String) {
    let dir = scratch("tty");
    keygen(&dir.0, &dir.0.join("id"));
    let mut cmd = match wrapper {
        None => openssh_with(&dir.0, &dir.0.join("id"), "accept-new", serve, &["-tt"], &[]),
        Some(wrapper) => {
            let proxy = format!("{wrapper} {}", serve_command(&dir.0, serve));
            openssh_proxy(&dir.0, &dir.0.join("id"), "accept-new", &proxy, &["-tt"], &[])
        }
    };
    cmd.env("TERM", "xterm").stdin(Stdio::piped()).stdout(Stdio::piped());
    let started = Instant::now();
    let mut child = cmd.spawn().expect("ssh runs");
    let mut out = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = out.read_to_end(&mut bytes);
        let _ = tx.send(bytes);
    });
    let mut stdin = child.stdin.take().expect("stdin");
    for (pause, bytes) in keys {
        std::thread::sleep(Duration::from_millis(*pause));
        let _ = stdin.write_all(bytes);
        let _ = stdin.flush();
    }
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if started.elapsed() > BOUND {
            let _ = child.kill();
            let _ = child.wait();
            break child.wait().expect("wait");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    drop(stdin);
    let text = String::from_utf8_lossy(&rx.recv_timeout(BOUND).unwrap_or_default()).into_owned();
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    ((text, status.code()), err)
}

/// Whether serve can answer tty calls on this host: serve's own probe,
/// which doctor's line `pty notify` also runs.
fn notify_here() -> bool {
    podssh_ssh::server::notify::probe().is_ok()
}

#[test]
fn bash_sees_a_tty_that_serve_answers_with_no_pty() {
    if !have_openssh() {
        eprintln!("did not run: no OpenSSH client here");
        return;
    }
    if !notify_here() {
        eprintln!("did not run: this kernel refuses seccomp's user notification (podssh doctor: pty notify)");
        return;
    }
    let serve = " --pty notify --shell /bin/bash";
    let keys: &[(u64, &[u8])] = &[
        (2500, b"test -t 0 && echo TTY-YES-$(stty size | tr ' ' x)\r"),
        (500, b"test -t 3 3</dev/tty && echo DEVTTY-$((1+1))\r"),
        (800, b"sleep 30\r"),
        (1000, b"\x03"),
        (500, b"echo AFTER-$?\r"),
        (500, b"less /etc/os-release\r"),
        (1500, b"q"),
        (500, b"echo LESS-DONE-$?\r"),
        (500, b"vi -u NONE /etc/os-release\r"),
        (1500, b"\x1b:q!\r"),
        (500, b"echo VI-DONE-$?\r"),
        (500, b"top -n 1\r"),
        (2500, b"echo TOP-DONE-$?\r"),
        (500, b"exit 9\r"),
    ];
    let (text, code) = session(serve, keys);
    assert!(text.contains("TTY-YES-24x80"), "test -t 0 and stty size on the socket: {text:?}");
    assert!(text.contains("DEVTTY-2"), "/dev/tty opens, and is a tty: {text:?}");
    assert!(text.contains("AFTER-130"), "Ctrl-C ended sleep, and the shell went on: {text:?}");
    assert!(text.contains("NAME="), "less drew the file: {text:?}");
    assert!(text.contains("LESS-DONE-0"), "less read its q from /dev/tty and ended: {text:?}");
    assert!(text.contains("VI-DONE-0"), "vi drew its screen and read :q!: {text:?}");
    assert!(text.contains("load average"), "top drew its screen: {text:?}");
    assert!(text.contains("TOP-DONE-0"), "top ended after one frame: {text:?}");
    assert_eq!(code, Some(9), "{text:?}");
}

#[test]
fn pty_names_notify_among_its_modes() {
    // `--pty notify` is a mode the CLI takes; a value it does not know is 64.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["serve", "--stdio", "--pty", "nonesuch", "--authorized-keys", "/nonexistent"])
        .stdin(Stdio::null())
        .output()
        .expect("serve runs");
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains("auto, notify, line or no"));
}

/// A wrapper that installs a seccomp filter which allows each call and
/// holds a listener, kept open across its exec, then execs its arguments:
/// a second listener, serve's, is then refused with EBUSY, as in a sandbox
/// whose own filter has one.
const LISTENER_HELD: &str = r#"
import ctypes, os, platform, struct, sys
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(38, ctypes.c_ulong(1), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
    sys.exit(70)
code = struct.pack("HBBI", 0x06, 0, 0, 0x7FFF0000)
buf = ctypes.create_string_buffer(code, len(code))
class Prog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
prog = Prog(1, ctypes.cast(buf, ctypes.c_void_p))
nr = 317 if platform.machine() == "x86_64" else 277
fd = libc.syscall(ctypes.c_long(nr), ctypes.c_ulong(1), ctypes.c_ulong(8), ctypes.byref(prog))
if fd < 0:
    sys.exit(71)
os.set_inheritable(fd, True)
os.execvp(sys.argv[1], sys.argv[1:])
"#;

#[test]
fn where_a_listener_already_stands_serve_answers_the_tty_by_ptrace() {
    if !have_openssh() {
        eprintln!("did not run: no OpenSSH client here");
        return;
    }
    if podssh_ssh::server::notify::probe_trace().is_err() {
        eprintln!("did not run: ptrace is refused here");
        return;
    }
    let python = std::process::Command::new("python3").arg("-c").arg("pass").status();
    if !python.is_ok_and(|s| s.success()) {
        eprintln!("did not run: no python3 here, to hold a listener");
        return;
    }
    let dir = scratch("tty-held");
    let wrapper = dir.0.join("listener_held.py");
    std::fs::write(&wrapper, LISTENER_HELD).unwrap();
    let wrapper = format!("python3 '{}'", wrapper.display());
    let keys: &[(u64, &[u8])] = &[
        (2500, b"test -t 0 && echo TTY-YES-$(stty size | tr ' ' x)\r"),
        (500, b"test -t 3 3</dev/tty && echo DEVTTY-$((1+1))\r"),
        (800, b"sleep 30\r"),
        (1000, b"\x03"),
        (500, b"echo AFTER-$?\r"),
        (500, b"less /etc/os-release\r"),
        (1500, b"q"),
        (500, b"echo LESS-DONE-$?\r"),
        (500, b"exit 9\r"),
    ];
    let ((text, code), err) = session_in(" --pty notify --shell /bin/bash", keys, Some(&wrapper));
    assert!(err.contains("answered by ptrace"), "serve took the ptrace route: {err}");
    assert!(text.contains("TTY-YES-24x80"), "test -t 0 and stty size, traced: {text:?}");
    assert!(text.contains("DEVTTY-2"), "/dev/tty opens as the socket's copy, and is a tty: {text:?}");
    assert!(text.contains("AFTER-130"), "Ctrl-C ended sleep, and the shell went on: {text:?}");
    assert!(text.contains("NAME=") && text.contains("LESS-DONE-0"), "less read its q from /dev/tty: {text:?}");
    assert_eq!(code, Some(9), "{text:?}");
}
