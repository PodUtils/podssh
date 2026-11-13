//! direct-tcpip into the cage through `podssh serve --stdio` (T-109), against
//! software that podssh did not write: OpenSSH's client, with the server as
//! its ProxyCommand. `-W` to an echo listener of the test carries a million
//! bytes each way, equal; `-W` to a port where nothing listens exits 255 and
//! shows the system's reason; `--no-forwarding` is named in the refusal;
//! `-L` carries bytes through OpenSSH's own listener; `-J` reaches a second
//! serve behind the first and gets its exit status. Unix's, as
//! `serve_openssh.rs`; a host with no OpenSSH client says that the test did
//! not run.

#![cfg(unix)]

mod serve_kit;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serve_kit::{finish, have_openssh, keygen, openssh_with, podssh_env, run, scratch, Scratch, BIN, LIMIT};

/// A scratch home with the key `id` (listed) made, or None where this host
/// has no OpenSSH client.
fn home(tag: &str) -> Option<Scratch> {
    if !have_openssh() {
        eprintln!("did not run: no OpenSSH client here");
        return None;
    }
    let dir = scratch(tag);
    keygen(&dir.0, &dir.0.join("id"));
    Some(dir)
}

/// A listener of the test that echoes one connection until its EOF, then
/// closes: its port, and the count it echoed.
fn echo_once() -> (u16, JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = std::thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(LIMIT)).unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        let mut echoed = 0;
        loop {
            match tcp.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tcp.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    echoed += n;
                }
            }
        }
        let _ = tcp.shutdown(Shutdown::Write);
        echoed
    });
    (port, task)
}

/// A port where nothing listens: a listener's, closed.
fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn bytes(n: u32) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect()
}

#[test]
fn w_carries_a_million_bytes_to_an_echo_and_back() {
    let Some(dir) = home("fwd-w") else { return };
    let (port, echo) = echo_once();
    let target = format!("127.0.0.1:{port}");
    let cmd = openssh_with(&dir.0, &dir.0.join("id"), "accept-new", "", &["-W", &target], &[]);
    let sent = bytes(1_000_000);
    let (code, back, err) = run(cmd, Some(sent.clone()));
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(back.len(), sent.len(), "{err}");
    assert!(back == sent, "the bytes came back changed");
    assert_eq!(echo.join().unwrap(), sent.len(), "the target saw each byte");
}

#[test]
fn w_to_a_closed_port_is_255_with_the_system_s_reason() {
    let Some(dir) = home("fwd-closed") else { return };
    let target = format!("127.0.0.1:{}", closed_port());
    let cmd = openssh_with(&dir.0, &dir.0.join("id"), "accept-new", "", &["-W", &target], &[]);
    let (code, err) = finish(cmd);
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("connect failed: podssh serve: "), "the refusal's words: {err}");
    assert!(err.contains(&target), "the target in the words: {err}");
    assert!(err.contains("Connection refused"), "the system's reason: {err}");
}

#[test]
fn no_forwarding_is_named_in_the_refusal() {
    let Some(dir) = home("fwd-none") else { return };
    let (port, _echo) = echo_once();
    let target = format!("127.0.0.1:{port}");
    let cmd = openssh_with(&dir.0, &dir.0.join("id"), "accept-new", " --no-forwarding", &["-W", &target], &[]);
    let (code, err) = finish(cmd);
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("administratively prohibited"), "{err}");
    assert!(err.contains("--no-forwarding"), "{err}");
    // A command still runs: the flag is about forwards alone.
    let cmd = openssh_with(&dir.0, &dir.0.join("id"), "accept-new", " --no-forwarding", &[], &["exit 4"]);
    let (code, err) = finish(cmd);
    assert_eq!(code, Some(4), "{err}");
}

/// `cmd` started, killed when the guard is dropped.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn l_carries_bytes_through_openssh_s_listener() {
    let Some(dir) = home("fwd-l") else { return };
    let (port, echo) = echo_once();
    let local = closed_port();
    let spec = format!("127.0.0.1:{local}:127.0.0.1:{port}");
    let options = ["-N", "-o", "ExitOnForwardFailure=yes", "-L", &spec];
    let mut cmd = openssh_with(&dir.0, &dir.0.join("id"), "accept-new", "", &options, &[]);
    cmd.stderr(Stdio::null());
    let mut ssh = Running(cmd.spawn().expect("ssh runs"));
    // OpenSSH listens once it logged in.
    let deadline = Instant::now() + LIMIT;
    let mut tcp = loop {
        if let Ok(tcp) = TcpStream::connect(("127.0.0.1", local)) {
            break tcp;
        }
        if let Ok(Some(status)) = ssh.0.try_wait() {
            panic!("ssh ended before it listened: {status}");
        }
        assert!(Instant::now() < deadline, "ssh did not listen within {LIMIT:?}");
        std::thread::sleep(Duration::from_millis(50));
    };
    tcp.set_read_timeout(Some(LIMIT)).unwrap();
    let sent = bytes(200_000);
    let writer = {
        let (mut tcp, sent) = (tcp.try_clone().unwrap(), sent.clone());
        std::thread::spawn(move || {
            tcp.write_all(&sent).unwrap();
            tcp.shutdown(Shutdown::Write).unwrap();
        })
    };
    let mut back = Vec::new();
    tcp.read_to_end(&mut back).expect("the echo's end within the limit");
    writer.join().unwrap();
    assert!(back == sent, "the bytes came back changed: {} of {}", back.len(), sent.len());
    assert_eq!(echo.join().unwrap(), sent.len());
    drop(ssh);
}

/// A second `podssh serve --stdio` behind a listener of the test, as an
/// sshd on a port of the cage: the one connection it takes is the server's
/// stdin and stdout.
fn hop_once(home: &Path) -> (u16, mpsc::Receiver<Child>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    let home = home.to_path_buf();
    std::thread::spawn(move || {
        let Ok((tcp, _)) = listener.accept() else { return };
        let mut cmd = Command::new(BIN);
        cmd.args(["serve", "--stdio", "--authorized-keys"]).arg(home.join("id.pub"));
        cmd.stdin(Stdio::from(OwnedFd::from(tcp.try_clone().unwrap())))
            .stdout(Stdio::from(OwnedFd::from(tcp)))
            .stderr(Stdio::null());
        podssh_env(&mut cmd, &home);
        let _ = tx.send(cmd.spawn().expect("the hop's serve runs"));
    });
    (port, rx)
}

#[test]
fn j_reaches_a_second_serve_behind_the_first() {
    let Some(dir) = home("fwd-j") else { return };
    let home = &dir.0;
    let (port, hop) = hop_once(home);
    // OpenSSH gives the jump's own ssh this file and none of the -o options,
    // so each setting is here.
    let config = format!(
        "Host *\n  BatchMode yes\n  IdentitiesOnly yes\n  IdentityFile {home}/id\n  UserKnownHostsFile \
         {home}/known_hosts\n  StrictHostKeyChecking accept-new\n  LogLevel VERBOSE\n  ConnectTimeout 30\n  User \
         anyone\nHost serve\n  HostKeyAlias podssh-serve-test\n  ProxyCommand '{BIN}' serve --stdio \
         --authorized-keys '{home}/id.pub'\nHost hop\n  HostName 127.0.0.1\n  Port {port}\n  HostKeyAlias \
         podssh-hop-test\n  ProxyJump serve\n",
        home = home.display()
    );
    let file = home.join("ssh_config");
    std::fs::write(&file, config).unwrap();
    let mut cmd = Command::new("ssh");
    cmd.arg("-F").arg(&file).args(["hop", "exit 5"]);
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    podssh_env(&mut cmd, home);
    let (code, err) = finish(cmd);
    let child = hop.recv_timeout(LIMIT).map(Running);
    assert_eq!(code, Some(5), "the hop's exit status through the first serve: {err}");
    assert!(child.is_ok(), "the hop took one connection: {err}");
}
