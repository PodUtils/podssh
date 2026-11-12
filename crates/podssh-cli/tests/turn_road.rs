//! `--turn` (T-621) against coturn, a TURN server that podssh did not
//! write: its `turnserver`, whose path `PODSSH_TURN_TEST_BIN` names
//! (turn-interop.yml installs Ubuntu's coturn and sets it), on the loopback
//! with no TLS, which `turn:` takes for this host alone. Through `podssh
//! proxy`: 1 MiB each way to an echo with equal bytes, on the two
//! connections of RFC 6062; a coturn with `no-tcp-relay` refused in the
//! words of step 5 (69); a wrong password refused (77); and an allocation
//! that coturn holds to 60 s carrying bytes past 90 s by its Refresh. Each
//! says "did not run" with no coturn, and the workflow fails on that word.
//! TLS on 443 and the host's squid are the workflow's own steps.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The tests' own throwaway credential, no secret.
const USER: &str = "podssh-test";
const PASSWORD: &str = "turn-test-password";
const REALM: &str = "podssh.test";

/// coturn on the loopback; killed, and its directory gone, at the end.
struct Coturn {
    child: Child,
    dir: PathBuf,
    port: u16,
}

impl Drop for Coturn {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// coturn with `extra` options, or `None` (and the words "did not run")
/// with no binary.
fn coturn(tag: &str, extra: &[&str]) -> Option<Coturn> {
    let Some(bin) = std::env::var_os("PODSSH_TURN_TEST_BIN") else {
        println!("did not run: PODSSH_TURN_TEST_BIN names no coturn turnserver (turn-interop.yml sets it)");
        return None;
    };
    let dir = std::env::temp_dir().join(format!("podssh-turn-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let port = free_port();
    let mut cmd = Command::new(bin);
    // No configuration file of the host; the loopback alone, TCP alone.
    cmd.args(["-n", "--no-cli", "--no-tls", "--no-dtls", "--no-udp", "--simple-log", "--log-file", "stdout"]);
    cmd.args(["--listening-ip", "127.0.0.1", "--relay-ip", "127.0.0.1", "--allow-loopback-peers"]);
    cmd.args(["--listening-port", &port.to_string(), "--lt-cred-mech", "--realm", REALM]);
    cmd.arg(format!("--user={USER}:{PASSWORD}"));
    cmd.args(extra).current_dir(&dir);
    let log = std::fs::File::create(dir.join("coturn.log")).unwrap();
    let child = cmd.stdout(log.try_clone().unwrap()).stderr(log).stdin(Stdio::null()).spawn().unwrap();
    let server = Coturn { child, dir, port };
    let until = Instant::now() + Duration::from_secs(15);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < until, "coturn did not listen: {}", log_of(&server.dir));
        std::thread::sleep(Duration::from_millis(100));
    }
    Some(server)
}

fn log_of(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("coturn.log")).unwrap_or_default()
}

/// A target that echoes each byte, on the loopback.
fn echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut back = conn.try_clone().unwrap();
                let mut conn = conn;
                let _ = std::io::copy(&mut conn, &mut back);
            });
        }
    });
    port
}

/// The credential file, private.
fn auth(dir: &Path, name: &str, password: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, format!("{USER}:{password}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path.display().to_string()
}

/// `podssh proxy --turn turn:127.0.0.1:PORT --turn-auth-file FILE
/// 127.0.0.1 TARGET`, with none of the machine's proxies or settings.
fn proxy(server: &Coturn, file: &str, target: u16) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    let uri = format!("turn:127.0.0.1:{}", server.port);
    cmd.args(["proxy", "--turn", &uri, "--turn-auth-file", file, "127.0.0.1", &target.to_string()]);
    cmd.env("HOME", &server.dir).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_CACHE_DIR", server.dir.join("cache"));
    for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "PODSSH_TURN"] {
        cmd.env_remove(name);
    }
    cmd
}

/// Bytes of no pattern that a cut or a shift would hide.
fn bytes(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// The pipe of `cmd`: `first` sent and echoed, then, after `pause`,
/// `second`; stdin is closed only once each byte came back, as coturn ends
/// the target's connection with the client's. What came back.
fn echoed(mut cmd: Command, first: &[u8], pause: Duration, second: &[u8]) -> Vec<u8> {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (a, b) = (first.to_vec(), second.to_vec());
    let writer = std::thread::spawn(move || {
        stdin.write_all(&a).unwrap();
        std::thread::sleep(pause);
        stdin.write_all(&b).unwrap();
        stdin
    });
    let want = first.len() + second.len();
    let reader = std::thread::spawn(move || {
        let mut got = vec![0u8; want];
        let read = stdout.read_exact(&mut got).map(|()| got);
        (read, stdout)
    });
    let deadline = Instant::now() + pause + Duration::from_secs(120);
    while !reader.is_finished() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("the echo did not come back in time");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let (got, _stdout) = reader.join().unwrap();
    drop(writer.join().unwrap());
    let _ = child.kill();
    let mut err = String::new();
    let _ = child.stderr.take().unwrap().read_to_string(&mut err);
    let _ = child.wait();
    got.unwrap_or_else(|e| panic!("the pipe ended early ({e}): {err}"))
}

/// The exit code and stderr of `cmd`, with nothing on stdin, bounded.
fn refused(mut cmd: Command) -> (i32, String) {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "podssh proxy did not end");
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut err = String::new();
    let _ = child.stderr.take().unwrap().read_to_string(&mut err);
    (status.code().unwrap_or(-1), err)
}

#[test]
fn a_mib_each_way_goes_through_coturn_s_tcp_allocation() {
    let Some(server) = coturn("mib", &[]) else { return };
    let file = auth(&server.dir, "auth", PASSWORD);
    let sent = bytes(1024 * 1024);
    let back = echoed(proxy(&server, &file, echo()), &sent, Duration::ZERO, &[]);
    assert!(back == sent, "the bytes that came back are not the bytes sent: {}", log_of(&server.dir));
}

#[test]
fn a_coturn_with_no_tcp_relay_is_refused_in_the_words_of_step_5() {
    let Some(server) = coturn("no-tcp", &["--no-tcp-relay"]) else { return };
    let file = auth(&server.dir, "auth", PASSWORD);
    let (code, err) = refused(proxy(&server, &file, echo()));
    assert_eq!(code, 69, "{err}");
    assert!(err.contains("refused a TCP allocation") && err.contains("offers no RFC 6062"), "{err}");
}

#[test]
fn a_wrong_password_is_refused_and_never_shown() {
    let Some(server) = coturn("wrong", &[]) else { return };
    let file = auth(&server.dir, "auth", "not-the-turn-test-password");
    let (code, err) = refused(proxy(&server, &file, echo()));
    assert_eq!(code, 77, "{err}");
    assert!(err.contains("refused the credential") && !err.contains("not-the-turn-test-password"), "{err}");
}

#[test]
fn an_allocation_of_60_s_lives_past_90_s_by_its_refresh() {
    // coturn caps each lifetime at 60 s: with no Refresh, it ends the
    // allocation and its data connection before the second write.
    let Some(server) = coturn("refresh", &["--max-allocate-lifetime", "60"]) else { return };
    let file = auth(&server.dir, "auth", PASSWORD);
    let (first, second) = (bytes(4096), bytes(8192));
    let back = echoed(proxy(&server, &file, echo()), &first, Duration::from_secs(95), &second[4096..]);
    assert_eq!(back.len(), 8192);
    assert!(back[..4096] == first[..] && back[4096..] == second[4096..], "the bytes past 90 s are not the bytes sent");
}
