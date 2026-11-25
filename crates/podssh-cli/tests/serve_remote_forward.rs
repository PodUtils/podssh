//! A stock `ssh -R` through `podssh serve --stdio` (T-123), against
//! software that podssh did not write: OpenSSH's client, with serve as its
//! ProxyCommand. Through the stand-in relay of the reverse road (Python and
//! openssl), a request of port 0 is a pair whose node runs in serve:
//! serve's log names the pair, OpenSSH prints the port that it was told and,
//! at `-v`, serve's `SSH_MSG_DEBUG` with the name; `podssh operator LABEL`
//! reads the banner of the client's service through the client's channel;
//! serve holds no listening socket meanwhile; and the client's end stops the
//! pair at the relay and forgets its stored copy. With `PODSSH_OFFLINE`, the
//! forward is refused and OpenSSH's `ExitOnForwardFailure` ends it. The
//! same steps against the live relay: `-- --ignored`. A host with no OpenSSH
//! client, Python or openssl says that the test did not run. With
//! `--remote-listen` (step 4) the forward is a listener on serve's loopback
//! instead, and `PODSSH_LISTEN=no` refuses the flag at the start. Unix's.

#![cfg(unix)]

mod serve_kit;
mod ssh_harness;
mod throughput_harness;

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use serve_kit::{finish, have_openssh, keygen, number_in, openssh_proxy, podssh_env, wrapped_serve_with, LIMIT};
use throughput_harness::{lines_of, without_proxy, Cell, Session};

/// A child killed when the guard goes.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Each line of `lines` into `seen` until one holds `needle`, within
/// [`LIMIT`]: that line.
fn until(lines: &Receiver<String>, needle: &str, seen: &mut Vec<String>) -> String {
    let deadline = Instant::now() + LIMIT;
    loop {
        match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => {
                seen.push(line.clone());
                if line.contains(needle) {
                    return line;
                }
            }
            Err(_) => panic!("no {needle:?} within {LIMIT:?}: {}", seen.join("\n")),
        }
    }
}

/// The text between `before` and `after` in `line`.
fn between<'a>(line: &'a str, before: &str, after: &str) -> &'a str {
    let rest = line.split_once(before).map_or("", |(_, rest)| rest);
    rest.split_once(after).map_or(rest, |(word, _)| word)
}

/// The first file under `dir` whose name starts with `name`.
fn found(dir: &Path, name: &str) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    entries.flatten().find_map(|e| {
        let path = e.path();
        match path.file_name().is_some_and(|n| n.to_string_lossy().starts_with(name)) {
            true => Some(path),
            false if path.is_dir() => found(&path, name),
            false => None,
        }
    })
}

/// The tokens of a stored pair: each long word of its file but its name.
fn tokens(file: &Path, name: &str) -> Vec<String> {
    let text = std::fs::read_to_string(file).unwrap_or_default();
    let long = |w: &&str| *w != name && w.len() >= 32 && w.chars().all(|c| c.is_ascii_alphanumeric());
    text.split('"').filter(long).map(str::to_string).collect()
}

/// The TCP sockets that `pid` holds in the listening state, where `/proc`
/// tells them; None elsewhere.
fn listening(pid: i32) -> Option<usize> {
    let fds = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    let inodes: Vec<String> = fds
        .flatten()
        .filter_map(|fd| std::fs::read_link(fd.path()).ok())
        .filter_map(|link| link.to_string_lossy().strip_prefix("socket:[")?.strip_suffix(']').map(str::to_string))
        .collect();
    let mut count = 0;
    for table in ["tcp", "tcp6"] {
        let text = std::fs::read_to_string(format!("/proc/{pid}/net/{table}")).unwrap_or_default();
        // The fourth column is the state (0A: listening); the tenth, the inode.
        for row in text.lines().skip(1).map(|l| l.split_whitespace().collect::<Vec<_>>()) {
            if row.get(3) == Some(&"0A") && row.get(9).is_some_and(|inode| inodes.iter().any(|i| i == inode)) {
                count += 1;
            }
        }
    }
    Some(count)
}

/// The first line of `child`'s stdout, within [`LIMIT`].
fn first_line(child: &mut Child) -> String {
    let out = child.stdout.take().expect("stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(out).read_line(&mut line);
        let _ = tx.send(line);
    });
    rx.recv_timeout(LIMIT).unwrap_or_default()
}

/// OpenSSH's `ssh -v -N -R 0:127.0.0.1:PORT` through serve, for the test's
/// SSH server, with `env` on ssh and so on serve, its ProxyCommand; serve
/// takes `--publish-remote` where `publish` holds (Q108).
fn ssh_r(s: &Session, env: &[(&str, &str)], clean: bool, publish: bool) -> Command {
    ssh_r_flags(s, env, clean, if publish { " --publish-remote" } else { "" })
}

/// [`ssh_r`] with serve's `flags`, the way out of the test's host taken off.
fn ssh_r_with(s: &Session, env: &[(&str, &str)], flags: &str) -> Command {
    ssh_r_flags(s, env, true, flags)
}

fn ssh_r_flags(s: &Session, env: &[(&str, &str)], clean: bool, flags: &str) -> Command {
    let home = &s.home;
    keygen(home, &home.join("id"));
    let spec = format!("0:127.0.0.1:{}", s.port);
    let options = ["-v", "-N", "-o", "ExitOnForwardFailure=yes", "-R", &spec];
    let serve = wrapped_serve_with(home, flags);
    let cmd = openssh_proxy(home, &home.join("id"), "accept-new", &serve, &options, &[]);
    let mut cmd = if clean { without_proxy(cmd) } else { cmd };
    cmd.envs(env.iter().copied());
    cmd
}

/// The whole road: the pair, the lines, the banner through an operator, no
/// listener, and the pair's stop at the client's end. `env` names the relay.
fn forward_reaches_the_client(s: &Session, env: &[(&str, &str)], clean: bool) {
    let home = s.home.clone();
    let mut ssh = Running(ssh_r(s, env, clean, true).spawn().expect("ssh runs"));
    let lines = lines_of(&mut ssh.0);
    let mut seen = Vec::new();
    // serve's log: the label, the forward, the pair's relay name.
    let made = until(&lines, " is the pair ", &mut seen);
    let label = between(&made, "podssh serve: ", ": -R ").to_string();
    let name = between(&made, " is the pair ", " at ").to_string();
    assert!(label.starts_with('r') && !name.is_empty(), "{made}");
    // OpenSSH's own line of the port that it was told.
    let allocated = until(&lines, "Allocated port ", &mut seen);
    let port: u32 = between(&allocated, "Allocated port ", " ").parse().expect("a port");
    assert!((49_152..=65_535).contains(&port), "{allocated}");
    // serve's SSH_MSG_DEBUG, which OpenSSH shows at -v as "Remote: ...";
    // OpenSSH asks a -R with no bind address for "localhost".
    let told = seen.iter().find(|l| l.contains("Remote: podssh serve: -R ")).cloned().unwrap_or_default();
    assert!(told.contains(&format!("-R localhost:{port} is published as {label}")), "{}", seen.join("\n"));
    assert!(made.contains(&format!("-R localhost:{port} of key ")), "{made}");
    let kept = found(&home, &format!("pair-{label}.json")).expect("the pair is kept for the operator");
    let secrets = tokens(&kept, &name);
    assert_eq!(secrets.len(), 3, "the node's, the connect and the stop token");
    let pid = number_in(&home.join("serve.pid"));
    if let Some(count) = listening(pid) {
        assert_eq!(count, 0, "serve binds no socket for -R");
    }

    // An operator on this host reads the banner of the client's service.
    let cmd = s.command(&["operator".to_string(), label.clone()]);
    let mut cmd = if clean { without_proxy(cmd) } else { cmd };
    podssh_env(&mut cmd, &home);
    cmd.envs(env.iter().copied()).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut operator = Running(cmd.spawn().expect("podssh operator runs"));
    let banner = first_line(&mut operator.0);
    assert!(banner.starts_with("SSH-2.0-"), "the client's service answered: {banner:?}");
    drop(operator);
    assert!(s.connections.load(std::sync::atomic::Ordering::SeqCst) >= 1, "the client dialed its own service");

    // The client's end: serve stops the pair, forgets its copy, and ends.
    drop(ssh);
    // Its exit code is the connection's, cut here: its end is the point.
    let _ = number_in(&home.join("serve.status"));
    while let Ok(line) = lines.recv_timeout(Duration::from_millis(200)) {
        seen.push(line);
    }
    let shown = seen.join("\n");
    assert!(!shown.contains("did not answer the pair's stop"), "{shown}");
    assert!(found(&home, &format!("pair-{label}.json")).is_none(), "the stopped pair's copy is gone: {shown}");
    let events = home.join("fake-relay-normal-relay.pem-events.log");
    if let Ok(text) = std::fs::read_to_string(events) {
        assert!(text.contains(&format!("reverse: stopped {name}")), "the relay heard the stop: {text}");
    }
    // Asserted by position, so that a failure prints no token.
    let leaked = secrets.iter().position(|t| shown.contains(t.as_str()));
    assert_eq!(leaked, None, "a line holds token number {leaked:?} of the pair");
}

/// The stand-in relay's place: its host, its pins and its CA, for serve and
/// for the operator; None where it cannot run here.
fn stand_in(s: &Session) -> Option<(String, String)> {
    if !have_openssh() {
        eprintln!("did not run: no OpenSSH client here");
        return None;
    }
    match Cell::fake_relay_mode(s, "normal", "the stand-in relay") {
        Ok(cell) => {
            let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone());
            Some((at("--relay-host")?, at("--ca-file")?))
        }
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            None
        }
    }
}

#[test]
fn a_stock_r_is_a_pair_whose_operator_reaches_the_client() {
    let s = Session::start("serve-rfwd");
    let Some((relay, ca)) = stand_in(&s) else { return };
    let pins = "relay-a.test=127.0.0.1";
    let env = [("PODSSH_RELAY", relay.as_str()), ("PODSSH_RELAY_ADDR", pins), ("SSL_CERT_FILE", ca.as_str())];
    forward_reaches_the_client(&s, &env, true);
}

/// With no way out, the forward is refused with serve's reason, and
/// `ExitOnForwardFailure` ends OpenSSH as a refused bind would.
#[test]
fn an_offline_serve_refuses_the_forward_and_says_why() {
    if !have_openssh() {
        return eprintln!("did not run: no OpenSSH client here");
    }
    let s = Session::start("serve-rfwd-off");
    let cmd = ssh_r(&s, &[("PODSSH_OFFLINE", "1")], true, true);
    let (code, err) = finish(cmd);
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("remote port forwarding failed"), "OpenSSH's words: {err}");
    assert!(err.contains("refused: not attempted: PODSSH_OFFLINE is set"), "serve's: {err}");
    assert!(found(&s.home, "pair-").is_none(), "no pair was made");
}

/// Without `--publish-remote`, serve makes no pair and connects to no relay
/// (Q108): the -R is refused with serve's line, as before T-123.
#[test]
fn without_publish_remote_a_forward_is_refused_and_no_pair_is_made() {
    if !have_openssh() {
        return eprintln!("did not run: no OpenSSH client here");
    }
    let s = Session::start("serve-rfwd-plain");
    let (code, err) = finish(ssh_r(&s, &[], true, false));
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("remote port forwarding failed"), "OpenSSH's words: {err}");
    assert!(err.contains("serve --publish-remote publishes it at the relay"), "serve's: {err}");
    assert!(found(&s.home, "pair-").is_none(), "no pair was made");
}

/// The live relay, with this host's way out: `-- --ignored`.
#[test]
#[ignore = "the live relay"]
fn a_stock_r_through_the_live_relay() {
    if !have_openssh() {
        return eprintln!("did not run: no OpenSSH client here");
    }
    let s = Session::start("serve-rfwd-live");
    forward_reaches_the_client(&s, &[], false);
}

/// `--remote-listen` (step 4): the forward is a listener on serve's
/// loopback at the port that OpenSSH was told; a connection there reads the
/// banner of the client's service; serve holds that one listening socket,
/// and the client's end closes it. No pair is made.
#[test]
fn with_remote_listen_a_stock_r_is_a_loopback_listener() {
    if !have_openssh() {
        return eprintln!("did not run: no OpenSSH client here");
    }
    let s = Session::start("serve-rfwd-listen");
    let home = s.home.clone();
    let mut ssh = Running(ssh_r_with(&s, &[], " --remote-listen").spawn().expect("ssh runs"));
    let lines = lines_of(&mut ssh.0);
    let mut seen = Vec::new();
    let allocated = until(&lines, "Allocated port ", &mut seen);
    let port: u16 = between(&allocated, "Allocated port ", " ").parse().expect("a port");
    // serve's SSH_MSG_DEBUG comes before OpenSSH's own line.
    let told = seen.iter().find(|l| l.contains("Remote: podssh serve: -R ")).cloned().unwrap_or_default();
    assert!(told.contains(&format!("-R localhost:{port} is published as 127.0.0.1:{port}")), "{}", seen.join("\n"));
    let pid = number_in(&home.join("serve.pid"));
    if let Some(count) = listening(pid) {
        assert_eq!(count, 1, "serve holds the forward's listener alone");
    }
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("the forward's listener takes it");
    stream.set_read_timeout(Some(LIMIT)).unwrap();
    let mut banner = String::new();
    let _ = BufReader::new(&mut stream).read_line(&mut banner);
    assert!(banner.starts_with("SSH-2.0-"), "the client's service answered: {banner:?}");
    drop(stream);
    assert!(found(&home, "pair-").is_none(), "no pair was made");

    // The client's end ends serve, and its listener with it.
    drop(ssh);
    let _ = number_in(&home.join("serve.status"));
    let gone = std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_secs(2));
    assert!(gone.is_err(), "the listener is closed with the forward");
}

/// `PODSSH_LISTEN=no` refuses `--remote-listen` at serve's start (78),
/// with its line, before any forward.
#[test]
fn podssh_listen_no_refuses_remote_listen_at_the_start() {
    if !have_openssh() {
        return eprintln!("did not run: no OpenSSH client here");
    }
    let s = Session::start("serve-rfwd-nolisten");
    let (code, err) = finish(ssh_r_with(&s, &[("PODSSH_LISTEN", "no")], " --remote-listen"));
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("PODSSH_LISTEN=no turns listening off"), "serve's: {err}");
    assert_eq!(number_in(&s.home.join("serve.status")), 78, "{err}");
}
