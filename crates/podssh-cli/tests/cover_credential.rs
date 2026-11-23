//! The delegated credential on the live tunnel (#225, T-765): `podssh proxy
//! --cover-credential` asks the cover relay for a credential after the TLS
//! handshake, checks its issuer, chain, window, subject key and exporter,
//! and upgrades on that same connection. The role is a process of the test's
//! certificate and its cover site; the tunnel carries lines to an echo
//! target. A covered relay that did not mint the token answers the request
//! with its 404, and the proxy refuses the session rather than upgrading past
//! the check.

#![cfg(unix)]

mod serve_certs;

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;

use serve_certs::{ca_and_leaf, podssh, replace, until, until_role, Killed, Scratch};

const NAME: &str = "relay-a.test";

/// A target that sends back each line that it gets.
fn echo_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut back = stream.try_clone().unwrap();
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    if writeln!(back, "{line}").is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

/// A scratch directory with a certificate for NAME, a site and a cache.
struct Place {
    s: Scratch,
    ca: std::path::PathBuf,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    site: std::path::PathBuf,
    socket: std::path::PathBuf,
}

impl Place {
    fn new(tag: &str) -> Place {
        let s = Scratch(std::env::temp_dir().join(format!(
            "podssh-cover-credential-{tag}-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        )));
        std::fs::create_dir_all(s.0.join("cache")).unwrap();
        std::fs::create_dir_all(s.0.join("site")).unwrap();
        std::fs::write(s.0.join("site/index.html"), b"<html><body>cover</body></html>").unwrap();
        let (ca, leaf, key) = ca_and_leaf(tag);
        let (ca_file, cert, key_file) = (s.0.join("ca.pem"), s.0.join("cert.pem"), s.0.join("key.pem"));
        std::fs::write(&ca_file, ca).unwrap();
        replace(&cert, &leaf);
        replace(&key_file, &key);
        let (site, socket) = (s.0.join("site"), s.0.join("control.sock"));
        Place { s, ca: ca_file, cert, key: key_file, site, socket }
    }

    /// The role on a free loopback port, its events on stdout to `events`,
    /// its lines on stderr to `said`, its port in `port_file`, and a cover
    /// only when `covered`. A role that ends before its port fails the test
    /// with its status and both files.
    fn serve(&self, name: &str, covered: bool) -> (u16, Killed) {
        let (events, port_file) = (self.s.0.join(format!("{name}.events")), self.s.0.join(format!("{name}.port")));
        let said = self.s.0.join(format!("{name}.stderr"));
        let mut cmd: Command = podssh(&self.s.0);
        cmd.args(["relay", "serve", "--listen", "127.0.0.1:0", "--mint", "anyone", "--allow-private"])
            .arg("--cert")
            .arg(&self.cert)
            .arg("--key")
            .arg(&self.key)
            .arg("--port-file")
            .arg(&port_file);
        if covered {
            cmd.arg("--cover").arg(&self.site).arg("--control-socket").arg(&self.socket);
        }
        cmd.stdin(Stdio::null())
            .stdout(std::fs::File::create(&events).unwrap())
            .stderr(std::fs::File::create(&said).unwrap());
        let mut role = Killed(cmd.spawn().unwrap());
        let mut port = 0;
        until_role("the role's port", &mut role, &[events.as_path(), said.as_path()], || {
            port = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse().ok()).unwrap_or(0);
            port != 0
        });
        (port, role)
    }
}

/// A proxy through `port` to `target`, its stdin and stdout, and its log.
fn proxy(
    place: &Place,
    port: u16,
    target: u16,
    log: &str,
    token: Option<&str>,
) -> (std::process::Child, std::path::PathBuf) {
    let log = place.s.0.join(log);
    let mut cmd: Command = podssh(&place.s.0);
    if let Some(token) = token {
        cmd.env("PODSSH_RELAY_TOKEN", token);
    }
    let proxy = cmd
        .arg("proxy")
        .args(["--relay-host", &format!("{NAME}:{port}"), "--relay-addr", &format!("{NAME}=127.0.0.1")])
        .arg("--ca-file")
        .arg(&place.ca)
        .arg("--cover-credential")
        .arg("127.0.0.1")
        .arg(target.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    (proxy, log)
}

#[test]
fn the_credential_and_a_shape_are_refused_together() {
    let s = Scratch(std::env::temp_dir().join(format!(
        "podssh-cover-choice-{}-{:08x}",
        std::process::id(),
        rand::random::<u32>()
    )));
    std::fs::create_dir_all(&s.0).unwrap();
    let out = podssh(&s.0)
        .args(["proxy", "--cover-credential", "--h2-shape", "browser", "127.0.0.1", "1"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64), "the two roads are refused together: {out:?}");
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("--cover-credential"), "the words name the credential: {said}");
    assert!(said.contains("--h2-shape"), "the words name the shape: {said}");
}

#[test]
fn the_live_tunnel_takes_a_checked_credential_and_upgrades_on_that_connection() {
    let place = Place::new("live");
    let (port, _role) = place.serve("covered", true);
    let target = echo_target();
    let (mut proxy, log) = proxy(&place, port, target, "proxy.log", None);
    let (mut to_proxy, from_proxy) = (proxy.stdin.take().unwrap(), proxy.stdout.take().unwrap());
    let _proxy = Killed(proxy);
    let (lines_tx, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(from_proxy).lines().map_while(Result::ok) {
            let _ = lines_tx.send(line);
        }
    });
    writeln!(to_proxy, "through the covered tunnel").unwrap();
    to_proxy.flush().unwrap();
    let back = lines
        .recv_timeout(Duration::from_secs(60))
        .unwrap_or_else(|e| panic!("{e}; the proxy said: {}", std::fs::read_to_string(&log).unwrap_or_default()));
    assert_eq!(back, "through the covered tunnel");
    // The role issued the credential that the tunnel used, on the connection
    // that carried it: the event is the server's, not the client's claim.
    let events = place.s.0.join("covered.events");
    until("the delegate event", &events, || {
        std::fs::read_to_string(&events).is_ok_and(|text| text.contains(&format!("delegate {NAME}")))
    });
}

#[test]
fn a_covered_relay_refuses_a_credential_it_did_not_mint() {
    let place = Place::new("badtoken");
    let (port, _role) = place.serve("covered", true);
    let target = echo_target();
    let (mut proxy, log) = proxy(&place, port, target, "proxy.log", Some("not-a-minted-token"));
    let mut stdin = proxy.stdin.take().expect("a stdin");
    writeln!(stdin, "a line that the refused road never carries").unwrap();
    stdin.flush().unwrap();
    let _proxy = Killed(proxy);
    // The refusal is the first attempt's, so it is said at once; the run may
    // go on to another road, which is not this test's.
    until("the refused credential", &log, || std::fs::read_to_string(&log).is_ok_and(|text| text.contains("404")));
    let said = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(said.contains("cover credential"), "the failure names the credential: {said}");
    assert!(said.contains("404"), "the relay's 404 is what refused it: {said}");
}
