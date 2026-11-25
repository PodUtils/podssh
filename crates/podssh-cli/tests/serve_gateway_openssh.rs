//! `podssh serve --gateway FILE` (T-836) against software that podssh did
//! not write at both ends: OpenSSH's client, with the gateway as its
//! ProxyCommand, and two stock OpenSSH servers as the upstreams, each with
//! `TrustedUserCAKeys` of the route's CA and no authorized key of its own.
//! `user-a@` reaches one server and `user-b@` the other, each by a
//! certificate whose key id names the route; a name with no route is
//! refused (255, one line that says why); an upstream whose host key the
//! route does not pin is refused before the login; and a client that offers
//! 20 keys of the route and signs with none causes no login upstream.
//! Unix's; a host with no OpenSSH client or no sshd says the test did not
//! run.

#![cfg(unix)]

mod live_harness;
mod serve_kit;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use live_harness::sshd::{self, Sshd};
use serve_kit::{finish, have_openssh, keygen, podssh_env, run, scratch, Scratch, BIN};

/// This user's name: each upstream runs as it, and the certificate's
/// principal must be it.
fn this_user() -> Option<String> {
    let name = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).ok().filter(|u| !u.is_empty());
    name.or_else(|| {
        let out = Command::new("id").arg("-un").output().ok()?;
        Some(String::from_utf8(out.stdout).ok()?.trim().to_string()).filter(|u| !u.is_empty())
    })
}

/// The first line of a public key file, `TYPE BASE64 [COMMENT]`.
fn line_of(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap().lines().next().unwrap().trim().to_string()
}

/// A scratch home with the client's key and the CA, and the two upstreams,
/// each trusting the CA and listing no key; None where a tool is missing.
struct Lab {
    home: Scratch,
    user: String,
    a: Sshd,
    b: Sshd,
}

impl Lab {
    fn start(tag: &str) -> Option<Lab> {
        let Some(user) = this_user().filter(|_| have_openssh()) else {
            eprintln!("did not run: no OpenSSH client or no user name here");
            return None;
        };
        let home = scratch(tag);
        keygen(&home.0, &home.0.join("id"));
        keygen(&home.0, &home.0.join("ca"));
        let mut upstreams = Vec::new();
        for name in ["a", "b"] {
            let dir = home.0.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            // No key of its own: the certificate alone lets the gateway in.
            let none = dir.join("authorized_keys");
            std::fs::write(&none, "").unwrap();
            let trust = format!("TrustedUserCAKeys {}\nLogLevel VERBOSE\n", home.0.join("ca.pub").display());
            match sshd::start_with(&dir, &none, &trust) {
                Ok(sshd) => upstreams.push(sshd),
                Err(why) => {
                    eprintln!("did not run: {why}");
                    return None;
                }
            }
        }
        let b = upstreams.pop().unwrap();
        let a = upstreams.pop().unwrap();
        Some(Lab { home, user, a, b })
    }

    fn dir(&self) -> &Path {
        &self.home.0
    }

    /// A route block for `pattern` to `sshd` of `dir`, pinning `host_key`,
    /// and taking each key line of `keys`.
    fn route(&self, pattern: &str, sshd: &Sshd, host_key: &str, keys: &[String]) -> String {
        let mut text = format!(
            "route {pattern}\n    upstream 127.0.0.1:{}\n    host-key {host_key}\n    principal {}\n    ca-key ca\n",
            sshd.port, self.user
        );
        for key in keys {
            text.push_str(&format!("    key {key}\n"));
        }
        text
    }

    /// The pinned host key of upstream `name`.
    fn host_key(&self, name: &str) -> String {
        line_of(&self.dir().join(name).join("sshd_host_key.pub"))
    }

    /// `text` as the route table, `routes` in the scratch home.
    fn write_routes(&self, text: &str) -> PathBuf {
        let path = self.dir().join("routes");
        std::fs::write(&path, text).unwrap();
        // Writable by this user alone, whatever the umask, as serve asks.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        path
    }

    /// OpenSSH's client as `user@box`, with the gateway as its ProxyCommand,
    /// logging in with each identity of `keys`, running `remote`.
    fn ssh(&self, user: &str, keys: &[PathBuf], remote: &[&str]) -> Command {
        let proxy = format!(
            "'{BIN}' serve --stdio --gateway '{}' --host-key '{}'",
            self.dir().join("routes").display(),
            self.dir().join("gateway_host_key").display()
        );
        let mut cmd = Command::new("ssh");
        cmd.args(["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "LogLevel=DEBUG1"])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.dir().join("known_hosts").display()))
            .args(["-o", "StrictHostKeyChecking=no", "-o", "HostKeyAlias=podssh-gateway-test"])
            .args(["-o", "ConnectTimeout=30"]);
        for key in keys {
            cmd.arg("-i").arg(key);
        }
        cmd.arg("-o")
            .arg(format!("ProxyCommand={proxy}"))
            .arg(format!("{user}@box"))
            .args(remote)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        podssh_env(&mut cmd, self.dir());
        cmd
    }

    /// The lines of upstream `name`'s log that hold `words`.
    fn logged(&self, name: &str, words: &str) -> usize {
        let log = std::fs::read_to_string(self.dir().join(name).join("sshd.log")).unwrap_or_default();
        log.lines().filter(|l| l.contains(words)).count()
    }
}

/// The port of the server that ran a command, from its `SSH_CONNECTION`.
fn server_port(out: &[u8]) -> Option<u16> {
    String::from_utf8_lossy(out).split_whitespace().nth(3)?.parse().ok()
}

#[test]
fn two_names_reach_two_upstreams_by_certificate() {
    let Some(lab) = Lab::start("gateway-two") else { return };
    let me = line_of(&lab.dir().join("id.pub"));
    let keys = [me];
    let text = lab.route("user-a", &lab.a, &lab.host_key("a"), &keys)
        + &lab.route("user-b", &lab.b, &lab.host_key("b"), &keys);
    lab.write_routes(&text);
    let id = [lab.dir().join("id")];
    for (user, sshd, name) in [("user-a", &lab.a, "a"), ("user-b", &lab.b, "b")] {
        let (code, out, err) = run(lab.ssh(user, &id, &["echo $SSH_CONNECTION"]), None);
        assert_eq!(code, Some(0), "{user}: {err}");
        assert_eq!(server_port(&out), Some(sshd.port), "{user} reached the other upstream: {err}");
        // The upstream's own line names the certificate's key id: the route
        // and the login name.
        let id_words = format!("ID podssh-gateway route={user} user={user} key=SHA256:");
        assert_eq!(lab.logged(name, &id_words), 1, "{user}: upstream {name}'s log");
        assert!(err.contains(&format!("logged in as {user} by the route {user}")), "{user}: serve's line: {err}");
    }
}

#[test]
fn a_name_with_no_route_and_an_unpinned_upstream_are_refused_with_one_line() {
    let Some(lab) = Lab::start("gateway-refused") else { return };
    let me = line_of(&lab.dir().join("id.pub"));
    let keys = [me];
    // user-b's route pins upstream a's key, and dials b.
    let text = lab.route("user-a", &lab.a, &lab.host_key("a"), &keys)
        + &lab.route("user-b", &lab.b, &lab.host_key("a"), &keys);
    lab.write_routes(&text);
    let id = [lab.dir().join("id")];
    let (code, err) = finish(lab.ssh("nobody", &id, &["true"]));
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("refused as nobody: no route of --gateway matches the login name"), "{err}");
    let (code, err) = finish(lab.ssh("user-b", &id, &["true"]));
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("that the route pins: refused before the login"), "{err}");
    assert_eq!(lab.logged("b", "Accepted publickey"), 0, "upstream b let someone in");
}

/// A throwaway key at `path` with a passphrase: a client in batch mode
/// offers it and cannot sign with it.
fn locked_key(home: &Path, path: &Path) {
    let mut cmd = Command::new(BIN);
    cmd.args(["keygen", "-q", "-t", "ed25519", "-N", "not-asked", "-f"]).arg(path).stdin(Stdio::null());
    podssh_env(&mut cmd, home);
    let out = cmd.output().expect("podssh keygen runs");
    assert!(out.status.success(), "podssh keygen: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn a_client_that_offers_twenty_keys_and_signs_none_causes_no_upstream_login() {
    let Some(lab) = Lab::start("gateway-offers") else { return };
    // Twenty keys of the route, each behind a passphrase that batch mode
    // never asks for: OpenSSH's client offers each, hears that the gateway
    // would take it, and signs with none.
    let mut lines = Vec::new();
    let mut offered = Vec::new();
    for n in 0..20 {
        let key = lab.dir().join(format!("k{n}"));
        locked_key(lab.dir(), &key);
        lines.push(line_of(&key.with_extension("pub")));
        offered.push(key);
    }
    lab.write_routes(&lab.route("user-a", &lab.a, &lab.host_key("a"), &lines));
    let (code, err) = finish(lab.ssh("user-a", &offered, &["true"]));
    assert_eq!(code, Some(255), "{err}");
    let accepted = err.lines().filter(|l| l.contains("Server accepts key")).count();
    assert_eq!(accepted, 20, "each offer was taken, or the test proves nothing: {err}");
    // A gateway that dialed on an offer would have logged in by certificate.
    assert_eq!(lab.logged("a", "ID podssh-gateway"), 0, "a key offered and never signed went upstream");
    assert!(!err.contains("logged in as"), "{err}");
}
