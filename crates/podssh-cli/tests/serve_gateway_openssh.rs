//! `podssh serve --gateway FILE` (T-836) against software that podssh did
//! not write at both ends: OpenSSH's client, with the gateway as its
//! ProxyCommand, and two stock OpenSSH servers as the upstreams, each with
//! `TrustedUserCAKeys` of the route's CA and no authorized key of its own.
//! `user-a@` reaches one server and `user-b@` the other, each by a
//! certificate whose key id names the route; a name with no route is
//! refused (255, one line that says why); an upstream whose host key the
//! route does not pin is refused before the login; and a client that offers
//! 20 keys of the route and signs with none causes no login upstream.
//! With `--gateway net:NAME` (T-902) the routes come from the net's
//! document that its owner signed, served by the test over TLS
//! (`net_doc_kit`), and a document whose signature fails leaves the routes
//! in force. Unix's; a host with no OpenSSH client or no sshd says the test
//! did not run.

#![cfg(unix)]

mod live_harness;
mod net_doc_kit;
mod serve_kit;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use live_harness::sshd::{self, Sshd};
use net_doc_kit::{Server, NAME};
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
        self.route_by(pattern, sshd, host_key, keys, "ca")
    }

    /// [`Lab::route`] with `ca` as the word of `ca-key`: a file, or in a
    /// net's document the CA's public key (T-902).
    fn route_by(&self, pattern: &str, sshd: &Sshd, host_key: &str, keys: &[String], ca: &str) -> String {
        let mut text = format!(
            "route {pattern}\n    upstream 127.0.0.1:{}\n    host-key {host_key}\n    principal {}\n    ca-key {ca}\n",
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
        self.ssh_by(&format!("--gateway '{}'", self.dir().join("routes").display()), user, keys, remote)
    }

    /// [`Lab::ssh`] with `gateway` as serve's flags of its routes.
    fn ssh_by(&self, gateway: &str, user: &str, keys: &[PathBuf], remote: &[&str]) -> Command {
        let proxy =
            format!("'{BIN}' serve --stdio {gateway} --host-key '{}'", self.dir().join("gateway_host_key").display());
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
/// offers it and cannot sign with it. OpenSSH's `ssh-keygen` makes it, as
/// `podssh keygen` takes no passphrase on its command line.
fn locked_key(path: &Path) {
    let mut cmd = Command::new("ssh-keygen");
    cmd.args(["-q", "-t", "ed25519", "-N", "not-asked", "-C", "", "-f"]).arg(path).stdin(Stdio::null());
    let out = cmd.output().expect("ssh-keygen runs");
    assert!(out.status.success(), "ssh-keygen: {}", String::from_utf8_lossy(&out.stderr));
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
        locked_key(&key);
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

/// Where the armoured signature of a signed net's document starts.
fn armour_at(signed: &[u8]) -> usize {
    let mark = b"-----BEGIN SSH SIGNATURE-----";
    signed.windows(mark.len()).position(|w| w == mark).expect("a signed document")
}

/// The record of the last fetch of `--net-url` made older than its TTL, as
/// if 400 s had passed: the next start of serve fetches again.
fn age_the_copy(lab: &Lab) {
    let path = lab.dir().join("cache").join("net-url.json");
    let mut record: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let fetched = record["fetched_ms"].as_i64().expect("a fetch was recorded");
    record["fetched_ms"] = serde_json::json!(fetched - 400_000);
    std::fs::write(&path, record.to_string()).unwrap();
}

/// T-902: the gateway takes its routes from the net's document that its
/// owner signed, served by the test at an https:// URL, and routes user-a@
/// as the route file did; within the TTL it fetches nothing; a document
/// whose signature fails leaves the routes in force, with one line; the
/// newer serial, once it reads, moves user-a@ to the other upstream.
#[test]
fn a_gateway_of_the_net_routes_by_the_owner_s_signed_document() {
    let Some(lab) = Lab::start("gateway-net") else { return };
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (tls_ca, cert, key) = net_doc_kit::ca_and_leaf();
    let tls_ca_file = lab.dir().join("tls-ca.pem");
    std::fs::write(&tls_ca_file, tls_ca).unwrap();
    let server = Server::start(&rt, &cert, &key);
    let url = format!("https://{NAME}:{}/fleet.doc", server.port);
    let cache = lab.dir().join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700)).unwrap();

    // The owner's net, on the owner's own document; its CA's public half.
    keygen(lab.dir(), &lab.dir().join("owner"));
    let owner = line_of(&lab.dir().join("owner.pub")).split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let doc = lab.dir().join("owner.doc");
    let owner_net = |args: &[&str]| {
        let mut cmd = Command::new(BIN);
        cmd.arg("net").args(args).arg("--owner-key").arg(lab.dir().join("owner")).stdin(Stdio::null());
        podssh_env(&mut cmd, lab.dir());
        cmd.env("PODSSH_NET", &doc).env("PODSSH_SETTINGS", "none");
        let out = cmd.output().expect("podssh net runs");
        assert!(out.status.success(), "podssh net {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    };
    owner_net(&["init", "fleet"]);
    let (me, ca) = (line_of(&lab.dir().join("id.pub")), line_of(&lab.dir().join("ca.pub")));
    let routes = lab.dir().join("net-routes");
    let set = |upstream: &Sshd, name: &str| {
        let text = lab.route_by("user-a", upstream, &lab.host_key(name), std::slice::from_ref(&me), &ca);
        std::fs::write(&routes, text).unwrap();
        owner_net(&["gateway", "set", "gw", &routes.display().to_string()]);
        std::fs::read(&doc).unwrap()
    };
    let two = set(&lab.a, "a");

    // The gateway: its CA's private key here, the document from the URL.
    let gateway = format!(
        "--gateway net:gw --gateway-ca '{}' --net-url '{url}' --net-owner '{owner}'",
        lab.dir().join("ca").display()
    );
    let ssh = |user: &str| {
        let mut cmd = lab.ssh_by(&gateway, user, &[lab.dir().join("id")], &["echo $SSH_CONNECTION"]);
        for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "PODSSH_RELAY", "PODSSH_NET"] {
            cmd.env_remove(name);
        }
        cmd.env("SSL_CERT_FILE", &tls_ca_file).env("PODSSH_SETTINGS", "none");
        cmd.env("PODSSH_RELAY_ADDR", format!("{NAME}=127.0.0.1"));
        run(cmd, None)
    };
    let shown = format!("the net from https://{NAME}:{}/...", server.port);

    // Serial 2, fetched: user-a reaches a, as the route file routed it.
    server.answer(200, &two);
    let (code, out, err) = ssh("user-a");
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(server_port(&out), Some(lab.a.port), "{err}");
    assert!(err.contains(&format!("{shown}: serial 2, the first held here")), "{err}");
    assert!(err.contains("net:gw: the routes of serial 2, 1 in all"), "{err}");
    assert!(err.contains("logged in as user-a by the route user-a"), "{err}");
    assert_eq!(lab.logged("a", "ID podssh-gateway route=user-a user=user-a"), 1, "upstream a's log");

    // Within the TTL a new client meets the copy held: no GET (Q105).
    let (code, out, err) = ssh("user-a");
    assert_eq!((code, server_port(&out)), (Some(0), Some(lab.a.port)), "{err}");
    assert!(err.contains("its copy of") && err.contains("younger than 300 s"), "{err}");
    assert_eq!(server.asked(), 1, "one fetch for two clients within the TTL");

    // The owner moves user-a to b; the server gives that document under
    // serial 2's signature. The routes in force stay, with one line.
    let three = set(&lab.b, "b");
    let forged = [&three[..armour_at(&three)], &two[armour_at(&two)..]].concat();
    server.answer(200, &forged);
    age_the_copy(&lab);
    let (code, out, err) = ssh("user-a");
    assert_eq!((code, server_port(&out)), (Some(0), Some(lab.a.port)), "the routes before: {err}");
    let said: Vec<&str> = err.lines().filter(|l| l.contains("the net from")).collect();
    assert_eq!(said.len(), 1, "one line: {err}");
    assert!(said[0].contains("signature") && said[0].contains("its copy of"), "{}", said[0]);
    assert_eq!(server.asked(), 2);
    assert_eq!(lab.logged("b", "ID podssh-gateway"), 0, "the forged routes reached b");

    // Serial 3 itself: taken, and user-a reaches b.
    server.answer(200, &three);
    age_the_copy(&lab);
    let (code, out, err) = ssh("user-a");
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(server_port(&out), Some(lab.b.port), "{err}");
    assert!(err.contains(&format!("{shown}: serial 3, in place of 2")), "{err}");
    assert_eq!(lab.logged("b", "ID podssh-gateway route=user-a user=user-a"), 1, "upstream b's log");
}
