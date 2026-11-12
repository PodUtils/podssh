//! The Pinggy road of the command line from end to end (T-548), on this
//! machine's loopback: a stand-in of Pinggy's server (`pinggy_stand_in`),
//! SSH raw or inside TLS on one port and its visitors' port that routes TLS
//! by SNI; a stand-in proxy of the node's and the client's that takes a
//! CONNECT to the server's name and to the tunnels' names alone, and refuses
//! each other one, as a cage whose proxy passes TLS by name and no upgrade
//! (and, when asked, nothing but TLS); an SSH server for the node's TARGET;
//! `podssh node lab TARGET --pinggy --allow FILE`, whose leg is raw SSH, and
//! `podssh ssh node://tester@lab --pinggy-name NAME#PIN greet` with the
//! pair's road down: the race goes to Pinggy, and stderr names the third
//! party. A later run with no address falls back on the one kept, last;
//! `PODSSH_LAST_RESORT=no` turns that off. A stranger at the name, of
//! another TLS key, is refused at TLS by the pin; one that holds the node's
//! TLS key but not its own key is refused by the end-to-end channel. Behind
//! a proxy that passes TLS alone, the node's leg is SSH inside TLS, which
//! the host's trust verifies. The name comes from the session's text when
//! port 4300 does not answer. A node with no pair and each other road off
//! serves the road unasked (Q78). 1 MiB comes down whole, and the node says
//! the visitor's bytes each way. With the iroh road's test servers, a member
//! of the net with no address given or kept finds it in the node's record
//! of pkarr (`pinggy_record`). Planted: the client's check of the node's
//! key skipped (`scripts/plants/t548-any-node.patch`), or the pin's
//! comparison skipped (`scripts/plants/t548-any-pin.patch`), and the test of
//! the stranger fails.

mod cleanup;
#[cfg(feature = "iroh-test")]
mod pinggy_record;
mod pinggy_stand_in;
mod ssh_harness;

use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use pinggy_stand_in::{StandIn, DOMAIN, SERVER};
use podssh_relay::identity::file::{self, Place};
use podssh_relay::session::OsEntropy;
use ssh_harness::GREETING;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LIMIT: Duration = Duration::from_secs(60);

/// A fresh, empty, private scratch directory, removed when the test ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-pinggy-road-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh ARGS` with HOME and the cache under `home`, the stand-in's
/// server and the stand-in proxy, and none of the settings of the machine
/// that runs the test.
fn command(home: &Path, proxy: u16, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
    for name in ["PODSSH_OFFLINE", "PODSSH_DERP", "PODSSH_DERP_SERVER", "PODSSH_RELAY", "PODSSH_RELAY_ADDR"] {
        cmd.env_remove(name);
    }
    for name in ["SSL_CERT_FILE", "SSH_AUTH_SOCK", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "http_proxy"] {
        cmd.env_remove(name);
    }
    cmd.env_remove("PODSSH_LAST_RESORT");
    let proxy = format!("http://127.0.0.1:{proxy}");
    cmd.env("HTTPS_PROXY", &proxy).env("https_proxy", &proxy).env("HTTP_PROXY", &proxy);
    cmd.env("PODSSH_PINGGY", SERVER).env("PODSSH_SERVEO", "no").env("PODSSH_SSH_J", "no");
    // The roads of the test alone: no OpenTunnel, no transit relay, no
    // Piping Server, no record at n0's server of pkarr.
    cmd.env("PODSSH_OPENTUNNEL", "no").env("PODSSH_TRANSIT", "no").env("PODSSH_CROC", "no").env("PODSSH_PIPING", "no");
    // Nor the last roads of all (Q78): localhost.run (T-565), localtunnel (T-568), bore (T-569).
    cmd.env("PODSSH_LOCALHOST_RUN", "no").env("PODSSH_SANDHOLE", "no");
    cmd.env("PODSSH_LOCALTUNNEL", "no").env("PODSSH_HOSTC", "no").env("PODSSH_SMEE", "no").env("PODSSH_BORE", "no");
    cmd.env("PODSSH_IROH_PKARR", "off");
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

/// Run `podssh ARGS` to its end, within the limit: (code, stdout, stderr).
/// Both pipes are read while it runs: a pipe that nobody reads holds a
/// child that writes more than its 64 KiB (T-548's live stall).
fn run(cmd: &mut Command) -> (i32, String, String) {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("it runs");
    let drain = |mut pipe: Box<dyn std::io::Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            String::from_utf8_lossy(&bytes).into_owned()
        })
    };
    let (out, err) = (drain(Box::new(child.stdout.take().unwrap())), drain(Box::new(child.stderr.take().unwrap())));
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().expect("wait").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("podssh did not end within {} s; it said: {}", LIMIT.as_secs(), err.join().unwrap_or_default());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let code = child.wait().expect("wait").code().unwrap_or(-1);
    (code, out.join().unwrap_or_default(), err.join().unwrap_or_default())
}

/// Kills the node when the test ends.
struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The lines of the node's stderr up to the first that holds `needle`.
fn wait_for(lines: &mpsc::Receiver<String>, needle: &str) -> Vec<String> {
    let deadline = Instant::now() + LIMIT;
    let mut seen = Vec::new();
    loop {
        match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => {
                let found = line.contains(needle);
                seen.push(line);
                if found {
                    return seen;
                }
            }
            Err(_) => panic!("no line with {needle:?} from the node within {} s: {seen:#?}", LIMIT.as_secs()),
        }
    }
}

/// The stand-in proxy: a CONNECT to the server's name goes to its SSH port,
/// one to a tunnel's name to its visitors' port, and each other is refused;
/// with `tls_only`, a connection whose first byte opens no TLS record is cut,
/// as a proxy that passes TLS alone does.
async fn proxy(ssh: u16, visitors: u16, tls_only: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let tls_only = tls_only.clone();
            tokio::spawn(async move {
                let Ok((request, rest)) = podssh_ws::http::read_request(&mut tcp, Vec::new()).await else { return };
                let target = podssh_ws::http::request::connect_target(&request.target);
                let to = match (request.method.as_str(), target) {
                    ("CONNECT", Ok((host, 443))) if host == SERVER => ssh,
                    ("CONNECT", Ok((host, 443))) if host.ends_with(&format!(".{DOMAIN}")) => visitors,
                    _ => {
                        let words = "this proxy passes the names of the service alone";
                        let _ = tcp.write_all(&podssh_ws::http::request::refusal(403, words, &[])).await;
                        return;
                    }
                };
                let Ok(mut far) = TcpStream::connect((Ipv4Addr::LOCALHOST, to)).await else { return };
                let _ = tcp.write_all(&podssh_ws::http::request::established()).await;
                let mut rest = rest;
                if tls_only.load(Ordering::SeqCst) {
                    let mut first = [0u8; 1];
                    if rest.is_empty() && !matches!(tcp.read(&mut first).await, Ok(1)) {
                        return;
                    }
                    if rest.is_empty() {
                        rest = first.to_vec();
                    }
                    if rest[0] != 0x16 {
                        return;
                    }
                }
                if !rest.is_empty() && far.write_all(&rest).await.is_err() {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut far).await;
            });
        }
    });
    port
}

/// The place of one test: its runtime, which serves the stand-in, the proxy
/// and the SSH server; the node's home and the client's.
struct Lab {
    runtime: tokio::runtime::Runtime,
    stand_in: Arc<StandIn>,
    proxy: u16,
    /// Whether the proxy passes TLS alone.
    tls_only: Arc<AtomicBool>,
    /// The stand-in CA, which signs the TLS of the stand-in's SSH port.
    ca: String,
    target: String,
    node_home: PathBuf,
    client_home: PathBuf,
    allow: PathBuf,
    client_key: String,
    known: String,
}

impl Lab {
    fn new(name: &str) -> Lab {
        let home = scratch(name);
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let stand_in = Arc::new(StandIn::default());
        let tls_only = Arc::new(AtomicBool::new(false));
        let (proxy_port, ca_pem) = runtime.block_on(async {
            let (ssh, visitors, ca) = stand_in.listen().await;
            (proxy(ssh, visitors, tls_only.clone()).await, ca)
        });
        let ca = home.join("ca.pem");
        std::fs::write(&ca, ca_pem).unwrap();
        let host_key = home.join("host_key");
        let host_key_text = host_key.to_string_lossy().into_owned();
        let keygen = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &host_key_text];
        let (rc, _, err) = run(&mut command(&home, proxy_port, &keygen));
        assert_eq!(rc, 0, "{err}");
        let port = runtime.block_on(ssh_harness::start(&host_key));
        let (node_home, client_home) = (home.join("node"), home.join("client"));
        for dir in [&node_home, &client_home] {
            podssh_relay::cache::private_dir(dir).unwrap();
        }
        let allow = node_home.join("allow");
        std::fs::write(&allow, "# the client keys that may come in\n").unwrap();
        Lab {
            runtime,
            stand_in,
            proxy: proxy_port,
            tls_only,
            ca: ca.to_string_lossy().into_owned(),
            target: format!("127.0.0.1:{port}"),
            client_key: client_home.join("client.key").to_string_lossy().into_owned(),
            known: client_home.join("known_hosts").to_string_lossy().into_owned(),
            node_home,
            client_home,
            allow,
        }
    }

    /// `podssh node lab TARGET` with `extra` and the node key `key`, its
    /// lines, and its tunnel's name and address (`NAME#PIN`) once it said
    /// them.
    fn node(&self, key: &str, extra: &[&str], env: &[(&str, &str)]) -> (Node, mpsc::Receiver<String>, String, String) {
        let (key, allow) = (self.node_home.join(key), self.allow.to_string_lossy().into_owned());
        let key = key.to_string_lossy().into_owned();
        let mut args = vec!["node", "lab", self.target.as_str(), "--allow", allow.as_str(), "--key", key.as_str()];
        args.extend_from_slice(extra);
        let mut cmd = command(&self.node_home, self.proxy, &args);
        cmd.envs(env.iter().copied());
        let mut child = cmd.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        let node = Node(child);
        let seen = wait_for(&lines, ": name ");
        let line = seen.last().unwrap();
        let name = line.split(": name ").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
        let address = line.split("--pinggy-name ").nth(1).unwrap().trim_end_matches(')').to_string();
        assert!(address.starts_with(&format!("{name}#SHA256:")), "{line}");
        assert!(line.contains(&format!(" pin {}", &address[name.len() + 1..])), "{line}");
        // The lines before the name, for a test that reads them.
        let (tx, earlier) = mpsc::channel();
        for line in seen {
            let _ = tx.send(line);
        }
        std::thread::spawn(move || {
            for line in lines.iter() {
                let _ = tx.send(line);
            }
        });
        (node, earlier, name, address)
    }

    /// `podssh ssh` from the client's home, with its key and known hosts.
    fn ssh(&self, words: &[&str]) -> Command {
        let known = format!("UserKnownHostsFile={}", self.known);
        let mut args = vec!["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", &known];
        args.extend_from_slice(&["--client-key", &self.client_key]);
        args.extend_from_slice(words);
        command(&self.client_home, self.proxy, &args)
    }

    /// Let the client's key in, as the node's operator does.
    fn let_in(&self) {
        let key = file::load(&Place::File(PathBuf::from(&self.client_key)), &mut OsEntropy).expect("the key");
        let mut list = std::fs::OpenOptions::new().append(true).open(&self.allow).unwrap();
        writeln!(list, "{} the test's client", key.identity.public().fingerprint()).unwrap();
    }

    /// A pair of the client's under `lab` whose relay is a port of the
    /// loopback where nothing listens, so the pair's road fails at once.
    fn pair_down(&self) {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let relay = podssh_relay::relay::Relay { host: "127.0.0.1".into(), port: closed };
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
        // The repository's fixture form of a token, which names no credential.
        let token = |kind: &str| format!("testonly{kind}{}", "0".repeat(56 - kind.len()));
        let body = serde_json::json!({
            "name": "p-0123456789abcdef0123456789abcdef",
            "node_token": token("node"),
            "connect_token": token("connect"),
            "stop_token": token("stop"),
            "expires": now + 72 * 3600 * 1000,
        });
        let pair = podssh_relay::pair::parse(&relay, body.to_string().as_bytes(), now).expect("a test pair");
        let cache = self.client_home.join("cache").join("podssh");
        podssh_relay::pair::store_in_first(&[cache], "lab", &pair).expect("the pair stored");
    }
}

#[test]
fn with_the_pair_s_road_down_the_race_gives_the_session_to_pinggy_and_a_kept_name_falls_back_last() {
    let lab = Lab::new("race");
    lab.let_in();
    lab.pair_down();
    let (_node, lines, name, address) = lab.node("node.key", &["--pinggy"], &[]);
    assert!(name.ends_with(&format!(".{DOMAIN}")), "{name}");
    let said: Vec<String> = lines.try_iter().collect();
    assert!(said.iter().any(|l| l.contains("nobody vouches for") && l.contains("Q78")), "{said:#?}");
    assert!(said.iter().any(|l| l.contains("host key") && l.contains("unpinned")), "{said:#?}");
    assert!(said.iter().any(|l| l.contains("host key") && l.contains("over raw SSH")), "{said:#?}");
    assert_eq!(lab.stand_in.users(), vec!["tls".to_string()], "the keyword of a TLS tunnel");
    assert_eq!(lab.stand_in.forwards(), vec!["localhost".to_string()], "as ssh -R0: asks");
    let ways = (lab.stand_in.raw.load(Ordering::SeqCst), lab.stand_in.tls.load(Ordering::SeqCst));
    assert_eq!(ways, (1, 0), "the node's leg is raw SSH where the proxy passes it");

    let (rc, out, err) = run(&mut lab.ssh(&["-v", "--pinggy-name", &address, "node://tester@lab", "greet"]));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over the road");
    assert!(err.contains("the Pinggy road answered first"), "{err}");
    assert!(err.contains("a third party that nobody vouches for"), "the line of Q78: {err}");
    assert!(err.contains("the Pinggy name is kept in"), "{err}");
    assert!(lab.stand_in.visits.load(Ordering::SeqCst) >= 1, "a visitor came down the tunnel");

    // No address now: the kept one, last, once each road before it failed (Q78).
    let (rc, out, err) = run(&mut lab.ssh(&["-v", "node://tester@lab", "greet"]));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING);
    assert!(err.contains("when each road before it failed (a kept name, the last fallback of Q78)"), "{err}");

    // PODSSH_LAST_RESORT=no: the pair's road alone, which fails.
    let (rc, out, err) = run(lab.ssh(&["node://tester@lab", "greet"]).env("PODSSH_LAST_RESORT", "no"));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(!err.contains("Pinggy"), "no Pinggy road with PODSSH_LAST_RESORT=no: {err}");
    assert_eq!(lab.stand_in.made.load(Ordering::SeqCst), 1, "one tunnel for the node");
    drop(lab.runtime);
}

/// The stand-in gives the node's name to another node's tunnel: the client,
/// which holds the first node's pin and key, refuses the second at TLS, as
/// its certificate is of another key; and refuses a third, which holds the
/// first node's TLS key but not its own key, by the end-to-end channel
/// (T-548's Prove).
#[test]
fn a_stranger_at_the_tunnel_s_name_is_refused_by_the_pin_or_the_end_to_end_channel() {
    let lab = Lab::new("stranger");
    lab.let_in();
    lab.pair_down();
    let (_node, _lines, name, address) = lab.node("node.key", &["--pinggy"], &[]);
    let (rc, out, err) = run(&mut lab.ssh(&["--pinggy-name", &address, "node://tester@lab", "greet"]));
    assert_eq!((rc, out.as_str()), (0, GREETING), "{err}");
    let served = lab.stand_in.visits.load(Ordering::SeqCst);

    // Another node, of another TLS key and another key, behind the name.
    let (_stranger, _lines, other, other_address) = lab.node("stranger.key", &["--pinggy"], &[]);
    assert_ne!(other, name);
    assert_ne!(other_address[other.len()..], address[name.len()..], "another node, another pin");
    lab.stand_in.hijack(&name, &other);
    let (rc, out, err) = run(&mut lab.ssh(&["-v", "--pinggy-name", &address, "node://tester@lab", "greet"]));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(out.is_empty(), "nothing of the stranger's: {out:?}");
    assert!(err.contains("not the node's pin"), "refused at TLS: {err}");
    assert!(!err.contains("refused the node"), "TLS refused it before the channel: {err}");
    assert!(lab.stand_in.visits.load(Ordering::SeqCst) > served, "the stranger was reached, and refused");

    // A third node with the first one's TLS key, copied, and a key of its own.
    let tls_key = lab.node_home.join(format!("node.key{}", ".pinggy-tls.pem"));
    let body = std::fs::read(&tls_key).expect("the node's TLS key, beside its key");
    let copy = lab.node_home.join("thief.key.pinggy-tls.pem");
    podssh_relay::cache::create_new_private(&copy).unwrap().write_all(&body).unwrap();
    let (_thief, _lines, third, third_address) = lab.node("thief.key", &["--pinggy"], &[]);
    assert_eq!(third_address[third.len()..], address[name.len()..], "the first node's pin");
    lab.stand_in.hijack(&name, &third);
    let (rc, out, err) = run(&mut lab.ssh(&["--pinggy-name", &address, "node://tester@lab", "greet"]));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(out.is_empty(), "nothing of the thief's: {out:?}");
    assert!(err.contains("refused the node"), "refused by the end-to-end channel: {err}");
    drop(lab.runtime);
}

/// A proxy that passes TLS alone cuts raw SSH before its version line: the
/// node's leg is then SSH inside TLS, which the host's trust verifies, so it
/// passes with the stand-in CA as --ca-file and fails without it.
#[test]
fn behind_a_proxy_that_passes_tls_alone_the_leg_is_ssh_inside_tls_that_the_host_s_trust_verifies() {
    let lab = Lab::new("tls-only");
    lab.tls_only.store(true, Ordering::SeqCst);
    let allow = lab.allow.to_string_lossy().into_owned();
    let words = ["node", "lab", &lab.target, "--pinggy", "--allow", &allow, "--ephemeral-key"];
    let (rc, out, err) = run(&mut command(&lab.node_home, lab.proxy, &words));
    assert_ne!(rc, 0, "stdout {out:?}, stderr {err}");
    assert!(err.contains("failed before SSH's version line"), "{err}");
    assert!(err.contains("then TLS with"), "TLS that no root of this host signs is refused: {err}");
    assert_eq!(lab.stand_in.made.load(Ordering::SeqCst), 0, "no tunnel made: {err}");

    let (_node, lines, name, _) = lab.node("node.key", &["--pinggy", "--ca-file", &lab.ca], &[]);
    assert!(name.ends_with(&format!(".{DOMAIN}")), "{name}");
    let said: Vec<String> = lines.try_iter().collect();
    assert!(said.iter().any(|l| l.contains("failed before SSH's version line")), "{said:#?}");
    assert!(said.iter().any(|l| l.contains("host key") && l.contains("over SSH inside TLS")), "{said:#?}");
    assert_eq!(lab.stand_in.raw.load(Ordering::SeqCst), 0, "the proxy cut each raw SSH");
    assert_eq!(lab.stand_in.tls.load(Ordering::SeqCst), 1);
    drop(lab.runtime);
}

/// 1 MiB down the tunnel, as the live run takes it (`source`), whole; with
/// `PODSSH_PINGGY_TRACE=1`, the node says the visitor's end and its bytes
/// each way. Before `run` read the pipes as the child ran, the child stalled
/// at 64 KiB of stdout, as the first three live runs did.
#[test]
fn a_mebibyte_comes_down_the_tunnel_whole_and_the_node_says_the_visitor_s_bytes() {
    let lab = Lab::new("down");
    lab.let_in();
    lab.pair_down();
    let trace = [("PODSSH_PINGGY_TRACE", "1")];
    let (_node, lines, _, address) = lab.node("node.key", &["--pinggy"], &trace);
    let mut ssh = lab.ssh(&["-v", "--pinggy-name", &address, "node://tester@lab", "source 1048576"]);
    let (rc, out, err) = run(ssh.envs(trace));
    assert_eq!((rc, out.len()), (0, 1 << 20), "{err}");
    let end = wait_for(&lines, "ended (");
    let end = end.last().unwrap();
    let out = end.split("bytes in, ").nth(1).and_then(|rest| rest.split(' ').next()?.parse::<usize>().ok());
    assert!(out.is_some_and(|out| out > 1 << 20), "the visitor's bytes out: {end}");
    drop(lab.runtime);
}

#[test]
fn the_name_comes_from_the_session_s_text_when_port_4300_does_not_answer() {
    let lab = Lab::new("text");
    lab.stand_in.no_api.store(true, Ordering::SeqCst);
    let (_node, _lines, name, _) = lab.node("node.key", &["--pinggy"], &[]);
    assert_eq!(name, format!("t1.{DOMAIN}"), "the name of the shell's text, through its escapes");
    drop(lab.runtime);
}

#[test]
fn a_node_with_no_pair_and_each_other_road_off_serves_pinggy_unasked_and_names_the_third_party() {
    let lab = Lab::new("unasked");
    let (_node, lines, name, _) = lab.node("node.key", &[], &[("PODSSH_DERP", "no")]);
    assert!(name.ends_with(&format!(".{DOMAIN}")), "{name}");
    let said: Vec<String> = lines.try_iter().collect();
    let unasked = said.iter().find(|l| l.contains("unasked")).unwrap_or_else(|| panic!("{said:#?}"));
    assert!(unasked.contains("PODSSH_OPENTUNNEL=no") && unasked.contains("the last"), "{unasked}");
    assert!(said.iter().any(|l| l.contains("nobody vouches for") && l.contains("PODSSH_LAST_RESORT=no")), "{said:#?}");
    drop(lab.runtime);
}

#[test]
fn the_switches_turn_the_road_off_and_a_node_with_no_door_is_refused_before_it_connects() {
    let lab = Lab::new("refused");
    for (var, value) in [("PODSSH_LAST_RESORT", "no"), ("PODSSH_PINGGY", "no")] {
        let mut cmd = command(&lab.node_home, lab.proxy, &["node", "lab", &lab.target, "--pinggy", "--allow"]);
        cmd.arg(&lab.allow).env(var, value);
        let (rc, out, err) = run(&mut cmd);
        assert_eq!(rc, 64, "{var}: stdout {out:?}, stderr {err}");
        assert!(err.contains(&format!("{var}=no turns the Pinggy road off")), "{err}");
    }
    let (rc, out, err) = run(&mut command(&lab.node_home, lab.proxy, &["node", "lab", &lab.target, "--pinggy"]));
    assert_eq!(rc, 64, "stdout {out:?}, stderr {err}");
    assert!(err.contains("--pinggy needs --allow FILE"), "{err}");
    assert!(err.contains("Pinggy is a third party that nobody vouches for"), "{err}");
    let (rc, _, err) = run(&mut lab.ssh(&["--pinggy-name", "not a name", "node://tester@lab", "true"]));
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--pinggy-name"), "{err}");
    // A name with no pin: TLS would prove nothing, so it is refused.
    let (rc, _, err) = run(&mut lab.ssh(&["--pinggy-name", &format!("t1.{DOMAIN}"), "node://tester@lab", "true"]));
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--pinggy-name: a node's address at Pinggy is NAME#SHA256:"), "{err}");
    assert_eq!(lab.stand_in.made.load(Ordering::SeqCst), 0, "no tunnel made");
    drop(lab.runtime);
}
