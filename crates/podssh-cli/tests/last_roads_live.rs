//! The last roads of all (Q78) through their own public servers, by the
//! operator's rulings Q78 and Q91: localhost.run (T-565), localtunnel's
//! `localtunnel.me` (T-568) and bore.pub (T-569), each named by
//! `pod-services`. One short run of each, from GitHub Actions
//! (`.github/workflows/last-roads-live.yml`), never in the gate, so each is
//! ignored unless asked. A node with a throwaway key serves the loopback's
//! SSH server of the tests over the road alone, each other road off; a
//! client that names the node's key runs `greet`, then takes 1 MiB down; the
//! node is stopped at the end, which gives its tunnel up. With
//! `PODSSH_LAST_TEST_PLANT=stranger`, the client names another node's key,
//! and the run must fail: the check is not vacuous. Sandhole's demo (T-743)
//! too; and the Bare hop (T-740): the client's proxy of the test passes the
//! Bare node of `pod-services` alone, so the tunnel's name of localhost.run
//! is reached through that node, the last road of all. srv.us (T-566),
//! whose name the client derives from the node's whole key.

mod cleanup;
mod ssh_harness;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use podssh_relay::identity::file::{self, Place};
use podssh_relay::session::OsEntropy;
use ssh_harness::GREETING;

const LIMIT: Duration = Duration::from_secs(120);
/// The bytes taken down: a few MiB at most (T-548's Decision, which these follow).
const DOWN: usize = 1 << 20;

/// Each last road's switch, which a run turns off but for its own.
const LAST_ROADS: [&str; 8] = [
    "PODSSH_PINGGY",
    "PODSSH_SSH_J",
    "PODSSH_SERVEO",
    "PODSSH_LOCALHOST_RUN",
    "PODSSH_SANDHOLE",
    "PODSSH_SRV_US",
    "PODSSH_LOCALTUNNEL",
    "PODSSH_BORE",
];

/// `podssh ARGS` with HOME and the cache under `home`, the runner's own
/// egress, and none of the roads but the one of the switch `road`.
fn command(home: &Path, road: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
    for name in ["PODSSH_LAST_RESORT", "PODSSH_RELAY", "PODSSH_RELAY_ADDR", "SSH_AUTH_SOCK", road] {
        cmd.env_remove(name);
    }
    cmd.env("PODSSH_OPENTUNNEL", "no").env("PODSSH_TRANSIT", "no").env("PODSSH_CROC", "no").env("PODSSH_PIPING", "no");
    for name in LAST_ROADS.iter().filter(|name| **name != road) {
        cmd.env(name, "no");
    }
    cmd.env("PODSSH_DERP", "no").env("PODSSH_IROH_PKARR", "off");
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

/// Run to its end, within the limit: (code, stdout as bytes, stderr). Both
/// pipes are read while it runs: a pipe that nobody reads holds a child that
/// writes more than its 64 KiB, which stalled the 1 MiB of the first three
/// live runs after SSH's login, with each road's bytes through.
fn run(cmd: &mut Command) -> (i32, Vec<u8>, String) {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("it runs");
    let drain = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            bytes
        })
    };
    let (out, err) = (drain(Box::new(child.stdout.take().unwrap())), drain(Box::new(child.stderr.take().unwrap())));
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().expect("wait").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            // Its words name where it waited, and how much came.
            let said = String::from_utf8_lossy(&err.join().unwrap_or_default()).into_owned();
            let came = out.join().map(|out| out.len()).unwrap_or_default();
            panic!("podssh did not end within {} s, with {came} bytes out; it said: {said}", LIMIT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let code = child.wait().expect("wait").code().unwrap_or(-1);
    let err = String::from_utf8_lossy(&err.join().unwrap_or_default()).into_owned();
    (code, out.join().unwrap_or_default(), err)
}

/// Stops the node when the run ends, which gives its tunnel up.
struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One road's run: the node with `flag`, ready at its line that holds
/// `ready`; the client's lines must say that `answered` answered first.
/// `url_of` takes the address that a client gives from the ready line, as
/// `--tunnel-url` names one, where the road needs it.
fn live(road: &str, flag: &str, ready: &str, answered: &str, url_of: Option<fn(&str) -> String>) {
    live_via(road, flag, ready, answered, url_of, None, false)
}

/// A proxy of the client's on the loopback that passes a CONNECT to
/// `allowed` on port 443 alone, and refuses each other with 403: its port.
fn proxy_of(allowed: String) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut tcp in listener.incoming().map_while(Result::ok) {
            let allowed = allowed.clone();
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
                    if tcp.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let line = String::from_utf8_lossy(&head).lines().next().unwrap_or_default().to_string();
                let target = line.split_whitespace().nth(1).unwrap_or_default().to_string();
                if target != format!("{allowed}:443") {
                    let _ = tcp.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
                    return;
                }
                let Ok(far) = std::net::TcpStream::connect((allowed.as_str(), 443)) else { return };
                let _ = tcp.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                let (mut up, mut down) = (tcp.try_clone().unwrap(), far.try_clone().unwrap());
                let (mut tcp, mut far) = (tcp, far);
                std::thread::spawn(move || std::io::copy(&mut up, &mut down));
                let _ = std::io::copy(&mut far, &mut tcp);
            });
        }
    });
    port
}

/// [`live`], with the client behind a proxy that passes `only` alone, when given.
fn live_via(
    road: &str,
    flag: &str,
    ready: &str,
    answered: &str,
    url_of: Option<fn(&str) -> String>,
    only: Option<String>,
    whole: bool,
) {
    let home =
        std::env::temp_dir().join(format!("podssh-last-live-{}-{}", flag.trim_start_matches('-'), std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    podssh_relay::cache::private_dir(&home).unwrap();
    cleanup::at_test_end(&home);
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let host_key = home.join("host_key");
    let host_key_text = host_key.to_string_lossy().into_owned();
    let (rc, _, err) =
        run(&mut command(&home, road, &["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &host_key_text]));
    assert_eq!(rc, 0, "{err}");
    let port = runtime.block_on(ssh_harness::start(&host_key));
    let (node_home, client_home): (PathBuf, PathBuf) = (home.join("node"), home.join("client"));
    for dir in [&node_home, &client_home] {
        podssh_relay::cache::private_dir(dir).unwrap();
    }
    let client_key = client_home.join("client.key");
    let key = file::load(&Place::File(client_key.clone()), &mut OsEntropy).expect("the client's key");
    let allow = node_home.join("allow");
    std::fs::write(&allow, format!("{} the live run's client\n", key.identity.public().fingerprint())).unwrap();

    let target = format!("127.0.0.1:{port}");
    let allow_text = allow.to_string_lossy().into_owned();
    // `whole`: the node's key in a file of the run, so that the client names
    // the whole key, from which srv.us's name derives (T-566).
    let node_file = node_home.join("node.key");
    let node_whole = whole.then(|| {
        let made = file::load(&Place::File(node_file.clone()), &mut OsEntropy).expect("the node's key");
        made.identity.public()
    });
    let node_file_text = node_file.to_string_lossy().into_owned();
    let mut words = vec!["node", "lab", target.as_str(), flag, "--allow", allow_text.as_str()];
    match whole {
        true => words.extend_from_slice(&["--key", node_file_text.as_str()]),
        false => words.push("--ephemeral-key"),
    }
    let mut node = command(&node_home, road, &words);
    let mut child = node.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let stderr = child.stderr.take().unwrap();
    let _node = Node(child);
    let (tx, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            eprintln!("node: {line}");
            let _ = tx.send(line);
        }
    });
    let deadline = Instant::now() + LIMIT;
    let (mut at, mut node_key) = (None, None);
    while at.is_none() || node_key.is_none() {
        let line = lines.recv_timeout(deadline.saturating_duration_since(Instant::now())).expect("the node's line");
        if let Some(rest) = line.split(": key ").nth(1) {
            node_key = rest.split_whitespace().next().map(str::to_string);
        }
        // The node holds its tunnel: a client can reach it now.
        if line.contains(ready) {
            at = Some(line);
        }
    }
    let at = at.unwrap();
    let url = url_of.map(|url_of| url_of(&at));
    let mut node_key = node_key.expect("the node's key line");
    if let Some(public) = node_whole {
        // srv.us named the tunnel as the client derives it from the key.
        let zone = podssh_relay::ssh_http::Service::hosted(podssh_relay::ssh_http::SRV_US).expect("srv.us").host;
        let derived = podssh_relay::ssh_http::srv_us::name(&public, &zone);
        assert!(at.contains(&format!("tunnel https://{derived} ")), "srv.us's name is the key's: {at}");
        node_key = public.hex();
    }

    // The planted run names another node's key: the client must refuse.
    let planted = std::env::var("PODSSH_LAST_TEST_PLANT").ok().as_deref() == Some("stranger");
    let stranger_key = file::load(&Place::Ephemeral, &mut OsEntropy).unwrap().identity.public();
    let stranger = if whole { stranger_key.hex() } else { stranger_key.fingerprint() };
    let expected = if planted { stranger } else { node_key };
    let proxy = only.map(proxy_of);
    let ssh = |words: &[&str]| {
        let known = format!("UserKnownHostsFile={}", client_home.join("known_hosts").display());
        let client_key = client_key.to_string_lossy().into_owned();
        let mut args = vec!["ssh", "-v", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", &known];
        args.extend_from_slice(&["--client-key", &client_key, "--node-key", &expected]);
        if let Some(url) = &url {
            args.extend_from_slice(&["--tunnel-url", url]);
        }
        args.extend_from_slice(words);
        let mut cmd = command(&client_home, road, &args);
        if let Some(port) = proxy {
            let proxy = format!("http://127.0.0.1:{port}");
            cmd.env("HTTPS_PROXY", &proxy).env("https_proxy", &proxy).env_remove("NO_PROXY").env_remove("no_proxy");
        }
        run(&mut cmd)
    };
    let (rc, out, err) = ssh(&["node://tester@lab", "greet"]);
    eprintln!("client, greet: {err}");
    assert_eq!(rc, 0, "the client over {flag}");
    assert_eq!(String::from_utf8_lossy(&out), GREETING);
    assert!(err.contains(&format!("{answered} answered first")) && err.contains("nobody vouches for"), "{err}");
    let source = format!("source {DOWN}");
    let (rc, out, err) = ssh(&["node://tester@lab", &source]);
    eprintln!("client, {source}: {err}");
    assert_eq!(rc, 0, "{err}");
    assert_eq!(out.len(), DOWN, "1 MiB down, whole");
    let _ = std::io::stderr().flush();
    drop(runtime);
}

/// The URL of a line `... tunnel https://NAME (...)`.
fn tunnel_url(line: &str) -> String {
    let after = line.split(": tunnel https://").nth(1).expect("a line of the tunnel");
    format!("https://{}", after.split_whitespace().next().unwrap())
}

#[test]
#[ignore = "a live run through localhost.run: last-roads-live.yml"]
fn a_node_behind_localhost_run_serves_a_client_at_its_tunnel_s_url() {
    live("PODSSH_LOCALHOST_RUN", "--localhost-run", ": tunnel https://", "the localhost.run road", Some(tunnel_url));
}

#[test]
#[ignore = "a live run through Sandhole's public server: last-roads-live.yml"]
fn a_node_behind_sandhole_serves_a_client_at_its_tunnel_s_url() {
    live("PODSSH_SANDHOLE", "--sandhole", ": tunnel https://", "the Sandhole road", Some(tunnel_url));
}

#[test]
#[ignore = "a live run through localtunnel.me: last-roads-live.yml"]
fn a_node_behind_localtunnel_serves_a_client_that_names_its_key() {
    live("PODSSH_LOCALTUNNEL", "--localtunnel", "over the localtunnel road alone", "the localtunnel road", None);
}

#[test]
#[ignore = "a live run through bore.pub: last-roads-live.yml"]
fn a_node_at_its_bore_port_serves_a_client_that_names_its_key() {
    live("PODSSH_BORE", "--bore", ": bore port ", "the bore road", None);
}

#[test]
#[ignore = "a live run through localhost.run and the Bare node of pod-services: last-roads-live.yml"]
fn behind_a_proxy_that_passes_the_bare_node_alone_the_bare_hop_carries_the_session() {
    let node = pod_services::of_kind("bare-node").next().expect("pod-services names a Bare node");
    let host = node.endpoint("bare").expect("its endpoint").host().to_string();
    let road = ("PODSSH_LOCALHOST_RUN", "--localhost-run", ": tunnel https://");
    live_via(road.0, road.1, road.2, "the Bare hop", Some(tunnel_url), Some(host), false);
}

/// srv.us (T-566): the client names the node's whole key and no URL, and
/// derives the tunnel's name; the planted stranger's whole key derives
/// another name, where no node is.
#[test]
#[ignore = "a live run through srv.us: last-roads-live.yml"]
fn a_node_at_srv_us_serves_a_client_that_derives_its_name_from_its_key() {
    live_via("PODSSH_SRV_US", "--srv-us", ": tunnel https://", "the srv.us road", None, None, true);
}
