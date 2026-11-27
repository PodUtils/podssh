//! End-to-end iroh discovery through a net's relay member (T-720): a net whose
//! relay member runs `podssh relay serve --relay-roads iroh`, queried by
//! `podssh relay status` so its `/relays.json` `meet.iroh` is cached, then
//! `podssh node --iroh` and `podssh ssh iroh:TICKET` with neither `--iroh-relay`
//! nor `PODSSH_IROH_RELAY` pick that member as their home relay and carry an
//! SSH session end to end through the role alone.
#![cfg(feature = "iroh")]

mod ssh_harness;
mod throughput_harness;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use pod_iroh::keys::{self, Place};
use podssh_relay::identity::Identity;
use throughput_harness::{lines_of, wait_for, Cell, Session};

const LIMIT: Duration = Duration::from_secs(120);

fn words(args: &[&str]) -> Vec<String> {
    args.iter().map(|a| a.to_string()).collect()
}

fn shown(path: &Path) -> String {
    path.display().to_string()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn ran(mut cmd: Command) -> Output {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("podssh runs");
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().expect("wait").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{cmd:?} did not end within {} s", LIMIT.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().expect("output")
}

/// `podssh ARGS` under `home` with the net's document in `doc`, no proxy,
/// no machine settings, and no `--iroh-relay` or `PODSSH_IROH_RELAY`.
fn client(home: &Path, doc: &Path, args: &[String]) -> Command {
    let mut cmd = throughput_harness::without_proxy(throughput_harness::command_in(home, args));
    for name in [
        "PODSSH_RELAY",
        "PODSSH_RELAY_TOKEN",
        "PODSSH_RELAY_KEYS",
        "PODSSH_CACHE_DIR",
        "PODSSH_RELAY_ADDR",
        "PODSSH_IROH_RELAY",
        "PODSSH_IROH_UDP",
        "SSL_CERT_FILE",
    ] {
        cmd.env_remove(name);
    }
    cmd.env("PODSSH_SETTINGS", "none").env("PODSSH_DIRECT", "no").env("PODSSH_NET", doc);
    cmd
}

/// Pin `relay-a.test`, the default relay pool hosts, and n0's iroh relays to
/// `127.0.0.1` so nothing in the test ever leaves the loopback.
fn loopback_pins() -> String {
    let mut hosts = BTreeSet::new();
    hosts.insert("relay-a.test".to_string());
    hosts.insert(podssh_relay::relay::default_relay_host().to_string());
    for host in podssh_relay::pool::seed() {
        hosts.insert(host.to_string());
    }
    for relay in pod_iroh::relays::defaults() {
        if let Some(host) = relay.host_str() {
            hosts.insert(host.trim_end_matches('.').to_string());
        }
    }
    hosts.into_iter().map(|h| format!("{h}=127.0.0.1")).collect::<Vec<_>>().join(",")
}

fn private(home: &Path) -> PathBuf {
    let dir = home.join("net-private");
    podssh_relay::cache::private_dir(&dir).unwrap();
    dir
}

/// A net `home` of one relay member `lab` at `host`, signed by `owner` into `doc`.
fn net_of(home: &Path, doc: &Path, owner: &str, key_hex: &str, host: &str) {
    let init = ran(client(home, doc, &words(&["net", "init", "home", "--owner-key", owner])));
    assert_eq!(init.status.code(), Some(0), "net init: {}", text(&init.stderr));
    let add = words(&["net", "add", "lab", key_hex, "--roles", "relay", "--relay-host", host, "--owner-key", owner]);
    let added = ran(client(home, doc, &add));
    assert_eq!(added.status.code(), Some(0), "net add: {}", text(&added.stderr));
}

#[test]
fn a_net_s_relay_member_becomes_the_iroh_home_relay_without_iroh_relay_flag() {
    let s = Session::start("serve-meet-iroh-net");
    let role = match Cell::podssh_relay(&s, "podssh's relay role with iroh", &["--relay-roads", "iroh"]) {
        Ok(cell) => cell,
        Err((_, why)) if why.contains("no openssl") || why.contains("no Python") => {
            eprintln!("did not run: {why}");
            return;
        }
        Err((name, why)) => panic!("{name}: {why}"),
    };
    let at = |flag: &str| role.args.iter().position(|a| a == flag).map(|i| role.args[i + 1].clone()).unwrap();
    let role_host = at("--relay-host");
    let ca = at("--ca-file");
    let expected_relay = format!("https://{role_host}/");

    // A net whose relay member `lab` serves at `role_host`.
    let safe = private(&s.home);
    let (owner, doc) = (safe.join("owner"), safe.join("net.doc"));
    let keygen = words(&["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &shown(&owner)]);
    let made = ran(throughput_harness::command_in(&s.home, &keygen));
    assert_eq!(made.status.code(), Some(0), "keygen: {}", text(&made.stderr));
    let member_key = Identity::from_seed(&[0x42; 32]).public().hex();
    net_of(&s.home, &doc, &shown(&owner), &member_key, &role_host);

    // Pin the role, the default relay pool, and n0's iroh relays to 127.0.0.1
    // so nothing can accidentally reach n0's public relays.
    let pins = loopback_pins();

    // `relay status` asks the net's relay member for `/relays.json` and caches
    // its `meet.iroh` entry in `relay-members.json`.
    let status = words(&["relay", "status", "--ca-file", &ca, "--relay-addr", &pins]);
    let out = ran(client(&s.home, &doc, &status));
    let stdout = text(&out.stdout);
    let stderr = text(&out.stderr);
    assert!(
        matches!(out.status.code(), Some(0 | 69)),
        "relay status exit {:?}\nstdout: {stdout}\nstderr: {stderr}",
        out.status.code()
    );
    let asked = format!(
        "member lab of the net home: the role relay at {role_host}; its list not taken: \
         its /relays.json carries no signed list"
    );
    assert!(stdout.contains(&asked), "relay status asked the net member:\nstdout: {stdout}\nstderr: {stderr}");

    // Prepare the client's iroh key and the node's allowlist.
    let client_key = s.home.join("iroh-client.key");
    let key = podssh_cli::iroh_way::load_key(&Place::File(client_key.clone()), &mut podssh_relay::session::OsEntropy)
        .expect("client iroh key");
    let allow = s.home.join("iroh-allow");
    std::fs::write(&allow, format!("{}\n", keys::fingerprint(&key.public()))).unwrap();

    // Start `podssh node --iroh` with no `--iroh-relay` and no `PODSSH_IROH_RELAY`:
    // it must take the net member's cached `meet.iroh` URL as its home relay.
    let node_args = words(&[
        "node",
        "netiroh",
        &format!("127.0.0.1:{}", s.port),
        "--iroh",
        "--iroh-allow",
        &shown(&allow),
        "--iroh-key",
        &shown(&s.home.join("iroh-node.key")),
        "--ca-file",
        &ca,
        "--relay-addr",
        &pins,
    ]);
    let mut node_cmd = client(&s.home, &doc, &node_args);
    node_cmd.env(pod_iroh::endpoint::UDP_ENV, "off").stdin(Stdio::null()).stderr(Stdio::piped());
    let mut node = node_cmd.spawn().expect("node runs");
    let lines = lines_of(&mut node);
    s.keep(node);
    let line = wait_for(&lines, "ticket iroh:").unwrap_or_else(|why| panic!("the node did not print a ticket: {why}"));
    let raw = line.split_once("ticket iroh:").expect("ticket iroh: prefix").1.trim().to_string();
    let ticket = format!("iroh:{raw}");
    let addr = pod_iroh::ticket::parse(&raw).expect("a valid iroh ticket");
    let ticket_relays: Vec<String> = addr.relay_urls().map(ToString::to_string).collect();
    assert_eq!(
        ticket_relays,
        vec![expected_relay.clone()],
        "node chose the net relay member as its home relay without --iroh-relay"
    );

    // Connect `podssh ssh iroh:TICKET` with no `--iroh-relay` and no
    // `PODSSH_IROH_RELAY`, carrying a session end to end through the role alone.
    let mut ssh_args = words(&["ssh", "-v"]);
    ssh_args.extend(s.common());
    ssh_args.extend(words(&[
        "--ca-file",
        &ca,
        "--relay-addr",
        &pins,
        "--iroh-key",
        &shown(&client_key),
        &format!("tester@{ticket}"),
        "greet",
    ]));
    let mut ssh_cmd = client(&s.home, &doc, &ssh_args);
    ssh_cmd.env(pod_iroh::endpoint::UDP_ENV, "off");
    let out = ran(ssh_cmd);
    let ssh_stdout = text(&out.stdout);
    let ssh_stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "ssh failed:\nstdout: {ssh_stdout}\nstderr: {ssh_stderr}");
    assert_eq!(ssh_stdout, ssh_harness::GREETING);
    assert!(ssh_stderr.contains(pod_iroh::client::RELAY_ONLY), "session ran through the relay alone:\n{ssh_stderr}");
    assert!(
        ssh_stderr.contains(&expected_relay),
        "ssh connected through the net relay member {expected_relay}:\n{ssh_stderr}"
    );

    // Both endpoints came up at the net's relay role.
    let events = std::fs::read_to_string(s.home.join("fake-relay-normal-events.log")).unwrap_or_default();
    let words_of = podssh_relay::serve::said::words;
    let up = events.lines().filter(|l| l.starts_with("iroh: the endpoint ") && words_of(l).ends_with(" is up")).count();
    assert!(up >= 2, "both endpoints came up at the role: {events}");
}
