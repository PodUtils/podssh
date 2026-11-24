//! The DNS road (T-877), through the binary: `podssh node box TARGET
//! --carrier dns:NODE` and `podssh operator --carrier dns:CLIENT box`, with
//! no relay and no pair, the client's queries to a stand-in resolver on the
//! loopback that passes them to the node's responder (pod-link's, software
//! that podssh did not write) and its answers back. Bytes come back whole
//! from an echo server behind the node, also where the resolver strips the
//! OPT record; a resolver that cuts each answer, and a node whose key is not
//! the client's pin, each end in one line and 69; a file over Q107's bound
//! is 78. Nothing leaves the loopback. A run through `unbound` as the
//! recursor waits for the build image (the entry's Prove).

mod live_harness;

use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use live_harness::{echo_server, scratch};
use podssh_relay::identity::Identity;

/// The road is slow by Q107's bound: 20 queries a second.
const LIMIT: Duration = Duration::from_secs(240);
const ZONE: &str = "t.example";
const NODE_SEED: [u8; 32] = [1; 32];
const CLIENT_SEED: [u8; 32] = [2; 32];

/// Removes the scratch directory, with its keys, however the test ends.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Ends a node that a failed test left running.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn pattern(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x9e37_79b9;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// The key file of `seed` in `dir`, private, as podssh writes one: the
/// seed in hex and a newline; and its public key in hex.
fn key_file(dir: &Path, name: &str, seed: [u8; 32]) -> String {
    let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    pod_core::files::create_private(&dir.join(name), format!("{hex}\n").as_bytes()).expect("a private key file");
    Identity::from_seed(&seed).public().hex()
}

/// A free UDP port of the loopback, for the node's `listen`.
fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// The node's file and the client's, as `--carrier` names them: the node at
/// `listen`, the client toward `resolver`, the client pinning `pinned`.
fn files(dir: &Path, listen: SocketAddr, resolver: SocketAddr, pinned: &str, extra: &str) -> (String, String) {
    let _ = key_file(dir, "node.key", NODE_SEED);
    let client_key = key_file(dir, "client.key", CLIENT_SEED);
    let node = dir.join("node.conf");
    std::fs::write(&node, format!("zone = {ZONE}\nlisten = {listen}\nkey-file = node.key\npeer = {client_key}\n"))
        .unwrap();
    let client = dir.join("client.conf");
    let text = format!("zone = {ZONE}\nresolver = {resolver}\nkey-file = client.key\npeer = {pinned}\n{extra}");
    std::fs::write(&client, text).unwrap();
    (format!("dns:{}", node.display()), format!("dns:{}", client.display()))
}

/// What the stand-in resolver does on the way.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Way {
    /// It passes each query and each answer whole.
    Whole,
    /// It removes the OPT record of each query: a resolver with no EDNS0.
    Stripped,
    /// It answers each query itself, with TC set and no record.
    Cut,
}

/// The query `q` with no OPT record, where its last record is one.
fn strip_opt(q: &mut Vec<u8>) {
    let n = q.len();
    if n > 23 && q[11] == 1 && q[n - 11] == 0 && q[n - 10..n - 8] == [0, 41] {
        q.truncate(n - 11);
        q[11] = 0;
    }
}

/// A stand-in recursive resolver on the loopback in front of `responder`,
/// written here apart from pod-dns: its address.
fn resolver(responder: SocketAddr, way: Way) -> SocketAddr {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let back = UdpSocket::bind("127.0.0.1:0").unwrap();
    back.connect(responder).unwrap();
    let back = Arc::new(back);
    let addr = front.local_addr().unwrap();
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let (f, b, c) = (front.clone(), back.clone(), client.clone());
    // A read that fails (an ICMP error of an earlier send, as a port that
    // was not bound yet gives) goes on: the socket lives with the test.
    let pause = || std::thread::sleep(Duration::from_millis(10));
    std::thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        loop {
            let Ok((n, from)) = f.recv_from(&mut buffer) else {
                pause();
                continue;
            };
            *c.lock().unwrap() = Some(from);
            let mut query = buffer[..n].to_vec();
            match way {
                Way::Whole => {}
                Way::Stripped => strip_opt(&mut query),
                Way::Cut => {
                    // The header and the question, QR, TC and RA, no record.
                    let mut end = 12;
                    while end < n && query[end] != 0 {
                        end += 1 + usize::from(query[end]);
                    }
                    query.truncate((end + 5).min(n));
                    query[2] |= 0x82;
                    query[3] = 0x80;
                    query[6..12].fill(0);
                    let _ = f.send_to(&query, from);
                    continue;
                }
            }
            let _ = b.send(&query);
        }
    });
    std::thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        loop {
            let Ok(n) = back.recv(&mut buffer) else {
                pause();
                continue;
            };
            if let Some(to) = *client.lock().unwrap() {
                let _ = front.send_to(&buffer[..n], to);
            }
        }
    });
    addr
}

/// `cmd` with `input` on stdin, within `limit`: its code, stdout, stderr.
fn run_with(mut cmd: Command, input: Vec<u8>, limit: Duration) -> (Option<i32>, Vec<u8>, String) {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("it runs");
    let mut stdin = child.stdin.take().expect("stdin");
    std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let reader = |mut pipe: Box<dyn Read + Send>| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            let _ = tx.send(bytes);
        });
        rx
    };
    let out = reader(Box::new(child.stdout.take().expect("stdout")));
    let err = reader(Box::new(child.stderr.take().expect("stderr")));
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{cmd:?} did not end within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let (out, err) = (out.recv_timeout(LIMIT).unwrap_or_default(), err.recv_timeout(LIMIT).unwrap_or_default());
    (status.code(), out, String::from_utf8_lossy(&err).into_owned())
}

/// The node's exit code within `limit`, and its stderr.
fn node_end(mut node: Running, limit: Duration) -> (Option<i32>, String) {
    let deadline = Instant::now() + limit;
    let code = loop {
        if let Some(status) = node.0.try_wait().expect("wait") {
            break status.code();
        }
        if Instant::now() > deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut err = String::new();
    if let Some(mut pipe) = node.0.stderr.take() {
        if code.is_some() {
            let _ = pipe.read_to_string(&mut err);
        }
    }
    (code, err)
}

/// What a session gave: the operator's code, stdout and stderr; the node's
/// code and stderr.
struct Ran {
    code: Option<i32>,
    out: Vec<u8>,
    err: String,
    node_code: Option<i32>,
    node_err: String,
}

impl Ran {
    fn both(&self) -> String {
        format!("{}\nthe node: {}", self.err, self.node_err)
    }
}

/// A node on the loopback and an operator through a stand-in resolver of
/// `way`, pinning `pinned` (the node's key when none), with `sent` on its
/// stdin; the node gets `node_wait` to end after the operator.
fn session(tag: &str, way: Way, pinned: Option<&str>, sent: &[u8], node_wait: Duration) -> Ran {
    let home = scratch(tag);
    let _scratch = Scratch(home.clone());
    let target = format!("127.0.0.1:{}", echo_server());
    let listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let node_pub = Identity::from_seed(&NODE_SEED).public().hex();
    let pin = pinned.unwrap_or(&node_pub);
    let (node_file, client_file) = files(&home, listen, resolver(listen, way), pin, "");
    let node = live_harness::command(&home, &["node", "box", &target, "--carrier", &node_file])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the node runs");
    let node = Running(node);
    // The node's bind before the first query: a lost query is sent again,
    // but the test need not wait for that.
    std::thread::sleep(Duration::from_millis(500));
    let operator = live_harness::command(&home, &["operator", "--carrier", &client_file, "box"]);
    let (code, out, err) = run_with(operator, sent.to_vec(), LIMIT);
    let (node_code, node_err) = node_end(node, node_wait);
    Ran { code, out, err, node_code, node_err }
}

#[test]
fn an_operator_reaches_a_node_through_a_resolver_and_both_end_with_0() {
    let sent = pattern(16 * 1024);
    let ran = session("dns-echo", Way::Whole, None, &sent, Duration::from_secs(60));
    let both = ran.both();
    assert_eq!(ran.code, Some(0), "{both}");
    assert!(ran.out == sent, "{} bytes came back, changed or short: {both}", ran.out.len());
    assert_eq!(ran.node_code, Some(0), "the client's Close ends the node: {both}");
    assert!(ran.node_err.contains("over the carrier dns:"), "{both}");
    assert!(ran.node_err.contains("took the stream"), "{both}");
}

/// A resolver that strips OPT: answers of 512 bytes, slower, still whole.
#[test]
fn a_resolver_with_no_edns0_still_carries_the_stream() {
    let sent = pattern(4 * 1024);
    let ran = session("dns-plain", Way::Stripped, None, &sent, Duration::from_secs(60));
    let both = ran.both();
    assert_eq!(ran.code, Some(0), "{both}");
    assert!(ran.out == sent, "{} bytes came back, changed or short: {both}", ran.out.len());
}

/// A resolver that cuts each answer, and a node whose key is not the
/// client's pin (the plant: another key): the client's own line of the DNS
/// carrier, and 69.
#[test]
fn a_cut_answer_and_a_wrong_key_each_end_in_one_line_and_69() {
    let other = Identity::from_seed(&[3; 32]).public().hex();
    for (tag, way, pinned) in [("dns-cut", Way::Cut, None), ("dns-key", Way::Whole, Some(other.as_str()))] {
        let ran = session(tag, way, pinned, &[], Duration::from_secs(1));
        assert_eq!(ran.code, Some(69), "{tag}: {}", ran.both());
        assert!(ran.out.is_empty(), "{tag}: {:?}", ran.out);
        let own = ran.err.lines().any(|l| l.starts_with("podssh: the DNS carrier: ") && l.contains("client.conf"));
        assert!(own, "{tag}: the client's own line: {}", ran.err);
    }
}

/// Q107's bound: a file that asks more than 20 queries a second, or more
/// than 8 in flight, is 78 at either end, before anything is sent or bound.
#[test]
fn a_file_over_the_bound_of_q107_is_78() {
    let home = scratch("dns-bound");
    let _scratch = Scratch(home.clone());
    let any: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let zero = "0".repeat(64);
    let (_, client) = files(&home, any, any, &zero, "queries-per-second = 21\n");
    let node = home.join("node.conf");
    let text = format!("zone = {ZONE}\nlisten = {any}\nkey-file = k\npeer = {zero}\nin-flight = 9\n");
    std::fs::write(&node, text).unwrap();
    let node = format!("dns:{}", node.display());
    for (args, says) in [
        (vec!["operator", "--carrier", client.as_str(), "box"], "queries-per-second 21"),
        (vec!["node", "box", "127.0.0.1:1", "--carrier", node.as_str()], "in-flight 9"),
    ] {
        let (code, out, err) = run_with(live_harness::command(&home, &args), Vec::new(), Duration::from_secs(30));
        assert_eq!(code, Some(78), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out:?}");
        assert!(err.contains(says) && err.contains("(Q107)"), "{args:?}: {err}");
    }
}
