//! The live test with two nodes of `podssh ts` (T-106): node A, an echo on
//! the tailnet stack of podssh's adapter in this process (`podssh_ts::echo`),
//! and node B, the real binary, `podssh ts -W A:4242`, both in `relay` mode,
//! pinned first to podssh's own relay role on the loopback (`podssh relay
//! serve --derp-keys FILE`, which admits the two node keys alone), then,
//! where a variable names one, to a server of Tailscale's tailcat fleet
//! (Q58: short). B sends random bytes, A sends each back: what A got and
//! what B got back have the SHA-256 of what B sent. A third node, whose key
//! the role's file does not list, is refused with 1008, exit 77: the role
//! admits what its owner listed, and no other key.
//!
//! Live and ignored. The control server and its key come from variables that
//! only this test reads, as `scripts/ts-headscale.sh` makes them for
//! headscale, or as the operator's machine holds them for a real tailnet:
//!
//! - `PODSSH_TS_TWO_KEY_FILE`: the file of an auth key or a pre-auth key,
//!   reusable, which goes to each node by its path alone;
//! - `PODSSH_TS_TWO_CONTROL_URL`: `https://HOST:PORT` of the control server,
//!   unset for Tailscale's;
//! - `PODSSH_TS_TWO_CA_FILE`: the CA of that server, when it is a test's;
//! - `PODSSH_TS_TWO_STATE_DIR`: where the two state files stay across runs
//!   (`a.json`, `b.json`), so that their keys stay; a scratch directory else;
//! - `PODSSH_TS_TWO_TAILCAT`: a host of tailcat's fleet, such as
//!   `tc301a.ipn.dev`, for the second part.
//!
//! Each part says "did not run" on stderr without its variables.
//!
//! ```sh
//! CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --features ts --test ts_two_nodes -- --ignored --nocapture
//! ```
#![cfg(all(feature = "ts", unix))]

mod cleanup;
mod update_support;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use podssh_ts::config::{TsConfig, TsMode};
use podssh_ts::echo::{self, Echo, Echoed};
use podssh_ts::node::TsNode;
use podssh_ts::secret::AuthKey;
use sha2::{Digest, Sha256};

/// The port of A's echo, on its tailnet address alone.
const ECHO_PORT: u16 = 4242;
/// What B sends through podssh's relay role, and through tailcat's (Q58).
const ROLE_BYTES: usize = 1 << 20;
const TAILCAT_BYTES: usize = 64 << 10;
/// The bound of each node's start and of each run of B.
const WAIT: Duration = Duration::from_secs(180);

/// The variables of the test; `None` when the key's is not set.
struct Live {
    key_file: PathBuf,
    control_url: Option<String>,
    ca_file: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    tailcat: Option<String>,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn live() -> Option<Live> {
    Some(Live {
        key_file: var("PODSSH_TS_TWO_KEY_FILE")?.into(),
        control_url: var("PODSSH_TS_TWO_CONTROL_URL"),
        ca_file: var("PODSSH_TS_TWO_CA_FILE").map(Into::into),
        state_dir: var("PODSSH_TS_TWO_STATE_DIR").map(Into::into),
        tailcat: var("PODSSH_TS_TWO_TAILCAT"),
    })
}

/// A child of the test, ended when the test ends.
struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn sha256(bytes: &[u8]) -> String {
    echo::hex_sha256(&Sha256::digest(bytes))
}

/// The key of the variable's file, trimmed, in memory that is cleared.
fn auth_key(file: &Path) -> AuthKey {
    let mut raw = zeroize::Zeroizing::new(std::fs::read(file).expect("PODSSH_TS_TWO_KEY_FILE is read"));
    while raw.last().is_some_and(|b| b.is_ascii_whitespace()) {
        raw.pop();
    }
    AuthKey::new(raw).expect("PODSSH_TS_TWO_KEY_FILE holds a key")
}

/// The binary, copied beside a `podssh-ca.pem` of `bundle`, which its checks
/// before the start trust (`crates/podssh-cli/src/ts/probe.rs`).
fn binary_beside(dir: &Path, bundle: &Path) -> PathBuf {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let copy = bin.join("podssh");
    std::fs::copy(env!("CARGO_BIN_EXE_podssh"), &copy).expect("the binary is copied");
    std::fs::copy(bundle, bin.join("podssh-ca.pem")).unwrap();
    copy
}

/// A command of `bin` with no proxy, agent or home of this host, and the
/// test's CAs for the fork's TLS.
fn podssh(bin: &Path, dir: &Path, bundle: &Path) -> Command {
    let mut cmd = Command::new(bin);
    for name in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    cmd.env("HOME", dir).env("PODSSH_CACHE_DIR", dir.join("cache")).env("PODSSH_TS_TEST_CA_FILE", bundle);
    cmd
}

/// Wait for `child` at most `bound`, then end it: its exit code, read
/// directly; `None` when the bound passed.
fn wait_bounded(child: &mut Child, bound: Duration) -> Option<i32> {
    let end = Instant::now() + bound;
    loop {
        if let Some(status) = child.try_wait().expect("the child is waited for") {
            return status.code();
        }
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The relay role on a free port of the loopback, with DERP for the keys of
/// `keys`: the child, and its port, read from its port file within 30 s.
fn role(bin: &Path, dir: &Path, bundle: &Path, cert: &Path, key: &Path, keys: &Path) -> (Killed, u16) {
    let port_file = dir.join("role.port");
    let child = podssh(bin, dir, bundle)
        .args(["relay", "serve", "--listen", "127.0.0.1:0", "--port-file"])
        .arg(&port_file)
        .arg("--cert")
        .arg(cert)
        .arg("--key")
        .arg(key)
        .arg("--derp-keys")
        .arg(keys)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(dir.join("role.log")).unwrap())
        .stderr(std::fs::File::create(dir.join("role.err")).unwrap())
        .spawn()
        .expect("podssh relay serve starts");
    let child = Killed(child);
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        let port = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse().ok());
        if let Some(port) = port {
            return (child, port);
        }
        let said = std::fs::read_to_string(dir.join("role.err")).unwrap_or_default();
        assert!(Instant::now() < end, "the role wrote no port within 30 s; it said:\n{said}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Node A in this process, in `relay` mode pinned to `host:port`, its echo
/// waiting once its DERP link is up.
fn node_a(rt: &tokio::runtime::Runtime, live: &Live, state: &Path, host: &str, port: u16) -> (TsNode, Echo) {
    let cfg = TsConfig {
        state_file: state.to_path_buf(),
        control_url: live.control_url.clone(),
        hostname: Some("podssh-ts-echo".to_string()),
        ephemeral: false,
        mode: TsMode::Relay { host: host.to_string(), port },
        proxy_url: None,
        no_proxy: None,
        retry_refused: false,
        link_events: None,
    };
    rt.block_on(async {
        let mut key = auth_key(&live.key_file);
        let node = tokio::time::timeout(WAIT, TsNode::start(&cfg, &key))
            .await
            .expect("node A started within the bound")
            .unwrap_or_else(|e| panic!("node A did not start: {e:?}"));
        key.expire();
        node.derp_ready_within(WAIT)
            .await
            .unwrap_or_else(|e| panic!("node A has no DERP link at {host}:{port}: {e:?}"));
        let echo = echo::start(&node, ECHO_PORT, WAIT).await.unwrap_or_else(|e| panic!("node A's echo: {e:?}"));
        (node, echo)
    })
}

/// What one run of node B gave: its exit, what came back, and its stderr.
struct Run {
    code: Option<i32>,
    back: Vec<u8>,
    said: String,
}

/// What each run of the test shares: the runtime of node A, the copy of
/// the binary, the scratch directory, the CAs and the variables.
struct Ctx {
    rt: tokio::runtime::Runtime,
    bin: PathBuf,
    dir: PathBuf,
    bundle: PathBuf,
    live: Live,
}

impl Ctx {
    /// `podssh ts` as node B with `state`, in `relay` mode pinned to
    /// `relay`, with `extra` (`-W A:PORT`), and `sent` on stdin.
    fn node_b(&self, state: &Path, relay: &str, extra: &[&str], sent: &[u8], tag: &str) -> Run {
        let dir = &self.dir;
        let (up, down, err) =
            (dir.join(format!("{tag}.in")), dir.join(format!("{tag}.out")), dir.join(format!("{tag}.err")));
        std::fs::write(&up, sent).unwrap();
        let mut cmd = podssh(&self.bin, dir, &self.bundle);
        cmd.arg("ts");
        if let Some(url) = &self.live.control_url {
            cmd.args(["--ts-control-url", url.as_str()]);
        }
        cmd.arg("--ts-auth-key-file").arg(&self.live.key_file).arg("--ts-state").arg(state);
        let bound = format!("{}s", WAIT.as_secs());
        cmd.args(["--ts-mode", "relay", "--ts-relay", relay, "--timeout", bound.as_str()]);
        cmd.args(extra);
        let mut child = cmd
            .stdin(std::fs::File::open(&up).unwrap())
            .stdout(std::fs::File::create(&down).unwrap())
            .stderr(std::fs::File::create(&err).unwrap())
            .spawn()
            .expect("podssh ts starts");
        let code = wait_bounded(&mut child, WAIT + Duration::from_secs(30));
        Run {
            code,
            back: std::fs::read(&down).unwrap_or_default(),
            said: std::fs::read_to_string(&err).unwrap_or_default(),
        }
    }

    /// What A's echo got for one connection, within 30 s.
    fn echoed(&self, echo: &mut Echo) -> Echoed {
        // The timer is made inside the runtime, which its clock needs.
        let got = self.rt.block_on(async { tokio::time::timeout(Duration::from_secs(30), echo.ended.recv()).await });
        got.expect("A's echo ended within 30 s").expect("A's echo told its end").expect("A's echo got the stream whole")
    }

    /// B with `state` through A's echo, pinned to `relay`: what A got and
    /// what came back are what B sent, by their SHA-256.
    fn both_ways(&self, echo: &mut Echo, state: &Path, relay: &str, bytes: usize, tag: &str) {
        let sent: Vec<u8> = (0..bytes).map(|_| rand::random::<u8>()).collect();
        let target = echo.addr.to_string();
        let run = self.node_b(state, relay, &["-W", target.as_str()], &sent, tag);
        assert_eq!(run.code, Some(0), "{tag}: node B's exit; it said:\n{}", run.said);
        let got = self.echoed(echo);
        let want = sha256(&sent);
        assert_eq!((got.bytes, got.sha256.as_str()), (bytes as u64, want.as_str()), "{tag}: what A got");
        assert_eq!((run.back.len(), sha256(&run.back)), (bytes, want.clone()), "{tag}: what came back to B");
        eprintln!("ts_two_nodes: {tag}: {bytes} bytes each way through {relay}, sha256 {want} both ways");
    }

    fn stop(&self, node: TsNode, echo: Echo) {
        drop(echo);
        let _ = self.rt.block_on(node.shutdown(Some(Duration::from_secs(2))));
    }
}

#[test]
#[ignore = "M10 (T-106): live; needs a control server's key, named by PODSSH_TS_TWO_KEY_FILE (scripts/ts-headscale.sh, or a tailnet's)"]
fn two_nodes_exchange_bytes_through_the_relay_role_and_tailcat() {
    let Some(live) = live() else {
        eprintln!("ts_two_nodes: did not run: PODSSH_TS_TWO_KEY_FILE names no key file");
        return;
    };
    let dir = std::env::temp_dir().join(format!("podssh-ts-two-{}-{:08x}", std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(dir.join("cache")).unwrap();
    cleanup::at_test_end(&dir);
    let states = live.state_dir.clone().unwrap_or_else(|| dir.clone());
    std::fs::create_dir_all(&states).expect("the directory of the state files");
    let (state_a, state_b, state_c) = (states.join("a.json"), states.join("b.json"), dir.join("c.json"));
    // The role's certificate, for its address on the loopback, and each CA
    // that the fork's TLS needs: the role's, and the control server's.
    let (cert, cert_key, role_ca) = update_support::pem_files(&dir, &["127.0.0.1"]);
    let mut bundle_pem = std::fs::read_to_string(&role_ca).unwrap();
    if let Some(ca) = &live.ca_file {
        bundle_pem.push_str(&std::fs::read_to_string(ca).expect("PODSSH_TS_TWO_CA_FILE is read"));
    }
    let bundle = dir.join("bundle.pem");
    std::fs::write(&bundle, bundle_pem).unwrap();
    // SAFETY: set before the runtime makes a thread or the fork reads its
    // roots, and this binary runs this one test: it owns the environment.
    unsafe {
        std::env::set_var("PODSSH_TS_TEST_CA_FILE", &bundle);
    }
    let bin = binary_beside(&dir, &bundle);
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let ctx = Ctx { rt, bin, dir: dir.clone(), bundle, live };

    // The two keys, before either node runs, in the role's file alone.
    let key_of =
        |state: &Path| ctx.rt.block_on(podssh_ts::keys::node_key(state)).expect("the node key of a state file");
    let keys = dir.join("derp-keys");
    std::fs::write(&keys, format!("# node A and node B of T-106\n{}\n{}\n", key_of(&state_a), key_of(&state_b)))
        .unwrap();

    // Part 1: podssh's relay role on the loopback.
    let (_role, port) = role(&ctx.bin, &dir, &ctx.bundle, &cert, &cert_key, &keys);
    let pinned = format!("127.0.0.1:{port}");
    let (node, mut echo) = node_a(&ctx.rt, &ctx.live, &state_a, "127.0.0.1", port);
    ctx.both_ways(&mut echo, &state_b, &pinned, ROLE_BYTES, "role");
    // A key that the file does not list, of a node for this run alone: refused
    // with 1008, as the operator's relay refuses one, and said by the role.
    let refused = ctx.node_b(&state_c, &pinned, &["--ts-ephemeral"], b"", "unlisted");
    let role_log = std::fs::read_to_string(dir.join("role.log")).unwrap_or_default();
    assert_eq!(refused.code, Some(77), "a node key that the role does not list; it said:\n{}", refused.said);
    assert!(role_log.contains("derp: refused the node key"), "the role's lines:\n{role_log}");
    ctx.stop(node, echo);

    // Part 2: a server of tailcat's fleet, short (Q58).
    let Some(tailcat) = ctx.live.tailcat.clone() else {
        eprintln!("ts_two_nodes: tailcat: did not run: PODSSH_TS_TWO_TAILCAT names no server");
        return;
    };
    let (node, mut echo) = node_a(&ctx.rt, &ctx.live, &state_a, &tailcat, 443);
    ctx.both_ways(&mut echo, &state_b, &tailcat, TAILCAT_BYTES, "tailcat");
    ctx.stop(node, echo);
}
