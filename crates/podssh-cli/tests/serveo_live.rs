//! The Serveo road through Serveo itself (T-549), by the operator's rulings
//! Q78 and Q91: one short run, from GitHub Actions
//! (`.github/workflows/serveo-live.yml`), never in the gate, so it is
//! ignored unless asked. A node with a throwaway key serves the loopback's
//! SSH server of the tests at the private alias of its key at Serveo
//! (`serveo.net`, pod-services), as `ssh -R ALIAS:22:localhost:22` does; a
//! client that names the node's key jumps to that alias, runs `greet`, then
//! takes 1 MiB down; the node is stopped at the end, which gives the alias
//! up. With `PODSSH_SERVEO_TEST_PLANT=stranger`, the client names another
//! node's key, so another alias, and the run must fail: the check is not
//! vacuous.

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
/// The bytes taken down: a few MiB at most (T-548's Decision, which T-549 follows).
const DOWN: usize = 1 << 20;

/// `podssh ARGS` with HOME and the cache under `home`, the runner's own
/// egress, and none of the other roads.
fn command(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
    for name in ["PODSSH_SERVEO", "PODSSH_LAST_RESORT", "PODSSH_RELAY", "PODSSH_RELAY_ADDR", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    cmd.env("PODSSH_OPENTUNNEL", "no").env("PODSSH_TRANSIT", "no").env("PODSSH_CROC", "no").env("PODSSH_PIPING", "no");
    // Nor the roads before Serveo's: Pinggy (T-548) and ssh-j (T-570).
    cmd.env("PODSSH_PINGGY", "no").env("PODSSH_SSH_J", "no");
    // Nor the last roads of all (Q78): localhost.run (T-565), localtunnel (T-568), bore (T-569).
    cmd.env("PODSSH_LOCALHOST_RUN", "no").env("PODSSH_SANDHOLE", "no");
    cmd.env("PODSSH_LOCALTUNNEL", "no").env("PODSSH_HOSTC", "no").env("PODSSH_SMEE", "no").env("PODSSH_BORE", "no");
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

#[test]
#[ignore = "a live run through Serveo: serveo-live.yml"]
fn a_node_at_its_serveo_alias_serves_a_client_that_names_its_key() {
    let home = std::env::temp_dir().join(format!("podssh-serveo-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    podssh_relay::cache::private_dir(&home).unwrap();
    cleanup::at_test_end(&home);
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let host_key = home.join("host_key");
    let host_key_text = host_key.to_string_lossy().into_owned();
    let (rc, _, err) = run(&mut command(&home, &["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &host_key_text]));
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
    let words = ["node", "lab", &target, "--serveo", "--allow", &allow_text, "--ephemeral-key"];
    let mut node = command(&node_home, &words);
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
    let (mut alias, mut node_key) = (None, None);
    while alias.is_none() {
        let line = lines.recv_timeout(deadline.saturating_duration_since(Instant::now())).expect("the node's alias");
        if let Some(rest) = line.split(": key ").nth(1) {
            node_key = rest.split_whitespace().next().map(str::to_string);
        }
        // The node holds its alias at Serveo: a client can jump to it now.
        if let Some(rest) = line.split(": alias ").nth(1) {
            alias = rest.split_whitespace().next().map(str::to_string);
        }
    }
    let alias = alias.unwrap();
    let node_key = node_key.expect("the node's key line");

    // The planted run names another node's key: the client must refuse.
    let planted = std::env::var("PODSSH_SERVEO_TEST_PLANT").ok().as_deref() == Some("stranger");
    let stranger = file::load(&Place::Ephemeral, &mut OsEntropy).unwrap().identity.public().fingerprint().to_string();
    let expected = if planted { stranger } else { node_key };
    let ssh = |words: &[&str]| {
        let known = format!("UserKnownHostsFile={}", client_home.join("known_hosts").display());
        let client_key = client_key.to_string_lossy().into_owned();
        let mut args = vec!["ssh", "-v", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", &known];
        args.extend_from_slice(&["--client-key", &client_key, "--node-key", &expected]);
        args.extend_from_slice(words);
        run(&mut command(&client_home, &args))
    };
    let (rc, out, err) = ssh(&["node://tester@lab", "greet"]);
    eprintln!("client, greet: {err}");
    assert_eq!(rc, 0, "the client over Serveo");
    assert_eq!(String::from_utf8_lossy(&out), GREETING);
    assert!(err.contains("the Serveo road answered first") && err.contains("nobody vouches for"), "{err}");
    assert!(err.contains(&format!("jumps to {alias}")), "the client jumped to the node's alias: {err}");
    let source = format!("source {DOWN}");
    let (rc, out, err) = ssh(&["node://tester@lab", &source]);
    eprintln!("client, {source}: {err}");
    assert_eq!(rc, 0, "{err}");
    assert_eq!(out.len(), DOWN, "1 MiB down, whole");
    let _ = std::io::stderr().flush();
    drop(runtime);
}
