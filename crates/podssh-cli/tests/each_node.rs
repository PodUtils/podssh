//! `podssh each`, `run` and `job` reach a node (T-708, cfb's A-S-01): through
//! the stand-in relay's reverse road on the loopback, two nodes of two pairs
//! in front of the test's SSH server whose commands run in sh
//! (`job_harness`), and a third pair whose node is not running. `each --json`
//! over the three gives each running node its own result and fails the
//! stopped one alone (the planted defect, a reach that takes a node for a
//! host, fails each); `run` sends its project to a node and gives its
//! status; `job start` on a node, then its `log` once it ended. A host with
//! no `sftp-server`, no Python or no openssl says that the test did not run.
#![cfg(unix)]

mod cleanup;
mod job_harness;
mod ssh_harness;
mod throughput_harness;

use std::io::Read;
use std::process::Stdio;
use std::time::{Duration, Instant};

use job_harness::Far;
use serde_json::Value;
use throughput_harness::{lines_of, wait_for, Cell, Session};

/// The stand-in relay's name, on the loopback.
const PINS: [&str; 2] = ["--relay-addr", "relay-a.test=127.0.0.1"];
/// The bound on each run of podssh.
const RUN_LIMIT: Duration = Duration::from_secs(180);

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|w| w.to_string()).collect()
}

/// `podssh ARGS` in the session's home, with the stand-in's CA and its
/// address: the code, stdout and stderr, within [`RUN_LIMIT`].
fn ran(session: &Session, ca: &str, args: &[String]) -> (i32, String, String) {
    let mut cmd = session.stand_in(&args[..1], ca);
    cmd.args(PINS).args(&args[1..]).current_dir(&session.home);
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let read = |mut from: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = from.read_to_string(&mut text);
            text
        })
    };
    let out = read(Box::new(child.stdout.take().expect("stdout")));
    let err = read(Box::new(child.stderr.take().expect("stderr")));
    let end = Instant::now() + RUN_LIMIT;
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code().unwrap_or(-1);
        }
        if Instant::now() > end {
            let _ = child.kill();
            let _ = child.wait();
            break -1;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    (code, out.join().unwrap_or_default(), err.join().unwrap_or_default())
}

#[test]
fn each_run_and_job_reach_nodes_and_a_stopped_node_fails_alone() {
    if ssh_harness::sftp::server_path().is_none() {
        eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return;
    }
    let session = Session::start("each-node");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    // The far host: a server whose commands run in sh, as a node's TARGET.
    let far = Far::new("each-node-far", std::env::var("PATH").unwrap_or_default(), None);
    let target = format!("127.0.0.1:{}", far.port);
    for name in ["na", "nb", "nc"] {
        let (rc, _, err) = ran(&session, &ca, &words(&["relay", "pair", name, "--relay-host", &relay]));
        assert_eq!(rc, 0, "podssh relay pair {name}: {err}");
    }
    // Two nodes run; the pair `nc` has none.
    for name in ["na", "nb"] {
        let mut node = session.stand_in(&words(&["node"]), &ca);
        node.args(PINS).args([name, target.as_str()]);
        let mut node = node.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let lines = lines_of(&mut node);
        session.keep(node);
        wait_for(&lines, "online").expect("the node is online");
    }
    let with = |verb: &str, rest: &[&str]| {
        let mut args = words(&[verb]);
        args.extend(session.common());
        args.extend(words(rest));
        ran(&session, &ca, &args)
    };

    // each: one result for each node, in the order of the list.
    let (rc, out, err) =
        with("each", &["--json", "node://a@na,node://a@nb,node://a@nc", "--", "echo", "from-$((40+2))"]);
    let record: Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}\n{err}"));
    let hosts = record["hosts"].as_array().expect("hosts");
    assert_eq!(hosts.len(), 3, "{out}");
    for host in &hosts[..2] {
        assert_eq!(host["exit"], 0, "{out}\n{err}");
        assert_eq!(host["stdout"], "from-42\n", "{out}");
    }
    assert_ne!(hosts[2]["exit"], 0, "the node that is not running: {out}");
    assert_ne!(rc, 0, "a host failed: {err}");

    // run: the project to the node, its command there, its status back.
    let proj = session.home.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join("run.sh"), "echo ran-on-node; exit 6\n").unwrap();
    let from = proj.display().to_string();
    let (rc, out, err) = with("run", &["--from", from.as_str(), "node://a@na", "--", "sh", "run.sh"]);
    assert_eq!(rc, 6, "{out}\n{err}");
    assert!(out.contains("ran-on-node"), "{out}\n{err}");

    // job: started on the node, its log after its end.
    let (rc, out, err) = with("job", &["start", "node://a@nb", "--no-tmux", "--", "echo job-$((6*7))"]);
    assert_eq!(rc, 0, "{err}");
    let id = out.trim().to_string();
    assert!(id.len() == 8 && id.bytes().all(|b| b.is_ascii_hexdigit()), "{out}");
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        let (rc, log, err) = with("job", &["log", "node://a@nb", id.as_str()]);
        if rc == 0 && log.contains("job-42") {
            break;
        }
        assert!(Instant::now() < until, "no log of the job: {rc} {log} {err}");
        std::thread::sleep(Duration::from_millis(500));
    }
    let (rc, list, err) = with("job", &["list", "node://a@nb"]);
    assert_eq!(rc, 0, "{err}");
    assert!(list.contains(&id), "{list}");
}
