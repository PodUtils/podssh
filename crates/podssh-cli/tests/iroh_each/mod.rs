//! `podssh each` over the iroh road (T-782): the node of an `iroh:` ticket,
//! once its allowlist lets the client's key in, runs the command as a host
//! does; `each --json` gives its output and status (the planted defect, the
//! old refusal of a ticket, gives 64 with no key named).

use std::io::Write;
use std::process::Stdio;

use super::{command, fingerprint_after, line_with, lines_of, run, scratch, wait_for, Node, GREETING};

#[test]
fn each_runs_its_command_on_the_node_of_an_iroh_ticket() {
    let home = scratch("each");
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let relay = runtime.block_on(podssh_iroh::test_relay::spawn(&home)).expect("a relay on the loopback");
    let host_key = home.join("host_key").to_string_lossy().into_owned();
    let (rc, _, err) = run(&home, &["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &host_key]);
    assert_eq!(rc, 0, "{err}");
    let port = runtime.block_on(super::ssh_harness::start(std::path::Path::new(&host_key)));
    let (cert, url) = (relay.cert.to_string_lossy().into_owned(), relay.url.to_string());
    let allow = home.join("allow");
    std::fs::write(&allow, "# the client keys that may connect\n").unwrap();
    let allow_text = allow.to_string_lossy().into_owned();
    let node_key = home.join("node.key").to_string_lossy().into_owned();
    let target = format!("127.0.0.1:{port}");
    let node_args = [
        "node",
        "lab",
        &target,
        "--iroh",
        "--iroh-relay",
        &url,
        "--ca-file",
        &cert,
        "--iroh-allow",
        &allow_text,
        "--iroh-key",
        &node_key,
    ];
    let mut child = command(&home, &node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().expect("the node");
    let lines = lines_of(&mut child);
    let _node = Node(child);
    let started = wait_for(&lines, "ticket iroh:");
    let ticket_line = line_with(&started, "ticket iroh:");
    let ticket = ticket_line[ticket_line.find("iroh:").unwrap()..].trim().to_string();
    let known = format!("UserKnownHostsFile={}", home.join("known_hosts").display());
    let destination = format!("tester@{ticket}");
    // `each` takes the relays from the variable and the client's key of its cache.
    let each = |home: &std::path::Path| {
        let args = [
            "each",
            "--json",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            &known,
            "--ca-file",
            &cert,
            &destination,
            "--",
            "greet",
        ];
        let mut cmd = command(home, &args);
        let out = cmd.env("PODSSH_IROH_RELAY", &url).stdin(Stdio::null()).output().unwrap();
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
    };
    // Refused at the node, which names the key that it refused.
    let (rc, out, err) = each(&home);
    assert_ne!(rc, 0, "{out}\n{err}");
    let key = fingerprint_after(&err, "refused this client's key ");
    assert_eq!(key.len(), 50, "the client says its key's fingerprint: {err}");
    let mut file = std::fs::OpenOptions::new().append(true).open(&allow).unwrap();
    writeln!(file, "{key} the test's client").unwrap();
    drop(file);
    let (rc, out, err) = each(&home);
    assert_eq!(rc, 0, "{out}\n{err}");
    let record: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}\n{err}"));
    let host = &record["hosts"][0];
    assert_eq!((&host["exit"], &host["stdout"]), (&serde_json::json!(0), &serde_json::json!(GREETING)), "{out}");
    drop(relay);
}
