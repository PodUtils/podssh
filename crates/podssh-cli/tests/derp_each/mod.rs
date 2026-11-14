//! `podssh each` and `podssh job` over the DERP road (T-782): the node of a
//! `derp:` ticket, whose allowlist lets the client in, runs each command as a
//! host does; `each --json` gives its output and status (the planted defect,
//! the old refusal of a ticket, gives 64).

use std::io::Write;
use std::path::PathBuf;

use podssh_relay::identity::file::{self, Place};
use podssh_relay::session::OsEntropy;

use super::{run, ticket_in, Lab, GREETING};

#[test]
fn each_runs_its_command_on_the_node_of_a_derp_ticket() {
    let lab = Lab::new("each");
    // `each` takes the client's key of its cache, which the node lets in.
    let key = PathBuf::from(&lab.client_home).join("cache").join("podssh").join("client.key");
    podssh_relay::cache::private_dir(key.parent().unwrap()).unwrap();
    let made = file::load(&Place::File(key), &mut OsEntropy).expect("the client's key");
    let mut list = std::fs::OpenOptions::new().append(true).open(&lab.allow).unwrap();
    writeln!(list, "{} the client of each", made.identity.public().fingerprint()).unwrap();
    let (_node, _lines, started) = lab.node(&["--derp", "--derp-server", &lab.servers()]);
    let ticket = ticket_in(&started, "ticket derp:");
    let (servers, destination) = (lab.servers(), format!("tester@{ticket}"));
    let known = format!("UserKnownHostsFile={}", lab.known);
    let args = [
        "each",
        "--json",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        known.as_str(),
        "--ca-file",
        lab.ca.as_str(),
        destination.as_str(),
        "--",
        "greet",
    ];
    // `each` has no `--derp-server`: the variable names the servers.
    let mut cmd = super::command(&lab.client_home, &args);
    let (rc, out, err) = run(cmd.env("PODSSH_DERP_SERVER", &servers));
    assert_eq!(rc, 0, "stdout {out}, stderr {err}");
    let record: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}\n{err}"));
    let host = &record["hosts"][0];
    assert_eq!((&host["exit"], &host["stdout"]), (&serde_json::json!(0), &serde_json::json!(GREETING)), "{out}");
    drop(lab.runtime);
}
