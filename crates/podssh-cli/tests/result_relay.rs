//! `--result-file`'s `relay` for the verbs that carry a session through the
//! resumable layer (T-822): `podssh sftp`, `cp` and `scp` through podssh's
//! own relay role name the relay host that carried them, one table. The layer's road runs on a thread
//! of its own; the planted defect, its relay host written to the process's
//! record in place of the session's, gives `relay` null and fails it. It
//! says that it did not run where this host has no openssl for the role's
//! certificate, or no `sftp-server`.

mod ssh_harness;
mod throughput_harness;

use std::process::Stdio;

use throughput_harness::{Cell, Session};

#[test]
fn each_copy_through_the_layer_names_its_relay() {
    if ssh_harness::sftp::server_path().is_none() {
        eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return;
    }
    let s = Session::start("result-relay");
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let ca = cell.args.iter().position(|a| a == "--ca-file").map(|i| cell.args[i + 1].clone()).unwrap();
    let batch = s.home.join("result-relay-batch");
    std::fs::write(&batch, "pwd\n").unwrap();
    std::fs::write(s.home.join("result-relay.txt"), b"carried\n").unwrap();
    // The flags of the cell, with `-p` as the copies' `-P`, and its target
    // last, which each verb takes in its own form.
    let (target, flags) = cell.args[1..].split_last().unwrap();
    let flags: Vec<String> = flags.iter().map(|a| if a == "-p" { "-P".to_string() } else { a.clone() }).collect();
    let from = format!("{target}:{}", s.home.join("result-relay.txt").display());
    let rows: [(&str, Vec<String>); 3] = [
        ("sftp", vec!["-b".into(), batch.display().to_string(), target.clone()]),
        ("cp", vec!["--timeout".into(), "60s".into(), from.clone(), s.home.join("cp-copy.txt").display().to_string()]),
        ("scp", vec!["--timeout".into(), "60s".into(), from, s.home.join("scp-copy.txt").display().to_string()]),
    ];
    for (verb, tail) in rows {
        let file = s.home.join(format!("result-relay-{verb}.json"));
        let mut args = vec![verb.to_string(), "--result-file".into(), file.display().to_string()];
        args.extend(flags.iter().cloned());
        args.extend(tail);
        let out = s
            .stand_in(&args, &ca)
            .env("PODSSH_RELAY_LAYER", "yes")
            .current_dir(&s.home)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{verb}: {err}");
        let text = std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{verb}: no result file ({e}): {err}"));
        let r: serde_json::Value = serde_json::from_str(&text).unwrap();
        let host = r["relay"]["host"].as_str().unwrap_or_else(|| panic!("{verb}: relay is not named: {text}"));
        assert!(host.contains("relay-a.test"), "{verb}: {text}");
    }
}
