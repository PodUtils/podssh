//! `podssh node --print-unit` and `podssh serve --print-unit`, and the
//! refusals of `--install --system --run-as` and `--uninstall --system`
//! (T-709), as a process, offline: a printed unit is on stdout and no file
//! is written; a flag that goes with no other is refused with 64 before
//! anything is probed; a run with no root is refused with 77, and a user
//! with no passwd entry with 69. No test needs root, and none writes a unit.
//! A unit of this user's node is printed as `--install` would write it: a
//! TARGET that the node refuses is 64, and a pair not stored 78 (T-1024).
#![cfg(unix)]

mod pair_harness;

use std::path::Path;

use pair_harness::{cache_dir, podssh, scratch, store};

/// Each file under `dir`, for the check that nothing was written.
fn files(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(at) = todo.pop() {
        for entry in std::fs::read_dir(&at).into_iter().flatten().flatten() {
            let path = entry.path();
            match path.is_dir() {
                true => todo.push(path),
                false => found.push(path.display().to_string()),
            }
        }
    }
    found.sort();
    found
}

fn root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn a_printed_unit_of_a_node_is_on_stdout_and_nothing_is_written() {
    let home = scratch("t709-print");
    store(&home, "lab", 0);
    let before = files(&home);
    let (rc, out, err) = podssh(&home, &["node", "lab", "127.0.0.1:22", "--print-unit"], &[]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.starts_with("# Written by podssh node.\n"), "{out}");
    let env = cache_dir(&home).join("node-lab.env");
    assert!(out.contains(&format!("node lab 127.0.0.1:22 --env-file {}", env.display())), "{out}");
    assert!(out.contains("WantedBy=default.target"), "{out}");
    assert!(!env.exists(), "the file of the variables was written");
    assert_eq!(files(&home), before, "a printed unit writes nothing");
}

/// A unit is printed only where `--install` would write it: each case is
/// refused with its code, its line names the cause, and stdout is empty.
#[test]
fn a_printed_unit_of_a_node_is_refused_where_its_install_would_be() {
    let home = scratch("t1024-print");
    store(&home, "lab", 0);
    for (args, code, says) in [
        (vec!["node", "nosuch", "127.0.0.1:22", "--print-unit"], 78, "no pair is stored under \"nosuch\""),
        (vec!["node", "lab", "--print-unit"], 64, "missing TARGET"),
        (vec!["node", "lab", "127.0.0.1:0x", "--print-unit"], 64, "TARGET 127.0.0.1:0x"),
        (vec!["node", "nosuch", "--print-unit"], 64, "missing TARGET"),
    ] {
        let (rc, out, err) = podssh(&home, &args, &[]);
        assert_eq!(rc, code, "{args:?}: {err}");
        assert!(err.contains(says), "{args:?}: {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
    }
}

#[test]
fn a_printed_unit_of_serve_names_its_flags_and_writes_nothing() {
    let home = scratch("t709-serve");
    let before = files(&home);
    let args = ["serve", "lab", "--no-forwarding", "--authorized-keys", "keys", "--print-unit"];
    let (rc, out, err) = podssh(&home, &args, &[]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.starts_with("# Written by podssh serve.\n"), "{out}");
    assert!(out.contains(" serve lab --authorized-keys /") && out.contains(" --no-forwarding"), "{out}");
    assert_eq!(files(&home), before, "a printed unit writes nothing");
    let (rc, _, err) = podssh(&home, &["serve", "--stdio", "--print-unit"], &[]);
    assert_eq!(rc, 64, "{err}");
}

#[test]
fn the_flags_of_a_system_unit_that_go_with_no_other_are_refused_with_64() {
    let home = scratch("t709-flags");
    for (args, says) in [
        (vec!["--print-unit", "--install"], "--print-unit"),
        (vec!["--system"], "--system goes with"),
        (vec!["--install", "--run-as", "nobody"], "--run-as USER goes with --system"),
        (vec!["--install", "--system"], "--system needs --run-as"),
        (vec!["--print-unit", "--system"], "--system needs --run-as"),
    ] {
        let mut all = vec!["node", "lab", "127.0.0.1:22"];
        all.extend_from_slice(&args);
        let (rc, out, err) = podssh(&home, &all, &[]);
        assert_eq!(rc, 64, "{all:?}: {err}");
        assert!(err.contains(says), "{all:?}: {err}");
        assert!(out.is_empty(), "{all:?}: {out}");
    }
}

#[test]
fn a_system_install_with_no_root_is_refused_with_77_and_writes_nothing() {
    if root() {
        eprintln!("did not run: this test runs as root, whose install would be real");
        return;
    }
    let home = scratch("t709-root");
    let args = ["node", "lab", "127.0.0.1:22", "--install", "--system", "--run-as", "nobody"];
    let (rc, _, err) = podssh(&home, &args, &[]);
    assert_eq!(rc, 77, "{err}");
    assert!(err.contains("root"), "{err}");
    let (rc, _, err) = podssh(&home, &["node", "lab", "--uninstall", "--system"], &[]);
    assert_eq!(rc, 77, "{err}");
}

#[test]
fn a_system_unit_of_a_user_with_no_passwd_entry_is_refused_with_69() {
    let home = scratch("t709-user");
    let args = ["node", "lab", "127.0.0.1:22", "--print-unit", "--system", "--run-as", "no-such-user-t709"];
    let (rc, out, err) = podssh(&home, &args, &[]);
    assert_eq!(rc, 69, "{err}");
    assert!(err.contains("/etc/passwd") && err.contains("no-such-user-t709"), "{err}");
    assert!(out.is_empty(), "{out}");
}
