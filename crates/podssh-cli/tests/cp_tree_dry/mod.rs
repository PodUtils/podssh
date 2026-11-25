//! The black-box pass of 2026-11-25 on the file commands, a module of
//! `cp_tree`, whose server (OpenSSH's `sftp-server` behind the test's SSH
//! server) and helpers it takes. `-r --dry-run` with a source that is one
//! file changes nothing, for `cp` and `mv`, and plans it (T-924); `mv -r`
//! names each path that it removed in its record (T-925); `scp -r` copies a
//! directory reached twice, and refuses a link back to an ancestor (T-926);
//! several sources into a destination that cannot take them, and a tree
//! onto a file, are said once (T-935); a plan names only what would change,
//! with one meaning for each key (T-934).

use std::path::Path;

use super::{cp, podssh_in, scratch, server};
// The macro `need_server!` names it.
use crate::ssh_harness;

/// The objects of `--jsonl` whose event is `event`.
fn objects(out: &str, event: &str) -> Vec<serde_json::Value> {
    out.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["event"] == event)
        .collect()
}

/// Each name in `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut all: Vec<String> =
        std::fs::read_dir(dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    all.sort();
    all
}

#[test]
fn a_dry_run_of_one_file_changes_nothing_and_plans_it() {
    need_server!();
    let home = scratch("dryfile");
    let (_runtime, port) = server(&home);
    std::fs::create_dir_all(home.join("src")).unwrap();
    std::fs::create_dir_all(home.join("dd")).unwrap();
    std::fs::write(home.join("src/f"), b"new").unwrap();
    std::fs::write(home.join("dd/f"), b"old").unwrap();
    // Up, onto a file that is there, with -b: the backup and the copy are
    // planned, and nothing is written.
    let (rc, out, err) = cp(&home, port, &["-r", "--dry-run", "-b", "src/f", "u@127.0.0.1:dd/f"]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.lines().any(|l| l == "backup dd/f -> dd/f~"), "{out}");
    assert!(out.lines().any(|l| l.starts_with("copy ") && l.ends_with(" -> dd/f")), "{out}");
    assert_eq!(std::fs::read(home.join("dd/f")).unwrap(), b"old", "the destination stays");
    assert_eq!(names(&home.join("dd")), ["f"], "no backup and no temporary file");
    // --jsonl: plan objects, and no done object.
    let (rc, out, err) = cp(&home, port, &["-r", "--dry-run", "--jsonl", "src/f", "u@127.0.0.1:dd/new"]);
    assert_eq!(rc, 0, "{err}");
    assert!(objects(&out, "done").is_empty(), "{out}");
    let plan = objects(&out, "plan");
    assert_eq!(plan.len(), 1, "{out}");
    assert_eq!((plan[0]["action"].as_str(), plan[0]["destination"].as_str()), (Some("copy"), Some("dd/new")));
    assert!(!home.join("dd/new").exists(), "no copy");
    // Down: nothing written here.
    std::fs::create_dir_all(home.join("here")).unwrap();
    let (rc, out, err) = cp(&home, port, &["-r", "--dry-run", "u@127.0.0.1:dd/f", "here"]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.lines().any(|l| l.starts_with("copy dd/f -> ")), "{out}");
    assert!(names(&home.join("here")).is_empty(), "nothing came down");
    // mv -r --dry-run moves nothing and removes nothing.
    let (rc, out, err) = podssh_in(&home, port, &["mv", "-r", "--dry-run", "src/f", "u@127.0.0.1:dd/moved"]);
    assert_eq!(rc, 0, "{err}");
    assert!(out.contains("copy "), "{out}");
    assert!(home.join("src/f").exists() && !home.join("dd/moved").exists(), "{err}");
    // A missing source fails as the copy would, with nothing written.
    let (rc, _, err) = cp(&home, port, &["-r", "--dry-run", "src/nope", "u@127.0.0.1:dd/x"]);
    assert_eq!(rc, 66, "{err}");
    assert!(!err.contains("os error"), "the system's words alone: {err}");
}

#[test]
fn a_plan_names_only_what_would_change_with_a_key_for_each_meaning() {
    need_server!();
    let home = scratch("dryplan");
    let (_runtime, port) = server(&home);
    std::fs::create_dir_all(home.join("tree/sub")).unwrap();
    std::fs::write(home.join("tree/sub/f"), b"f").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("sub/f", home.join("tree/l")).unwrap();
    std::fs::create_dir_all(home.join("mir")).unwrap();
    let (rc, _, err) = cp(&home, port, &["-r", "tree", "u@127.0.0.1:mir"]);
    assert_eq!(rc, 0, "{err}");
    // All is there as the copy would make it: under -n, no mkdir, no link,
    // and the file a skip with its reason apart.
    let (rc, out, err) = cp(&home, port, &["-r", "--dry-run", "-n", "--jsonl", "tree", "u@127.0.0.1:mir"]);
    assert_eq!(rc, 0, "{err}");
    let plan = objects(&out, "plan");
    let actions: Vec<&str> = plan.iter().filter_map(|p| p["action"].as_str()).collect();
    assert!(!actions.contains(&"mkdir") && !actions.contains(&"link"), "{out}");
    for skip in plan.iter().filter(|p| p["action"] == "skip") {
        assert_eq!(
            (skip["reason"].as_str(), &skip["destination"]),
            (Some("exists"), &serde_json::Value::Null),
            "{out}"
        );
    }
    // A new target: each link names its target apart from its destination.
    let (rc, out, err) = cp(&home, port, &["-r", "--dry-run", "--jsonl", "tree", "u@127.0.0.1:fresh"]);
    assert_eq!(rc, 0, "{err}");
    #[cfg(unix)]
    {
        let links: Vec<_> = objects(&out, "plan").into_iter().filter(|p| p["action"] == "link").collect();
        assert_eq!(links.len(), 1, "{out}");
        assert_eq!((links[0]["destination"].as_str(), links[0]["target"].as_str()), (Some("fresh/l"), Some("sub/f")));
    }
    let _ = (out, err);
}

#[test]
fn several_sources_and_a_tree_onto_a_file_are_said_once() {
    need_server!();
    let home = scratch("once");
    let (_runtime, port) = server(&home);
    std::fs::create_dir_all(home.join("gl")).unwrap();
    for name in ["a1.log", "a2.log", "gl/a1.log"] {
        std::fs::write(home.join(name), name.as_bytes()).unwrap();
    }
    let (rc, _, err) = cp(&home, port, &["a1.log", "a2.log", "u@127.0.0.1:gl/a1.log"]);
    assert_eq!(rc, 73, "{err}");
    assert_eq!(err.matches("gl/a1.log: not a directory, and there are several sources").count(), 1, "{err}");
    let (rc, _, err) = cp(&home, port, &["a1.log", "a2.log", "u@127.0.0.1:nodir/"]);
    assert_eq!(rc, 73, "{err}");
    assert_eq!(err.matches("no such directory").count(), 1, "{err}");
    // A tree onto a file: one line, and nothing else tried.
    std::fs::create_dir_all(home.join("tree/a/b")).unwrap();
    std::fs::write(home.join("tree/a/b/f"), b"f").unwrap();
    std::fs::write(home.join("b.txt"), b"file").unwrap();
    let (rc, _, err) = cp(&home, port, &["-r", "tree", "u@127.0.0.1:b.txt"]);
    assert_eq!(rc, 73, "{err}");
    assert_eq!(err.lines().filter(|l| l.contains("b.txt")).count(), 1, "{err}");
    assert_eq!(std::fs::read(home.join("b.txt")).unwrap(), b"file");
}

#[cfg(unix)]
#[test]
fn scp_r_copies_a_directory_reached_twice_and_refuses_a_loop() {
    need_server!();
    let home = scratch("twice");
    let (_runtime, port) = server(&home);
    std::fs::create_dir_all(home.join("dm/real")).unwrap();
    std::fs::write(home.join("dm/real/f"), b"f").unwrap();
    std::os::unix::fs::symlink("real", home.join("dm/alias")).unwrap();
    let (rc, _, err) = podssh_in(&home, port, &["scp", "-r", "dm", "u@127.0.0.1:out"]);
    assert_eq!(rc, 0, "{err}");
    assert_eq!(std::fs::read(home.join("out/real/f")).unwrap(), b"f");
    assert_eq!(std::fs::read(home.join("out/alias/f")).unwrap(), b"f", "the directory reached twice goes twice");
    std::fs::create_dir_all(home.join("lp/a")).unwrap();
    std::os::unix::fs::symlink("..", home.join("lp/a/up")).unwrap();
    let (rc, _, err) = podssh_in(&home, port, &["scp", "-r", "lp", "u@127.0.0.1:lpo"]);
    assert_eq!(rc, 66, "{err}");
    assert!(err.contains("a loop"), "{err}");
}

#[test]
fn mv_r_names_each_path_that_it_removed() {
    need_server!();
    let home = scratch("mvrec");
    let (_runtime, port) = server(&home);
    std::fs::create_dir_all(home.join("t/sub")).unwrap();
    std::fs::write(home.join("t/sub/f"), b"f").unwrap();
    std::fs::write(home.join("t/g"), b"g").unwrap();
    let record = home.join("r.json").display().to_string();
    let (rc, _, err) = podssh_in(&home, port, &["mv", "-r", "--result-file", &record, "t", "u@127.0.0.1:moved"]);
    assert_eq!(rc, 0, "{err}");
    assert!(!home.join("t").exists(), "{err}");
    let object: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
    let removed: Vec<&str> = object["removed"].as_array().unwrap().iter().filter_map(|v| v.as_str()).collect();
    // A local name is in this system's form (`t\sub` on Windows).
    let shown = |rel: &str| rel.split('/').fold(Path::new("t").to_path_buf(), |p, c| p.join(c)).display().to_string();
    for rel in ["g", "sub/f", "sub"] {
        assert!(removed.contains(&shown(rel).as_str()), "{} in {removed:?}", shown(rel));
    }
    assert!(removed.contains(&"t"), "the directory itself: {removed:?}");
}
