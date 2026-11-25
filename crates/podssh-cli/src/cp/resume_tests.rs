//! The tests of the record of a copy that goes on: its side file, its load
//! and its states.

use super::*;

#[test]
fn only_podssh_s_temporary_names_count_as_temporary() {
    assert!(is_temp(&format!("dir/{}", transfer::temp_name("a b.txt"))));
    assert!(is_temp(r"C:\x\.f.podssh-0123456789abcdef.part"));
    for not in ["f.part", ".f.part", ".f.podssh-xyz.part", "dir/.f.podssh-0123456789abcdef", "/etc/passwd"] {
        assert!(!is_temp(not), "{not}");
    }
}

#[test]
fn a_side_file_names_neither_path() {
    let a = side_name("u@h", 22, "/srv/secret.db", "local.db");
    assert!(a.starts_with("podssh-cp-") && a.ends_with(".resume") && !a.contains("secret"), "{a}");
    assert_ne!(a, side_name("u@h", 22, "/srv/secret.db", "other.db"));
    assert_ne!(a, side_name("u@h", 2222, "/srv/secret.db", "local.db"));
}

/// A cache directory of the test's own.
fn scratch() -> PathBuf {
    std::env::temp_dir().join(format!("podssh-resume-{:016x}", rand::random::<u64>()))
}

#[test]
fn a_side_file_continues_the_same_source_only() {
    let dir = scratch();
    let temp = format!("srv/{}", transfer::temp_name("f"));
    let load = |state: &str| Progress::load_in(vec![dir.clone()], "s.resume".into(), state.into());
    let (mut first, stale) = load("local 5 x");
    assert_eq!((first.temp.as_deref(), stale), (None, None));
    first.begin("srv/f", &temp);
    first.advance(SAVE_EVERY + 1);
    // The same source: the copy goes on where the side file says.
    let (again, stale) = load("local 5 x");
    assert_eq!(stale, None);
    assert_eq!(again.temp.as_deref(), Some(temp.as_str()));
    assert_eq!((again.target.as_deref(), again.offset), (Some("srv/f"), SAVE_EVERY + 1));
    // A changed source: the copy starts over, the stale temporary file is
    // given back for removal, and the side file goes.
    let (fresh, stale) = load("local 6 y");
    assert_eq!(stale.as_deref(), Some(temp.as_str()));
    assert_eq!((fresh.temp, fresh.offset), (None, 0));
    let (gone, stale) = load("local 5 x");
    assert_eq!((gone.temp, stale), (None, None), "the stale side file was removed");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_side_file_follows_each_four_mib_and_goes_when_done() {
    let dir = scratch();
    let load = || Progress::load_in(vec![dir.clone()], "t.resume".into(), "state".into()).0;
    let mut p = load();
    p.begin("f", &transfer::temp_name("f"));
    p.advance(SAVE_EVERY - 1);
    assert_eq!(load().offset, 0, "not written yet");
    p.advance(SAVE_EVERY);
    assert_eq!(load().offset, SAVE_EVERY);
    p.clear();
    assert_eq!(load().temp, None, "a copy that is done leaves no side file");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The chunks of a copy in chunks (T-141): done out of order, the offset
/// moves over each one next to it, and the side file keeps the others.
#[test]
fn the_map_of_chunks_moves_the_offset_and_survives_a_new_run() {
    let dir = scratch();
    let load = || Progress::load_in(vec![dir.clone()], "c.resume".into(), "state".into()).0;
    let mut p = load();
    p.begin("f", &transfer::temp_name("f"));
    p.begin_chunks(8);
    // A file of 30 bytes: chunks at 0, 8, 16 and 24 (the last of 6).
    p.finish_chunk(16, 8, 30);
    p.finish_chunk(8, 8, 30);
    assert_eq!((p.offset, p.has_chunk(8), p.has_chunk(16), p.has_chunk(0)), (0, true, true, false));
    let again = load();
    assert_eq!((again.chunk, again.chunks.iter().copied().collect::<Vec<_>>()), (8, vec![8, 16]));
    p.finish_chunk(0, 8, 30);
    assert_eq!((p.offset, p.chunks.len()), (24, 0), "0, 8 and 16 are contiguous");
    p.finish_chunk(24, 8, 30);
    assert_eq!(p.offset, 30, "the last chunk ends at the size");
    // A run in one stream after it keeps the offset, and no chunk.
    let mut q = load();
    q.begin_sequential();
    assert_eq!((q.offset, q.chunk, q.chunks.len()), (30, 0, 0));
    // A run in chunks of another size counts only what is below the offset.
    let mut r = load();
    r.offset = 21;
    r.begin_chunks(10);
    assert_eq!((r.offset, r.has_chunk(10), r.has_chunk(20)), (20, true, false));
    p.clear();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_side_file_that_names_another_file_is_not_trusted() {
    let dir = scratch();
    let load = || Progress::load_in(vec![dir.clone()], "u.resume".into(), "state".into());
    load().0.begin("f", "/etc/passwd");
    let (fresh, stale) = load();
    assert_eq!((fresh.temp, stale), (None, None), "never a file that podssh did not make");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_prefix_of_a_file_goes_into_the_digest() {
    let data = b"0123456789";
    let mut hasher = Sha256::new();
    hash_prefix(&mut &data[..], &mut hasher, 4).expect("four bytes");
    hasher.update(&data[4..]);
    assert_eq!(<[u8; 32]>::from(hasher.finalize()), <[u8; 32]>::from(Sha256::digest(data)));
    let mut short = Sha256::new();
    assert!(hash_prefix(&mut &data[..], &mut short, 11).is_err(), "a file shorter than its offset");
}

/// A copy to a destination that another run copies to now keeps no side
/// file and goes on in none (T-828): the other holder's lock stands for a
/// second process, whose `.part` is never shared.
#[test]
fn a_copy_that_another_runs_now_keeps_no_side_file() {
    let dir = scratch();
    let load = || Progress::load_in(vec![dir.clone()], "v.resume".into(), "state".into()).0;
    let mut first = load();
    first.begin("f", &transfer::temp_name("f"));
    first.advance(SAVE_EVERY);
    drop(first);
    let other = FileLock::try_lock(&dir.join("v.resume.lock"), Mode::Exclusive).unwrap().expect("free");
    let busy = load();
    assert_eq!((busy.temp, busy.offset), (None, 0), "the other run's file is not taken");
    assert!(busy.dirs.is_empty(), "this run keeps no side file");
    drop(other);
    // flock(2) belongs to the open file description: a sibling test that
    // forks while `other` is open gives its child a copy of the descriptor,
    // and the lock stands until that child execs (T-849, twice on macOS).
    // So the lock may be refused for a moment after the drop; load again
    // until it is taken, within a bound, before judging the side file.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut again = load();
    while again.dirs.is_empty() && std::time::Instant::now() < deadline {
        drop(again);
        std::thread::sleep(std::time::Duration::from_millis(20));
        again = load();
    }
    // Which branch, at a failure: the lock still refused after the bound
    // (no side file kept), or the side file not read.
    let side = std::fs::read_to_string(dir.join("v.resume")).map_err(|e| e.to_string());
    let why = format!("lock taken: {}, side file: {side:?}", !again.dirs.is_empty());
    assert_eq!(again.offset, SAVE_EVERY, "the side file is the next run's once the lock is free; {why}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The state of a source is in a form of its own (T-929), and a side file
/// that an earlier podssh wrote in Rust's `Debug` form is still read.
#[test]
fn a_state_has_a_stable_form_and_the_old_one_is_still_read() {
    // A whole 100 ns: Windows keeps a time in units of 100 ns.
    let at = UNIX_EPOCH + std::time::Duration::from_nanos(1_700_000_000_123_456_700);
    let local = Before::Local { len: 3, modified: Some(at), id: Some((65024, 819359)) };
    let cases = [
        (local, "local 3 1700000000123456700 65024:819359"),
        (Before::Local { len: 0, modified: None, id: None }, "local 0 - -"),
        (Before::Sftp { size: Some(7), mtime: Some(9) }, "sftp 7 9"),
        (Before::Sftp { size: None, mtime: Some(9) }, "sftp - 9"),
        (Before::Exec("123 -rw-r--r-- 1 0 0 3 Jan 1 f".into()), "exec 123 -rw-r--r-- 1 0 0 3 Jan 1 f"),
    ];
    for (before, want) in &cases {
        assert_eq!(before.key(), *want);
        // The new form reads as itself.
        assert_eq!(upgraded(want), *want);
    }
    for (old, new) in [
        ("local 3 Some(1700000000123456789) Some((65024, 819359))", "local 3 1700000000123456789 65024:819359"),
        ("local 0 None None", "local 0 - -"),
        ("sftp Some(7) Some(9)", "sftp 7 9"),
        ("sftp None Some(9)", "sftp - 9"),
        ("exec 1 Some(x) None", "exec 1 Some(x) None"),
    ] {
        assert_eq!(upgraded(old), new, "{old}");
    }
    // A side file in the old form goes on where it was.
    let dir = scratch();
    std::fs::create_dir_all(&dir).unwrap();
    let temp = format!("srv/{}", transfer::temp_name("f"));
    let body = serde_json::json!({"state": "sftp Some(7) Some(9)", "target": "f", "temp": temp, "offset": 5});
    // As podssh writes a side file: private, so that it is read back.
    podssh_relay::cache::store_file_in_first(std::slice::from_ref(&dir), "o.resume", body.to_string().as_bytes())
        .unwrap();
    let (kept, stale) = Progress::load_in(vec![dir.clone()], "o.resume".into(), "sftp 7 9".into());
    assert_eq!((kept.offset, kept.temp.as_deref(), stale), (5, Some(temp.as_str()), None));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A copy that failed before its first byte leaves no record and no lock
/// (T-930); one with bytes in its file keeps both.
#[test]
fn a_copy_that_never_started_keeps_no_record() {
    let dir = scratch();
    std::fs::create_dir_all(&dir).unwrap();
    let load = |side: &str| Progress::load_in(vec![dir.clone()], side.into(), "state".into()).0;
    let mut none = load("n.resume");
    let temp = transfer::temp_name("f");
    none.begin("f", &temp);
    assert!(dir.join("n.resume").exists() && dir.join("n.resume.lock").exists());
    assert_eq!(none.drop_unstarted().as_deref(), Some(temp.as_str()), "its temporary file, to remove");
    assert!(!dir.join("n.resume").exists(), "no record");
    // Windows removes no file that its lock holds open.
    #[cfg(unix)]
    assert!(!dir.join("n.resume.lock").exists(), "no lock file left in the cache");
    assert!(each_current().iter().all(|(t, _)| t != &temp), "an interruption names no partial copy");
    let mut some = load("s.resume");
    some.begin("f", &transfer::temp_name("f"));
    some.advance(SAVE_EVERY);
    assert_eq!(some.drop_unstarted(), None);
    assert!(dir.join("s.resume").exists(), "a record with bytes stays");
    let _ = std::fs::remove_dir_all(&dir);
}
