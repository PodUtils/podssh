//! The cache's places, in temporary directories: where it falls back to,
//! what it refuses, and the access list of a file on Windows. The tests of
//! the entries of a relay token are pod-relay's (PodUtils/podcrates, T-684).

#[cfg(unix)]
mod cache_owner;
mod cleanup;

use std::path::PathBuf;

use podssh_relay::cache::{candidate_dirs_from, chosen_from, chosen_note, store_noting, Chosen};

const NOW: i64 = 1_900_000_000_000;
const TOKEN: &str = "ephm1.1900000000000.forward.TESTONLYNOTACREDENTIAL";

/// A fresh, empty scratch directory unique to one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-token-cache-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// An environment for [`candidate_dirs_from`]: each pair is a variable.
fn env<'a>(pairs: &'a [(&'a str, PathBuf)]) -> impl Fn(&str) -> Option<std::ffi::OsString> + 'a {
    move |name| pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| v.clone().into_os_string())
}

/// The order of T-243: the directory of PODSSH_CACHE_DIR, the user's cache
/// directory, the runtime directory, the temporary directory with the
/// user's tag, the working directory.
#[test]
fn the_order_follows_the_environment() {
    let root = scratch("order");
    let user_cache = if cfg!(windows) { "LOCALAPPDATA" } else { "XDG_CACHE_HOME" };
    let pairs = [
        ("PODSSH_CACHE_DIR", root.join("chosen")),
        (user_cache, root.join("cache")),
        ("XDG_RUNTIME_DIR", root.join("run")),
        ("TMPDIR", root.join("tmp")),
    ];
    let dirs = candidate_dirs_from(&env(&pairs), Some(root.join("work")));
    assert_eq!(dirs.len(), 5, "{dirs:?}");
    assert_eq!(dirs[0], root.join("chosen"));
    assert_eq!(dirs[1], root.join("cache").join("podssh"));
    assert_eq!(dirs[2], root.join("run").join("podssh"));
    assert!(dirs[3].starts_with(root.join("tmp")), "{dirs:?}");
    assert!(dirs[3].file_name().unwrap().to_string_lossy().starts_with("podssh-"), "{dirs:?}");
    assert_eq!(dirs[4], root.join("work").join(".podssh"));
    // With no variable, the user's places are missing, never guessed.
    let bare = candidate_dirs_from(&env(&[]), None);
    assert!(!bare.iter().any(|d| d.ends_with("podssh") && !d.to_string_lossy().contains("podssh-")), "{bare:?}");
}

/// PODSSH_CACHE_DIR=none gives no directory, and a store says why; a
/// relative path is not used.
#[test]
fn none_keeps_no_file_and_a_relative_path_is_not_used() {
    let root = scratch("none");
    for spelling in ["none", "NONE"] {
        let pairs = [("PODSSH_CACHE_DIR", PathBuf::from(spelling)), ("TMPDIR", root.clone())];
        assert_eq!(chosen_from(&env(&pairs)), Chosen::Nothing);
        assert!(candidate_dirs_from(&env(&pairs), Some(root.clone())).is_empty());
    }
    let err = store_noting(&[], "relay.example", b"x").unwrap_err();
    assert!(err.contains("PODSSH_CACHE_DIR is none"), "{err}");
    let pairs = [("PODSSH_CACHE_DIR", PathBuf::from("relative/dir")), ("TMPDIR", root.clone())];
    assert_eq!(chosen_from(&env(&pairs)), Chosen::Relative("relative/dir".into()));
    let dirs = candidate_dirs_from(&env(&pairs), None);
    assert!(!dirs.iter().any(|d| d.ends_with("dir")), "{dirs:?}");
    assert_eq!(chosen_from(&env(&[("PODSSH_CACHE_DIR", PathBuf::new())])), Chosen::Unset);
}

/// A named directory that refuses a write is skipped, the next one takes
/// the file, and the note names the refusal.
#[test]
fn a_refused_cache_dir_is_named_and_the_next_one_takes_the_file() {
    let root = scratch("refused");
    let blocked = root.join("blocked");
    std::fs::write(&blocked, b"a file where the directory should be").unwrap();
    let chosen = blocked.join("cache");
    let next = root.join("next");
    let stored = store_noting(&[chosen.clone(), next.clone()], "relay.example", b"body").unwrap();
    assert!(stored.path.starts_with(&next), "{stored:?}");
    let note = chosen_note(&Chosen::Dir(chosen.clone()), &stored).expect("a note");
    assert!(note.contains("PODSSH_CACHE_DIR could not be used") && note.contains("blocked"), "{note}");
    // A choice that was followed says nothing.
    let followed = store_noting(std::slice::from_ref(&next), "relay.example", b"body").unwrap();
    assert_eq!(chosen_note(&Chosen::Dir(next), &followed), None);
}

/// With no variable that names the temporary directory, the fixed places
/// of Unix come last, after each place that the environment gives.
#[cfg(unix)]
#[test]
fn with_no_temporary_variable_the_fixed_places_come_last() {
    let root = scratch("fixed");
    let pairs = [("XDG_CACHE_HOME", root.join("cache"))];
    let dirs = candidate_dirs_from(&env(&pairs), Some(root.join("work")));
    let n = dirs.len();
    assert!(dirs[n - 3].starts_with("/tmp") && dirs[n - 2].starts_with("/dev/shm"), "{dirs:?}");
    assert_eq!(dirs[0], root.join("cache").join("podssh"));
}

/// No absolute path stays in the code of the cache's module but the temporary
/// directory's two fixed places, in their one list (T-243, and the
/// operator's ruling of 2026-10-08), and the file of the user database, whose
/// home comes in place of another user's (T-593, as T-500 reads it).
#[test]
fn the_scan_finds_no_other_absolute_path_in_the_cache() {
    let code = [
        include_str!("../src/cache.rs"),
        include_str!("../src/cache/dirs.rs"),
        include_str!("../src/cache/own.rs"),
        include_str!("../src/cache/owner.rs"),
    ]
    .concat();
    let mut found = Vec::new();
    for (i, _) in code.match_indices('"') {
        let rest = &code[i + 1..];
        let Some(end) = rest.find('"') else { continue };
        let word = &rest[..end];
        let windows = word.len() > 2 && word.as_bytes()[1] == b':' && word.as_bytes()[0].is_ascii_alphabetic();
        if word.starts_with('/') && word.len() > 1 || windows {
            found.push(word.to_string());
        }
    }
    found.sort();
    found.dedup();
    assert_eq!(found, ["/dev/shm", "/etc/passwd", "/tmp"], "{found:?}");
    let fixed = code.lines().filter(|l| l.contains("\"/tmp\"") || l.contains("\"/dev/shm\"")).count();
    assert_eq!(fixed, 1, "the fixed places are in one list");
}

/// `icacls FILE ARGS`, as a user would open a file to others.
#[cfg(windows)]
fn icacls(file: &std::path::Path, args: &[&str]) {
    let out = std::process::Command::new("icacls").arg(file).args(args).output().expect("icacls runs");
    assert!(out.status.success(), "icacls {args:?}: {}", String::from_utf8_lossy(&out.stdout));
}

/// On Windows the owner and the access list say whether a file is closed,
/// as OpenSSH for Windows reads them (T-274). podssh's own token file is read
/// back, and ignored once the group Users (S-1-5-32-545) may read it. A list
/// that the group may read is still read as a file that others may read,
/// and refused as a secret; one that it may write, append to, or whose access
/// list it may change is refused.
#[cfg(windows)]
#[test]
fn on_windows_a_file_that_others_may_open_is_not_trusted() {
    use podssh_relay::cache::{load_from, read_own, store_in_first, Others, MIN_REMAINING_MS};
    let dir = scratch("win-acl");
    let path =
        store_in_first(std::slice::from_ref(&dir), "relay.example", TOKEN, NOW + MIN_REMAINING_MS * 2, "relay.example")
            .unwrap();
    assert!(load_from(std::slice::from_ref(&dir), "relay.example", NOW).is_some(), "podssh's own file is read");
    icacls(&path, &["/grant", "*S-1-5-32-545:(R)"]);
    assert!(load_from(std::slice::from_ref(&dir), "relay.example", NOW).is_none(), "a token that others may read");

    let list = dir.join("list");
    std::fs::write(&list, "a list\n").unwrap();
    assert_eq!(read_own(&list, Others::Read).unwrap().as_deref(), Some("a list\n"));
    icacls(&list, &["/grant", "*S-1-5-32-545:(R)"]);
    assert_eq!(read_own(&list, Others::Read).unwrap().as_deref(), Some("a list\n"), "others may read a list");
    let why = read_own(&list, Others::NoAccess).unwrap_err();
    assert!(why.contains("others can read it") && why.contains("S-1-5-32-545"), "{why}");
    for right in ["W", "AD", "WDAC"] {
        let file = dir.join(format!("open-{right}"));
        std::fs::write(&file, "x").unwrap();
        icacls(&file, &["/grant", &format!("*S-1-5-32-545:({right})")]);
        let why = read_own(&file, Others::Read).unwrap_err();
        assert!(why.contains("others can change it") && why.contains("the group Users"), "{right}: {why}");
    }
}

/// A directory that others may open is made private: it gets an access list
/// of its own, and the file in it, which others could change, is closed.
#[cfg(windows)]
#[test]
fn on_windows_a_directory_open_to_others_is_made_private() {
    use podssh_relay::cache::{read_own, Others};
    let dir = scratch("win-dir").join("open");
    std::fs::create_dir_all(&dir).unwrap();
    icacls(&dir, &["/grant", "*S-1-5-32-545:(OI)(CI)(M)"]);
    let file = dir.join("list");
    std::fs::write(&file, "x").unwrap();
    assert!(read_own(&file, Others::Read).unwrap_err().contains("others can change it"));
    podssh_relay::cache::private_dir(&dir).unwrap();
    assert_eq!(read_own(&file, Others::NoAccess).unwrap().as_deref(), Some("x"), "closed now");
}
