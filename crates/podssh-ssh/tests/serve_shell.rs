//! The shell of `podssh serve` (T-222, GitHub #32), found with no passwd
//! entry and no `/etc/shells`: given a directory `sh`, a data file `dash`
//! of mode 0644, a data file of mode 0755 (whose start or run fails), a link
//! to a missing file and a good shell, each failure is named with its
//! reason and the good shell wins. A named shell is strict. A copy of
//! `/bin/sh` on a noexec mount is refused as one, where this host has one.

#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use podssh_ssh::server::shell::{self, Candidate};

/// A scratch directory, removed at the end of the test.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(tag: &str, under: &Path) -> Option<Scratch> {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.subsec_nanos();
    let dir = under.join(format!("podssh-serve-shell-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    Some(Scratch(dir))
}

fn env() -> Vec<(OsString, OsString)> {
    vec![("PATH".into(), std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into()))]
}

fn file(path: &Path, body: &[u8], mode: u32) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn candidate(path: &Path) -> Candidate {
    Candidate { label: path.display().to_string(), path: path.to_path_buf() }
}

/// The shell of this host that the test copies or links to.
fn host_shell() -> PathBuf {
    ["/bin/sh", "/usr/bin/sh"].iter().map(PathBuf::from).find(|p| p.is_file()).expect("this host has a /bin/sh")
}

#[test]
fn each_failure_is_named_and_the_good_shell_wins() {
    let dir = scratch("each", &std::env::temp_dir()).expect("a scratch directory");
    let d = &dir.0;
    std::fs::create_dir(d.join("sh")).unwrap();
    file(&d.join("dash"), b"this is no shell\n", 0o644);
    file(&d.join("data"), b"this is no program\n", 0o755);
    std::os::unix::fs::symlink(d.join("missing"), d.join("link")).unwrap();
    std::os::unix::fs::symlink(host_shell(), d.join("good")).unwrap();
    let list: Vec<Candidate> = ["sh", "dash", "data", "link", "good"].iter().map(|n| candidate(&d.join(n))).collect();

    let found = shell::find(&list, &env()).expect("the good shell runs");
    assert_eq!(found.path, d.join("good"));
    let why: Vec<(&str, &str)> = found
        .failed
        .iter()
        .map(|f| (Path::new(&f.label).file_name().unwrap().to_str().unwrap(), f.why.as_str()))
        .collect();
    assert_eq!(why.len(), 4, "{why:?}");
    // Running as root, a file with no x bit still fails the access check.
    assert_eq!(why[0], ("sh", "a directory"), "{why:?}");
    assert_eq!(why[1], ("dash", "not executable (mode 0644)"), "{why:?}");
    // A start that the kernel refuses, or glibc's script fallback that then
    // fails the run: either way the reason names the run, not the file.
    assert_eq!(why[2].0, "data", "{why:?}");
    assert!(
        why[2].1.contains("exec format error") || why[2].1.starts_with("ran -c 'exit 0'"),
        "a data file of mode 0755: {why:?}"
    );
    assert_eq!(why[3], ("link", "a link to a missing file"), "{why:?}");
    let line = found.passed_over().expect("a line names those passed over");
    assert!(line.contains("sh: a directory; ") && line.contains("link: a link to a missing file"), "{line}");
}

#[test]
fn a_named_shell_is_strict_and_said_by_its_flag() {
    let list = shell::candidates(Some(Path::new("/nonexistent")), Some("/bin/sh".as_ref()));
    let none = shell::find(&list, &env()).expect_err("no other shell is tried");
    assert_eq!(none.failed.len(), 1);
    assert_eq!(none.to_string(), "no shell runs here: --shell /nonexistent: no such file");
}

#[test]
fn shell_then_the_list_and_a_relative_shell_is_passed_over() {
    let list = shell::candidates(None, Some("bin/sh".as_ref()));
    let found = shell::find(&list, &env()).expect("a shell of the list runs");
    assert_eq!(found.failed[0].label, "SHELL=bin/sh");
    assert_eq!(found.failed[0].why, "not an absolute path");
    assert!(shell::FALLBACKS.iter().any(|f| found.path == Path::new(f)), "{found:?}");
}

#[test]
fn a_copy_on_a_noexec_mount_is_refused_as_one() {
    let shm = Path::new("/dev/shm");
    let noexec = std::process::Command::new("findmnt")
        .args(["-n", "-o", "OPTIONS", "--target"])
        .arg(shm)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| String::from_utf8_lossy(&o.stdout).split(',').any(|f| f.trim() == "noexec"));
    if !noexec {
        eprintln!("did not run: /dev/shm is not a noexec mount here (or findmnt is missing)");
        return;
    }
    let Some(dir) = scratch("noexec", shm) else {
        eprintln!("did not run: /dev/shm takes no directory here");
        return;
    };
    let copy = dir.0.join("sh");
    std::fs::copy(host_shell(), &copy).unwrap();
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755)).unwrap();
    let none = shell::find(&[candidate(&copy)], &env()).expect_err("refused");
    let why = &none.failed[0].why;
    assert!(why == "not executable (noexec mount)" || why.starts_with("refused at its start"), "{why}");
}
