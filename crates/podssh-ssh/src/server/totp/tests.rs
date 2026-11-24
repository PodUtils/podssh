//! The secret's file and its state (T-115): a new secret is private and
//! never written over; a secret that others may read, or that is not
//! base32, refuses the start; a check keeps its step across two values of
//! one file, as two serve processes; a state that does not read refuses.
//! Unix's, as serve is: the modes are Unix's.

#![cfg(unix)]

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{code, state_path, Checked, Totp};

/// A scratch directory, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
        let dir = std::env::temp_dir().join(format!("podssh-totp-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_new_secret_is_private_and_never_written_over() {
    let dir = Scratch::new("new");
    let path = dir.0.join("totp");
    Totp::create_new(&path).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(code::decode_base32(&text).unwrap().len(), super::NEW_SECRET);
    let again = Totp::create_new(&path).expect_err("exists");
    assert!(again.contains("exists") && !again.contains(text.trim()), "{again}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text, "not written over");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        Totp::open(&path).unwrap();
        assert_eq!(std::fs::metadata(state_path(&path)).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let refused = Totp::open(&path).expect_err("others may read it");
        assert!(!refused.contains(text.trim()), "the secret is never said: {refused}");
    }
}

/// Each file that cannot be a secret refuses, with its reason and never
/// its text.
#[test]
fn a_file_that_is_no_secret_refuses() {
    let dir = Scratch::new("bad");
    for (body, words) in [("not base32 at all!\n", "not base32"), ("GEZDGNBV\n", "fewer than 10")] {
        let path = dir.0.join("totp");
        let _ = std::fs::remove_file(&path);
        let mut file = pod_core::files::create_new_private(&path).unwrap();
        std::io::Write::write_all(&mut file, body.as_bytes()).unwrap();
        drop(file);
        let said = Totp::open(&path).expect_err(body);
        assert!(said.contains(words) && !said.contains(body.trim()), "{said}");
    }
    let missing = Totp::open(&dir.0.join("none")).expect_err("missing");
    assert!(missing.contains("no such file"), "{missing}");
}

/// Two values of one file, as two serve processes: a code that one took
/// is a replay for the other; a state that does not read refuses.
#[test]
fn a_code_taken_by_one_process_is_a_replay_for_another() {
    let dir = Scratch::new("two");
    let path = dir.0.join("totp");
    Totp::create_new(&path).unwrap();
    let secret = code::decode_base32(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let (one, two) = (Totp::open(&path).unwrap(), Totp::open(&path).unwrap());
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_015);
    let answer = code::code_of(&secret, code::step_of(1_800_000_015)).unwrap();
    assert_eq!(one.check("k", answer.as_bytes(), now), Ok(Checked::Accepted));
    assert_eq!(two.check("k", answer.as_bytes(), now), Ok(Checked::Replayed));
    std::fs::write(state_path(&path), "garbage\n").unwrap();
    let said = one.check("k", b"000000", now).expect_err("a broken state");
    assert!(said.contains("remove it"), "{said}");
    let before = UNIX_EPOCH.checked_sub(Duration::from_secs(1));
    if let Some(before) = before {
        assert!(one.check("k", b"000000", before).is_err());
    }
}
