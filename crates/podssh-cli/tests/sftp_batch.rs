//! The exit codes of `podssh sftp -b` against the test's SSH server, whose
//! subsystem sftp is OpenSSH's `sftp-server` in the far home (`job_harness`):
//! a path that a command names and the server does not have is a missing
//! input, 66, for each command (T-995); a batch file that is not text is bad
//! data, 65 (T-997). With no `sftp-server` on this host, each test says so
//! and passes.
#![cfg(unix)]

mod cleanup;
mod job_harness;
mod ssh_harness;

use job_harness::Far;

/// The far host, or `None` with no `sftp-server` here, said.
fn far(name: &str) -> Option<Far> {
    if ssh_harness::sftp::server_path().is_none() {
        eprintln!("did not run: no sftp-server here; PODSSH_TEST_SFTP_SERVER names one");
        return None;
    }
    Some(Far::new(name, std::env::var("PATH").unwrap_or_default(), None))
}

/// `podssh sftp -P PORT -b BATCH a@127.0.0.1` with `bytes` as the batch.
fn batch(far: &Far, bytes: &[u8]) -> (i32, String, String) {
    let file = far.local.join("batch");
    std::fs::write(&file, bytes).unwrap();
    let (port, file) = (far.port.to_string(), file.display().to_string());
    far.podssh("sftp", &["-P", port.as_str(), "-b", file.as_str(), "a@127.0.0.1"])
}

/// One table: each command of a missing path is 66, with the path named.
#[test]
fn a_missing_path_is_66_for_each_command() {
    let Some(far) = far("sftp-batch-missing") else { return };
    std::fs::write(far.home.join("here.txt"), b"x").unwrap();
    for (line, names) in [
        ("rm absent.txt", "absent.txt"),
        ("rename absent.txt other.txt", "absent.txt"),
        ("cd absent-dir", "absent-dir"),
        ("ls absent-dir", "absent-dir"),
    ] {
        let (code, out, err) = batch(&far, format!("{line}\n").as_bytes());
        assert_eq!(code, 66, "{line}: {out}{err}");
        assert!(err.contains(names), "{line}: the path is named: {err}");
        assert!(!err.contains("os error"), "{line}: {err}");
    }
    // No command of a missing path touched another file.
    assert!(far.home.join("here.txt").exists());
}

/// A batch whose bytes are not UTF-8 is 65, in podssh's words, before any
/// connection.
#[test]
fn a_batch_that_is_not_text_is_65() {
    let Some(far) = far("sftp-batch-bytes") else { return };
    let (code, out, err) = batch(&far, b"pwd\n\xff\xfe\n");
    assert_eq!(code, 65, "{out}{err}");
    assert!(err.contains("not text: its bytes are not UTF-8"), "{err}");
    assert!(!err.contains("stream did not contain"), "the library's words: {err}");
    assert_eq!(far.connections(), 0, "a batch that cannot be read connects nowhere");
}
