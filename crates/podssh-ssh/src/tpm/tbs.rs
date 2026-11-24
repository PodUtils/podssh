//! The parts of the way to a TPM on Windows (`windows.rs`) that need no
//! Windows: the codes of the TPM Base Services (TBS) in words, and the bound
//! of one command. They are built on each system, so that each system's
//! tests check them.
//!
//! `Tbsip_Submit_Command` waits for the TPM with no limit of its own that
//! podssh can set; so a command runs on a thread of its own, and past its
//! time it is cancelled (`Tbsip_Cancel_Commands`), which ends the wait.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

/// How long a cancelled command has to end before it is left behind.
pub(super) const GRACE: Duration = Duration::from_secs(5);

/// The codes of TBS (tbs.h) that say that this host has no TPM that podssh
/// may use: a context of TBS is then refused.
#[rustfmt::skip]
const NO_TPM: &[(u32, &str)] = &[
    (0x8028_400F, "TBS_E_TPM_NOT_FOUND: Windows finds no TPM of this version on this host"),
    (0x8028_4008, "TBS_E_SERVICE_NOT_RUNNING: the TPM Base Services do not run"),
    (0x8028_4010, "TBS_E_SERVICE_DISABLED: the TPM Base Services are disabled"),
    (0x8028_400B, "TBS_E_SERVICE_START_PENDING: the TPM Base Services are starting; try again"),
    (0x8028_4012, "TBS_E_ACCESS_DENIED: this user may not use the TPM"),
    (0x8028_4009, "TBS_E_TOO_MANY_TBS_CONTEXTS: too many programs use the TPM now"),
    (0x8028_4007, "TBS_E_INVALID_CONTEXT_PARAM: this Windows gives no context of TPM 2.0"),
];

/// The other codes of TBS that a context or a command can meet.
#[rustfmt::skip]
const OTHER: &[(u32, &str)] = &[
    (0x8028_4001, "TBS_E_INTERNAL_ERROR: the TPM Base Services failed"),
    (0x8028_4002, "TBS_E_BAD_PARAMETER: a parameter was not right"),
    (0x8028_4003, "TBS_E_INVALID_OUTPUT_POINTER: a place of an answer was not right"),
    (0x8028_4004, "TBS_E_INVALID_CONTEXT: the context is not one of TBS"),
    (0x8028_4005, "TBS_E_INSUFFICIENT_BUFFER: the TPM's answer is longer than its buffer"),
    (0x8028_4006, "TBS_E_IOERROR: the TPM's device failed"),
    (0x8028_400A, "TBS_E_TOO_MANY_RESOURCES: the TPM holds too many objects"),
    (0x8028_400D, "TBS_E_COMMAND_CANCELED: the command was cancelled"),
    (0x8028_400E, "TBS_E_BUFFER_TOO_LARGE: the command is too long for TBS"),
];

/// The words of a code of TBS, with the code.
pub(super) fn words(code: u32) -> String {
    let named = NO_TPM.iter().chain(OTHER).find(|(c, _)| *c == code).map(|(_, words)| *words);
    match named {
        Some(words) => format!("{words} ({code:#010x})"),
        None => format!("TBS gave the code {code:#010x}"),
    }
}

/// Why TBS made no context, or told nothing of its TPM: one line that
/// starts "no TPM: ".
pub(super) fn no_tpm(code: u32) -> String {
    format!("no TPM: Windows' TPM Base Services refused: {}", words(code))
}

/// The value of `work`, run on a thread of its own for `limit` at most.
/// Past it, `cancel` runs once and the work has [`GRACE`] more (`grace` in
/// the tests) to end; it is then left behind, never waited for. Either way
/// the command did not answer in its time.
pub(super) fn bounded<T: Send + 'static>(
    limit: Duration,
    grace: Duration,
    work: impl FnOnce() -> T + Send + 'static,
    cancel: impl FnOnce(),
) -> Result<T, String> {
    let (sender, answer) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("podssh-tpm".into())
        .spawn(move || {
            let _ = sender.send(work());
        })
        .map_err(|e| format!("no thread for the TPM's command: {e}"))?;
    match answer.recv_timeout(limit) {
        Ok(done) => return Ok(done),
        Err(RecvTimeoutError::Disconnected) => return Err("the thread of the TPM's command failed".into()),
        Err(RecvTimeoutError::Timeout) => {}
    }
    cancel();
    // What the cancelled command answers is not used: its time is over.
    let _ = answer.recv_timeout(grace);
    Err(format!("the TPM did not answer within {} s, and its command was cancelled", limit.as_secs()))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    use super::*;

    /// Each code of a missing TPM gives one line that starts "no TPM: " and
    /// names the code; a code of no table names its number.
    #[test]
    fn each_refusal_of_tbs_is_one_line_of_no_tpm() {
        for (code, name) in NO_TPM.iter().chain(OTHER) {
            let line = no_tpm(*code);
            assert!(line.starts_with("no TPM: "), "{line}");
            assert!(line.contains(name.split(':').next().unwrap()), "{line}");
            assert!(line.contains(&format!("{code:#010x}")), "{line}");
            assert!(!line.contains('\n'), "{line}");
        }
        assert_eq!(no_tpm(0x8028_4FFF), "no TPM: Windows' TPM Base Services refused: TBS gave the code 0x80284fff");
        let codes: Vec<u32> = NO_TPM.iter().chain(OTHER).map(|(c, _)| *c).collect();
        let mut unique = codes.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), codes.len(), "each code once");
    }

    #[test]
    fn a_command_that_answers_in_time_gives_its_answer() {
        let ran = Arc::new(AtomicBool::new(false));
        let cancelled = ran.clone();
        let got = bounded(Duration::from_secs(5), Duration::from_secs(1), || 42, move || {
            cancelled.store(true, Ordering::SeqCst)
        });
        assert_eq!(got, Ok(42));
        assert!(!ran.load(Ordering::SeqCst), "no cancel for a command that answered");
    }

    /// A command past its time is cancelled; the cancel ends its wait, as
    /// `Tbsip_Cancel_Commands` ends `Tbsip_Submit_Command`'s.
    #[test]
    fn a_late_command_is_cancelled_and_said_late() {
        let (stop, stopped) = mpsc::channel::<()>();
        let start = Instant::now();
        let got = bounded(
            Duration::from_millis(100),
            Duration::from_secs(5),
            move || stopped.recv_timeout(Duration::from_secs(30)).is_ok(),
            move || {
                let _ = stop.send(());
            },
        );
        let why = got.unwrap_err();
        assert!(why.contains("did not answer within 0 s") && why.contains("cancelled"), "{why}");
        assert!(start.elapsed() < Duration::from_secs(5), "the cancel ended the wait: {:?}", start.elapsed());
    }

    /// A command that a cancel does not end is left behind after the grace:
    /// the caller never waits for it.
    #[test]
    fn a_command_that_never_ends_is_left_behind() {
        let start = Instant::now();
        let got = bounded(
            Duration::from_millis(50),
            Duration::from_millis(50),
            || std::thread::sleep(Duration::from_secs(3)),
            || {},
        );
        assert!(got.is_err());
        assert!(start.elapsed() < Duration::from_secs(2), "{:?}", start.elapsed());
    }

    /// A command whose thread fails says so, and is not taken for an answer.
    #[test]
    fn a_failed_thread_is_no_answer() {
        let got: Result<(), String> =
            bounded(Duration::from_secs(5), Duration::from_secs(1), || panic!("planted"), || {});
        assert!(got.unwrap_err().contains("failed"));
    }
}
