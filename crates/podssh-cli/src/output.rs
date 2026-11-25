//! The output of a command whose answer is its stdout (T-965): `keygen`,
//! `doctor`, `man`, `status`, `config import`, `agent list` and `update`.
//! A write that fails (a full disk, a device that refuses it) is said in one
//! line, and the command exits 74 (`EX_IOERR`) where it would have exited 0;
//! a command that failed keeps its own code. A reader that went away
//! (`| head`) is no failure, as elsewhere in podssh (`job follow`, a unit's
//! print). One helper, so that no command checks its writes its own way.

use std::io::{self, Write};

use crate::exitmap::sysexits::EX_IOERR;

/// `out`, whose first failure is kept; each write after it fails at once,
/// so that a broken stdout is not written to again and again.
pub struct Checked<'a> {
    out: &'a mut dyn Write,
    failed: Option<io::Error>,
}

impl<'a> Checked<'a> {
    pub fn new(out: &'a mut dyn Write) -> Self {
        Checked { out, failed: None }
    }

    fn kept<T>(&mut self, done: io::Result<T>) -> io::Result<T> {
        if let Err(e) = &done {
            if self.failed.is_none() {
                self.failed = Some(io::Error::new(e.kind(), e.to_string()));
            }
        }
        done
    }

    fn again(&self) -> Option<io::Error> {
        self.failed.as_ref().map(|e| io::Error::new(e.kind(), e.to_string()))
    }
}

impl Write for Checked<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(e) = self.again() {
            return Err(e);
        }
        let done = self.out.write(buf);
        self.kept(done)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(e) = self.again() {
            return Err(e);
        }
        let done = self.out.flush();
        self.kept(done)
    }
}

/// Run `command` with `out` checked, then flush it: the command's code, or
/// 74 with one line when its output could not be written.
pub fn deliver(
    verb: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
    command: impl FnOnce(&mut dyn Write, &mut dyn Write) -> i32,
) -> i32 {
    let mut checked = Checked::new(out);
    let code = command(&mut checked, err);
    let _ = checked.flush();
    match checked.failed {
        None => code,
        Some(e) if e.kind() == io::ErrorKind::BrokenPipe => code,
        Some(e) => {
            let _ = writeln!(err, "podssh {verb}: the output could not be written: {}", podssh_ws::text::said(&e));
            if code == 0 {
                EX_IOERR
            } else {
                code
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sink that takes `room` bytes, then fails each write with `kind`.
    struct Full {
        room: usize,
        kind: io::ErrorKind,
        writes: usize,
    }

    impl Write for Full {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.room == 0 {
                return Err(io::Error::new(self.kind, "No space left on device (os error 28)"));
            }
            let n = buf.len().min(self.room);
            self.room -= n;
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Each case: what the command returns, the sink's failure, and the
    /// code and the line that follow.
    #[test]
    fn a_failed_write_is_said_once_and_exits_74_where_the_command_succeeded() {
        let cases: [(i32, Option<io::ErrorKind>, i32, Option<&str>); 6] = [
            (0, None, 0, None),
            (1, None, 1, None),
            (0, Some(io::ErrorKind::StorageFull), 74, Some("podssh keygen: the output could not be written: No space")),
            (0, Some(io::ErrorKind::Other), 74, Some("the output could not be written")),
            (1, Some(io::ErrorKind::StorageFull), 1, Some("the output could not be written")),
            (0, Some(io::ErrorKind::BrokenPipe), 0, None),
        ];
        for (returned, kind, code, line) in cases {
            let room = if kind.is_some() { 3 } else { usize::MAX };
            let mut sink = Full { room, kind: kind.unwrap_or(io::ErrorKind::Other), writes: 0 };
            let mut err = Vec::new();
            let got = deliver("keygen", &mut sink, &mut err, |out, _| {
                for _ in 0..5 {
                    let _ = writeln!(out, "a line of the answer");
                }
                returned
            });
            let said = String::from_utf8(err).unwrap();
            assert_eq!(got, code, "{kind:?}: {said}");
            match line {
                Some(line) => {
                    assert!(said.contains(line), "{kind:?}: {said}");
                    assert_eq!(said.lines().count(), 1, "said once: {said}");
                    assert!(!said.contains("os error"), "{said}");
                }
                None => assert!(said.is_empty(), "{kind:?}: {said}"),
            }
            if kind.is_some() {
                assert!(sink.writes <= 2, "the sink was not written to again after it failed: {}", sink.writes);
            }
        }
    }
}
