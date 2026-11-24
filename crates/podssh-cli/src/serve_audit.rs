//! The audit log of `podssh serve` on the command line (T-116):
//! `--audit-log FILE` opened at the start, which refuses a file that others
//! may read (78); and `--audit-verify FILE`, which recomputes the chain of
//! a log and prints what it found, with the last line's SHA-256 for a copy
//! kept off the host.

use std::io::{BufReader, Write};
use std::path::Path;
use std::sync::Arc;

use podssh_ssh::server::audit::{chain, Audit};
use podssh_ssh::server::Say;

use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::{EX_DATAERR, EX_NOINPUT};
use crate::relay_settings::Refusal;
use crate::serve::ServeArgs;

/// The log of `--audit-log`, or None. `--audit-commands` with no log is a
/// usage error (64); a file that cannot be the log refuses the start (78).
pub fn open(args: &ServeArgs) -> Result<Option<Arc<Audit>>, Refusal> {
    let Some(path) = args.audit_log.as_deref() else {
        if args.audit_commands {
            return Err(Refusal::usage("--audit-commands records into the log of --audit-log FILE: give that too"));
        }
        return Ok(None);
    };
    let say = Say(Arc::new(|line: &str| {
        let _ = writeln!(std::io::stderr(), "podssh serve: {line}");
    }));
    Audit::open(Path::new(path), args.audit_commands, Some(say)).map(Some).map_err(Refusal::config)
}

/// `podssh serve --audit-verify FILE`: the verdict on `out`, one line on
/// `err` when the chain does not hold. 0 when it holds, 65 when it does
/// not, 66 when FILE cannot be read, 64 with a flag of a server.
pub fn verify(args: &ServeArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(file) = args.audit_verify.as_deref() else { return EXIT_USAGE };
    if args.stdio || args.name.is_some() || args.audit_log.is_some() {
        let _ = writeln!(err, "podssh serve: --audit-verify checks a log and serves nothing: give it alone");
        return EXIT_USAGE;
    }
    let opened = std::fs::File::open(file);
    let verdict = opened.and_then(|f| chain::verify(&mut BufReader::new(f)));
    let verdict = match verdict {
        Ok(verdict) => verdict,
        Err(e) => {
            let _ = writeln!(err, "podssh serve: --audit-verify {file}: {e}");
            return EX_NOINPUT;
        }
    };
    let _ = out.write_all(said(file, &verdict).as_bytes());
    if verdict.holds() {
        return 0;
    }
    let count = verdict.problems.len() + verdict.more;
    let _ = writeln!(err, "podssh serve: {file}: the chain does not hold ({count} problems, above)");
    EX_DATAERR
}

/// The verdict in lines: the count, each problem, each unfinished run, and
/// the last hash.
fn said(file: &str, verdict: &chain::Verdict) -> String {
    let mut text = if verdict.holds() {
        format!("{file}: {} lines, the chain holds\n", verdict.lines)
    } else {
        format!("{file}: {} lines, the chain does not hold\n", verdict.lines)
    };
    for problem in &verdict.problems {
        text.push_str(&format!("{problem}\n"));
    }
    if verdict.more > 0 {
        text.push_str(&format!("and {} more problems\n", verdict.more));
    }
    for run in &verdict.unfinished {
        text.push_str(&format!(
            "run {run}: no serve.stop: it still runs, it was killed, or the file was cut after it\n"
        ));
    }
    text.push_str(&format!(
        "last line's SHA-256: {} (kept off this host, it shows a later cut of the tail)\n",
        verdict.last
    ));
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> ServeArgs {
        ServeArgs::default()
    }

    /// `--audit-commands` alone, and a log with a server's flag, are usage
    /// errors; a file that is missing is 66.
    #[test]
    fn the_flags_of_the_log_refuse_what_cannot_work() {
        let mut a = args();
        a.audit_commands = true;
        assert_eq!(open(&a).expect_err("no log").code, EXIT_USAGE);
        assert!(open(&args()).unwrap().is_none());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        a = args();
        a.audit_verify = Some("/nonexistent/podssh/audit.log".into());
        assert_eq!(verify(&a, &mut out, &mut err), EX_NOINPUT, "{}", String::from_utf8_lossy(&err));
        a.stdio = true;
        assert_eq!(verify(&a, &mut out, &mut err), EXIT_USAGE);
    }

    /// The verdict names each problem and each unfinished run, and the hash.
    #[test]
    fn the_verdict_says_what_it_found() {
        let verdict = chain::Verdict {
            lines: 3,
            problems: vec!["line 2: the chain breaks here".into()],
            more: 0,
            unfinished: vec!["abc".into()],
            last: "f00".into(),
        };
        let text = said("audit.log", &verdict);
        assert!(text.starts_with("audit.log: 3 lines, the chain does not hold\nline 2:"), "{text}");
        assert!(text.contains("run abc: no serve.stop") && text.contains("SHA-256: f00"), "{text}");
    }
}
