//! `podssh health --policy FILE` (T-838): a probe of the server's
//! algorithms, with no login. The host is reached as `podssh ssh` reaches
//! it (the relay or --direct, -J hops logged in as usual); the
//! destination's handshake runs to its host key, where the policy judges
//! the server's KEXINIT, and the connection ends there. No credential is
//! needed for the destination, and its host key is not checked against
//! known_hosts: nothing is sent to it.
//!
//! The verdict is one JSON object on stdout, also with no reading; the exit
//! is the verdict's: 0 pass, 78 a mismatch, 69 no reading (no connection,
//! a KEXINIT that does not read, or a check that one exchange cannot make).

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::policy::{Judge, Reading};
use podssh_ssh::Log;

use crate::ssh::resolve::Resolved;

/// The bound on the probe: the road and one handshake.
const LIMIT: Duration = Duration::from_secs(90);

/// Probe the destination of `resolved` with its policy; the exit code.
pub fn probe(mut resolved: Resolved, destination: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(given) = resolved.options.algorithm_policy.take() else {
        let _ = writeln!(err, "podssh health: --policy was given and no policy was read");
        return podssh_ssh::policy::EXIT_NO_READING;
    };
    // The same policy, as a probe: each verdict ends the connection.
    let judge = Judge::new(given.policy().clone(), true);
    resolved.options.algorithm_policy = Some(judge.clone());
    let log = Arc::new(Log::new(resolved.options.log_level));
    for note in &resolved.notes {
        log.verbose(note);
    }
    for warning in &resolved.warnings {
        log.warning(warning);
    }
    let why = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => {
            let judged = runtime.block_on(crate::ssh::transport::settled(async {
                tokio::time::timeout(LIMIT, Box::pin(reach_and_judge(&resolved, &log))).await
            }));
            // A read of a helper thread may still wait; the probe is over.
            runtime.shutdown_background();
            judged.unwrap_or_else(|_| format!("the probe passed its limit of {} s", LIMIT.as_secs()))
        }
        Err(e) => format!("could not start the async runtime: {e}"),
    };
    let (doc, code) = judge.report(&why);
    let _ = writeln!(out, "{doc}");
    let line = match judge.reading() {
        Reading::Judged(verdict) => verdict.line(),
        Reading::Failed(failed) => format!("no verdict: {failed}"),
        Reading::None => format!("no verdict: {why}"),
    };
    if code == podssh_ssh::policy::EXIT_PASS {
        log.verbose(&format!("health {destination}: {line}"));
    } else {
        log.error(&format!("health {destination}: {line}"));
    }
    code
}

/// Reach the host and run the destination's handshake to the verdict; what
/// ended it, in words, for a probe with no reading.
async fn reach_and_judge(resolved: &Resolved, log: &Arc<Log>) -> String {
    let reached = match crate::layer_told::claimed(crate::ssh::transport::reach(resolved, log)).await {
        Ok(reached) => reached,
        Err(not) if not.lines.is_empty() => return "no connection".into(),
        Err(not) => return not.lines.join("; "),
    };
    match podssh_ssh::run::connect_hops(reached.stream, &resolved.options, log).await {
        // The judge ends each probe; a login that went through is a fault
        // of this code, said as one.
        Ok(handles) => {
            podssh_ssh::run::disconnect_all(&handles).await;
            crate::ssh::transport::settle(reached.layer).await;
            "the login went on past the policy's verdict".into()
        }
        Err(e) => {
            crate::ssh::transport::settle(reached.layer).await;
            crate::layer_told::failed(e.to_string(), log)
        }
    }
}
