//! The `Parsed::Command` arm of the dispatch: the `--timeout` gate, then the
//! handler of the verb that parsed. It lives beside [`super`] so that the
//! dispatch stays a list of arms and this file holds the one arm that is a
//! page of its own.

use crate::flags::VERB_OWNER;
use crate::pager::Tty;

use super::{refusals, Streams, EXIT_NOT_IMPLEMENTED, EXIT_USAGE};

/// Dispatch one parsed verb: the deadline of `--timeout`, then its handler.
#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    verb: &'static str,
    refused: &[(String, &'static str, &'static str)],
    tag: &Option<String>,
    timeout: &Option<String>,
    jsonl: bool,
    ssh: &Option<Box<crate::ssh::args::SshArgs>>,
    keygen: &Option<Box<crate::keygen::KeygenArgs>>,
    cp: &Option<Box<crate::cp::CpArgs>>,
    sftp: &Option<Box<crate::sftp::SftpArgs>>,
    chat: &Option<Box<crate::chat::ChatArgs>>,
    tty: Tty,
    s: &mut Streams<'_>,
) -> i32 {
    // `-P TAG` on ssh is a Tag (T-045); one that is a number was most
    // likely meant as a port, and the note says so before it connects.
    if let Some(notice) = tag.as_deref().and_then(crate::refuse::tag_notice) {
        let _ = writeln!(s.err, "{notice}");
    }
    // The `--timeout` gate, computed once and passed down: the attachment from
    // the probed TTY and `--jsonl`, then the required `--timeout`.
    // Only verbs whose table declares `--timeout` enter the gate, so
    // enforcement follows the flag's existence and never invents a
    // requirement the tree cannot satisfy (`ssh` carries no timeout
    // row and skips it). `man` never reaches here (handled above: it
    // has no `--timeout` row and its pipeless acceptance forbids one),
    // and neither do `Help`/`Version` or the parse-level refusals.
    //
    // A verb that is not implemented skips the gate and is refused
    // below (70): it has nothing to bound, and a 64 would tell a script
    // that its command line is wrong. A --timeout that was given and
    // does not parse is wrong for each verb, so it stays 64.
    //
    // A row that is `optional` bounds the run and is never required
    // (`scp` and `sftp`, Q72): OpenSSH's run in pipes with no such
    // flag, and ConnectTimeout bounds their login.
    let not_yet = VERB_OWNER.iter().any(|(name, _)| *name == verb);
    let row = crate::flags::verb_for(verb).and_then(|v| v.flags.iter().find(|r| r.long == "timeout"));
    let checked = match row {
        _ if not_yet => timeout.as_deref().map(crate::non_interactive::parse_timeout).transpose(),
        Some(row) if row.optional => {
            crate::non_interactive::optional_timeout(timeout.as_deref(), |n| std::env::var(n).ok())
        }
        Some(_) => {
            let attachment = crate::non_interactive::resolve_tty(tty, jsonl);
            crate::non_interactive::require_timeout_or_env(verb, attachment, timeout.as_deref(), |n| {
                std::env::var(n).ok()
            })
        }
        None => Ok(None),
    };
    let deadline = match checked {
        Ok(deadline) => deadline,
        Err(refusal) => {
            let _ = writeln!(s.err, "{}", refusal.message);
            return refusal.fault.code();
        }
    };
    // Refused flags first, and they refuse before anything else
    // happens, so nothing is half-done.
    if refusals(verb, refused, s.err) {
        return EXIT_USAGE;
    }
    if let Some(args) = ssh {
        return crate::ssh::run_ssh(args, tty, s.err);
    }
    if let Some(args) = keygen {
        // Each write of the answer is checked: 74 when it fails (T-965).
        return crate::output::deliver("keygen", s.out, s.err, |out, err| crate::keygen::run_keygen(args, out, err));
    }
    if let Some(args) = cp {
        return crate::cp::run_cp(args, deadline, jsonl, s.out, s.err);
    }
    if let Some(args) = sftp {
        return crate::sftp::run_sftp(args, deadline, tty, s.out, s.err);
    }
    if let Some(args) = chat {
        return crate::chat::run_chat(args, deadline, jsonl, s.out, s.err);
    }
    // A verb that parses and has no behaviour is refused, never a stub
    // that exits 0. A verb with neither a handler above nor a
    // VERB_OWNER row is a dispatch bug, and is refused the same way.
    if VERB_OWNER.iter().any(|(name, _)| *name == verb) {
        let _ = writeln!(s.err, "{}", crate::refuse::not_implemented(verb));
    } else {
        let _ = writeln!(s.err, "podssh: internal error: '{verb}' has no handler.");
    }
    EXIT_NOT_IMPLEMENTED
}
