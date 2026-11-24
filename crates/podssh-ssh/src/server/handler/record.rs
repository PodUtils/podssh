//! The audit log's part of the handler (T-116): the session that started
//! on a channel, or the request that was refused there, under the key that
//! logged in. Apart from the handler, so that each file stays short.

use russh::ChannelId;

use super::Served;
use crate::server::audit::{Asked, Place};
use crate::server::rules::{Asked as Wanted, Plan};

/// The words of a program that did not start: its own line went to the
/// client's stderr, and may name a path of the host.
const NOT_STARTED: &str = "the program did not start; its line went to the client";

impl Served {
    /// The channel `channel` of the key that logged in.
    pub(super) fn place(&self, channel: ChannelId) -> Place<'_> {
        Place { channel: u32::from(channel), key: &self.who }
    }

    /// After `wanted` was answered by `plan` on `channel`: the start of
    /// the session that runs there now, or the refusal with its reason.
    pub(super) fn record(&mut self, channel: ChannelId, wanted: Wanted<'_>, plan: &Plan) {
        let asked = match wanted {
            Wanted::Exec(command) => Asked::Exec(command),
            Wanted::Shell => Asked::Shell,
            Wanted::Sftp => Asked::Subsystem("sftp"),
        };
        if let Plan::Refuse(why) = plan {
            self.trail.session_refused(self.place(channel), asked, why);
            return;
        }
        let Some(open) = self.channels.get(&channel) else { return };
        if !open.started() {
            self.trail.session_refused(self.place(channel), asked, NOT_STARTED);
            return;
        }
        if open.mark.is_some() {
            return;
        }
        #[cfg(unix)]
        let pty = open.pty.is_some() || open.line.is_some();
        #[cfg(not(unix))]
        let pty = false;
        let mark = self.trail.session(self.place(channel), asked, forced(wanted, plan), pty, open.tally.clone());
        if let Some(open) = self.channels.get_mut(&channel) {
            open.mark = mark;
        }
    }
}

/// The command that a key's `command=` runs in place of what the client
/// asked for; None where the client's own runs.
fn forced<'a>(wanted: Wanted<'_>, plan: &'a Plan) -> Option<&'a [u8]> {
    match (wanted, plan) {
        // The client's own exec has no original beside it.
        (Wanted::Exec(_), Plan::Command(_, None)) => None,
        (_, Plan::Command(command, _)) => Some(command),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A forced command is told from the client's own, for each request.
    #[test]
    fn a_forced_command_is_told_from_the_clients_own() {
        let own = Plan::Command(b"ls".to_vec(), None);
        let forced_exec = Plan::Command(b"echo forced".to_vec(), Some(b"ls".to_vec()));
        let forced_shell = Plan::Command(b"echo forced".to_vec(), None);
        let cases: [(Wanted<'_>, &Plan, Option<&[u8]>); 5] = [
            (Wanted::Exec(b"ls"), &own, None),
            (Wanted::Exec(b"ls"), &forced_exec, Some(b"echo forced")),
            (Wanted::Shell, &forced_shell, Some(b"echo forced")),
            (Wanted::Shell, &Plan::Shell, None),
            (Wanted::Sftp, &Plan::Sftp, None),
        ];
        for (wanted, plan, ran) in cases {
            assert_eq!(forced(wanted, plan), ran, "{plan:?}");
        }
    }
}
