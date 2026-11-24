//! The requests of the kept shells on a connection of `podssh serve` (T-158,
//! T-159), apart from the handler so that each file stays short: the `env`
//! requests of podssh's own names, `~d`'s detach, the shell request that
//! joins a kept shell, and the subsystem that lists them.
//!
//! Only a key that logged in may ask, under rules that run a shell; a login
//! under a shared shell's name may not (T-837). Where serve keeps no shell
//! (a lease of 0), each request is refused, as by a far end that does not
//! know it. A refusal of a join is SUCCESS for the shell request, then the
//! words on stderr and the status 1, as a program that failed: the client
//! exits with it (T-158).

use russh::server::Session;
use russh::ChannelId;

use super::super::kept::Keeper;
use super::super::kept_join;
use super::super::rules::{Asked as Wanted, Plan};
use super::Served;
use crate::keep::{check_name, ATTACH, COUNT, DETACH, FROM, KEEP, LEASE, RESET, TAKE};

impl Served {
    /// An `env` request of podssh's own names, taken here before
    /// `--accept-env` sees it: its answer; None for another name.
    pub(super) fn keep_env(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Option<Result<(), russh::Error>> {
        if name == DETACH {
            return Some(self.detach(channel, value, session));
        }
        if ![ATTACH, TAKE, FROM, KEEP, LEASE, COUNT, RESET].contains(&name) {
            return None;
        }
        let keeps = !self.settings.keep_lease.is_zero() && self.viewer.is_none() && self.rules().is_ok();
        let taken = keeps
            && match self.channels.get_mut(&channel) {
                Some(open) if !open.started() => open.keep.note(name, value) == Some(true),
                _ => false,
            };
        Some(if taken { session.channel_success(channel) } else { session.channel_failure(channel) })
    }

    /// Where a login shell of `channel` is kept, where serve keeps shells.
    pub(super) fn keeper(&self, channel: ChannelId) -> Option<Keeper> {
        let open = self.channels.get(&channel)?;
        Keeper::of(&self.control.shelf, &self.who, self.settings.keep_lease, &open.keep)
    }

    /// `env detach@podssh NAME` on a running shell: keep it as NAME, answer
    /// SUCCESS and close the channel; else its reason on stderr and FAILURE,
    /// and the session goes on.
    fn detach(&mut self, channel: ChannelId, name: &str, session: &mut Session) -> Result<(), russh::Error> {
        let held = self.channels.get(&channel).and_then(|open| open.kept.clone());
        let kept = match (self.rules(), held) {
            (Err(why), _) => Err(why),
            (Ok(_), None) if self.settings.keep_lease.is_zero() => Err("this server keeps no shells".to_string()),
            (Ok(_), None) => Err("only a login shell on a pty is kept".to_string()),
            (Ok(_), Some(held)) => check_name(name).and_then(|()| held.shell.detach(held.generation, name)),
        };
        match kept {
            Ok(()) => {
                self.settings.say(&format!("key {}: kept a shell as {name}", self.who));
                session.channel_success(channel)?;
                session.eof(channel)?;
                session.close(channel)
            }
            Err(why) => {
                session.extended_data(channel, 1, format!("podssh serve: {why}\r\n").into_bytes())?;
                session.channel_failure(channel)
            }
        }
    }

    /// Whether the shell request of `channel` joins a kept shell.
    pub(super) fn joins(&self, channel: ChannelId) -> bool {
        self.channels.get(&channel).is_some_and(|open| open.keep.attach.is_some())
    }

    /// The shell request of a channel that asked to join a kept shell.
    pub(super) fn join_kept(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
        let allowed = match self.rules().map(|rules| rules.plan(Wanted::Shell)) {
            Ok(Plan::Shell) => Ok(()),
            Ok(Plan::Refuse(why)) | Err(why) => Err(why),
            Ok(_) => Err("this key's rules run a command in the place of a shell, so it joins no kept shell".into()),
        };
        let (shelf, who) = (self.control.shelf.clone(), self.who.clone());
        let Some(open) = self.channels.get_mut(&channel) else { return session.channel_failure(channel) };
        let joined = allowed.and_then(|()| kept_join::join(open, &shelf, &who, channel));
        session.channel_success(channel)?;
        match joined {
            Ok(name) => {
                self.settings.say(&format!("key {}: joined the kept shell {name}", self.who));
                Ok(())
            }
            Err(why) => {
                session.extended_data(channel, 1, format!("podssh serve: {why}\r\n").into_bytes())?;
                session.exit_status_request(channel, 1)?;
                session.eof(channel)?;
                session.close(channel)
            }
        }
    }

    /// The subsystem `shells@podssh`: this key's kept shells, one line each,
    /// and the status 0.
    pub(super) fn list_kept(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
        if self.settings.keep_lease.is_zero() || self.viewer.is_some() || self.rules().is_err() {
            return session.channel_failure(channel);
        }
        let lines = self.control.shelf.lines(&self.who);
        session.channel_success(channel)?;
        if !lines.is_empty() {
            session.data(channel, lines.into_bytes())?;
        }
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)
    }
}
