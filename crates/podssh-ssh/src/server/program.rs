//! The start of what a session channel runs, apart from the handler so that
//! each file stays short: a program with the shell found at its start
//! (T-108, T-222) and the parts of a login's start (T-119, T-120, `start.rs`), or
//! the SFTP server in the process (T-112).

#[cfg(unix)]
use std::sync::Arc;

use russh::server::Session;
use russh::ChannelId;

use super::channel::{Open, Program};
use super::Settings;

/// Serve SFTP in the process on `channel` (T-112). A channel that runs
/// a program, or SFTP already, takes no second one.
pub(super) fn sftp(
    open: Option<&mut Open>,
    settings: &Settings,
    channel: ChannelId,
    session: &mut Session,
) -> Result<(), russh::Error> {
    let Some(open) = open.filter(|open| !open.started()) else { return session.channel_failure(channel) };
    #[cfg(unix)]
    let started = super::sftp::start(open, settings);
    #[cfg(not(unix))]
    let started: Result<(), String> = {
        let _ = (open, settings);
        Err("not on this system: podssh serve serves SFTP on a Unix host".into())
    };
    match started {
        Ok(()) => session.channel_success(channel),
        Err(line) => {
            session.extended_data(channel, 1, format!("podssh serve: {line}\n").into_bytes())?;
            session.channel_failure(channel)
        }
    }
}

/// Find the shell (T-222), at each start and with no cache, then start the
/// program with it. The search runs programs and waits for them, so it
/// runs on a blocking thread.
#[cfg(unix)]
pub(super) async fn start_program(
    open: &mut Open,
    id: ChannelId,
    settings: &Settings,
    program: Program<'_>,
    original: Option<Vec<u8>>,
) -> Result<(), String> {
    use super::{child, env, shell, start};
    use std::os::unix::ffi::OsStringExt;
    let base = settings.base();
    let candidates = shell::candidates(settings.shell.as_deref(), env::lookup(&base, "SHELL"));
    let probe_env = env::without_credentials(&base);
    let line = open.line.as_ref().is_some_and(|grant| !grant.notify);
    let tty = open.pty.is_some() || open.line.is_some();
    let kind = start::Kind { login: matches!(program, Program::Login), tty, line };
    let (taken, held) = (open.env.clone(), Arc::new(settings.clone()));
    // The parts of a login's start read and write files (T-119, T-120): on
    // the same blocking thread as the search, after it.
    let (found, child_env, (extras, said)) = tokio::task::spawn_blocking(move || {
        let found = shell::find(&candidates, &probe_env)?;
        let child_env = env::child_env(&base, &found.path, &taken);
        let extras = start::extras(&held, kind, &found.path, &child_env);
        Ok::<_, shell::NoShell>((found, child_env, extras))
    })
    .await
    .map_err(|e| format!("the search for a shell failed: {e}"))?
    .map_err(|none| none.to_string())?;
    said.iter().for_each(|line| settings.say(line));
    open.extras = extras;
    let child_env = env::with_original(child_env, original.map(std::ffi::OsString::from_vec));
    child::spawn(open, id, &found.path, program, child_env)
}

#[cfg(not(unix))]
pub(super) async fn start_program(
    _: &mut Open,
    _: ChannelId,
    _: &Settings,
    _: Program<'_>,
    _: Option<Vec<u8>>,
) -> Result<(), String> {
    Err("not on this system: podssh serve runs programs on a Unix host".into())
}
