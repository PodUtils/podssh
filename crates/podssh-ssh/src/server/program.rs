//! The start of what a session channel runs, apart from the handler so that
//! each file stays short: a program with the shell found at its start
//! (T-108, T-222), or the SFTP server in the process (T-112).

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
    use super::{child, env, shell};
    use std::os::unix::ffi::OsStringExt;
    let base = settings.base();
    let candidates = shell::candidates(settings.shell.as_deref(), env::lookup(&base, "SHELL"));
    let probe_env = env::without_credentials(&base);
    let found = tokio::task::spawn_blocking(move || shell::find(&candidates, &probe_env))
        .await
        .map_err(|e| format!("the search for a shell failed: {e}"))?
        .map_err(|none| none.to_string())?;
    let child_env = env::child_env(&base, &found.path, &open.env);
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
