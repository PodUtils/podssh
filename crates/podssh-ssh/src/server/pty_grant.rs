//! The pty of a session channel at its request (T-110), apart from the
//! handler so that each file stays short: what a `pty-req` asked for, the
//! grant where a master opens now, and a window change.

use super::channel::Open;
use super::Settings;
use russh::Pty;

/// What a `pty-req` asked for.
#[cfg_attr(not(unix), allow(dead_code))]
pub(super) struct Asked<'a> {
    pub(super) term: &'a str,
    pub(super) cols: u32,
    pub(super) rows: u32,
    pub(super) pix_width: u32,
    pub(super) pix_height: u32,
    pub(super) modes: &'a [(Pty, u32)],
}

/// Grant a pty to `open` when a master opens now, before its program and
/// once; nothing is kept for the next request.
#[cfg(unix)]
pub(super) fn grant_pty(open: &mut Open, settings: &Settings, asked: &Asked<'_>) -> bool {
    use super::{line::LineGrant, pty, pty_child::Granted, PtyMode};
    if open.started() || open.pty.is_some() || open.line.is_some() {
        return false;
    }
    if !matches!(settings.pty, PtyMode::Line | PtyMode::Notify) {
        let paths = settings.ptmx.clone().unwrap_or_else(|| pty::PTMX.iter().map(std::path::PathBuf::from).collect());
        let devpts = settings.devpts.unwrap_or(settings.ptmx.is_none());
        if let Ok(pair) = pty::open_with(&paths, devpts) {
            let size = pty::size_of(asked.cols, asked.rows, asked.pix_width, asked.pix_height);
            if let Ok(granted) = Granted::new(pair, asked.term, size, asked.modes) {
                open.pty = Some(granted);
                return true;
            }
        }
    }
    // No pty: a tty that serve answers (T-776), else serve is the line
    // discipline (T-111), where the mode lets it.
    let (line, notify) = match settings.pty {
        PtyMode::Line => (true, false),
        PtyMode::No => (false, false),
        PtyMode::Notify => (notify_here(), true),
        PtyMode::Auto => (settings.ptmx.is_none(), notify_here()),
    };
    if line {
        let mut grant = LineGrant::new(asked.term, asked.cols, asked.rows, asked.modes);
        grant.notify = notify;
        open.line = Some(grant);
    }
    line
}

/// Whether serve can answer a child's tty calls on this host (T-776).
#[cfg(unix)]
fn notify_here() -> bool {
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    return super::notify::probe().is_ok();
    #[allow(unreachable_code)]
    false
}

/// On Windows a pty request fails: serve runs no program there.
#[cfg(not(unix))]
pub(super) fn grant_pty(_: &mut Open, _: &Settings, _: &Asked<'_>) -> bool {
    false
}

#[cfg(unix)]
pub(super) fn resize_pty(open: &Open, cols: u32, rows: u32, pix_width: u32, pix_height: u32) {
    if let Some(granted) = open.pty.as_ref() {
        granted.resize(super::pty::size_of(cols, rows, pix_width, pix_height));
    }
    if let Some(line) = open.line.as_ref() {
        line.resize(cols, rows);
    }
}

#[cfg(not(unix))]
pub(super) fn resize_pty(_: &Open, _: u32, _: u32, _: u32, _: u32) {}
