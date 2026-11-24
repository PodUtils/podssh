//! The message of the day of `podssh serve` (T-119), as sshd prints it: the
//! file of `--motd FILE`, else `/etc/motd`, before an interactive login
//! shell on a pty or on serve's line discipline; never for a command or a
//! subsystem, and never when `$HOME/.hushlogin` exists.
//!
//! A cage may have no `/etc/motd`, so the default file is read only where
//! it is there, in silence otherwise. The text is the server's, shown on
//! the client's terminal: control characters other than tab and newline
//! are dropped, and it is cut at [`LIMIT`], so that no file can drive the
//! terminal or flood the session.

use std::ffi::OsStr;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

/// The most bytes of the file that are shown.
pub const LIMIT: usize = 64 * 1024;

/// The file that sshd shows when no other is named.
pub const DEFAULT: &str = "/etc/motd";

/// Which file is the message of the day, and whether the operator named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Motd {
    pub path: PathBuf,
    /// `--motd FILE`: a file that cannot be read is said. The default file
    /// is shown where it is there, and missed in silence.
    pub named: bool,
}

impl Motd {
    /// The file of `--motd FILE`.
    pub fn named(path: impl Into<PathBuf>) -> Motd {
        Motd { path: path.into(), named: true }
    }

    /// `/etc/motd`, where it is there.
    pub fn default_file() -> Motd {
        Motd { path: PathBuf::from(DEFAULT), named: false }
    }
}

/// What a read of the file gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    /// At most [`LIMIT`] bytes of the file, as they are.
    pub bytes: Vec<u8>,
    /// Whether the file held more than [`LIMIT`] bytes.
    pub cut: bool,
}

/// The file at `path`, at most [`LIMIT`] bytes of it. `Ok(None)` is no
/// file. A file that is not a regular file (a FIFO, a device, a directory)
/// is refused before a byte is read: a FIFO would hold the session.
pub fn read(path: &Path) -> Result<Option<Read>, String> {
    let mut file = match open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let meta = file.metadata().map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    let mut bytes = Vec::new();
    // One byte past the limit tells a file of exactly LIMIT bytes from a
    // longer one.
    (&mut file).take(LIMIT as u64 + 1).read_to_end(&mut bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let cut = bytes.len() > LIMIT;
    bytes.truncate(LIMIT);
    Ok(Some(Read { bytes, cut }))
}

/// Open with no wait on a FIFO and no controlling terminal taken from a
/// tty; the check of the file's type comes after.
#[cfg(unix)]
fn open(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::File::options().read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY).open(path)
}

#[cfg(not(unix))]
fn open(path: &Path) -> io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// The bytes for the client's terminal: the file as UTF-8 (a byte that is
/// not is shown as U+FFFD, and a character cut at the limit is dropped),
/// each control character but tab and newline dropped, each newline as CR
/// LF, and a last newline where the file has none, so that the prompt
/// starts a row of its own. Empty for a file with nothing to show.
pub fn for_screen(bytes: &[u8]) -> Vec<u8> {
    let text = whole_chars(bytes);
    let clean = podssh_ws::text::multi_line(&text);
    if clean.trim_matches(['\n', '\t', ' ']).is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(clean.len() + clean.len() / 16 + 2);
    for b in clean.bytes() {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    if !clean.ends_with('\n') {
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// `bytes` as text, without a character that the limit cut in two.
fn whole_chars(bytes: &[u8]) -> String {
    let end = match std::str::from_utf8(bytes) {
        // An incomplete sequence at the very end: cut by the limit.
        Err(e) if e.error_len().is_none() => e.valid_up_to(),
        _ => bytes.len(),
    };
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Whether `$HOME/.hushlogin` exists, as login(1) and sshd check it. An
/// empty or relative `HOME` hushes nothing.
pub fn hushed(home: Option<&OsStr>) -> bool {
    let Some(home) = home.map(Path::new).filter(|h| h.is_absolute()) else { return false };
    std::fs::metadata(home.join(".hushlogin")).is_ok()
}

/// What a login shows, and the line for serve's log when a named file
/// cannot be shown whole.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Shown {
    /// The bytes for the terminal; None shows nothing.
    pub screen: Option<Vec<u8>>,
    /// A line for serve's log.
    pub said: Option<String>,
}

/// The message of the day for a login whose home is `home`.
pub fn shown(motd: &Motd, home: Option<&OsStr>) -> Shown {
    if hushed(home) {
        return Shown::default();
    }
    let named = |why: String| Shown { screen: None, said: motd.named.then(|| format!("--motd: {why}")) };
    match read(&motd.path) {
        Ok(Some(Read { bytes, cut })) => {
            let screen = Some(for_screen(&bytes)).filter(|s| !s.is_empty());
            let said = cut.then(|| {
                format!(
                    "the message of the day {}: longer than {} KiB: the rest is not shown",
                    motd.path.display(),
                    LIMIT / 1024
                )
            });
            Shown { screen, said }
        }
        Ok(None) => named(format!("{}: no such file", motd.path.display())),
        Err(why) => named(why),
    }
}

/// The check of `--motd FILE` at serve's start: a file that is not there or
/// cannot be read is a mistake of the setup, said before a client comes.
pub fn check(path: &Path) -> Result<(), String> {
    match read(path) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(format!("{}: no such file", path.display())),
        Err(why) => Err(why),
    }
}
