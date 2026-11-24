//! The shell integration marks of `podssh serve --shell-integration`
//! (T-120): OSC 133 (where a prompt starts and ends, where a command's
//! output starts, and where it ends) and OSC 7 (the working directory), so
//! that a terminal jumps between commands and opens a tab in the same
//! directory. Off by default.
//!
//! Where serve is the line discipline (T-111), serve draws the prompt and
//! sees each line submitted, so it writes the marks itself. On a pty, or on
//! a tty that serve answers, only the shell knows: bash starts with
//! `--rcfile` and zsh with `ZDOTDIR` naming a file of serve's own, made for
//! the session in the child's `TMPDIR` (else `/tmp`), which reads the
//! user's own files and adds hooks. Invariant: no file of the user's is
//! written. Another shell gets no marks.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

/// The start of a prompt.
pub const A: &[u8] = b"\x1b]133;A\x07";
/// The end of a prompt: the input starts.
pub const B: &[u8] = b"\x1b]133;B\x07";
/// A line was submitted: the output starts.
pub const C: &[u8] = b"\x1b]133;C\x07";
/// The end of a command. With no help from the shell, serve's line
/// discipline knows no exit status, so it gives none.
pub const D: &[u8] = b"\x1b]133;D\x07";

/// The file that bash reads in place of `~/.bashrc`.
const BASH_RC: &str = include_str!("marks/bash-rc.sh");
/// The end of the `.zshenv` that zsh reads first.
const ZSHENV: &str = include_str!("marks/zshenv.sh");

/// The first prompt of the line discipline, marked.
pub fn first_prompt(prompt: &[u8]) -> Vec<u8> {
    [A, prompt, B].concat()
}

/// The echo of a submitted line, marked, where it ends with the next
/// `prompt` (the discipline draws the next prompt with the echo): the
/// command's output starts and ends there, as serve cannot see when the
/// shell is done, then the next prompt is marked. None where the echo does
/// not end with the prompt.
pub fn submitted(echo: &[u8], prompt: &[u8]) -> Option<Vec<u8>> {
    let before = echo.strip_suffix(prompt).filter(|_| !prompt.is_empty())?;
    Some([before, C, D, A, prompt, B].concat())
}

/// The shells whose start files take the marks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Zsh,
}

impl Shell {
    /// The shell of `path` by its file name; None for another shell.
    pub fn of(path: &Path) -> Option<Shell> {
        match path.file_name()?.to_str()? {
            "bash" => Some(Shell::Bash),
            "zsh" => Some(Shell::Zsh),
            _ => None,
        }
    }
}

/// The start of one login shell with the marks: its argv\[0\], the
/// arguments, the variables that it gets, and the directory of serve's
/// files, removed when this is dropped (at the session's end).
#[derive(Debug)]
pub struct Files {
    pub dir: PathBuf,
    /// The shell's argv\[0\]: bash reads `--rcfile` only when it is not a
    /// login shell, so its name has no dash.
    pub arg0: Option<OsString>,
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
}

impl Files {
    /// Start `cmd`, a login shell's command, with these files.
    #[cfg(unix)]
    pub(super) fn apply(&self, cmd: &mut tokio::process::Command) {
        if let Some(arg0) = &self.arg0 {
            cmd.arg0(arg0);
        }
        cmd.args(&self.args).envs(self.env.iter().map(|(k, v)| (k, v)));
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Make the files of `shell` in a new directory under `tmp`, mode 0700.
/// `zdotdir` is the session's own `ZDOTDIR`, given back to zsh first.
pub fn files(shell: Shell, tmp: &Path, zdotdir: Option<&OsStr>) -> Result<Files, String> {
    let dir = private_dir(tmp)?;
    // From here the directory goes with `files`, also on a failure.
    let mut files = Files { dir, arg0: None, args: Vec::new(), env: Vec::new() };
    match shell {
        Shell::Bash => {
            let rc = files.dir.join("bashrc");
            write_private(&rc, BASH_RC.as_bytes())?;
            files.arg0 = Some("bash".into());
            files.args = vec!["--rcfile".into(), rc.into_os_string(), "-i".into()];
        }
        Shell::Zsh => {
            let mut text = zdotdir_line(zdotdir);
            text.extend_from_slice(ZSHENV.as_bytes());
            write_private(&files.dir.join(".zshenv"), &text)?;
            files.env = vec![("ZDOTDIR".into(), files.dir.clone().into_os_string())];
        }
    }
    Ok(files)
}

/// The first line of the `.zshenv`: the session's `ZDOTDIR` back, in single
/// quotes, or none.
pub fn zdotdir_line(zdotdir: Option<&OsStr>) -> Vec<u8> {
    let Some(value) = zdotdir.filter(|v| !v.is_empty()) else { return b"unset ZDOTDIR\n".to_vec() };
    let mut line = b"ZDOTDIR=".to_vec();
    line.extend(single_quoted(value.as_encoded_bytes()));
    line.push(b'\n');
    line
}

/// `bytes` in single quotes for a POSIX shell: each quote as `'\''`.
pub fn single_quoted(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![b'\''];
    for &b in bytes {
        if b == b'\'' {
            out.extend_from_slice(b"'\\''");
        } else {
            out.push(b);
        }
    }
    out.push(b'\'');
    out
}

/// A new directory under `tmp` with a name that no other process takes
/// (`mkdtemp`: a pid is not unique across PID namespaces), mode 0700.
#[cfg(unix)]
fn private_dir(tmp: &Path) -> Result<PathBuf, String> {
    use std::os::unix::ffi::OsStringExt;
    let mut template = tmp.join("podssh-marks-XXXXXX").into_os_string().into_vec();
    template.push(0);
    // SAFETY: a writable buffer ending with NUL, which mkdtemp fills in place.
    let made = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
    if made.is_null() {
        return Err(format!("no directory for the marks in {}: {}", tmp.display(), std::io::Error::last_os_error()));
    }
    template.pop();
    Ok(PathBuf::from(OsString::from_vec(template)))
}

#[cfg(not(unix))]
fn private_dir(tmp: &Path) -> Result<PathBuf, String> {
    Err(format!("no directory for the marks in {}: not a Unix host", tmp.display()))
}

/// Write `bytes` to a new file at `path`, mode 0600, never over one.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let mut options = std::fs::File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// Where the files go: the child's `TMPDIR` when it is an absolute path,
/// else `/tmp`.
pub fn tmp_of(tmpdir: Option<&OsStr>) -> PathBuf {
    tmpdir.map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(|| PathBuf::from("/tmp"))
}
