//! A pty for a session channel of `podssh serve` (T-110): where a master
//! opens at the client's request, its slave becomes the child's terminal.
//!
//! Each request probes again, and nothing is kept for the next one: a cage
//! can gain or lose `/dev/ptmx` while serve runs. Where no master opens, or
//! no slave comes of it, the request is refused, and the command runs on
//! pipes (T-111 is the line discipline for that case). `podssh doctor`
//! asks the same probe, so the two never disagree.

use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use russh::Pty;

use crate::terminal::{modes, Size};

/// The masters tried, in order: the usual one, then devpts' own, which a
/// container with its own devpts instance may have alone.
pub const PTMX: &[&str] = &["/dev/ptmx", "/dev/pts/ptmx"];

/// The size of a pty whose request gave none, as sshd's.
pub const DEFAULT_SIZE: Size = Size { cols: 80, rows: 24, px_width: 0, px_height: 0 };

/// The `TERM` of a pty whose request gave none, as podssh's client sends.
pub const DEFAULT_TERM: &str = "xterm-256color";

/// A master and its slave, both closed on exec.
#[derive(Debug)]
pub struct Pair {
    pub master: OwnedFd,
    pub slave: OwnedFd,
    /// The slave's path, as `tty` prints it; or, where `path` is false, what
    /// the pair is (a devpts instance of podssh's own, T-775).
    pub name: String,
    /// Whether `name` is a path that the child could open (`SSH_TTY`).
    pub path: bool,
}

/// Why no pty came: each path tried, with its reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoPty {
    /// No master opened.
    Master(String),
    /// A master opened, but no slave came of it.
    Slave(String),
}

impl fmt::Display for NoPty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoPty::Master(why) | NoPty::Slave(why) => f.write_str(why),
        }
    }
}

/// The probe: a pair from the first of [`PTMX`] that gives one, then from a
/// devpts instance of podssh's own where the host lets it make one (T-775).
pub fn open() -> Result<Pair, NoPty> {
    open_with(PTMX, true)
}

/// A pair from the first of `paths`, then, with `devpts`, from a new devpts
/// instance; the reasons of each, in that order, where none gives one.
pub fn open_with<P: AsRef<Path>>(paths: &[P], devpts: bool) -> Result<Pair, NoPty> {
    let failed = match open_from(paths) {
        Ok(pair) => return Ok(pair),
        Err(failed) => failed,
    };
    if !devpts {
        return Err(failed);
    }
    match devpts_pair() {
        Ok(pair) => Ok(pair),
        Err(why) => Err(match failed {
            NoPty::Master(first) => NoPty::Master(format!("{first}; a devpts instance: {why}")),
            NoPty::Slave(first) => NoPty::Slave(format!("{first}; a devpts instance: {why}")),
        }),
    }
}

#[cfg(target_os = "linux")]
fn devpts_pair() -> Result<Pair, String> {
    super::pty_devpts::open()
}

/// devpts' instances are Linux's.
#[cfg(not(target_os = "linux"))]
fn devpts_pair() -> Result<Pair, String> {
    Err("not on this system: a devpts instance is Linux's".into())
}

/// A pair from the first of `paths` that gives one.
pub fn open_from<P: AsRef<Path>>(paths: &[P]) -> Result<Pair, NoPty> {
    let mut whys = Vec::new();
    let mut opened = false;
    for path in paths {
        let path = path.as_ref();
        // std adds O_CLOEXEC; O_NOCTTY keeps serve itself from taking it.
        let master = match File::options().read(true).write(true).custom_flags(libc::O_NOCTTY).open(path) {
            Ok(file) => OwnedFd::from(file),
            Err(e) => {
                whys.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        opened = true;
        match slave_of(&master) {
            Ok((slave, name)) => return Ok(Pair { master, slave, name, path: true }),
            Err(e) => whys.push(format!("{} opens, but no pty comes of it: {e}", path.display())),
        }
    }
    if whys.is_empty() {
        whys.push("no path to try".into());
    }
    let why = whys.join("; ");
    Err(if opened { NoPty::Slave(why) } else { NoPty::Master(why) })
}

/// The slave of `master`, opened, and its name.
fn slave_of(master: &OwnedFd) -> Result<(OwnedFd, String), String> {
    let fd = master.as_raw_fd();
    // SAFETY: `fd` is an open master for both calls.
    if unsafe { libc::grantpt(fd) } != 0 {
        return Err(format!("grantpt: {}", io::Error::last_os_error()));
    }
    if unsafe { libc::unlockpt(fd) } != 0 {
        return Err(format!("unlockpt: {}", io::Error::last_os_error()));
    }
    let name = pts_name(fd).map_err(|e| format!("ptsname: {e}"))?;
    let slave = File::options()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(&name)
        .map_err(|e| format!("{name}: {e}"))?;
    Ok((OwnedFd::from(slave), name))
}

#[cfg(target_os = "linux")]
fn pts_name(master: RawFd) -> io::Result<String> {
    let mut buf = [0 as libc::c_char; 128];
    // SAFETY: the buffer's length is passed with it.
    let rc = unsafe { libc::ptsname_r(master, buf.as_mut_ptr(), buf.len()) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    // SAFETY: ptsname_r ends the name with a NUL inside the buffer.
    Ok(unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned())
}

#[cfg(not(target_os = "linux"))]
fn pts_name(master: RawFd) -> io::Result<String> {
    // ptsname's buffer is static: one caller at a time, copied out at once.
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: `master` is an open master; the name is copied before the lock ends.
    let p = unsafe { libc::ptsname(master) };
    if p.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

/// The size of a request: a zero width or height is sshd's 80x24, and each
/// value past what termios holds is cut to its most.
pub fn size_of(cols: u32, rows: u32, px_width: u32, px_height: u32) -> Size {
    if cols == 0 || rows == 0 {
        return DEFAULT_SIZE;
    }
    Size { cols, rows, px_width, px_height }
}

/// Set `size` on the pty of `fd` (the master: the kernel then tells the
/// slave's foreground group with SIGWINCH).
pub fn set_size(fd: RawFd, size: Size) -> io::Result<()> {
    let cut = |v: u32| u16::try_from(v).unwrap_or(u16::MAX);
    let ws = libc::winsize {
        ws_row: cut(size.rows),
        ws_col: cut(size.cols),
        ws_xpixel: cut(size.px_width),
        ws_ypixel: cut(size.px_height),
    };
    // SAFETY: TIOCSWINSZ reads the struct passed, on a descriptor that the
    // caller holds open.
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Apply the request's modes to the slave `fd`. A mode that the table lacks
/// is passed over; when the kernel refuses the whole set, each mode is
/// tried alone, and each one that it refuses is passed over too. The modes
/// passed over are returned.
pub fn set_modes(fd: RawFd, asked: &[(Pty, u32)]) -> io::Result<Vec<Pty>> {
    let current = get(fd)?;
    let mut wanted = current;
    let mut passed = modes::apply(&mut wanted, asked);
    if put(fd, &wanted).is_ok() {
        return Ok(passed);
    }
    let mut kept = current;
    for &(pty, value) in asked {
        if passed.contains(&pty) {
            continue;
        }
        let mut one = kept;
        modes::apply(&mut one, &[(pty, value)]);
        if put(fd, &one).is_ok() {
            kept = one;
        } else {
            passed.push(pty);
        }
    }
    put(fd, &kept)?;
    Ok(passed)
}

fn get(fd: RawFd) -> io::Result<libc::termios> {
    // SAFETY: an all-zero termios is valid, and tcgetattr writes into it.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(t)
}

fn put(fd: RawFd, t: &libc::termios) -> io::Result<()> {
    // SAFETY: a termios that tcgetattr filled, on a descriptor held open.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The `TERM` of a request: its own, else [`DEFAULT_TERM`].
pub fn term_of(asked: &str) -> String {
    let asked = asked.trim();
    if asked.is_empty() || asked.contains('\0') {
        DEFAULT_TERM.to_string()
    } else {
        asked.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_size_is_80_by_24_and_a_term_is_never_empty() {
        assert_eq!(size_of(0, 50, 0, 0), DEFAULT_SIZE);
        assert_eq!(size_of(120, 0, 0, 0), DEFAULT_SIZE);
        assert_eq!(size_of(120, 40, 1, 2), Size { cols: 120, rows: 40, px_width: 1, px_height: 2 });
        assert_eq!(term_of(""), DEFAULT_TERM);
        assert_eq!(term_of("vt100"), "vt100");
    }

    #[test]
    fn no_master_names_each_path_tried() {
        let err = open_from(&["/nonexistent/ptmx", "/nonexistent/pts/ptmx"]).expect_err("no such master");
        let NoPty::Master(why) = &err else { panic!("{err:?}") };
        assert!(why.starts_with("/nonexistent/ptmx: "), "{why}");
        assert!(why.contains("; /nonexistent/pts/ptmx: "), "{why}");
    }

    /// The probe on this host: a pair whose slave is a terminal with the
    /// size and the modes set on it; or "did not run" where none opens.
    #[test]
    fn a_pair_takes_the_size_and_the_modes_where_one_opens() {
        let pair = match open() {
            Ok(pair) => pair,
            Err(why) => {
                eprintln!("did not run: no pty here: {why}");
                return;
            }
        };
        assert!(pair.name.starts_with("/dev/"), "{}", pair.name);
        // SAFETY: isatty only asks what the descriptor is.
        assert_eq!(unsafe { libc::isatty(pair.slave.as_raw_fd()) }, 1);
        set_size(pair.master.as_raw_fd(), size_of(132, 43, 0, 0)).unwrap();
        assert_eq!(crate::terminal::size_of_fd(pair.slave.as_raw_fd()).map(|s| (s.cols, s.rows)), Some((132, 43)));
        let passed = set_modes(pair.slave.as_raw_fd(), &[(Pty::ECHO, 0), (Pty::VERASE, 8), (Pty::VFLUSH, 1)]).unwrap();
        assert_eq!(passed, vec![Pty::VFLUSH], "a mode that the table lacks is passed over");
        let back = crate::terminal::pty_modes_of(pair.slave.as_raw_fd());
        assert!(back.contains(&(Pty::ECHO, 0)) && back.contains(&(Pty::VERASE, 8)), "{back:?}");
    }
}
