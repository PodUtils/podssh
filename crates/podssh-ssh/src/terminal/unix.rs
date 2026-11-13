//! Unix terminals, through termios.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::sync::Mutex;

use russh::Pty;
use zeroize::Zeroizing;

use super::Size;

pub fn is_console(_stderr: bool) -> bool {
    false
}

pub fn size() -> Option<Size> {
    [libc::STDOUT_FILENO, libc::STDIN_FILENO, libc::STDERR_FILENO].into_iter().find_map(size_of_fd)
}

/// The window size of the terminal behind `fd`: for podssh's own terminal,
/// and for a client's that a control master holds (T-039).
pub fn size_of_fd(fd: libc::c_int) -> Option<Size> {
    // SAFETY: an all-zero winsize is valid, and TIOCGWINSZ only writes into
    // the struct passed.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    (rc == 0 && ws.ws_col > 0 && ws.ws_row > 0).then(|| Size {
        cols: ws.ws_col.into(),
        rows: ws.ws_row.into(),
        px_width: ws.ws_xpixel.into(),
        px_height: ws.ws_ypixel.into(),
    })
}

/// The settings to put back, kept where a panic hook can reach them: the
/// release build aborts on panic, so `Drop` alone would leave the user's
/// terminal raw.
static SAVED: Mutex<Option<libc::termios>> = Mutex::new(None);

fn restore_saved() {
    let saved = SAVED.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(t) = saved {
        // SAFETY: `t` is a termios read by tcgetattr on the same descriptor.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &t) };
        super::set_raw_active(false);
    }
}

/// The local terminal in raw mode until this is dropped.
pub struct RawMode(());

impl RawMode {
    pub fn enter() -> std::io::Result<RawMode> {
        // SAFETY: plain termios calls on stdin with structs we own.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut saved) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut raw = saved;
        unsafe { libc::cfmakeraw(&mut raw) };
        *SAVED.lock().unwrap_or_else(|e| e.into_inner()) = Some(saved);
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &raw) } != 0 {
            let err = std::io::Error::last_os_error();
            SAVED.lock().unwrap_or_else(|e| e.into_inner()).take();
            return Err(err);
        }
        super::set_raw_active(true);
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_saved();
            previous(info);
        }));
        Ok(RawMode(()))
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        restore_saved();
    }
}

/// The local terminal's settings as RFC 4254 §8 terminal modes, so the remote
/// pty behaves like the local terminal (the erase key above all). Empty when
/// stdin is not a terminal, as OpenSSH sends.
pub fn pty_modes() -> Vec<(Pty, u32)> {
    pty_modes_of(libc::STDIN_FILENO)
}

/// The modes of the terminal behind `fd`, as [`pty_modes`] gives them.
pub fn pty_modes_of(fd: libc::c_int) -> Vec<(Pty, u32)> {
    // SAFETY: tcgetattr writes into a struct we own.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
        return Vec::new();
    }
    // One table, read the other way by `podssh serve` (T-110).
    super::modes::encode(&t)
}

/// Ask on the controlling terminal (`/dev/tty`), which works even when stdin
/// and stdout are pipes. An error when there is no controlling terminal
/// ([`super::ctty`]), and `TimedOut` when nobody answers within
/// [`super::prompt_limit`].
///
/// Without echo, the terminal is read one key at a time with signals off, so
/// Ctrl-C cancels the prompt (an `Interrupted` error) instead of killing
/// podssh with echo still turned off.
pub fn read_line(prompt: &str, echo: bool) -> std::io::Result<Zeroizing<String>> {
    let mut tty = super::ctty::open()?;
    let fd = tty.as_raw_fd();
    tty.write_all(prompt.as_bytes())?;
    tty.flush()?;
    // SAFETY: termios calls on a descriptor we hold open, structs we own.
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let have_termios = unsafe { libc::tcgetattr(fd, &mut saved) } == 0;
    if !echo && have_termios {
        let mut quiet = saved;
        quiet.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL | libc::ICANON | libc::ISIG);
        quiet.c_cc[libc::VMIN] = 1;
        quiet.c_cc[libc::VTIME] = 0;
        unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) };
    }
    let deadline = super::prompt_limit().map(|limit| std::time::Instant::now() + limit);
    let result = read_keys(&mut tty, !echo && have_termios, deadline);
    if !echo && have_termios {
        unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &saved) };
        let _ = tty.write_all(b"\n");
    }
    if result.as_ref().is_err_and(|e| e.kind() == std::io::ErrorKind::TimedOut) {
        let _ = tty.write_all(b"(no answer)\n");
    }
    result
}

fn read_keys(
    tty: &mut std::fs::File,
    keywise: bool,
    deadline: Option<std::time::Instant>,
) -> std::io::Result<Zeroizing<String>> {
    let mut line = Zeroizing::new(Vec::<u8>::new());
    let mut byte = [0u8; 1];
    loop {
        wait_readable(tty.as_raw_fd(), deadline)?;
        match tty.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => match byte[0] {
                b'\n' | b'\r' => break,
                0x03 if keywise => return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled")),
                0x04 if keywise && line.is_empty() => {
                    return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"))
                }
                0x7f | 0x08 if keywise => {
                    line.pop();
                }
                0x15 if keywise => line.clear(),
                b => line.push(b),
            },
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(Zeroizing::new(String::from_utf8_lossy(&line).into_owned()))
}

/// Wait until `fd` can be read, or fail with `TimedOut` at `deadline`. With
/// no deadline, return at once: the read itself waits.
fn wait_readable(fd: std::os::fd::RawFd, deadline: Option<std::time::Instant>) -> std::io::Result<()> {
    let Some(deadline) = deadline else { return Ok(()) };
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "no answer on the terminal"));
        }
        let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let ms = left.as_millis().clamp(1, i32::MAX as u128) as i32;
        // SAFETY: one pollfd that this function owns, for a descriptor held open.
        match unsafe { libc::poll(&mut p, 1, ms) } {
            n if n > 0 => return Ok(()),
            0 => continue,
            _ => {
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    fn pipe() -> (std::fs::File, std::fs::File) {
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for the two descriptors pipe() writes.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the descriptors are new and owned by nothing else.
        unsafe { (std::fs::File::from_raw_fd(fds[0]), std::fs::File::from_raw_fd(fds[1])) }
    }

    /// Nobody writes: the read stops at the deadline instead of waiting for
    /// ever, which is what a terminal that nobody watches needs.
    #[test]
    fn a_read_with_a_deadline_stops_when_nobody_answers() {
        let (mut rx, _tx) = pipe();
        let start = std::time::Instant::now();
        let deadline = Some(start + std::time::Duration::from_millis(300));
        let err = read_keys(&mut rx, false, deadline).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }

    /// The control: an answer that comes in time is read.
    #[test]
    fn an_answer_in_time_is_read() {
        let (mut rx, mut tx) = pipe();
        tx.write_all(b"yes\n").unwrap();
        let deadline = Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
        assert_eq!(read_keys(&mut rx, false, deadline).unwrap().as_str(), "yes");
    }
}
