//! The supervisor of one child (T-776): a thread of serve's that answers
//! the child's tty calls on the socket that serve gave it, from the one
//! termios state that the discipline also reads, and lets each other call
//! go on to the kernel. `open` of `/dev/tty` gets a copy of that socket. A
//! call on another descriptor, or one that no way here can tell, is the
//! kernel's; a request that a tty has and this one does not answer is
//! `ENOTTY`, as a tty that lacks it says.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use pod_term::termios::{flags::NCCS, Event, Termios, Tty, When};
use pod_term::window::Size;
use tokio::sync::mpsc;

use super::reach::{self, Ours};

// The tty requests that the supervisor answers (asm-generic, the same on
// x86_64 and aarch64).
const TCGETS: u32 = 0x5401;
const TCSETS: u32 = 0x5402;
const TCSETSW: u32 = 0x5403;
const TCSETSF: u32 = 0x5404;
const TCSBRK: u32 = 0x5409;
const TCXONC: u32 = 0x540a;
const TCFLSH: u32 = 0x540b;
const TIOCEXCL: u32 = 0x540c;
const TIOCNXCL: u32 = 0x540d;
const TIOCSCTTY: u32 = 0x540e;
const TIOCGPGRP: u32 = 0x540f;
const TIOCSPGRP: u32 = 0x5410;
const TIOCGWINSZ: u32 = 0x5413;
const TIOCSWINSZ: u32 = 0x5414;
const TIOCNOTTY: u32 = 0x5422;
const TIOCSETD: u32 = 0x5423;
const TIOCGETD: u32 = 0x5424;
const TCSBRKP: u32 = 0x5425;
const TIOCGSID: u32 = 0x5429;
const TCGETS2: u32 = 0x802c_542a;
const TCSETS2: u32 = 0x402c_542b;
const TCSETSW2: u32 = 0x402c_542c;
const TCSETSF2: u32 = 0x402c_542d;
/// The requests of the family that a socket answers itself: its bytes
/// waiting, its blocking and its close-on-exec.
const SOCKET_OWN: &[u32] = &[0x541b, 0x5411, 0x5421, 0x5450, 0x5451, 0x5452];

/// The kernel's `struct termios` (`TCGETS`) is 36 bytes; `termios2` adds
/// the two speeds.
const TERMIOS: usize = 36;
const TERMIOS2: usize = 44;

/// What the supervisor and the discipline share.
pub struct Shared {
    pub tty: Tty,
    /// `c_line`, and the speeds of `termios2`: kept as data.
    pub line: u8,
    pub speeds: (u32, u32),
    /// The pixels of `TIOCSWINSZ`, kept as data.
    pub pixels: (u16, u16),
    /// The foreground process group and the session, as `TIOCSPGRP` set it.
    pub fg: i32,
    pub sid: i32,
}

impl Shared {
    pub fn new(tty: Tty, leader: i32) -> Shared {
        Shared { tty, line: 0, speeds: (38400, 38400), pixels: (0, 0), fg: leader, sid: leader }
    }

    fn bytes(&self, len: usize) -> Vec<u8> {
        let s = self.tty.state();
        let mut out = Vec::with_capacity(TERMIOS2);
        for word in [s.iflag, s.oflag, s.cflag, s.lflag] {
            out.extend_from_slice(&word.to_ne_bytes());
        }
        out.push(self.line);
        out.extend_from_slice(&s.cc);
        out.extend_from_slice(&self.speeds.0.to_ne_bytes());
        out.extend_from_slice(&self.speeds.1.to_ne_bytes());
        out.truncate(len);
        out
    }
}

/// The state that `bytes`, as `TCSETS` or `TCSETS2` carried it, sets.
fn termios_of(bytes: &[u8]) -> (Termios, u8, Option<(u32, u32)>) {
    let word = |at: usize| u32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    let mut cc = [0u8; NCCS];
    cc.copy_from_slice(&bytes[17..17 + NCCS]);
    let speeds = (bytes.len() >= TERMIOS2).then(|| (word(36), word(40)));
    (Termios { iflag: word(0), oflag: word(4), cflag: word(8), lflag: word(12), cc }, bytes[16], speeds)
}

/// What the discipline does for a call of the child's.
#[derive(Debug)]
pub enum Told {
    /// Events of the tty: a new state's line, a signal for a new size.
    Events(Vec<Event>),
    /// `TCFLSH` of the output, or `TCSETSF`: drop what is held for the user.
    DropOutput,
    /// `TCXONC`: stop or start the output.
    Output(bool),
}

/// One answer to the kernel.
enum Answer {
    /// The value of the call.
    Value(i64),
    /// An error number.
    Error(i32),
    /// The kernel answers it.
    Kernel,
    /// Answered already (`/dev/tty` with `SECCOMP_ADDFD_FLAG_SEND`).
    Sent,
}

/// The supervisor of `listener`, until no process holds the filter or
/// `stop` is set.
pub struct Supervisor {
    pub listener: OwnedFd,
    pub ours: Ours,
    pub shared: Arc<Mutex<Shared>>,
    pub told: mpsc::UnboundedSender<Told>,
    pub stop: Arc<AtomicBool>,
}

impl Supervisor {
    /// The thread's loop. The listener reads as hung up once each process
    /// of the filter ended.
    pub fn run(self) {
        let mut sizes: libc::seccomp_notif_sizes = unsafe { std::mem::zeroed() };
        // SAFETY: the kernel writes the three sizes into `sizes`.
        unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_GET_NOTIF_SIZES as libc::c_ulong,
                0 as libc::c_ulong,
                &mut sizes as *mut libc::seccomp_notif_sizes,
            )
        };
        let room = (sizes.seccomp_notif as usize).max(std::mem::size_of::<libc::seccomp_notif>());
        let mut buf = vec![0u64; room.div_ceil(8)];
        let fd = self.listener.as_raw_fd();
        while !self.stop.load(Ordering::SeqCst) {
            let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            // SAFETY: one pollfd, which outlives the call.
            let ready = unsafe { libc::poll(&mut poll, 1, 250) };
            if ready < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return;
            }
            if poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                return;
            }
            if poll.revents & libc::POLLIN == 0 {
                continue;
            }
            buf.iter_mut().for_each(|w| *w = 0);
            let notif = buf.as_mut_ptr().cast::<libc::seccomp_notif>();
            // SAFETY: `buf` holds the kernel's size of a notification.
            if unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_RECV as _, notif) } != 0 {
                continue;
            }
            // SAFETY: the kernel filled the notification.
            let n = unsafe { &*notif };
            let answer = if n.data.nr == libc::SYS_ioctl as i32 { self.ioctl(n) } else { self.open(n) };
            self.reply(n.id, answer);
        }
    }

    fn reply(&self, id: u64, answer: Answer) {
        let (val, error, flags) = match answer {
            Answer::Sent => return,
            Answer::Value(v) => (v, 0, 0),
            Answer::Error(e) => (0, -e, 0),
            Answer::Kernel => (0, 0, libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32),
        };
        let mut resp = libc::seccomp_notif_resp { id, val, error, flags };
        // SAFETY: one response, which outlives the call; ENOENT is a child
        // whose call ended (a signal), and nothing waits for the answer.
        unsafe { libc::ioctl(self.listener.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_SEND as _, &mut resp) };
    }

    /// Whether the notification `id` still waits: a child that a signal
    /// took out of its call must not see the state that it asked for set.
    fn valid(&self, id: u64) -> bool {
        let mut id = id;
        // SAFETY: the kernel reads the id.
        unsafe { libc::ioctl(self.listener.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_ID_VALID as _, &mut id) == 0 }
    }

    fn ioctl(&self, n: &libc::seccomp_notif) -> Answer {
        let (fd, cmd, arg) = (n.data.args[0] as i32, n.data.args[1] as u32, n.data.args[2]);
        if SOCKET_OWN.contains(&cmd) {
            return Answer::Kernel;
        }
        match self.ours.holds(n.pid, fd) {
            Some(true) => {}
            _ => return Answer::Kernel,
        }
        let pid = n.pid;
        let put = |bytes: &[u8]| match reach::write(pid, arg, bytes) {
            Ok(()) => Answer::Value(0),
            Err(_) => Answer::Error(libc::EFAULT),
        };
        let mut shared = match self.shared.lock() {
            Ok(shared) => shared,
            Err(poisoned) => poisoned.into_inner(),
        };
        match cmd {
            TCGETS => put(&shared.bytes(TERMIOS)),
            TCGETS2 => put(&shared.bytes(TERMIOS2)),
            TCSETS | TCSETSW | TCSETSF | TCSETS2 | TCSETSW2 | TCSETSF2 => {
                let len = if matches!(cmd, TCSETS | TCSETSW | TCSETSF) { TERMIOS } else { TERMIOS2 };
                let mut bytes = vec![0u8; len];
                if reach::read(pid, arg, &mut bytes).is_err() {
                    return Answer::Error(libc::EFAULT);
                }
                if !self.valid(n.id) {
                    return Answer::Error(libc::EINTR);
                }
                let when = match cmd {
                    TCSETS | TCSETS2 => When::Now,
                    TCSETSW | TCSETSW2 => When::Drain,
                    _ => When::Flush,
                };
                let (state, line, speeds) = termios_of(&bytes);
                shared.line = line;
                if let Some(speeds) = speeds {
                    shared.speeds = speeds;
                }
                let events = shared.tty.set(state, when);
                if when == When::Flush {
                    let _ = self.told.send(Told::DropOutput);
                }
                if !events.is_empty() {
                    let _ = self.told.send(Told::Events(events));
                }
                Answer::Value(0)
            }
            TIOCGWINSZ => {
                let size = shared.tty.size();
                let mut w = Vec::with_capacity(8);
                for v in [size.rows, size.cols, shared.pixels.0, shared.pixels.1] {
                    w.extend_from_slice(&v.to_ne_bytes());
                }
                put(&w)
            }
            TIOCSWINSZ => {
                let mut w = [0u8; 8];
                if reach::read(pid, arg, &mut w).is_err() {
                    return Answer::Error(libc::EFAULT);
                }
                let half = |at: usize| u16::from_ne_bytes([w[at], w[at + 1]]);
                shared.pixels = (half(4), half(6));
                let events = shared.tty.resize(Size { rows: half(0), cols: half(2) });
                if !events.is_empty() {
                    let _ = self.told.send(Told::Events(events));
                }
                Answer::Value(0)
            }
            TIOCGPGRP => put(&shared.fg.to_ne_bytes()),
            TIOCGSID => put(&shared.sid.to_ne_bytes()),
            TIOCGETD => put(&0i32.to_ne_bytes()),
            TIOCSPGRP => {
                let mut g = [0u8; 4];
                if reach::read(pid, arg, &mut g).is_err() {
                    return Answer::Error(libc::EFAULT);
                }
                shared.fg = i32::from_ne_bytes(g);
                Answer::Value(0)
            }
            TCFLSH => {
                // TCIFLUSH 0, TCOFLUSH 1, TCIOFLUSH 2.
                if arg != 1 {
                    shared.tty.flush();
                }
                if arg != 0 {
                    let _ = self.told.send(Told::DropOutput);
                }
                Answer::Value(0)
            }
            TCXONC => {
                // TCOOFF 0 and TCOON 1; TCIOFF and TCION send a byte to a
                // device that has none here.
                if arg <= 1 {
                    let _ = self.told.send(Told::Output(arg == 1));
                }
                Answer::Value(0)
            }
            TCSBRK | TCSBRKP | TIOCSCTTY | TIOCNOTTY | TIOCSETD | TIOCEXCL | TIOCNXCL => Answer::Value(0),
            _ => Answer::Error(libc::ENOTTY),
        }
    }

    /// `open` and `openat`: `/dev/tty` is a copy of the child's socket; each
    /// other path is the kernel's.
    fn open(&self, n: &libc::seccomp_notif) -> Answer {
        let at = n.data.nr == libc::SYS_openat as i32;
        let (addr, flags) = if at { (n.data.args[1], n.data.args[2]) } else { (n.data.args[0], n.data.args[1]) };
        let Some(path) = reach::path(n.pid, addr, 16) else { return Answer::Kernel };
        if path != b"/dev/tty" || !self.valid(n.id) {
            return Answer::Kernel;
        }
        let cloexec = (flags as i32 & libc::O_CLOEXEC) as u32;
        let mut add = libc::seccomp_notif_addfd {
            id: n.id,
            flags: libc::SECCOMP_ADDFD_FLAG_SEND as u32,
            srcfd: self.ours.fd().as_raw_fd() as u32,
            newfd: 0,
            newfd_flags: cloexec,
        };
        let fd = self.listener.as_raw_fd();
        // SAFETY: one request, which outlives the call. With the flag SEND,
        // the kernel answers the call with the new descriptor (5.14).
        if unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_ADDFD as _, &mut add) } >= 0 {
            return Answer::Sent;
        }
        // An older kernel: the descriptor first, then its number as the value.
        add.flags = 0;
        // SAFETY: as above.
        let newfd = unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_ADDFD as _, &mut add) };
        if newfd >= 0 {
            Answer::Value(newfd as i64)
        } else {
            Answer::Error(libc::ENXIO)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_state_reads_back_as_tcgets_gives_it() {
        let shared = Shared::new(Tty::new(Termios::sane()), 1);
        let bytes = shared.bytes(TERMIOS2);
        assert_eq!(bytes.len(), TERMIOS2);
        let (state, line, speeds) = termios_of(&bytes);
        assert_eq!((state, line, speeds), (Termios::sane(), 0, Some((38400, 38400))));
        let (_, _, none) = termios_of(&shared.bytes(TERMIOS));
        assert_eq!(none, None, "TCSETS carries no speeds");
        // `stty -g` of a new Linux pty begins 500:5:bf:8a3b.
        let word = |at: usize| u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap());
        assert_eq!((word(0), word(4), word(8), word(12)), (0x500, 0x5, 0xbf, 0x8a3b));
    }
}
