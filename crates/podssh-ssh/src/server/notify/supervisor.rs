//! The supervisor of one child (T-776): a thread of serve's that takes the
//! child's tty calls as seccomp user notifications and answers them
//! ([`Answerer`]), and lets each other call go on to the kernel. `open` of
//! `/dev/tty` gets a copy of the child's socket.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::answer::{Answer, Answerer};
use super::reach;

/// The supervisor of `listener`, until no process holds the filter or
/// `stop` is set.
pub struct Supervisor {
    pub listener: OwnedFd,
    pub answerer: Answerer,
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
            let answer = if n.data.nr == libc::SYS_ioctl as i32 {
                let (fd, cmd, arg) = (n.data.args[0] as i32, n.data.args[1] as u32, n.data.args[2]);
                self.answerer.ioctl(n.pid, fd, cmd, arg, &|| self.valid(n.id))
            } else {
                self.open(n)
            };
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
            srcfd: self.answerer.ours.fd().as_raw_fd() as u32,
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
