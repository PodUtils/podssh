//! The tracer of one child (T-777, route 2b of T-248's study): where a
//! filter of the sandbox's already holds a listener (EBUSY), the child's
//! filter returns `SECCOMP_RET_TRACE`, and a thread of serve's, which seized
//! it before its exec, answers each of its tty calls at the call's stop,
//! from the registers ([`super::regs`]) and the same answers as the
//! notifications' ([`Answerer`]). It follows each process and thread that
//! the child starts, since a traced call with no tracer fails with ENOSYS;
//! a stop of job control stays a stop (`PTRACE_LISTEN`), and each other
//! signal goes on. `open` of `/dev/tty` becomes `fcntl(F_DUPFD)` of a
//! descriptor of the caller that holds the socket, or ENXIO where none
//! does. The child's own exit is left to its reaper (tokio's, by pidfd).

use std::collections::HashSet;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::answer::{Answer, Answerer};
use super::{reach, regs};

/// `addr` of a ptrace request that takes none: a whole word, as the call
/// is variadic and the kernel reads a pointer.
const NULL: *mut libc::c_void = std::ptr::null_mut();

const EVENT_FORK: i32 = 1;
const EVENT_VFORK: i32 = 2;
const EVENT_CLONE: i32 = 3;
const EVENT_SECCOMP: i32 = 7;
const EVENT_STOP: i32 = 128;

/// The pause of a loop that found no stop.
const IDLE: Duration = Duration::from_micros(500);

/// The options of the seize: each stop of the filter, each process and
/// thread that a tracee starts, and each tracee killed with serve.
pub const OPTIONS: libc::c_int = libc::PTRACE_O_TRACESECCOMP
    | libc::PTRACE_O_TRACEFORK
    | libc::PTRACE_O_TRACEVFORK
    | libc::PTRACE_O_TRACECLONE
    | libc::PTRACE_O_EXITKILL;

/// Seize `pid` from this thread, which is then its tracer.
pub fn seize(pid: i32) -> std::io::Result<()> {
    // SAFETY: a seize names a process and options; it writes no memory.
    let rc = unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, NULL, OPTIONS as libc::c_long) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// The tracer of `leader` and the processes it starts, on this thread.
pub struct Tracer {
    pub leader: i32,
    pub answerer: Answerer,
    pub stop: Arc<AtomicBool>,
}

impl Tracer {
    /// Until no tracee is left, or `stop` once the leader is gone.
    pub fn run(self) {
        let mut traced: HashSet<i32> = HashSet::from([self.leader]);
        while !traced.is_empty() {
            let mut any = false;
            for pid in traced.clone() {
                let Some(status) = self.next(pid, &mut traced) else { continue };
                any = true;
                self.handle(pid, status, &mut traced);
            }
            if !any {
                if self.stop.load(Ordering::SeqCst) && !traced.contains(&self.leader) {
                    return;
                }
                std::thread::sleep(IDLE);
            }
        }
    }

    /// The next event of `pid`, if one waits. The leader's exit is its
    /// reaper's: seen, not taken.
    fn next(&self, pid: i32, traced: &mut HashSet<i32>) -> Option<i32> {
        if pid == self.leader {
            // SAFETY: an all-zero siginfo is valid, and the kernel fills it.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let flags = libc::WEXITED | libc::WNOHANG | libc::WNOWAIT;
            // SAFETY: waitid writes one siginfo, which outlives the call.
            let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, flags) };
            let gone = rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD);
            // SAFETY: si_pid is set where waitid found the child's end.
            // A tracee's stops come to its tracer's waitid too, with no
            // WSTOPPED: the end is an exit, a kill or a dump alone.
            let ended = matches!(info.si_code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED);
            // SAFETY: si_pid is set where waitid found an event of the child.
            if gone || (rc == 0 && ended && unsafe { info.si_pid() } == pid) {
                traced.remove(&pid);
                return None;
            }
        }
        let mut status = 0;
        // SAFETY: waitpid writes one status.
        let got = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) };
        match got {
            0 => None,
            n if n < 0 => {
                traced.remove(&pid);
                None
            }
            _ => Some(status),
        }
    }

    fn handle(&self, pid: i32, status: i32, traced: &mut HashSet<i32>) {
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            traced.remove(&pid);
            return;
        }
        if !libc::WIFSTOPPED(status) {
            return;
        }
        let sig = libc::WSTOPSIG(status);
        match (status >> 16) & 0xff {
            EVENT_SECCOMP => {
                self.call(pid);
                cont(pid, 0);
            }
            EVENT_FORK | EVENT_VFORK | EVENT_CLONE => {
                let mut new: libc::c_ulong = 0;
                // SAFETY: GETEVENTMSG writes one word, the new tracee's pid.
                if unsafe { libc::ptrace(libc::PTRACE_GETEVENTMSG, pid, NULL, &mut new as *mut libc::c_ulong) } == 0 {
                    traced.insert(new as i32);
                }
                cont(pid, 0);
            }
            // A stop of job control stays one until SIGCONT; a new tracee's
            // first stop goes on.
            EVENT_STOP if matches!(sig, libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU) => {
                // SAFETY: LISTEN names a stopped tracee; it writes no memory.
                unsafe { libc::ptrace(libc::PTRACE_LISTEN, pid, NULL, 0 as libc::c_long) };
            }
            0 => cont(pid, sig),
            _ => cont(pid, 0),
        }
    }

    /// One call at its stop: answered and skipped, made another, or left
    /// to the kernel.
    fn call(&self, pid: i32) {
        let Ok(r) = regs::get(pid) else { return };
        let call = regs::call(&r);
        if call.nr == libc::SYS_ioctl {
            let (fd, cmd, arg) = (call.args[0] as i32, call.args[1] as u32, call.args[2]);
            match self.answerer.ioctl(pid as u32, fd, cmd, arg, &|| true) {
                Answer::Kernel | Answer::Sent => {}
                Answer::Value(v) => drop(regs::skip(pid, r, v)),
                Answer::Error(e) => drop(regs::skip(pid, r, -(e as i64))),
            }
            return;
        }
        let at = call.nr == libc::SYS_openat;
        let (addr, flags) = if at { (call.args[1], call.args[2]) } else { (call.args[0], call.args[1]) };
        if reach::path(pid as u32, addr, 16).as_deref() != Some(&b"/dev/tty"[..]) {
            return;
        }
        let dup = if flags as i32 & libc::O_CLOEXEC != 0 { libc::F_DUPFD_CLOEXEC } else { libc::F_DUPFD };
        let _ = match self.held_by(pid) {
            Some(fd) => regs::rewrite(pid, r, libc::SYS_fcntl, [fd as u64, dup as u64, 0]),
            None => regs::skip(pid, r, -(libc::ENXIO as i64)),
        };
    }

    /// A descriptor of `pid` that holds the tty socket: 0 to 2 first, then
    /// the rest of the first 256.
    fn held_by(&self, pid: i32) -> Option<i32> {
        (0..256).find(|fd| self.answerer.ours.holds(pid as u32, *fd) == Some(true))
    }
}

/// `pid` goes on, with `sig` delivered (0: none).
fn cont(pid: i32, sig: i32) {
    // SAFETY: CONT names a stopped tracee and a signal; it writes no memory.
    unsafe { libc::ptrace(libc::PTRACE_CONT, pid, NULL, sig as libc::c_long) };
}

/// The child's side, between its fork and its exec: its pid to the tracer
/// on `ctl`, then a wait for the tracer's byte, which comes once it seized
/// the child. Only calls that are safe there.
///
/// # Safety
///
/// `ctl` must be an open stream socket to the tracer.
pub unsafe fn wait_for_tracer(ctl: libc::c_int) -> std::io::Result<()> {
    // SAFETY: getpid, write and read on buffers of this frame.
    unsafe {
        let pid = libc::getpid().to_ne_bytes();
        if libc::write(ctl, pid.as_ptr().cast(), pid.len()) != pid.len() as isize {
            return Err(std::io::Error::last_os_error());
        }
        let mut go = [0u8; 1];
        if libc::read(ctl, go.as_mut_ptr().cast(), 1) != 1 {
            return Err(std::io::Error::other("the tracer did not seize this child"));
        }
    }
    Ok(())
}

/// The tracer's side: the child's pid from `ctl`, the seize, then the byte
/// that lets the child go on to its exec.
pub fn take(ctl: &OwnedFd) -> std::io::Result<i32> {
    let mut pid = [0u8; 4];
    // SAFETY: read into a buffer of this frame.
    if unsafe { libc::read(ctl.as_raw_fd(), pid.as_mut_ptr().cast(), 4) } != 4 {
        return Err(std::io::Error::other("the child sent no pid"));
    }
    let pid = i32::from_ne_bytes(pid);
    seize(pid)?;
    // SAFETY: write from a buffer of this frame.
    if unsafe { libc::write(ctl.as_raw_fd(), b"g".as_ptr().cast(), 1) } != 1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(pid)
}
