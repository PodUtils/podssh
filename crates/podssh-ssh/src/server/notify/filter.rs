//! The child's seccomp filter (T-776): each `ioctl` whose request is of the
//! tty family (`0x54xx`) and each `open` and `openat` go to serve as user
//! notifications; each other call, and each call of another architecture's
//! numbers, goes to the kernel as before. The filter is installed in the
//! child between its fork and its exec, from code of serve's own process,
//! and its listener goes back to serve over a socket of the pair; the
//! child's program gets no code of serve's.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// `AUDIT_ARCH_*` of this build's architecture: a call made with another
/// one's numbers (a 32-bit program on x86_64) goes to the kernel.
#[cfg(target_arch = "x86_64")]
const ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const ARCH: u32 = 0xc000_00b7;

/// The tty family of `ioctl` requests: `TCGETS` is `0x5401`, and the
/// termios2 requests (`0x802c542a`) keep `0x54` in their second byte.
const TTY_FAMILY: u32 = 0x5400;

// The classic BPF opcodes of the filter (linux/filter.h, linux/bpf_common.h):
// BPF_LD | BPF_W | BPF_ABS (0x00, 0x00, 0x20), BPF_JMP | BPF_JEQ | BPF_K
// (0x05, 0x10, 0x00), BPF_ALU | BPF_AND | BPF_K (0x04, 0x50, 0x00), and
// BPF_RET | BPF_K (0x06, 0x00).
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_RET_K: u16 = 0x06;

// The offsets in `struct seccomp_data`: nr, arch, then args at 16.
const NR: u32 = 0;
const AT_ARCH: u32 = 4;
const ARG1: u32 = 16 + 8;

const RET_ALLOW: u32 = 0x7fff_0000;
const RET_USER_NOTIF: u32 = 0x7fc0_0000;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// `SECCOMP_RET_TRACE`: the call stops for the tracer (T-777).
const RET_TRACE: u32 = 0x7ff0_0000;

/// The filter's program, as the study's probe has it: the calls go to
/// serve as user notifications.
pub fn program() -> Vec<libc::sock_filter> {
    with_action(RET_USER_NOTIF)
}

/// The same program for the tracer of T-777: the calls stop the child for
/// serve's `ptrace`.
pub fn traced() -> Vec<libc::sock_filter> {
    with_action(RET_TRACE)
}

fn with_action(action: u32) -> Vec<libc::sock_filter> {
    #[cfg(target_arch = "x86_64")]
    let opens = [libc::SYS_openat as u32, libc::SYS_open as u32];
    // aarch64 has no `open`: the same number twice keeps one program.
    #[cfg(target_arch = "aarch64")]
    let opens = [libc::SYS_openat as u32, libc::SYS_openat as u32];
    vec![
        stmt(BPF_LD_W_ABS, AT_ARCH),
        jump(BPF_JMP_JEQ_K, ARCH, 1, 0),
        stmt(BPF_RET_K, RET_ALLOW),
        stmt(BPF_LD_W_ABS, NR),
        jump(BPF_JMP_JEQ_K, opens[0], 6, 0),
        jump(BPF_JMP_JEQ_K, opens[1], 5, 0),
        jump(BPF_JMP_JEQ_K, libc::SYS_ioctl as u32, 0, 3),
        stmt(BPF_LD_W_ABS, ARG1),
        stmt(BPF_ALU_AND_K, 0xff00),
        jump(BPF_JMP_JEQ_K, TTY_FAMILY, 1, 0),
        stmt(BPF_RET_K, RET_ALLOW),
        stmt(BPF_RET_K, action),
    ]
}

/// Install `program` on the calling thread with a new listener, after
/// `PR_SET_NO_NEW_PRIVS`, which a filter of an unprivileged process needs.
/// Only calls that are safe between a fork and an exec.
///
/// # Safety
///
/// `program` must stay alive for the call; it is only read.
pub unsafe fn install(program: &[libc::sock_filter]) -> io::Result<RawFd> {
    // SAFETY: the caller keeps the contract above.
    unsafe { install_with(program, libc::SECCOMP_FILTER_FLAG_NEW_LISTENER as libc::c_ulong) }
}

/// [`install`] with no listener, for the tracer's program: a stop for a
/// tracer needs none, and a filter of the sandbox's that holds one (EBUSY
/// for a second) does not refuse it.
///
/// # Safety
///
/// As [`install`].
pub unsafe fn install_traced(program: &[libc::sock_filter]) -> io::Result<()> {
    // SAFETY: the caller keeps the contract above.
    unsafe { install_with(program, 0).map(|_| ()) }
}

unsafe fn install_with(program: &[libc::sock_filter], flags: libc::c_ulong) -> io::Result<RawFd> {
    // SAFETY: the caller keeps the function's contract, above.
    unsafe {
        if libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
            && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        {
            return Err(io::Error::last_os_error());
        }
        let prog = libc::sock_fprog { len: program.len() as u16, filter: program.as_ptr() as *mut libc::sock_filter };
        // Each argument as a whole word: a variadic call leaves the high half
        // of a narrower one unset.
        let fd = libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER as libc::c_ulong,
            flags,
            &prog as *const libc::sock_fprog,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd as RawFd)
    }
}

/// Send `fd` over `sock` as `SCM_RIGHTS`, or the error `errno` as the text
/// `E<errno>` when there is no descriptor. Safe between a fork and an exec.
///
/// # Safety
///
/// `sock` must be an open `AF_UNIX` socket.
pub unsafe fn send_fd(sock: RawFd, fd: Result<RawFd, i32>) -> bool {
    // SAFETY: the caller keeps the function's contract, above.
    unsafe {
        let mut space = [0u8; 64];
        let mut text = [0u8; 16];
        let mut msg: libc::msghdr = std::mem::zeroed();
        let len = match fd {
            Ok(_) => {
                text[0] = b'F';
                1
            }
            Err(errno) => {
                text[0] = b'E';
                let mut n = errno.unsigned_abs();
                let mut digits = [0u8; 10];
                let mut k = 0;
                loop {
                    digits[k] = b'0' + (n % 10) as u8;
                    k += 1;
                    n /= 10;
                    if n == 0 {
                        break;
                    }
                }
                for i in 0..k {
                    text[1 + i] = digits[k - 1 - i];
                }
                1 + k
            }
        };
        let mut iov = libc::iovec { iov_base: text.as_mut_ptr().cast(), iov_len: len };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if let Ok(fd) = fd {
            msg.msg_control = space.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
            std::ptr::copy_nonoverlapping(
                &fd as *const RawFd as *const u8,
                libc::CMSG_DATA(cmsg),
                std::mem::size_of::<RawFd>(),
            );
        }
        libc::sendmsg(sock, &msg, 0) == len as isize
    }
}

/// The listener that the child sent over `sock`, or why it has none.
pub fn recv_fd(sock: &OwnedFd) -> io::Result<OwnedFd> {
    let mut space = [0u8; 64];
    let mut text = [0u8; 16];
    // SAFETY: the buffers outlive the call, and the header points at them.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        let mut iov = libc::iovec { iov_base: text.as_mut_ptr().cast(), iov_len: text.len() - 1 };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = space.as_mut_ptr().cast();
        msg.msg_controllen = space.len() as _;
        let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n <= 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the child sent no listener"));
        }
        if text[0] == b'E' {
            let digits = std::str::from_utf8(&text[1..n as usize]).unwrap_or("0");
            return Err(io::Error::from_raw_os_error(digits.parse().unwrap_or(libc::EINVAL)));
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "the child's message held no descriptor"));
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut RawFd as *mut u8,
            std::mem::size_of::<RawFd>(),
        );
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_program_jumps_land_on_its_returns() {
        let p = program();
        // Each jump of the program lands inside it.
        for (at, f) in p.iter().enumerate() {
            if f.code == BPF_JMP_JEQ_K {
                assert!(at + 1 + (f.jt as usize) < p.len() && at + 1 + (f.jf as usize) < p.len());
            }
        }
        assert_eq!(p[4].jt as usize + 5, p.len() - 1, "openat goes to the notification");
        assert_eq!(p.last().map(|f| f.k), Some(RET_USER_NOTIF));
    }
}
