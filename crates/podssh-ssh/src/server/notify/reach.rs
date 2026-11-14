//! What the supervisor reads of a notified child, each with its fallback,
//! as the study measured them (T-248, route 2a): whether a descriptor of
//! the child is the tty socket that serve gave it (`kcmp`, else a copy by
//! `pidfd_getfd`, else `/proc/PID/fd`), and the child's memory, read and
//! written (`process_vm_readv` and `process_vm_writev`, else
//! `/proc/PID/mem`). A sandbox that refuses one way often allows the next.

use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt};

/// `KCMP_FILE` of linux/kcmp.h.
const KCMP_FILE: libc::c_long = 0;

/// The tty socket that serve gave the child, as serve holds a copy of it.
pub struct Ours {
    copy: OwnedFd,
    ino: u64,
    dev: u64,
}

impl Ours {
    pub fn new(copy: OwnedFd) -> io::Result<Ours> {
        let meta = std::fs::File::from(copy.try_clone()?).metadata()?;
        Ok(Ours { copy, ino: meta.ino(), dev: meta.dev() })
    }

    /// The copy, for `SECCOMP_IOCTL_NOTIF_ADDFD` of `/dev/tty`.
    pub fn fd(&self) -> &OwnedFd {
        &self.copy
    }

    /// Whether descriptor `fd` of `pid` is the tty socket; `None` when no
    /// way here can tell, and the kernel then answers the call.
    pub fn holds(&self, pid: u32, fd: i32) -> Option<bool> {
        // SAFETY: kcmp compares two descriptors and writes no memory.
        let same = unsafe {
            libc::syscall(
                libc::SYS_kcmp,
                libc::getpid() as libc::c_long,
                pid as libc::c_long,
                KCMP_FILE,
                self.copy.as_raw_fd() as libc::c_long,
                fd as libc::c_long,
            )
        };
        if same >= 0 {
            return Some(same == 0);
        }
        if let Some(found) = self.by_copy(pid, fd) {
            return Some(found);
        }
        let link = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
        Some(link.as_os_str() == format!("socket:[{}]", self.ino).as_str())
    }

    /// A copy of the child's descriptor by `pidfd_getfd`, compared by its
    /// inode; `None` where this kernel or sandbox refuses it.
    fn by_copy(&self, pid: u32, fd: i32) -> Option<bool> {
        // SAFETY: each call returns a new descriptor or -1, owned at once.
        unsafe {
            let pidfd = libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0 as libc::c_long);
            if pidfd < 0 {
                return None;
            }
            let pidfd = OwnedFd::from_raw_fd(pidfd as i32);
            let copy = libc::syscall(
                libc::SYS_pidfd_getfd,
                pidfd.as_raw_fd() as libc::c_long,
                fd as libc::c_long,
                0 as libc::c_long,
            );
            if copy < 0 {
                return (io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)).then_some(false);
            }
            let copy = std::fs::File::from(OwnedFd::from_raw_fd(copy as i32));
            let meta = copy.metadata().ok()?;
            Some(meta.ino() == self.ino && meta.dev() == self.dev)
        }
    }
}

/// `buf.len()` bytes of `pid`'s memory at `addr` into `buf`.
pub fn read(pid: u32, addr: u64, buf: &mut [u8]) -> io::Result<()> {
    let local = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    let remote = libc::iovec { iov_base: addr as *mut libc::c_void, iov_len: buf.len() };
    // SAFETY: the local iovec is `buf`, which outlives the call.
    let n = unsafe { libc::process_vm_readv(pid as libc::pid_t, &local, 1, &remote, 1, 0) };
    if n == buf.len() as isize {
        return Ok(());
    }
    let mem = OpenOptions::new().read(true).open(format!("/proc/{pid}/mem"))?;
    mem.read_exact_at(buf, addr)
}

/// `data` into `pid`'s memory at `addr`.
pub fn write(pid: u32, addr: u64, data: &[u8]) -> io::Result<()> {
    let local = libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() };
    let remote = libc::iovec { iov_base: addr as *mut libc::c_void, iov_len: data.len() };
    // SAFETY: the local iovec is `data`, only read; the remote one is the
    // child's, which the kernel checks.
    let n = unsafe { libc::process_vm_writev(pid as libc::pid_t, &local, 1, &remote, 1, 0) };
    if n == data.len() as isize {
        return Ok(());
    }
    let mem = OpenOptions::new().write(true).open(format!("/proc/{pid}/mem"))?;
    mem.write_all_at(data, addr)
}

/// The path that `pid` passed at `addr`, its first `max` bytes at most: a
/// read that crosses into a page the child has not mapped is tried again
/// shorter, as a path can end just before one.
pub fn path(pid: u32, addr: u64, max: usize) -> Option<Vec<u8>> {
    let mut len = max;
    while len > 0 {
        let mut buf = vec![0u8; len];
        if read(pid, addr, &mut buf).is_ok() {
            if let Some(end) = buf.iter().position(|&b| b == 0) {
                buf.truncate(end);
            }
            return Some(buf);
        }
        len /= 2;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_reads_and_writes_its_own_memory_and_knows_its_socket() {
        let me = std::process::id();
        let mut here = [1u8, 2, 3, 4];
        write(me, here.as_mut_ptr() as u64, &[9, 8, 7, 6]).unwrap();
        assert_eq!(here, [9, 8, 7, 6]);
        let mut back = [0u8; 4];
        read(me, here.as_ptr() as u64, &mut back).unwrap();
        assert_eq!(back, [9, 8, 7, 6]);
        let text = b"/dev/tty\0more";
        assert_eq!(path(me, text.as_ptr() as u64, 16).as_deref(), Some(&b"/dev/tty"[..]));

        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let ours = Ours::new(OwnedFd::from(a.try_clone().unwrap())).unwrap();
        assert_eq!(ours.holds(me, a.as_raw_fd()), Some(true));
        assert_eq!(ours.holds(me, b.as_raw_fd()), Some(false));
    }
}
