//! A traced child's call at its seccomp stop (T-777): its number and its
//! arguments, read from its registers; the call skipped with a value of
//! serve's, or made another call. x86_64 reads and writes the whole set
//! (`orig_rax` is the number, -1 skips it); aarch64 its general registers
//! and, for the number, `NT_ARM_SYSTEM_CALL`.

use std::io;

/// `addr` of a ptrace request that takes none: a whole word, as the call
/// is variadic and the kernel reads a pointer.
#[cfg(target_arch = "x86_64")]
const NULL: *mut libc::c_void = std::ptr::null_mut();

/// One call of a stopped child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Call {
    pub nr: i64,
    pub args: [u64; 6],
}

/// The registers of a stopped child, as read, to be written back changed.
pub struct Regs(libc::user_regs_struct);

#[cfg(target_arch = "x86_64")]
mod arch {
    use super::*;

    pub fn get(pid: i32) -> io::Result<Regs> {
        // SAFETY: an all-zero register set is valid, and the kernel fills it.
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        // SAFETY: GETREGS writes one `user_regs_struct`.
        let rc = unsafe { libc::ptrace(libc::PTRACE_GETREGS, pid, NULL, &mut regs as *mut libc::user_regs_struct) };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Regs(regs))
        }
    }

    pub fn put(pid: i32, regs: &Regs) -> io::Result<()> {
        // SAFETY: SETREGS reads one `user_regs_struct`.
        let rc = unsafe { libc::ptrace(libc::PTRACE_SETREGS, pid, NULL, &regs.0 as *const libc::user_regs_struct) };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn call(r: &Regs) -> Call {
        let r = &r.0;
        Call { nr: r.orig_rax as i64, args: [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9] }
    }

    /// The call skipped, `value` its return.
    pub fn skip(pid: i32, mut r: Regs, value: i64) -> io::Result<()> {
        r.0.orig_rax = u64::MAX;
        r.0.rax = value as u64;
        put(pid, &r)
    }

    /// The call made `nr` with the first three arguments `args`.
    pub fn rewrite(pid: i32, mut r: Regs, nr: i64, args: [u64; 3]) -> io::Result<()> {
        r.0.orig_rax = nr as u64;
        (r.0.rdi, r.0.rsi, r.0.rdx) = (args[0], args[1], args[2]);
        put(pid, &r)
    }
}

#[cfg(target_arch = "aarch64")]
mod arch {
    use super::*;

    const NT_PRSTATUS: libc::c_int = 1;
    const NT_ARM_SYSTEM_CALL: libc::c_int = 0x404;

    fn regset<T>(op: libc::c_uint, pid: i32, note: libc::c_int, value: &mut T) -> io::Result<()> {
        let mut iov = libc::iovec { iov_base: (value as *mut T).cast(), iov_len: std::mem::size_of::<T>() };
        // SAFETY: the iovec names `value`, of its own size, which outlives the call.
        let rc = unsafe { libc::ptrace(op, pid, note as libc::c_long, &mut iov as *mut libc::iovec) };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn get(pid: i32) -> io::Result<Regs> {
        // SAFETY: an all-zero register set is valid, and the kernel fills it.
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regset(libc::PTRACE_GETREGSET, pid, NT_PRSTATUS, &mut regs)?;
        Ok(Regs(regs))
    }

    fn set_nr(pid: i32, nr: i64) -> io::Result<()> {
        let mut nr = nr as i32;
        regset(libc::PTRACE_SETREGSET, pid, NT_ARM_SYSTEM_CALL, &mut nr)
    }

    pub fn call(r: &Regs) -> Call {
        let r = &r.0;
        Call { nr: r.regs[8] as i64, args: [r.regs[0], r.regs[1], r.regs[2], r.regs[3], r.regs[4], r.regs[5]] }
    }

    /// The call skipped, `value` its return: x0 is kept for a call that
    /// does not run.
    pub fn skip(pid: i32, mut r: Regs, value: i64) -> io::Result<()> {
        r.0.regs[0] = value as u64;
        regset(libc::PTRACE_SETREGSET, pid, NT_PRSTATUS, &mut r.0)?;
        set_nr(pid, -1)
    }

    /// The call made `nr` with the first three arguments `args`.
    pub fn rewrite(pid: i32, mut r: Regs, nr: i64, args: [u64; 3]) -> io::Result<()> {
        (r.0.regs[0], r.0.regs[1], r.0.regs[2]) = (args[0], args[1], args[2]);
        regset(libc::PTRACE_SETREGSET, pid, NT_PRSTATUS, &mut r.0)?;
        set_nr(pid, nr)
    }
}

pub use arch::{call, get, rewrite, skip};
