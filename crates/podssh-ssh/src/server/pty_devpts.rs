//! A pty of a devpts instance of podssh's own (T-775, route 1 of T-248),
//! where the host has no `/dev/ptmx` but lets a process make a user and a
//! mount namespace: the kernel's own tty, with nothing answered by podssh.
//!
//! A helper forked for each request (serve's threads make `unshare` fail
//! with EINVAL; a forked child has one) makes the namespaces, mounts devpts
//! with `newinstance`, opens its `ptmx`, unlocks it, takes the slave by
//! `TIOCGPTPEER` (no path that the child could open: `ptsname` would name
//! the host's instance, absent or another pty), sends both over a socket
//! by `SCM_RIGHTS`, and exits. Its namespaces end with it; the instance
//! lives as long as its descriptors. Where a step fails, the helper sends
//! the step and its errno, and the request goes to the next route.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use super::pty::Pair;

/// The name of such a pair, in place of a path, where `tty` would print one.
pub const NAME: &str = "a devpts instance of podssh";

/// Where the helper mounts the instance, each tried in turn: `/dev/pts`
/// where it exists, else over `/dev` or `/tmp`, hidden in its namespace
/// alone.
const TARGETS: [(&CStr, &CStr); 3] =
    [(c"/dev/pts", c"/dev/pts/ptmx"), (c"/dev", c"/dev/ptmx"), (c"/tmp", c"/tmp/ptmx")];

/// The bound of the helper's answer; measured, it comes in 0.5 to 5.8 ms.
const LIMIT: Duration = Duration::from_secs(2);

/// The helper's steps, as its answer names them.
const STEPS: [&str; 7] = ["", "unshare", "a private /", "mount devpts", "open ptmx", "TIOCSPTLCK", "TIOCGPTPEER"];
const UNSHARE: u8 = 1;
const PRIVATE: u8 = 2;
const MOUNT: u8 = 3;
const OPEN: u8 = 4;
const UNLOCK: u8 = 5;
const PEER: u8 = 6;

/// A pair from a new devpts instance, or why none came: the step and its
/// error, as `podssh doctor`'s line `pty devpts` says it.
pub fn open() -> Result<Pair, String> {
    let mut ends = [-1 as RawFd; 2];
    // SAFETY: `ends` holds the two descriptors that socketpair writes.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0, ends.as_mut_ptr()) } != 0
    {
        return Err(format!("socketpair: {}", io::Error::last_os_error()));
    }
    // SAFETY: socketpair gave two open descriptors that nothing else owns.
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) };
    // SAFETY: the child calls only the system calls of `helper`, with no
    // allocation and no lock, and leaves by _exit, as is safe after a
    // fork of a process with threads.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        helper(theirs.as_raw_fd());
    }
    drop(theirs);
    let answer = receive(&ours);
    reap(pid, answer.is_err());
    answer
}

/// The helper: each step, then the pair or the step that failed. It never
/// returns.
fn helper(to: RawFd) -> ! {
    // SAFETY: plain system calls on values made before the fork.
    unsafe {
        let fail = |step: u8| fail(to, step);
        if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
            fail(UNSHARE);
        }
        // No mount of the helper reaches the host's namespace.
        if libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) != 0
        {
            fail(PRIVATE);
        }
        let options = c"newinstance,ptmxmode=0666,mode=0620";
        let mut ptmx = None;
        for (target, at) in TARGETS {
            let flags = libc::MS_NOSUID | libc::MS_NOEXEC;
            if libc::mount(c"devpts".as_ptr(), target.as_ptr(), c"devpts".as_ptr(), flags, options.as_ptr().cast()) == 0
            {
                ptmx = Some(at);
                break;
            }
        }
        let Some(at) = ptmx else { fail(MOUNT) };
        let master = libc::open(at.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if master < 0 {
            fail(OPEN);
        }
        let unlock: libc::c_int = 0;
        if libc::ioctl(master, libc::TIOCSPTLCK, &unlock as *const libc::c_int) != 0 {
            fail(UNLOCK);
        }
        let slave = libc::ioctl(master, libc::TIOCGPTPEER, libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if slave < 0 {
            fail(PEER);
        }
        send_pair(to, [master, slave]);
        libc::_exit(0)
    }
}

/// Send the step that failed and its errno, then exit.
///
/// # Safety
/// After a fork: no allocation; `to` is open.
unsafe fn fail(to: RawFd, step: u8) -> ! {
    // SAFETY: the caller's; errno is this thread's, and the word lives
    // through the send.
    unsafe {
        let errno = *libc::__errno_location();
        let mut word = [0u8; 5];
        word[0] = step;
        word[1..].copy_from_slice(&errno.to_le_bytes());
        libc::send(to, word.as_ptr().cast(), word.len(), libc::MSG_NOSIGNAL);
        libc::_exit(1)
    }
}

/// One byte, 0, with the master and the slave in its control message.
///
/// # Safety
/// `to` and both descriptors are open; no allocation, as after a fork.
unsafe fn send_pair(to: RawFd, fds: [RawFd; 2]) {
    // SAFETY: the caller's; the message's buffers live through the send,
    // and the control message is written within its room.
    unsafe {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
        // Room for one control message of two descriptors, aligned as cmsghdr.
        let mut space = [0u64; 8];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = space.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of_val(&fds) as u32) as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(&fds) as u32) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg).cast::<RawFd>(), 2);
        libc::sendmsg(to, &msg, libc::MSG_NOSIGNAL);
    }
}

/// The helper's answer within [`LIMIT`]: the pair, or the step that failed.
fn receive(from: &OwnedFd) -> Result<Pair, String> {
    let mut poll = libc::pollfd { fd: from.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    // SAFETY: one pollfd, its count 1.
    let ready = unsafe { libc::poll(&mut poll, 1, LIMIT.as_millis() as libc::c_int) };
    if ready <= 0 {
        return Err(format!("the helper gave no answer within {} s", LIMIT.as_secs()));
    }
    let mut word = [0u8; 5];
    let mut iov = libc::iovec { iov_base: word.as_mut_ptr().cast(), iov_len: word.len() };
    let mut space = [0u64; 8];
    // SAFETY: the message's buffers live through the call; the kernel
    // writes at most their lengths.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = space.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&space) as _;
    // SAFETY: as above; MSG_CMSG_CLOEXEC keeps the pair from serve's other children.
    let got = unsafe { libc::recvmsg(from.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if got <= 0 {
        return Err("the helper ended with no answer".into());
    }
    let fds = received(&msg);
    match (word[0], got) {
        (0, 1) => match fds.as_slice() {
            [_, _] => {
                let mut fds = fds.into_iter();
                let (master, slave) = (fds.next().unwrap(), fds.next().unwrap());
                Ok(Pair { master, slave, name: NAME.to_string(), path: false })
            }
            _ => Err("the helper sent no pair".into()),
        },
        (step, 5) if (step as usize) < STEPS.len() => {
            let errno = i32::from_le_bytes([word[1], word[2], word[3], word[4]]);
            Err(format!("{}: {}", STEPS[step as usize], io::Error::from_raw_os_error(errno)))
        }
        _ => Err("the helper's answer does not read".into()),
    }
}

/// The descriptors of `msg`'s control messages, owned: each one is closed
/// where the answer is not a pair.
fn received(msg: &libc::msghdr) -> Vec<OwnedFd> {
    let mut fds = Vec::new();
    // SAFETY: the kernel wrote the control messages within msg_controllen;
    // CMSG_FIRSTHDR and CMSG_NXTHDR stay within it.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                for i in 0..bytes / std::mem::size_of::<RawFd>() {
                    fds.push(OwnedFd::from_raw_fd(data.add(i).read_unaligned()));
                }
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    fds
}

/// Wait for the helper, which exits once it answered; one that did not
/// answer is killed first, so that no helper outlives its request.
fn reap(pid: libc::pid_t, kill: bool) {
    // SAFETY: `pid` is this process's own child, waited for once.
    unsafe {
        if kill {
            libc::kill(pid, libc::SIGKILL);
        }
        let mut status = 0;
        while libc::waitpid(pid, &mut status, 0) < 0 && *libc::__errno_location() == libc::EINTR {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where the host lets this process make the namespaces (root, or a
    /// kernel that allows it to anyone), a pair comes with its size settable
    /// and a slave that is a tty; elsewhere the reason names the step.
    #[test]
    fn a_new_instance_gives_a_pair_or_names_the_step_that_failed() {
        match open() {
            Ok(pair) => {
                assert_eq!(pair.name, NAME);
                assert!(!pair.path, "a pair of an instance has no path");
                // SAFETY: isatty on an open descriptor.
                assert_eq!(unsafe { libc::isatty(pair.slave.as_raw_fd()) }, 1);
                let size = crate::terminal::Size { cols: 132, rows: 43, px_width: 0, px_height: 0 };
                super::super::pty::set_size(pair.master.as_raw_fd(), size).unwrap();
            }
            Err(why) => {
                eprintln!("did not run: no devpts instance here: {why}");
                assert!(
                    STEPS.iter().skip(1).any(|step| why.starts_with(step)) || why.starts_with("the helper"),
                    "{why}"
                );
            }
        }
    }
}
