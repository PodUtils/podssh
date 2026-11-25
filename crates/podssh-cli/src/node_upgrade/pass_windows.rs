//! The passing of a node's sessions to the binary that takes its place, on
//! Windows (T-678), which has no `execve`: this process starts the new
//! binary as its child with this run's words, hands it each target's socket
//! by `WSADuplicateSocketW` and the bytes of the sessions through an
//! anonymous pipe that only the child inherits, then waits for it and ends
//! with its code. So the pid that a supervisor or `podssh detached` knows,
//! and the locks of the run, stay this process's; a job closes the child
//! with it, should this process be ended. A child that does not start gives
//! the sessions back: each socket is still this process's. A socket that
//! WinSock does not duplicate (a Unix route's is AF_UNIX, T-852) ends its
//! session at its resume, and a line names it with WinSock's error: the
//! old process serves nothing once its child runs.

use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, AsRawSocket, FromRawHandle, FromRawSocket};
use std::path::Path;

use podssh_relay::session::handover::{Handed, LayerState, Moved};
use windows_sys::Win32::Foundation::{CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
use windows_sys::Win32::Networking::WinSock::{
    getsockname, WSADuplicateSocketW, WSAGetLastError, WSASocketW, WSAStartup, AF_INET, AF_INET6, AF_UNIX,
    FROM_PROTOCOL_INFO, INVALID_SOCKET, SOCKADDR_STORAGE, WSADATA, WSAPROTOCOL_INFOW, WSA_FLAG_OVERLAPPED,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Pipes::CreatePipe;

use super::state::{self, Decoded, Part, Session};
use super::Taken;

/// The bytes of one socket's duplicate.
const INFO: usize = std::mem::size_of::<WSAPROTOCOL_INFOW>();

/// The value of the variable for the child: the pipe's handle and a nonce
/// that the bytes repeat, so that no other reader takes them for its own.
fn value_of(handle: HANDLE, nonce: u64) -> String {
    format!("pipe:{}:nonce:{nonce:016x}", handle as usize)
}

/// The handle and the nonce that `value` names.
fn pipe_of(value: &str) -> Result<(HANDLE, u64), String> {
    let words: Vec<&str> = value.split(':').collect();
    let ["pipe", handle, "nonce", nonce] = words.as_slice() else {
        return Err(format!("{value:?} names no handover"));
    };
    let handle: usize = handle.parse().map_err(|_| format!("{value:?} names no handle"))?;
    let nonce = u64::from_str_radix(nonce, 16).map_err(|_| format!("{value:?} names no nonce"))?;
    Ok((handle as HANDLE, nonce))
}

/// Whether `value` is a handover of this system's kind.
pub fn is_ours(value: &str) -> bool {
    value.starts_with("pipe:")
}

/// The bytes on the pipe: the nonce, the length of the state, the state, the
/// count of sockets, then each socket's duplicate.
fn frame(nonce: u64, bytes: &[u8], infos: &[WSAPROTOCOL_INFOW]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + bytes.len() + infos.len() * INFO);
    out.extend_from_slice(&nonce.to_le_bytes());
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    out.extend_from_slice(&(infos.len() as u32).to_le_bytes());
    for info in infos {
        // SAFETY: a plain C struct of INFO bytes, read as bytes.
        out.extend_from_slice(unsafe {
            std::slice::from_raw_parts((info as *const WSAPROTOCOL_INFOW).cast::<u8>(), INFO)
        });
    }
    out
}

/// The state and the duplicates of a frame, once its nonce is `nonce`.
fn unframe(nonce: u64, bytes: &[u8]) -> Result<(Vec<u8>, Vec<WSAPROTOCOL_INFOW>), String> {
    let take = |at: usize, n: usize| bytes.get(at..at + n).ok_or_else(|| "the handover's bytes end early".to_string());
    let word = |at: usize| take(at, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap_or_default()));
    if word(0)? != nonce {
        return Err("the handover's bytes are another's".into());
    }
    let len = usize::try_from(word(8)?).map_err(|_| "the handover's length".to_string())?;
    let state = take(16, len)?.to_vec();
    let count = u32::from_le_bytes(take(16 + len, 4)?.try_into().unwrap_or_default()) as usize;
    let mut infos = Vec::with_capacity(count.min(1024));
    for i in 0..count {
        let raw = take(20 + len + i * INFO, INFO)?;
        // SAFETY: a zeroed C struct is a valid value; its bytes are then
        // those that the binary before this one wrote of one.
        let mut info: WSAPROTOCOL_INFOW = unsafe { std::mem::zeroed() };
        // SAFETY: INFO bytes into a struct of INFO bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(raw.as_ptr(), (&mut info as *mut WSAPROTOCOL_INFOW).cast::<u8>(), INFO)
        };
        infos.push(info);
    }
    Ok((state, infos))
}

/// What the binary before this one handed over through the pipe that
/// `value` names; the pipe is read to its end and closed.
pub fn read(value: &str) -> Result<Taken, String> {
    let (handle, nonce) = pipe_of(value)?;
    // SAFETY: the pipe's end that the binary before this one made for this
    // one alone and named in the variable; nothing else here owns it.
    let mut pipe = unsafe { File::from_raw_handle(handle) };
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes).map_err(|e| format!("the handover's pipe: {}", podssh_ws::text::said(&e)))?;
    drop(pipe);
    let (bytes, infos) = unframe(nonce, &bytes)?;
    startup();
    let Decoded { from, sessions, parts } = state::decode(&bytes).map_err(|e| e.to_string())?;
    let mut handed = Vec::with_capacity(sessions.len());
    for Session { layer, socket, channel } in sessions {
        let state = LayerState::decode(&layer).map_err(|e| e.to_string())?;
        let target = match socket.and_then(|i| usize::try_from(i).ok()).and_then(|i| infos.get(i)) {
            Some(info) => adopt(info).map(|socket| Moved { socket, channel }),
            // Its duplicate failed there, and that binary said why.
            None => Err("the binary before this one handed over no socket for it".to_string()),
        };
        handed.push(Handed { state, target });
    }
    Ok(Taken { from, handed, parts })
}

/// Winsock, started before a socket is made from a duplicate: no socket of
/// the standard library has started it yet in a new process.
fn startup() {
    // SAFETY: a zeroed WSADATA is a valid out value; a second start only
    // counts one more.
    let mut data: WSADATA = unsafe { std::mem::zeroed() };
    // SAFETY: version 2.2 and the out value above.
    let _ = unsafe { WSAStartup(0x0202, &mut data) };
}

/// A socket of the binary before this one, from its duplicate; overlapped,
/// as the runtime's sockets are.
fn adopt(info: &WSAPROTOCOL_INFOW) -> Result<std::net::TcpStream, String> {
    // SAFETY: a duplicate that WSADuplicateSocketW wrote for this process.
    let socket =
        unsafe { WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, info, 0, WSA_FLAG_OVERLAPPED) };
    if socket == INVALID_SOCKET {
        // SAFETY: the error of the call above, on this thread.
        return Err(format!("its socket did not come over (WSA error {})", unsafe { WSAGetLastError() }));
    }
    // SAFETY: a socket that this process just made and owns alone.
    Ok(unsafe { std::net::TcpStream::from_raw_socket(socket as u64) })
}

/// The duplicate of `socket` for the process `pid`, or why there is none:
/// WinSock's error, and the socket's family.
fn duplicate(socket: &std::net::TcpStream, pid: u32) -> Result<WSAPROTOCOL_INFOW, String> {
    let raw = socket.as_raw_socket() as usize;
    // SAFETY: a zeroed out value, which the call fills.
    let mut info: WSAPROTOCOL_INFOW = unsafe { std::mem::zeroed() };
    // SAFETY: a socket of this process, and the child's pid.
    if unsafe { WSADuplicateSocketW(raw, pid, &mut info) } == 0 {
        return Ok(info);
    }
    // SAFETY: the error of the call above, on this thread, read before any other.
    let code = unsafe { WSAGetLastError() };
    Err(format!("its {}socket did not go to the new binary (WinSock's error {code})", family(raw)))
}

/// The family of a target's socket, as a line names it: a Unix route's
/// socket is an AF_UNIX one of WinSock (T-852).
fn family(socket: usize) -> &'static str {
    // SAFETY: a zeroed SOCKADDR_STORAGE is a valid out value.
    let mut name: SOCKADDR_STORAGE = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<SOCKADDR_STORAGE>() as i32;
    // SAFETY: a socket of this process, and an out value of `len` bytes.
    let got = unsafe { getsockname(socket, (&mut name as *mut SOCKADDR_STORAGE).cast(), &mut len) };
    match (got, name.ss_family) {
        (0, AF_UNIX) => "Unix ",
        (0, AF_INET | AF_INET6) => "TCP ",
        _ => "",
    }
}

/// A pipe whose read end the child inherits and whose write end it does
/// not: (read, write).
fn pipe() -> Result<(File, File), String> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let (mut read, mut write): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: two out handles and the attributes above.
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
        return Err(format!("the handover's pipe: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: the handles that CreatePipe made, owned here alone.
    let (read, write) = unsafe { (File::from_raw_handle(read), File::from_raw_handle(write)) };
    // SAFETY: a flag of a handle that this process owns.
    if unsafe { SetHandleInformation(write.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(format!("the handover's pipe: {}", std::io::Error::last_os_error()));
    }
    Ok((read, write))
}

/// A job that ends `child` when this process ends, however it ends: the
/// handle stays open for the life of this process.
fn tie(child: &std::process::Child) {
    // SAFETY: a new job with no name.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return;
    }
    // SAFETY: a zeroed limit is a valid value; one flag is set.
    let mut limit: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let size = std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
    // SAFETY: the job above, and the limit of its size.
    let set = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&limit as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size,
        )
    };
    // SAFETY: the job and the child's process handle.
    if set == 0 || unsafe { AssignProcessToJobObject(job, child.as_raw_handle()) } == 0 {
        // SAFETY: the job made above, which nothing else holds.
        unsafe { CloseHandle(job) };
    }
    // Kept open on purpose: closing it would end the child.
}

/// The root of the node: the pid that its run's record and the request of
/// an upgrade name, which every binary after the first keeps.
pub const ROOT_VARIABLE: &str = "PODSSH_HANDOVER_ROOT";

/// Hand `handed` and the run's `parts` to `binary`, started as this
/// process's child with this run's words, and wait for it: its code. Once
/// the child has them, `went` hears how many sockets went and why each
/// other did not. When it does not start: the sessions back, as they were,
/// and why.
pub fn hand_to_child(
    binary: &Path,
    from: &str,
    handed: Vec<Handed>,
    parts: &[Part],
    went: &dyn Fn(usize, &[String]),
) -> Result<i32, (Vec<Handed>, String)> {
    let (read, mut write) = match pipe() {
        Ok(ends) => ends,
        Err(why) => return Err((handed, why)),
    };
    let nonce: u64 = rand::random();
    let mut words = std::env::args_os().skip(1);
    let mut cmd = std::process::Command::new(binary);
    cmd.args(&mut words)
        .env(super::VARIABLE, value_of(read.as_raw_handle(), nonce))
        .env(ROOT_VARIABLE, super::root_pid().to_string());
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => return Err((handed, format!("it does not start here: {}", podssh_ws::text::said(&e)))),
    };
    drop(read);
    tie(&child);
    let mut sessions = Vec::with_capacity(handed.len());
    let mut infos = Vec::new();
    let mut lost = Vec::new();
    for Handed { state, target } in &handed {
        let index = match target {
            // A session whose socket did not go ends at its resume there.
            Ok(Moved { socket, .. }) => match duplicate(socket, child.id()) {
                Ok(info) => {
                    infos.push(info);
                    Some((infos.len() - 1) as i32)
                }
                Err(why) => {
                    lost.push(why);
                    None
                }
            },
            Err(_) => None,
        };
        let channel = target.as_ref().ok().and_then(|m| m.channel.clone());
        sessions.push(Session { layer: state.encode(), socket: index, channel });
    }
    let bytes = state::encode(from, &sessions, parts);
    let sent = write.write_all(&frame(nonce, &bytes, &infos)).and_then(|()| write.flush());
    if sent.is_ok() {
        // Before the pipe's end, which the child waits for: these lines come
        // before the child's own.
        went(infos.len(), &lost);
    }
    drop(write);
    if let Err(e) = sent {
        let _ = child.kill();
        let _ = child.wait();
        return Err((handed, format!("its handover's pipe: {}", podssh_ws::text::said(&e))));
    }
    // The child holds each socket now: this process's copies close, which
    // leaves the connections open while the child's are, and ends each that
    // did not go.
    drop(handed);
    match child.wait() {
        Ok(status) => Ok(status.code().unwrap_or(1)),
        Err(e) => Err((Vec::new(), format!("its wait: {}", podssh_ws::text::said(&e)))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variable_reads_back_and_another_s_does_not() {
        let value = value_of(0x1234 as HANDLE, 0xfeed);
        assert!(is_ours(&value));
        assert_eq!(pipe_of(&value).map(|(h, n)| (h as usize, n)), Ok((0x1234, 0xfeed)));
        assert!(pipe_of("fd:3:pid:9").is_err());
        assert!(!is_ours("probe"));
    }

    #[test]
    fn a_frame_gives_its_state_and_duplicates_back_to_its_nonce_alone() {
        // SAFETY: a zeroed C struct is a valid value.
        let mut info: WSAPROTOCOL_INFOW = unsafe { std::mem::zeroed() };
        info.iAddressFamily = 23;
        info.dwCatalogEntryId = 7;
        let bytes = frame(5, b"state", &[info, info]);
        let Ok((state, infos)) = unframe(5, &bytes) else { panic!("the frame reads back") };
        assert_eq!((&state[..], infos.len()), (&b"state"[..], 2));
        assert_eq!((infos[1].iAddressFamily, infos[1].dwCatalogEntryId), (23, 7));
        let why = |result: Result<_, String>| result.err().unwrap_or_default();
        assert!(why(unframe(6, &bytes).map(|_| ())).contains("another's"));
        assert!(why(unframe(5, &bytes[..bytes.len() - 1]).map(|_| ())).contains("end early"));
    }
}
