//! The way to a TPM on Unix: the kernel's device with its resource manager,
//! `/dev/tpmrm0` (Linux 4.12 and later, FreeBSD), which keeps each
//! connection's handles apart and flushes them when it closes; or a socket
//! that the user names, as a software TPM (`swtpm socket --server
//! type=unixio`) gives one, speaking the same bytes. Nothing is assumed: a
//! container or a sandbox shows no such device, and the probe says so.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::flow::Transport;
use super::wire::{HEADER, MAX_MESSAGE};
use super::COMMAND_LIMIT;

/// Where the TPM is, and what kind of file it is.
#[derive(Debug, Clone)]
pub(super) struct Place {
    pub path: PathBuf,
    socket: bool,
}

impl Place {
    pub fn describe(&self) -> String {
        let kind = if self.socket { "the socket" } else { "the device" };
        format!("{kind} {}", self.path.display())
    }
}

/// The TPM of `named`, else `/dev/tpmrm0`.
pub(super) fn find(named: Option<&Path>) -> Result<Place, String> {
    find_in(Path::new("/dev"), named)
}

/// [`find`] in another directory of devices, for the tests.
pub(super) fn find_in(dev: &Path, named: Option<&Path>) -> Result<Place, String> {
    let path = match named {
        Some(path) => path.to_path_buf(),
        None => dev.join("tpmrm0"),
    };
    let meta = match std::fs::metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && named.is_none() => {
            let bare = dev.join("tpm0");
            return Err(if bare.exists() {
                format!(
                    "no TPM: this host shows {} but no {}, the kernel's resource manager; \
                     PODSSH_TPM_DEVICE={} uses it with no manager, while no other program does",
                    bare.display(),
                    path.display(),
                    bare.display()
                )
            } else {
                format!("no TPM: this host shows no {} (a container or a sandbox shows none)", path.display())
            });
        }
        Err(e) => return Err(format!("no TPM: {} cannot be read: {e}", path.display())),
    };
    let kind = meta.file_type();
    if kind.is_char_device() {
        return Ok(Place { path, socket: false });
    }
    if kind.is_socket() {
        return Ok(Place { path, socket: true });
    }
    Err(format!("no TPM: {} is neither a device nor a socket", path.display()))
}

/// A connection to the TPM of `place`.
pub(super) fn open(place: &Place) -> Result<Box<dyn Transport>, String> {
    if place.socket {
        let stream = UnixStream::connect(&place.path)
            .map_err(|e| format!("no TPM: {} does not answer: {e}", place.path.display()))?;
        let limit = Some(COMMAND_LIMIT);
        stream.set_read_timeout(limit).and_then(|()| stream.set_write_timeout(limit)).map_err(|e| e.to_string())?;
        return Ok(Box::new(Socket(stream)));
    }
    // Not blocking: a command's wait is bounded by a poll, where the
    // kernel can do that (Linux 5.0 and later; before it, a write waits
    // for the command and the poll returns at once).
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&place.path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => format!(
                "no TPM: this user may not open {} ({e}); on most systems the group tss may",
                place.path.display()
            ),
            _ => format!("no TPM: {} cannot be opened: {e}", place.path.display()),
        })?;
    Ok(Box::new(Device(file)))
}

/// The kernel's device: one write of a command, one read of its response.
struct Device(File);

impl Transport for Device {
    fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>, String> {
        let until = Instant::now() + COMMAND_LIMIT;
        let written = loop {
            match self.0.write(command) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => wait(&self.0, libc::POLLOUT, until)?,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                other => break other,
            }
        };
        match written {
            Ok(n) if n == command.len() => {}
            Ok(n) => return Err(format!("the TPM took {n} bytes of a command of {}", command.len())),
            Err(e) => return Err(format!("the TPM did not take the command: {e}")),
        }
        // The response comes in one read, which must hold it whole.
        let mut buffer = vec![0u8; MAX_MESSAGE];
        loop {
            match self.0.read(&mut buffer) {
                Ok(n) => {
                    buffer.truncate(n);
                    return whole(buffer);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => wait(&self.0, libc::POLLIN, until)?,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(format!("the TPM's answer cannot be read: {e}")),
            }
        }
    }
}

/// Wait until `file` is ready for `events`, or the time runs out.
fn wait(file: &File, events: libc::c_short, until: Instant) -> Result<(), String> {
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!("the TPM did not answer within {} s", COMMAND_LIMIT.as_secs()));
        }
        let mut poll = libc::pollfd { fd: file.as_raw_fd(), events, revents: 0 };
        let ms = left.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
        // SAFETY: one pollfd of this function, for a descriptor held open.
        match unsafe { libc::poll(&mut poll, 1, ms) } {
            0 => continue,
            n if n > 0 => return Ok(()),
            _ => {
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::Interrupted {
                    return Err(format!("the TPM cannot be waited for: {e}"));
                }
            }
        }
    }
}

/// A software TPM's socket: the command, then the header of the response,
/// whose size says how much follows.
struct Socket(UnixStream);

impl Transport for Socket {
    fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>, String> {
        let slow = |e: std::io::Error| match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                format!("the TPM did not answer within {} s", COMMAND_LIMIT.as_secs())
            }
            _ => format!("the TPM's socket failed: {e}"),
        };
        self.0.write_all(command).map_err(slow)?;
        let mut answer = vec![0u8; HEADER];
        self.0.read_exact(&mut answer).map_err(slow)?;
        let size = u32::from_be_bytes([answer[2], answer[3], answer[4], answer[5]]) as usize;
        if !(HEADER..=MAX_MESSAGE).contains(&size) {
            return Err(format!("the TPM's answer says {size} bytes, which no answer has"));
        }
        answer.resize(size, 0);
        self.0.read_exact(&mut answer[HEADER..]).map_err(slow)?;
        Ok(answer)
    }
}

/// A response read whole: at least its header, and as long as it says.
fn whole(bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    if bytes.len() < HEADER {
        return Err(format!("the TPM's answer has {} bytes, less than its header", bytes.len()));
    }
    Ok(bytes)
}
