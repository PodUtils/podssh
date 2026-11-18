//! A lock on a `known_hosts` file that only other writers see (T-029),
//! `pod_core::lock` (T-820) over this file's glue: the bound of the wait, a
//! file system with no locks, and which file the path names after the wait.
//! On Unix the lock is on the file itself, an advisory `flock` that no reader
//! meets; on Windows pod-core locks the whole file, which would refuse each
//! reader meanwhile (OpenSSH's among them), so the lock is on a file beside it.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pod_core::failure::Class;
use pod_core::lock::{FileLock, Mode};

/// How long a writer waits for another one to finish: a read and one line.
pub const WAIT: Duration = Duration::from_secs(5);

/// The file that carries the lock of the `known_hosts` file at `path`: the
/// file itself, its target when it is a link (pod-core opens no link), and
/// on Windows a file beside it.
fn target(path: &Path) -> PathBuf {
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    #[cfg(windows)]
    {
        let mut name = real.into_os_string();
        name.push(".podssh-lock");
        PathBuf::from(name)
    }
    #[cfg(not(windows))]
    real
}

/// Hold the lock of the file at `path`: `None` when its file system takes no
/// locks, so the caller writes without one and says so, and an error when
/// another writer kept it for `wait`. Never a wait without a limit.
pub fn hold(path: &Path, wait: Duration) -> std::io::Result<Option<FileLock>> {
    match FileLock::lock_within(&target(path), Mode::Exclusive, wait) {
        Ok(lock) => Ok(Some(lock)),
        Err(e) if e.class == Class::Unavailable => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("another writer held its lock for {} s", wait.as_secs()),
        )),
        Err(_) => Ok(None),
    }
}

/// Whether `file` is the file that `path` names now: a writer that waited
/// for the lock while a rewrite put another file in its place holds the
/// old one (T-019).
#[cfg(unix)]
pub fn same_file(file: &File, path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let now = match std::fs::metadata(path) {
        Ok(now) => now,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let held = file.metadata()?;
    Ok(held.dev() == now.dev() && held.ino() == now.ino())
}

#[cfg(windows)]
pub fn same_file(file: &File, path: &Path) -> std::io::Result<bool> {
    let now = match File::open(path) {
        Ok(now) => now,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    Ok(file_id(file)? == file_id(&now)?)
}

/// The volume and the index of an open file, which no other file shares.
#[cfg(windows)]
fn file_id(file: &File) -> std::io::Result<(u32, u32, u32)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
    // SAFETY: zeros are a valid BY_HANDLE_FILE_INFORMATION, which the call
    // fills.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open while `file` lives, and `info` outlives the
    // call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow))
}

#[cfg(not(any(unix, windows)))]
pub fn same_file(_: &File, _: &Path) -> std::io::Result<bool> {
    Ok(true)
}
