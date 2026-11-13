//! The file-system calls of the SFTP server, each a blocking call for the
//! session's thread, as the user that runs serve: no chroot, no other uid.
//! The answers are those of OpenSSH's `sftp-server` (`sftp-server.c`): its
//! map of each errno to a status code, its `ls -l` line in a listing, and
//! its order of a setstat (size, mode, times, owner).

use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions, ReadDir};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use russh_sftp::protocol::{File as Named, FileAttributes, OpenFlags, StatusCode};

/// The most names in one reply to a readdir, as `sftp-server` sends.
pub const NAMES_PER_READ: usize = 100;

/// The path of a request: a relative one starts at the home directory, as
/// `sftp-server` starts there, and an empty one is the home itself.
pub(super) fn resolve(home: &Path, path: &str) -> PathBuf {
    if path.is_empty() {
        return home.to_path_buf();
    }
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        home.join(path)
    }
}

/// The status code of a failed call: `errno_to_portable` of `sftp-server`.
pub(super) fn status_of(e: &io::Error) -> StatusCode {
    match e.raw_os_error() {
        Some(libc::ENOENT | libc::ENOTDIR | libc::EBADF | libc::ELOOP) => StatusCode::NoSuchFile,
        Some(libc::EPERM | libc::EACCES | libc::EFAULT) => StatusCode::PermissionDenied,
        Some(libc::ENAMETOOLONG | libc::EINVAL) => StatusCode::BadMessage,
        Some(libc::ENOSYS) => StatusCode::OpUnsupported,
        Some(_) => StatusCode::Failure,
        None => match e.kind() {
            io::ErrorKind::NotFound => StatusCode::NoSuchFile,
            io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
            io::ErrorKind::Unsupported => StatusCode::OpUnsupported,
            _ => StatusCode::Failure,
        },
    }
}

/// The system's words for a failed call, without Rust's "(os error N)".
pub(super) fn words(e: &io::Error) -> String {
    let text = e.to_string();
    match text.find(" (os error ") {
        Some(at) => text[..at].to_string(),
        None => text,
    }
}

/// A time as version 3 carries it: seconds in 32 bits.
fn seconds(t: i64) -> u32 {
    t.clamp(0, i64::from(u32::MAX)) as u32
}

/// What the client is told of a file: its whole mode, type bits included.
/// russh-sftp's own conversion sets the bits of a regular file on each
/// file that is no directory, a FIFO or a socket too.
pub(super) fn attrs(m: &Metadata) -> FileAttributes {
    FileAttributes {
        size: Some(m.size()),
        uid: Some(m.uid()),
        user: None,
        gid: Some(m.gid()),
        group: None,
        permissions: Some(m.mode()),
        atime: Some(seconds(m.atime())),
        mtime: Some(seconds(m.mtime())),
    }
}

/// The `ls -l` line of a listing, as `sftp-server` writes it (`ls_file`):
/// podssh's client line with the link count in place of its `?`. Owners go
/// by number: serve reads no passwd entry (`docs/target-environment.md`).
pub(super) fn long_name(name: &str, m: &Metadata, now: i64) -> String {
    let line = crate::sftp::long::long_line(name, &attrs(m), false, None, None, now);
    // The mode is ten ASCII characters, then four spaces and `?`: `%3s` of
    // the count is the three before the name's columns.
    match (line.get(..12), line.get(12..15), line.get(15..)) {
        (Some(head), Some("  ?"), Some(tail)) => format!("{head}{:>3}{tail}", m.nlink()),
        _ => line,
    }
}

/// Open `path` as `sftp-server` does: read and write as asked, read alone
/// when neither is; a new file takes the request's mode.
pub(super) fn open(path: &Path, flags: OpenFlags, attrs: &FileAttributes) -> io::Result<File> {
    let append = flags.contains(OpenFlags::APPEND);
    let write = flags.contains(OpenFlags::WRITE) || append;
    let read = flags.contains(OpenFlags::READ) || !write;
    let mut options = OpenOptions::new();
    options.read(read).write(write).append(append);
    if flags.contains(OpenFlags::CREATE) {
        if flags.contains(OpenFlags::EXCLUDE) {
            options.create_new(true);
        } else {
            options.create(true);
        }
    }
    options.truncate(flags.contains(OpenFlags::TRUNCATE));
    options.mode(attrs.permissions.map_or(0o666, |p| p & 0o7777));
    options.open(path)
}

/// Up to `len` bytes at `offset`; none at the end of the file.
pub(super) fn read_at(file: &File, offset: u64, len: u32) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len as usize];
    let n = loop {
        match file.read_at(&mut buf, offset) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => break other?,
        }
    };
    buf.truncate(n);
    Ok(buf)
}

/// Each byte of `data` at `offset`.
pub(super) fn write_at(file: &File, offset: u64, data: &[u8]) -> io::Result<()> {
    file.write_all_at(data, offset)
}

/// A path as a C string, for the calls that std does not have.
fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

/// The two times of `attrs` for `utimensat`: a time not sent is left.
fn times(attrs: &FileAttributes) -> [libc::timespec; 2] {
    let one = |t: Option<u32>| {
        // Zeroed first: a target's timespec can have padding fields.
        // SAFETY: timespec is plain integers, for which zero is valid.
        let mut spec: libc::timespec = unsafe { std::mem::zeroed() };
        spec.tv_sec = t.map_or(0, |t| t as libc::time_t);
        spec.tv_nsec = if t.is_some() { 0 } else { libc::UTIME_OMIT };
        spec
    };
    [one(attrs.atime), one(attrs.mtime)]
}

fn check(result: libc::c_int) -> io::Result<()> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// SETSTAT: size, mode, times and owner, in `sftp-server`'s order; the
/// first that fails is the answer.
pub(super) fn set_path(path: &Path, attrs: &FileAttributes) -> io::Result<()> {
    if let Some(size) = attrs.size {
        OpenOptions::new().write(true).open(path)?.set_len(size)?;
    }
    if let Some(mode) = attrs.permissions {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777))?;
    }
    if attrs.atime.is_some() || attrs.mtime.is_some() {
        let c = c_path(path)?;
        // SAFETY: a valid C string and two initialised timespecs.
        check(unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times(attrs).as_ptr(), 0) })?;
    }
    if attrs.uid.is_some() || attrs.gid.is_some() {
        std::os::unix::fs::chown(path, attrs.uid, attrs.gid)?;
    }
    Ok(())
}

/// FSETSTAT: the same on an open file.
pub(super) fn set_file(file: &File, attrs: &FileAttributes) -> io::Result<()> {
    if let Some(size) = attrs.size {
        file.set_len(size)?;
    }
    if let Some(mode) = attrs.permissions {
        file.set_permissions(std::fs::Permissions::from_mode(mode & 0o7777))?;
    }
    if attrs.atime.is_some() || attrs.mtime.is_some() {
        // SAFETY: an open descriptor and two initialised timespecs.
        check(unsafe { libc::futimens(file.as_raw_fd(), times(attrs).as_ptr()) })?;
    }
    if attrs.uid.is_some() || attrs.gid.is_some() {
        std::os::unix::fs::fchown(file, attrs.uid, attrs.gid)?;
    }
    Ok(())
}

/// MKDIR with the request's mode, else 0777 under the umask.
pub(super) fn mkdir(path: &Path, attrs: &FileAttributes) -> io::Result<()> {
    std::fs::DirBuilder::new().mode(attrs.permissions.map_or(0o777, |p| p & 0o7777)).create(path)
}

/// RENAME of version 3: never over a name that exists (posix-rename is
/// the one that replaces). The check and the rename are two calls, as
/// `sftp-server` makes them for a file that it cannot link.
pub(super) fn rename_new(from: &Path, to: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(to) {
        Ok(_) => Err(io::Error::from_raw_os_error(libc::EEXIST)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => std::fs::rename(from, to),
        Err(e) => Err(e),
    }
}

/// The absolute name of `path` with each link followed. The last part may
/// be missing, as OpenSSH's `sftp_realpath` allows: a client asks for the
/// name of a file it is about to make.
pub(super) fn realpath(path: &Path) -> io::Result<PathBuf> {
    match std::fs::canonicalize(path) {
        Ok(found) => Ok(found),
        Err(e) if e.kind() == io::ErrorKind::NotFound => match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => Ok(std::fs::canonicalize(parent)?.join(name)),
            _ => Err(e),
        },
        Err(e) => Err(e),
    }
}

/// An open directory: its path, for `.` and `..` and each entry's lstat,
/// and where its listing is.
pub(super) struct Dir {
    path: PathBuf,
    entries: ReadDir,
    dots_sent: bool,
}

impl Dir {
    pub(super) fn open(path: PathBuf) -> io::Result<Dir> {
        let entries = std::fs::read_dir(&path)?;
        Ok(Dir { path, entries, dots_sent: false })
    }

    /// The next names, [`NAMES_PER_READ`] at most; none at the end. `.` and
    /// `..` come first, as readdir(3) gives them; an entry that went away
    /// since the listing began is passed over.
    pub(super) fn next_names(&mut self, now: i64) -> io::Result<Vec<Named>> {
        let mut out = Vec::new();
        let named = |name: &str, m: &Metadata| Named {
            filename: name.to_string(),
            longname: long_name(name, m, now),
            attrs: attrs(m),
        };
        if !self.dots_sent {
            self.dots_sent = true;
            for (name, path) in [(".", self.path.clone()), ("..", self.path.join(".."))] {
                if let Ok(m) = std::fs::symlink_metadata(&path) {
                    out.push(named(name, &m));
                }
            }
        }
        while out.len() < NAMES_PER_READ {
            let Some(entry) = self.entries.next() else { break };
            let entry = entry?;
            // Names are text in russh-sftp: a byte that is not UTF-8 is U+FFFD.
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Ok(m) = std::fs::symlink_metadata(entry.path()) {
                out.push(named(&name, &m));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_path_starts_at_home_and_an_empty_one_is_home() {
        let home = Path::new("/home/cage");
        assert_eq!(resolve(home, ""), PathBuf::from("/home/cage"));
        assert_eq!(resolve(home, "a/b"), PathBuf::from("/home/cage/a/b"));
        assert_eq!(resolve(home, "/etc/x"), PathBuf::from("/etc/x"));
    }

    #[test]
    fn each_errno_has_sftp_server_s_code_and_the_words_lose_rust_s_number() {
        let code = |n| status_of(&io::Error::from_raw_os_error(n));
        assert_eq!(code(libc::ENOENT), StatusCode::NoSuchFile);
        assert_eq!(code(libc::ENOTDIR), StatusCode::NoSuchFile);
        assert_eq!(code(libc::EACCES), StatusCode::PermissionDenied);
        assert_eq!(code(libc::EPERM), StatusCode::PermissionDenied);
        assert_eq!(code(libc::EINVAL), StatusCode::BadMessage);
        assert_eq!(code(libc::ENOSYS), StatusCode::OpUnsupported);
        assert_eq!(code(libc::EEXIST), StatusCode::Failure);
        let said = words(&io::Error::from_raw_os_error(libc::ENOENT));
        assert!(!said.contains("os error") && said.contains("No such file"), "{said}");
    }

    #[test]
    fn the_long_name_has_the_link_count_where_the_client_line_has_a_question_mark() {
        let dir = std::env::temp_dir().join(format!("podssh-sftp-long-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let m = std::fs::symlink_metadata(&dir).unwrap();
        let line = long_name("top", &m, 0);
        assert!(line.starts_with('d'), "{line}");
        // A new directory with one below it has three links.
        assert_eq!(&line[12..15], "  3", "{line}");
        assert!(line.ends_with(" top"), "{line}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_fifo_keeps_its_type_bits() {
        let dir = std::env::temp_dir().join(format!("podssh-sftp-fs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("fifo");
        let c = c_path(&fifo).unwrap();
        // SAFETY: a valid C string.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let a = attrs(&std::fs::symlink_metadata(&fifo).unwrap());
        assert_eq!(a.permissions.unwrap() & 0o170_000, 0o010_000);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
