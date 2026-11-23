//! A control socket at a path longer than a socket's address holds (T-857).
//! `sun_path` takes 104 bytes with its NUL on macOS and the BSDs, 108 on
//! Linux, and `bind(2)` refuses a longer path; macOS's temporary directory
//! alone takes about 50. The path's directory is reached instead through a
//! short symbolic link of this process under `/tmp` (or `/var/tmp`): the
//! kernel follows the link, so the socket's file is made at the path that
//! the owner named, and the link goes at once. No `chdir`: the working
//! directory is the whole process's.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

/// The short directories, in order, where the link is made.
const SHORT: [&str; 2] = ["/tmp", "/var/tmp"];

/// At most this many names are tried in each short directory.
const NAMES: usize = 8;

/// The bytes of a socket's address for its path, with its NUL.
pub(crate) fn room() -> usize {
    // SAFETY: a sockaddr_un of zeros is a valid value; only its size is read.
    unsafe { std::mem::zeroed::<libc::sockaddr_un>() }.sun_path.len()
}

/// Whether `path` fits a socket's address of `room` bytes, with its NUL.
pub(crate) fn fits(path: &Path, room: usize) -> bool {
    path.as_os_str().len() < room
}

/// The listener at `path`, which does not fit `room`, bound through a short
/// link to its directory. Each failure is one line that says why; the caller
/// adds the path.
pub(crate) fn bind(path: &Path, room: usize) -> Result<UnixListener, String> {
    let long = format!(
        "a path of {} bytes, and a socket's address holds {} with its NUL on this system",
        path.as_os_str().len(),
        room - 1
    );
    let Some(leaf) = path.file_name() else {
        return Err(format!("{long}, and the path names no file"));
    };
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    // The link's target is absolute, so that it means the same from /tmp.
    let dir = std::fs::canonicalize(dir).map_err(|e| format!("{long}; its directory: {e}"))?;
    let mut tried = Vec::new();
    for base in SHORT {
        let base = Path::new(base);
        let link = match link_in(base, &dir) {
            Ok(link) => link,
            Err(why) => {
                tried.push(format!("{}: {why}", base.display()));
                continue;
            }
        };
        let through = link.join(leaf);
        let bound = if fits(&through, room) {
            UnixListener::bind(&through).map_err(|e| e.to_string())
        } else {
            Err(format!("its file name of {} bytes does not fit even there", leaf.len()))
        };
        // The link served its one call; it never outlives it.
        let _ = std::fs::remove_file(&link);
        match bound {
            Ok(listener) => return arrived(path, listener),
            Err(why) => tried.push(format!("{}: {why}", base.display())),
        }
    }
    Err(format!("{long}, and no short link to its directory served ({}): name a shorter path", tried.join("; ")))
}

/// The listener, once its file is a socket at `path`: a link that was not
/// the one made would have put it elsewhere, which is refused.
fn arrived(path: &Path, listener: UnixListener) -> Result<UnixListener, String> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => Ok(listener),
        _ => Err("the socket was not made at the path through its link".to_string()),
    }
}

/// A new symbolic link to `dir` in `base`, under a name that another user
/// cannot guess. `base` must be a directory whose links another user cannot
/// remove or replace: sticky, or this user's own.
fn link_in(base: &Path, dir: &Path) -> Result<PathBuf, String> {
    let meta = std::fs::metadata(base).map_err(|e| e.to_string())?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    if !meta.is_dir() || (meta.mode() & 0o1000 == 0 && meta.uid() != me) {
        return Err("neither sticky nor this user's".to_string());
    }
    let mut last = String::from("no name was free");
    for _ in 0..NAMES {
        let link = base.join(format!(".podssh-ctl-{:016x}", rand::random::<u64>()));
        match std::os::unix::fs::symlink(dir, &link) {
            Ok(()) => return Ok(link),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = e.to_string(),
            Err(e) => return Err(e.to_string()),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One rule for each system: a path fits when its bytes and its NUL do.
    /// The rule is pinned for macOS's 104 bytes on each system, and for
    /// Linux's 108.
    #[test]
    fn a_path_fits_when_its_bytes_and_its_nul_do() {
        for room in [104, 108] {
            for (len, fit) in [(1, true), (room - 1, true), (room, false), (120, false)] {
                let path = PathBuf::from(format!("/{}", "x".repeat(len - 1)));
                assert_eq!(path.as_os_str().len(), len);
                assert_eq!(fits(&path, room), fit, "{len} bytes in {room}");
            }
        }
        assert!(room() == 104 || room() == 108, "{}", room());
    }

    /// A directory of 120 bytes and more takes the socket at the path that
    /// was named, through a link that is gone after; a file name that fits
    /// no link is one line that says why.
    #[test]
    fn a_socket_in_a_directory_past_the_address_is_bound_at_its_path() {
        let top =
            std::env::temp_dir().join(format!("podssh-t857-{}-{:08x}", std::process::id(), rand::random::<u32>()));
        let mut dir = top.clone();
        while dir.as_os_str().len() < 120 {
            dir.push("d".repeat(20));
        }
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control.sock");
        assert!(!fits(&path, room()));
        assert!(UnixListener::bind(&path).is_err(), "the system refuses the path itself");

        let listener = bind(&path, room()).unwrap();
        assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        // A client reaches it by a short path of its own.
        let link = std::env::temp_dir().join(format!("podssh-t857-link-{:08x}", rand::random::<u32>()));
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let client = std::os::unix::net::UnixStream::connect(link.join("control.sock"));
        let _ = std::fs::remove_file(&link);
        assert!(client.is_ok(), "{client:?}");
        drop(listener);

        let name = "n".repeat(110);
        let refused = bind(&dir.join(&name), room()).unwrap_err();
        assert!(refused.contains("file name of 110 bytes"), "{refused}");
        assert!(refused.contains("name a shorter path"), "{refused}");
        let _ = std::fs::remove_dir_all(&top);
    }
}
