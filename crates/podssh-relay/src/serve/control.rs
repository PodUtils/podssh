//! The owner's control socket of a cover role (#225, T-767): the documents
//! and the probes that `--cover` takes off the public listener are served
//! here instead, on a Unix socket of mode 0600 that the owner names with
//! `--control-socket PATH`. The socket is local: no TLS, no token, the
//! owner's file mode alone. A socket file that already exists is refused
//! rather than replaced, so a role never takes a socket that another process
//! made. The bind is pod-core's `bind_staged` (T-857, PodUtils/podssh#343):
//! the socket takes its mode in a private stage beside the path and is
//! linked to the path, and a path longer than a socket's address holds
//! (macOS's temporary directory leaves little of its 104 bytes) is bound
//! through a short way to the stage, so it lands at the path that was named.

#[cfg(unix)]
mod unix {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use super::super::Config;

    /// The bytes of a socket's address for its path, with its NUL: 104 on
    /// macOS and the BSDs, 108 on Linux.
    pub(crate) fn room() -> usize {
        // SAFETY: a sockaddr_un of zeros is a valid value; only its size is read.
        unsafe { std::mem::zeroed::<libc::sockaddr_un>() }.sun_path.len()
    }

    /// Whether `path` fits a socket's address of `room` bytes, with its NUL.
    pub(crate) fn fits(path: &Path, room: usize) -> bool {
        path.as_os_str().len() < room
    }

    /// The owner's control socket, bound and of mode 0600.
    pub struct Control {
        path: PathBuf,
        listener: Option<std::os::unix::net::UnixListener>,
        /// The bytes that a socket's address holds, when the path passed
        /// them and a short way to its stage bound it.
        linked: Option<usize>,
    }

    impl Control {
        /// Bind `path` of mode 0600: a file that exists already and a path
        /// that cannot be bound are each refused with why. A path that does
        /// not fit a socket's address is bound through a short way to its
        /// stage, or refused with why.
        pub fn bind(path: &str) -> Result<Control, String> {
            let where_ = Path::new(path);
            // A dangling link is a file that exists, too.
            if where_.exists() || where_.symlink_metadata().is_ok() {
                return Err(format!("{path} exists: remove it, or name another --control-socket"));
            }
            let room = room();
            // Mode 0600 from the first instant: no window of the umask's mode.
            let listener = pod_core::files::bind_staged(where_, 0o600).map_err(|e| {
                // pod-core's own lines of a name or a race name the path.
                let why = e.to_string();
                if why.starts_with(path) {
                    why
                } else {
                    format!("{path}: {why}")
                }
            })?;
            let linked = (!fits(where_, room)).then_some(room);
            Ok(Control { path: where_.to_path_buf(), listener: Some(listener), linked })
        }

        /// The path of the socket, as the first line names it.
        pub fn path(&self) -> &Path {
            &self.path
        }

        /// The words of the first line for a path that passed a socket's
        /// address: a client too must reach it by a shorter path.
        pub fn note(&self) -> Option<String> {
            self.linked.map(|room| {
                format!(
                    "a path of {} bytes, more than a socket's address holds here ({}): a client reaches it by a \
                     shorter one, a link to its directory or a relative path",
                    self.path.as_os_str().len(),
                    room - 1
                )
            })
        }

        /// Serve each local connection as one request of the role's routes,
        /// with the documents and the probes kept here rather than moved.
        pub async fn serve(mut self: Box<Self>, cfg: Arc<Config>) {
            let Some(listener) = self.listener.take() else { return };
            if listener.set_nonblocking(true).is_err() {
                return;
            }
            let Ok(listener) = tokio::net::UnixListener::from_std(listener) else { return };
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        tokio::spawn(super::super::serve_local(stream, cfg.clone()));
                    }
                    // A failed accept is a descriptor spent: a pause, so that
                    // the loop does not take a whole core.
                    Err(_) => tokio::time::sleep(super::super::slots::ACCEPT_PAUSE).await,
                }
            }
        }
    }

    impl Drop for Control {
        /// The socket file goes with the role, so that the next start binds.
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(unix)]
pub use unix::Control;

#[cfg(not(unix))]
mod other {
    /// No Unix socket on this system: `--control-socket` and `--cover` are
    /// refused at the start, which names the system.
    pub struct Control;

    impl Control {
        pub fn bind(_path: &str) -> Result<Control, String> {
            Err("--control-socket needs Unix: this system has no Unix socket".to_string())
        }

        pub fn path(&self) -> &std::path::Path {
            std::path::Path::new("")
        }

        pub fn note(&self) -> Option<String> {
            None
        }

        pub async fn serve(self: Box<Self>, _cfg: std::sync::Arc<super::super::Config>) {}
    }
}

#[cfg(not(unix))]
pub use other::Control;

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::path::PathBuf;

    use super::unix::{fits, room};
    use super::Control;

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

    /// A directory of 120 bytes and more, which the system refuses to bind
    /// in directly, takes the socket at the path that was named, and a
    /// client reaches it through a short link of its own; nothing of the
    /// bind's stage stays beside it. A file name past the 255 bytes of a
    /// name is one line that names the path.
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
        assert!(std::os::unix::net::UnixListener::bind(&path).is_err(), "the system refuses the path itself");

        let control = Control::bind(path.to_str().unwrap()).unwrap();
        assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left, vec![std::ffi::OsString::from("control.sock")], "the stage stayed beside the socket");
        // The client's own short link: in /tmp, as $TMPDIR can be long itself.
        let short = if std::path::Path::new("/tmp").is_dir() { PathBuf::from("/tmp") } else { std::env::temp_dir() };
        let link = short.join(format!("podssh-t857-link-{:08x}", rand::random::<u32>()));
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let client = std::os::unix::net::UnixStream::connect(link.join("control.sock"));
        let _ = std::fs::remove_file(&link);
        assert!(client.is_ok(), "{client:?}");
        drop(control);

        let name = dir.join("n".repeat(256));
        let refused = Control::bind(name.to_str().unwrap()).err().expect("a name of 256 bytes");
        assert!(refused.starts_with(name.to_str().unwrap()), "{refused}");
        assert!(refused.contains("give a file name of 1 to 255 bytes"), "{refused}");
        let _ = std::fs::remove_dir_all(&top);
    }

    /// The role's socket at a path that passes the address (macOS's
    /// temporary directory and a test's scratch directory did, T-857): bound
    /// at that path, of mode 0600, said on the first line, and gone with the
    /// role; a second bind of the path is refused.
    #[test]
    fn a_control_socket_past_the_address_is_bound_of_mode_0600_and_said() {
        let top =
            std::env::temp_dir().join(format!("podssh-t857c-{}-{:08x}", std::process::id(), rand::random::<u32>()));
        let mut dir = top.clone();
        while dir.as_os_str().len() < 120 {
            dir.push("c".repeat(20));
        }
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control.sock");
        let control = Control::bind(path.to_str().unwrap()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let note = control.note().expect("the first line says how a client reaches it");
        assert!(note.contains(&format!("a path of {} bytes", path.as_os_str().len())), "{note}");
        let again = Control::bind(path.to_str().unwrap()).err().expect("a second bind of the path");
        assert!(again.contains("exists"), "{again}");
        drop(control);
        assert!(!path.exists(), "the socket went with the role");

        // A path that fits takes no link, and says nothing of it.
        let short = top.join("s.sock");
        if fits(&short, room()) {
            let control = Control::bind(short.to_str().unwrap()).unwrap();
            assert_eq!(control.note(), None);
        }
        let _ = std::fs::remove_dir_all(&top);
    }
}
