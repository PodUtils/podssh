//! The owner's control socket of a cover role (#225, T-767): the documents
//! and the probes that `--cover` takes off the public listener are served
//! here instead, on a Unix socket of mode 0600 that the owner names with
//! `--control-socket PATH`. The socket is local: no TLS, no token, the
//! owner's file mode alone. A socket file that already exists is refused
//! rather than replaced, so a role never takes a socket that another process
//! made. A path longer than a socket's address holds (macOS's temporary
//! directory leaves little of its 104 bytes) is bound through a short link
//! to its directory, at the path that was named (T-857).

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use super::super::control_link as link;
    use super::super::Config;

    /// The owner's control socket, bound and of mode 0600.
    pub struct Control {
        path: PathBuf,
        listener: Option<std::os::unix::net::UnixListener>,
        /// The bytes that a socket's address holds, when the path passed
        /// them and a link bound it.
        linked: Option<usize>,
    }

    impl Control {
        /// Bind `path`: a file that exists already, a path that cannot be
        /// bound, and a mode that cannot be set are each refused with why.
        /// A path that does not fit a socket's address is bound through a
        /// short link to its directory, or refused with why.
        pub fn bind(path: &str) -> Result<Control, String> {
            let where_ = Path::new(path);
            // A dangling link is a file that exists, too.
            if where_.exists() || where_.symlink_metadata().is_ok() {
                return Err(format!("{path} exists: remove it, or name another --control-socket"));
            }
            let room = link::room();
            let (listener, linked) = if link::fits(where_, room) {
                (std::os::unix::net::UnixListener::bind(where_).map_err(|e| format!("{path}: {e}"))?, None)
            } else {
                (link::bind(where_, room).map_err(|why| format!("{path}: {why}"))?, Some(room))
            };
            if let Err(e) = std::fs::set_permissions(where_, std::fs::Permissions::from_mode(0o600)) {
                let _ = std::fs::remove_file(where_);
                return Err(format!("{path}: the mode of the socket: {e}"));
            }
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
    use std::os::unix::fs::PermissionsExt;

    use super::Control;

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
        if short.as_os_str().len() < super::super::control_link::room() {
            let control = Control::bind(short.to_str().unwrap()).unwrap();
            assert_eq!(control.note(), None);
        }
        let _ = std::fs::remove_dir_all(&top);
    }
}
