//! The owner's control socket of a cover role (#225, T-767): the documents
//! and the probes that `--cover` takes off the public listener are served
//! here instead, on a Unix socket of mode 0600 that the owner names with
//! `--control-socket PATH`. The socket is local: no TLS, no token, the
//! owner's file mode alone. A socket file that already exists is refused
//! rather than replaced, so a role never takes a socket that another process
//! made.

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use super::super::Config;

    /// The owner's control socket, bound and of mode 0600.
    pub struct Control {
        path: PathBuf,
        listener: Option<std::os::unix::net::UnixListener>,
    }

    impl Control {
        /// Bind `path`: a file that exists already, a path that cannot be
        /// bound, and a mode that cannot be set are each refused with why.
        pub fn bind(path: &str) -> Result<Control, String> {
            let where_ = Path::new(path);
            if where_.exists() {
                return Err(format!("{path} exists: remove it, or name another --control-socket"));
            }
            let listener = std::os::unix::net::UnixListener::bind(where_).map_err(|e| format!("{path}: {e}"))?;
            if let Err(e) = std::fs::set_permissions(where_, std::fs::Permissions::from_mode(0o600)) {
                let _ = std::fs::remove_file(where_);
                return Err(format!("{path}: the mode of the socket: {e}"));
            }
            Ok(Control { path: where_.to_path_buf(), listener: Some(listener) })
        }

        /// The path of the socket, as the first line names it.
        pub fn path(&self) -> &Path {
            &self.path
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

        pub async fn serve(self: Box<Self>, _cfg: std::sync::Arc<super::super::Config>) {}
    }
}

#[cfg(not(unix))]
pub use other::Control;
