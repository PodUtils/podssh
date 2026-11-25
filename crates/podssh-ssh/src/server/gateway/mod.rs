//! `podssh serve --gateway FILE` (T-836): serve as a gateway in front of
//! private hosts. The login name picks a route of the table (`routes.rs`);
//! the route lists the keys that may take it and pins its upstream's host
//! key. Once russh verified the client's signature, and never on a key that
//! was only offered, the gateway makes a fresh key, signs a user
//! certificate of it with the route's CA for 30 s, and logs in upstream with
//! russh's client (`upstream.rs`). An upstream that trusts the CA
//! (`TrustedUserCAKeys` of a stock sshd) lets it in as the route's
//! principal; its log names the certificate's key id, which holds the
//! route, the login name and the client key's fingerprint. Each session
//! channel and each `direct-tcpip` of the client is then carried to a
//! channel of the upstream (`handler.rs`, `pump.rs`). No private key of a
//! user reaches the gateway, and no secret of a route rests anywhere but in
//! its CA key file.
//!
//! The choice of a certificate over a relayed agent signature, and what a
//! compromised gateway can do, are in T-836's Decision and `docs/design.md`
//! ("A gateway in front of private hosts").

mod handler;
mod pump;
pub mod routes;
pub mod upstream;

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use pod_core::files::{read_own, Others};
use russh::keys::{Algorithm, PrivateKey};
use zeroize::Zeroizing;

pub(super) use handler::Gateway;
pub use routes::{Route, Routes};

/// The route table that a gateway serves, read again on a reload: a login
/// meets the table of its moment, and keeps the route it logged in by.
pub struct Table {
    path: PathBuf,
    routes: RwLock<Arc<Routes>>,
}

impl std::fmt::Debug for Table {
    // Never the routes: each holds a CA key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Table({}, {} routes)", self.path.display(), self.now().len())
    }
}

impl Table {
    /// The table in the file at `path`. A file that others may write, that
    /// does not read, or that holds no route refuses: a gateway that
    /// nobody can pass is a setup that went wrong.
    pub fn open(path: &Path) -> Result<Table, String> {
        let routes = read(path)?;
        Ok(Table { path: path.to_path_buf(), routes: RwLock::new(Arc::new(routes)) })
    }

    /// The table of this moment.
    pub fn now(&self) -> Arc<Routes> {
        match self.routes.read() {
            Ok(routes) => routes.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Read the file again (SIGHUP): the count of its routes; else why not,
    /// and the table before stays whole, so that no reload locks each user
    /// out. A login that passed keeps its upstream.
    pub fn reload(&self) -> Result<usize, String> {
        let routes = Arc::new(read(&self.path)?);
        let count = routes.len();
        match self.routes.write() {
            Ok(mut now) => *now = routes,
            Err(poisoned) => *poisoned.into_inner() = routes,
        }
        Ok(count)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// The routes in `path`, read as `authorized_keys` is read (this user's,
/// no link, writable by none else), each CA key as a private key is.
fn read(path: &Path) -> Result<Routes, String> {
    let shown = path.display();
    let text = read_own(path, Others::Read)?.ok_or_else(|| format!("{shown}: no such file"))?;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let routes = Routes::parse(&text, dir, &mut |ca: &Path| read_ca(ca)).map_err(|why| format!("{shown}, {why}"))?;
    if routes.is_empty() {
        return Err(format!("{shown} holds no route, so nobody could pass: give route PATTERN and its parts"));
    }
    Ok(routes)
}

/// A route's CA key: this user's, closed to others, with no passphrase
/// (serve has nobody to ask), and one that signs in the process.
fn read_ca(path: &Path) -> Result<PrivateKey, String> {
    let shown = path.display();
    let text = Zeroizing::new(read_own(path, Others::NoAccess)?.ok_or_else(|| format!("{shown}: no such file"))?);
    let key = match crate::key_file::decode(&text, None) {
        Ok(key) => key,
        Err(russh::keys::Error::KeyIsEncrypted) => {
            return Err(format!("{shown} has a passphrase, and serve has nobody to ask: give a CA key with none"));
        }
        Err(e) => return Err(format!("{shown} is not a private key: {e}")),
    };
    if matches!(key.algorithm(), Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256) {
        return Err(format!("{shown} is a security key, which signs only when touched: give a key in a file"));
    }
    Ok(key)
}
