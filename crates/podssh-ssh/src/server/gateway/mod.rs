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
//!
//! The table comes from a [`Source`]: the file of `--gateway FILE`, or the
//! gateway's section of the net's signed document (`--gateway net:NAME`,
//! T-902), which podssh-cli reads and whose CA keys stay in files here.

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
pub use routes::{Planned, Route, Routes};

/// Where a gateway's routes come from: a file of the gateway's host
/// (T-836), or the gateway's section of a net's signed document, which the
/// binary reads (T-902).
pub trait Source: Send + Sync {
    /// The routes now, and a line for each route left out; `Err` keeps the
    /// routes before, as a read that failed decides nothing.
    fn read(&self) -> Result<(Routes, Vec<String>), String>;
    /// Where they come from, for a line: the file, or `net:NAME`.
    fn shown(&self) -> String;
    /// Why no route lets anyone in now, while the routes stay held: a
    /// document past its end. None by default.
    fn closed(&self) -> Option<String> {
        None
    }
}

/// A source shared with whoever watches it for a change (T-902).
impl<T: Source + ?Sized> Source for Arc<T> {
    fn read(&self) -> Result<(Routes, Vec<String>), String> {
        (**self).read()
    }

    fn shown(&self) -> String {
        (**self).shown()
    }

    fn closed(&self) -> Option<String> {
        (**self).closed()
    }
}

/// The routes of a file.
struct File(PathBuf);

impl Source for File {
    fn read(&self) -> Result<(Routes, Vec<String>), String> {
        read(&self.0).map(|routes| (routes, Vec::new()))
    }

    fn shown(&self) -> String {
        self.0.display().to_string()
    }
}

/// The route table that a gateway serves, read again on a reload: a login
/// meets the table of its moment, and keeps the route it logged in by.
pub struct Table {
    source: Box<dyn Source>,
    routes: RwLock<Arc<Routes>>,
}

impl std::fmt::Debug for Table {
    // Never the routes: each holds a CA key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Table({}, {} routes)", self.source.shown(), self.now().len())
    }
}

impl Table {
    /// The table in the file at `path`. A file that others may write, that
    /// does not read, or that holds no route refuses: a gateway that
    /// nobody can pass is a setup that went wrong.
    pub fn open(path: &Path) -> Result<Table, String> {
        Table::from_source(Box::new(File(path.to_path_buf()))).map(|(table, _)| table)
    }

    /// The table of `source`, read now, and the lines of its read; `Err`
    /// when it does not read. An empty table is the caller's to refuse.
    pub fn from_source(source: Box<dyn Source>) -> Result<(Table, Vec<String>), String> {
        let (routes, notes) = source.read()?;
        Ok((Table { source, routes: RwLock::new(Arc::new(routes)) }, notes))
    }

    /// The table of this moment.
    pub fn now(&self) -> Arc<Routes> {
        match self.routes.read() {
            Ok(routes) => routes.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Why no login passes now, whatever its route; never for a file.
    pub fn closed(&self) -> Option<String> {
        self.source.closed()
    }

    /// Read the source again (SIGHUP, or a newer document): the count of
    /// its routes and a line for each route left out; else why not, and
    /// the table before stays whole, so that no failed read locks each user
    /// out. A login that passed keeps its upstream.
    pub fn reload(&self) -> Result<(usize, Vec<String>), String> {
        let (routes, notes) = self.source.read()?;
        let routes = Arc::new(routes);
        let count = routes.len();
        match self.routes.write() {
            Ok(mut now) => *now = routes,
            Err(poisoned) => *poisoned.into_inner() = routes,
        }
        Ok((count, notes))
    }

    /// Where the routes come from: the file, or `net:NAME`.
    pub fn shown(&self) -> String {
        self.source.shown()
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
/// (serve has nobody to ask), and one that signs in the process: a route
/// file's `ca-key`, and each `--gateway-ca` of a gateway of a net (T-902).
pub fn read_ca(path: &Path) -> Result<PrivateKey, String> {
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
