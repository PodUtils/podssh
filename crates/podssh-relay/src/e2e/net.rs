//! The net's document between two ends (T-429): `pod-e2e`'s, with the
//! documents of this process. The binary installs them once (`podssh net`
//! checks the owner's signature and keeps the document), and each channel
//! of the process reads them: a node by [`process`], an operator by
//! [`installed`].

pub use pod_e2e::net::*;

use std::sync::{Arc, OnceLock};

use pod_identity::PublicKey;

static INSTALLED: OnceLock<Arc<dyn Docs>> = OnceLock::new();

/// The documents of this process, for each channel that it runs; the first
/// call wins, as a process has one user's net.
pub fn install(docs: Arc<dyn Docs>) {
    let _ = INSTALLED.set(docs);
}

/// The documents of this process, when it installed them.
pub fn installed() -> Option<Arc<dyn Docs>> {
    INSTALLED.get().cloned()
}

/// The documents of this process for a node's channels (`ends::Node::docs`):
/// each call reads [`installed`] anew, so a node made before the install
/// holds them too.
pub fn process() -> Option<Arc<dyn Docs>> {
    Some(Arc::new(Process))
}

/// The documents that this process installed, read at each call.
struct Process;

impl Docs for Process {
    fn held(&self) -> Option<(Held, Vec<u8>)> {
        installed()?.held()
    }

    fn shares_with(&self, peer: &PublicKey) -> bool {
        installed().is_some_and(|docs| docs.shares_with(peer))
    }

    fn take(&self, from: &PublicKey, bytes: &[u8]) -> Result<(), String> {
        installed().ok_or("this process holds no document of the net")?.take(from, bytes)
    }
}
