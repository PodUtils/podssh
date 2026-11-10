//! The node's TLS key of the Pinggy road (T-548): one P-256 key, kept in a
//! private file beside the node's own key, whose pin (the SHA-256 of its
//! SubjectPublicKeyInfo) the node says with each tunnel's name and clients
//! hold. So the pin stays across the hourly names and across restarts, and
//! a stranger at a name, which has another key, is refused at TLS. The
//! certificate is made of the key at each start: the pin is the key's, not
//! the certificate's. A node whose key is for its run alone
//! (`--ephemeral-key`), or whose file cannot be used, has a TLS key for its
//! run alone, and its line says so: its pin is then new at each start.

use std::path::{Path, PathBuf};

use podssh_relay::pinggy::Pin;
use zeroize::Zeroizing;

use crate::acme::certs::{self, Key};

/// The name in the node's certificate: no one's, as the client checks the
/// key alone, and a tunnel's name changes each hour.
const CERT_NAME: &str = "podssh-node.invalid";
/// What the file of the TLS key adds to the name of the node's key file.
pub(crate) const SUFFIX: &str = ".pinggy-tls.pem";

/// The node's TLS: its certificate and key as PEM, the pin, and where the
/// key is kept, for the node's line.
pub(crate) struct NodeTls {
    pub cert_pem: String,
    pub key_pem: Zeroizing<String>,
    pub pin: Pin,
    pub kept: String,
}

/// The file of the TLS key of the node whose key is in `node_key`.
pub(crate) fn path_beside(node_key: &Path) -> PathBuf {
    let mut name = node_key.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(SUFFIX);
    node_key.with_file_name(name)
}

/// The key of `path`, when the file is there; else none.
fn read(path: &Path) -> Result<Option<Key>, String> {
    if matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(None);
    }
    let text = Zeroizing::new(podssh_relay::cache::read_private(path)?);
    let der = certs::pem_block(&text, "PRIVATE KEY").ok_or_else(|| format!("{}: no PRIVATE KEY", path.display()))?;
    Key::from_pkcs8(&der).map(Some).map_err(|why| format!("{}: {why}", path.display()))
}

/// The key kept in `path`, made there when missing; and whether it is new.
fn kept_key(path: &Path) -> Result<(Key, bool), String> {
    if let Some(key) = read(path)? {
        return Ok((key, false));
    }
    let key = Key::generate()?;
    let written = podssh_relay::cache::create_new_private(path).and_then(|mut file| {
        use std::io::Write as _;
        file.write_all(key.pem().as_bytes())?;
        file.sync_all()
    });
    match written {
        Ok(()) => Ok((key, true)),
        // Another start made it first: its key, whose pin a client may hold.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            read(path)?.map(|key| (key, false)).ok_or_else(|| format!("{}: gone again", path.display()))
        }
        Err(e) => {
            let _ = std::fs::remove_file(path);
            Err(format!("{}: {e}", path.display()))
        }
    }
}

/// The TLS of the node whose key is in `node_key` (none: for its run alone).
pub(crate) fn load(node_key: Option<&Path>) -> Result<NodeTls, String> {
    let (key, kept) = match node_key.map(path_beside) {
        None => (Key::generate()?, "for this run only, as the node's key is".to_string()),
        Some(path) => match kept_key(&path) {
            Ok((key, true)) => (key, format!("a new key, in {}", path.display())),
            Ok((key, false)) => (key, format!("in {}", path.display())),
            Err(why) => (Key::generate()?, format!("for this run only, as its file cannot be used: {why}")),
        },
    };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    let cert_pem = certs::own(CERT_NAME, &key, now)?;
    let der = certs::pem_block(&cert_pem, "CERTIFICATE").ok_or("the node's certificate is not PEM")?;
    let pin = Pin::of_certificate(&der).ok_or("the node's certificate holds no key that can be read")?;
    Ok(NodeTls { cert_pem, key_pem: key.pem(), pin, kept })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_kept_beside_the_node_s_so_its_pin_stays_and_another_node_has_another() {
        let dir = std::env::temp_dir().join(format!("podssh-pinggy-cert-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        podssh_relay::cache::private_dir(&dir).unwrap();
        let node = dir.join("node.key");
        assert_eq!(path_beside(&node), dir.join("node.key.pinggy-tls.pem"));
        let first = load(Some(&node)).unwrap();
        assert!(first.kept.starts_with("a new key, in "), "{}", first.kept);
        let again = load(Some(&node)).unwrap();
        assert_eq!(again.pin, first.pin, "the same pin at the next start");
        assert!(again.kept.starts_with("in "), "{}", again.kept);
        assert_ne!(again.cert_pem, first.cert_pem, "a new certificate of the same key");
        let other = load(Some(&dir.join("stranger.key"))).unwrap();
        assert_ne!(other.pin, first.pin, "another node, another key");
        let run = load(None).unwrap();
        assert!(run.kept.starts_with("for this run only"), "{}", run.kept);
        assert_ne!(run.pin, first.pin);
        std::fs::write(dir.join("bad.key.pinggy-tls.pem"), "not a key").unwrap();
        let bad = load(Some(&dir.join("bad.key"))).unwrap();
        assert!(bad.kept.starts_with("for this run only, as its file cannot be used"), "{}", bad.kept);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
