//! The static cover site of a relay name (#225, T-764), and the
//! application-layer credential that its authenticated client is given
//! (T-765). The tree, the routing of a name to it and the `Server` value are
//! `pod-cover`'s: this module only hands it the request and the name, and
//! issues the credential with an operator key.
//!
//! The credential is not RFC 9345 and not TLS-level delegation: it is signed
//! after the handshake with an operator-held Ed25519 key, whose public half
//! this role pins, and it is checked against that key, the same name, its
//! window, the TLS exporter of the connection and the signatures already
//! spent (see `podssh_ws::delegated`).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use ed25519_dalek::{SigningKey, VerifyingKey};
use pod_cover::{Credential, CredentialError, Record, Script, Site, Sites};
use podssh_ws::delegated;
use podssh_ws::http::request::Request;

/// The path of the credential on an authenticated connection (T-765).
pub const DELEGATE: &str = "/v1/delegate";

/// How long a credential lives, in seconds.
pub const WINDOW_SECS: i64 = 300;

/// How far before the issue a credential is already valid, for a clock that
/// is a little behind.
pub const BACKDATE_SECS: i64 = 5;

/// The operator's Ed25519 issuer: the secret half that signs, when this
/// process holds it, and the public half that the role pins and checks.
#[derive(Clone)]
pub struct Issuer {
    signing: Option<SigningKey>,
    pinned: VerifyingKey,
}

impl fmt::Debug for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issuer").field("signs", &self.signing.is_some()).field("key", &self.fingerprint()).finish()
    }
}

impl Issuer {
    /// A fresh key of this process's: the public half is pinned for the
    /// process, and no certificate derives the secret. `--cover-issuer-key`
    /// keeps one across restarts.
    pub fn random() -> Issuer {
        Self::from_seed(rand::random())
    }

    /// The operator's key from its 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Issuer {
        Self::from_signing(delegated::issuer_signing_key(&seed))
    }

    /// The operator's key from a signing key read elsewhere.
    pub fn from_signing(signing: SigningKey) -> Issuer {
        Issuer { pinned: signing.verifying_key(), signing: Some(signing) }
    }

    /// A role that pins `pinned` and holds no secret of its own: it verifies
    /// a credential that an operator signed elsewhere, and issues none.
    pub fn verify_only(pinned: VerifyingKey) -> Issuer {
        Issuer { signing: None, pinned }
    }

    /// The pinned public key, which each upgrade is checked against.
    pub fn pinned(&self) -> VerifyingKey {
        self.pinned
    }

    /// Whether this process holds the signing half.
    pub fn signs(&self) -> bool {
        self.signing.is_some()
    }

    /// The first eight bytes of the pinned key, in hexadecimal: enough to
    /// name the key in a log, not enough to use it.
    pub fn fingerprint(&self) -> String {
        self.pinned.as_bytes()[..8].iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// Why the role did not admit a credential on an upgrade. Each refusal names
/// the field that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The credential's own check failed: another key, name, window or
    /// exporter.
    Credential(CredentialError),
    /// The signature was already spent on an earlier upgrade.
    Replayed,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Credential(why) => why.fmt(f),
            VerifyError::Replayed => f.write_str("the credential was replayed"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<CredentialError> for VerifyError {
    fn from(why: CredentialError) -> Self {
        VerifyError::Credential(why)
    }
}

/// The cover site of one role, and the operator key that issues and checks
/// its credentials.
pub struct Cover {
    sites: Sites,
    /// The one name of the certificate, which the credential names as its
    /// issuer and as its subject name.
    pub name: String,
    /// The operator key: the pinned public half, and the secret half when
    /// this process issues credentials.
    issuer: Issuer,
    /// Each signature already spent on an upgrade, with the end of its
    /// window: a credential is not single use unless the role remembers it.
    /// Expired entries are pruned, so the set is bounded by the credentials
    /// whose window still holds.
    spent: Mutex<HashMap<[u8; 64], i64>>,
    pub server: String,
    /// Each name that this role terminates here, lower-cased: the name of
    /// the certificate first, then each `--cover-name` (T-764). A name of
    /// `--publish` that is one of these is a refusal at the start.
    owned: Vec<String>,
    /// The cover script that the role was given, if any (podnet#491).
    pub script: Option<Script>,
}

impl std::fmt::Debug for Cover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cover")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("sites", &self.sites.names.len())
            .field("owned", &self.owned)
            .finish_non_exhaustive()
    }
}

impl Cover {
    /// A cover of `site` for `name`, with the operator `issuer`, and
    /// `server` as its `Server` value when one is named. The same site is
    /// the default, so a name that is not `name` gets its own 404 page
    /// (COVER-1).
    pub fn new(site: Site, name: &str, issuer: Issuer, server: Option<&str>) -> Result<Arc<Cover>, String> {
        Self::build(site, name, &[], issuer, server, None)
    }

    /// A cover that terminates `name` and each name of `owned` itself, and
    /// serves the one site for each of them. A name that is not a DNS name,
    /// or that is `name` twice, is skipped: the caller checks it.
    pub fn new_named(
        site: Site,
        name: &str,
        owned: &[String],
        issuer: Issuer,
        server: Option<&str>,
    ) -> Result<Arc<Cover>, String> {
        Self::build(site, name, owned, issuer, server, None)
    }

    /// [`Self::new_named`], with the cover script that the role was given.
    pub fn new_covered(
        site: Site,
        name: &str,
        owned: &[String],
        issuer: Issuer,
        server: Option<&str>,
        script: Option<Script>,
    ) -> Result<Arc<Cover>, String> {
        Self::build(site, name, owned, issuer, server, script)
    }

    fn build(
        mut site: Site,
        name: &str,
        owned: &[String],
        issuer: Issuer,
        server: Option<&str>,
        script: Option<Script>,
    ) -> Result<Arc<Cover>, String> {
        if let Some(value) = server {
            site.set_server(value).map_err(|e| e.to_string())?;
        }
        let shown = site.server().to_string();
        let mut sites = Sites::new(site.clone());
        let mut names = vec![name.to_ascii_lowercase()];
        sites.insert(name, site.clone());
        for extra in owned {
            let extra = extra.to_ascii_lowercase();
            if !names.contains(&extra) {
                sites.insert(&extra, site.clone());
                names.push(extra);
            }
        }
        Ok(Arc::new(Cover {
            sites,
            name: name.to_string(),
            issuer,
            spent: Mutex::new(HashMap::new()),
            server: shown,
            owned: names,
            script,
        }))
    }

    /// Each name that this role terminates itself, in lower case: the name
    /// of the certificate and each `--cover-name`.
    pub fn owned_names(&self) -> &[String] {
        &self.owned
    }

    /// The first `len` records of the script, as a replay: the same script
    /// and length give the same sizes and delays. `None` without a script.
    pub fn first_records(&self, len: usize) -> Option<Vec<Record>> {
        self.script.as_ref().map(|script| script.replay(len))
    }

    /// The answer of the site to `head`, for the name of the `Host` header
    /// or of the handshake.
    pub fn respond(&self, sni: Option<&str>, head: &Request) -> Vec<u8> {
        let host = head.header("host").map(host_name).or(sni);
        self.sites.respond(host, &request_bytes(head)).to_bytes()
    }

    /// The site's own 404 page, with the head of a HEAD when `head` is one.
    pub fn not_found(&self, head: &Request) -> Vec<u8> {
        self.sites.default.not_found(head.method == "HEAD").to_bytes()
    }

    /// The operator key that this role pins, and signs with when it holds
    /// the secret half.
    pub fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// The credential of `subject` at `now`, bound to `exporter`: the name
    /// that this connection presented (`name`) as issuer and subject when it
    /// is one that the role terminates, else the certificate's first name; a
    /// short window; and the exporter of the connection. A role that pins a
    /// key it does not hold issues none.
    pub fn issue(
        &self,
        subject: [u8; 32],
        now: i64,
        exporter: &[u8],
        name: Option<&str>,
    ) -> Result<Credential, String> {
        let key = self
            .issuer
            .signing
            .as_ref()
            .ok_or("this relay pins the issuer key and holds no secret half: no credential is issued here")?;
        let chosen = name
            .map(str::to_ascii_lowercase)
            .filter(|name| self.owned.contains(name))
            .unwrap_or_else(|| self.name.clone());
        Credential::issue(key, &chosen, &chosen, now - BACKDATE_SECS, now + WINDOW_SECS, subject, Some(exporter))
            .map_err(|e| e.to_string())
    }

    /// Whether the role admits `credential` on an upgrade of the name that
    /// the connection presented (`name`), at `now`, with `exporter`. The
    /// pinned key checks the signature, the name, the window and the
    /// exporter; a signature already spent is refused as a replay.
    pub fn admit(
        &self,
        credential: &Credential,
        exporter: &[u8],
        now: i64,
        name: Option<&str>,
    ) -> Result<(), VerifyError> {
        // One lock over the replay check, the check itself and the record,
        // so that two upgrades of the same credential cannot both pass.
        let mut spent = self.spent.lock().unwrap_or_else(PoisonError::into_inner);
        if spent.contains_key(&credential.signature) {
            return Err(VerifyError::Replayed);
        }
        let chosen = name
            .map(str::to_ascii_lowercase)
            .filter(|name| self.owned.contains(name))
            .unwrap_or_else(|| self.name.clone());
        credential.verify(&chosen, now, Some(exporter), &self.issuer.pinned)?;
        // An expired signature can never verify again, so its record can go.
        if spent.len() >= 1024 {
            spent.retain(|_, until| *until >= now);
        }
        spent.insert(credential.signature, credential.not_after);
        Ok(())
    }

    /// The header that carries a credential on an upgrade, lowercase.
    pub fn credential_header() -> &'static str {
        "x-cover-credential"
    }
}

/// The name of a `Host` header, with its port removed: `example.org:443` is
/// `example.org`, and an IPv6 literal in brackets is left as it came.
fn host_name(value: &str) -> &str {
    if value.starts_with('[') {
        return value;
    }
    match value.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && port.parse::<u16>().is_ok() => name,
        _ => value,
    }
}

/// The request head as the bytes that `Site::respond` reads: the request
/// line, each header, and the empty line. A body is no part of it.
fn request_bytes(head: &Request) -> Vec<u8> {
    let mut out = format!("{} {} HTTP/1.{}\r\n", head.method, head.target, head.minor).into_bytes();
    for (name, value) in &head.headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(text: &str) -> Request {
        podssh_ws::http::request::parse_request(text.as_bytes()).unwrap()
    }

    #[test]
    fn a_host_header_loses_its_port_and_a_name_is_taken_as_it_came() {
        assert_eq!(host_name("example.org:443"), "example.org");
        assert_eq!(host_name("example.org"), "example.org");
        assert_eq!(host_name("[::1]:443"), "[::1]:443");
        assert_eq!(host_name("example.org:no"), "example.org:no");
    }

    #[test]
    fn the_head_of_a_site_request_is_its_request_line_and_headers() {
        let text = "GET /a?b=1 HTTP/1.1\r\nHost: example.org\r\nAccept: */*\r\n\r\n";
        assert_eq!(
            String::from_utf8(request_bytes(&head(text))).unwrap(),
            "GET /a?b=1 HTTP/1.1\r\nhost: example.org\r\naccept: */*\r\n\r\n"
        );
    }
}
