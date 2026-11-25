//! The route table of a gateway (T-836): which upstream a login name
//! reaches, which keys may take that route, and how the gateway logs in
//! there. A text file of blocks, as ssh_config's `Host` blocks are read:
//!
//! ```text
//! route alice-*
//!     upstream 10.0.0.5:22
//!     host-key ssh-ed25519 AAAA... the upstream's host key, pinned
//!     principal alice
//!     ca-key /etc/podssh/gateway_ca
//!     key ssh-ed25519 AAAA... alice@laptop
//!     source-address 10.0.0.1
//! ```
//!
//! The first route whose pattern matches the login name decides; a key
//! that it does not list is refused, and no later route is tried, so one
//! name never reaches two upstreams. A name that no route matches is
//! refused: nothing maps to `none`. A route that lacks a part, a part twice,
//! an unknown word, or a value that does not read refuses the whole file,
//! with its line, so that a typing mistake never opens or closes a route
//! in silence.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use russh::keys::{PrivateKey, PublicKey};

/// The most routes in one file, and the most keys in one route: far more
/// than a person writes, and a bound on each login's search.
pub const MOST_ROUTES: usize = 1024;
pub const MOST_KEYS: usize = 1024;

/// The longest principal: OpenSSH's own limit on a user name is lower.
const MOST_PRINCIPAL: usize = 256;

/// One route. No Debug: it holds a CA key.
#[derive(Clone)]
pub struct Route {
    /// The login name's pattern, `*` and `?`, case-sensitive.
    pub pattern: String,
    /// The upstream's host and port, dialed as a forward is dialed.
    pub host: String,
    pub port: u16,
    /// The upstream's host key: any other key ends the dial.
    pub host_key: PublicKey,
    /// The keys that may take this route.
    pub keys: Vec<PublicKey>,
    /// The user that the gateway logs in as upstream, and the one principal
    /// of the certificate.
    pub principal: String,
    /// The key that signs each certificate of this route, and its file.
    pub ca: Arc<PrivateKey>,
    pub ca_path: PathBuf,
    /// The certificate's `source-address`, where the route gives one.
    pub source_address: Option<String>,
    /// The line of `route`, for a line of serve's log.
    pub line: usize,
}

impl Route {
    /// Whether `key` may take this route.
    pub fn admits(&self, key: &PublicKey) -> bool {
        self.keys.iter().any(|k| k.key_data() == key.key_data())
    }
}

/// Each route of a file, in its order.
#[derive(Clone, Default)]
pub struct Routes {
    routes: Vec<Arc<Route>>,
}

impl Routes {
    /// The first route whose pattern matches `user`; None refuses the login.
    pub fn route(&self, user: &str) -> Option<Arc<Route>> {
        self.routes.iter().find(|r| crate::known_hosts::wildcard(r.pattern.as_bytes(), user.as_bytes())).cloned()
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// The routes of `text`. `ca` reads a CA key file once for each path,
    /// which `dir` makes absolute when it is relative. `Err` names the line.
    pub fn parse(
        text: &str,
        dir: &Path,
        ca: &mut dyn FnMut(&Path) -> Result<PrivateKey, String>,
    ) -> Result<Routes, String> {
        let mut routes = Vec::new();
        let mut open: Option<Draft> = None;
        let mut keys_read: HashMap<PathBuf, Arc<PrivateKey>> = HashMap::new();
        for (n, raw) in text.lines().enumerate() {
            let n = n + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = |why: String| format!("line {n}: {why}");
            if line.chars().any(|c| c.is_control() && c != '\t') {
                return Err(at("a control character".into()));
            }
            let (word, rest) = line.split_once(char::is_whitespace).map_or((line, ""), |(w, r)| (w, r.trim()));
            if word == "route" {
                if let Some(draft) = open.take() {
                    routes.push(Arc::new(draft.close(dir, &mut keys_read, ca)?));
                }
                if routes.len() >= MOST_ROUTES {
                    return Err(at(format!("more than {MOST_ROUTES} routes")));
                }
                let pattern = pattern(rest).map_err(at)?;
                if routes.iter().any(|r: &Arc<Route>| r.pattern == pattern) {
                    return Err(at(format!("route {pattern} twice: the second could never match")));
                }
                open = Some(Draft { pattern, line: n, ..Draft::default() });
                continue;
            }
            let Some(draft) = open.as_mut() else {
                return Err(at(format!("{word} before any route: begin with route PATTERN")));
            };
            draft.take(word, rest).map_err(at)?;
        }
        if let Some(draft) = open.take() {
            routes.push(Arc::new(draft.close(dir, &mut keys_read, ca)?));
        }
        Ok(Routes { routes })
    }
}

/// A route as its lines come.
#[derive(Default)]
struct Draft {
    pattern: String,
    line: usize,
    upstream: Option<(String, u16)>,
    host_key: Option<PublicKey>,
    keys: Vec<PublicKey>,
    principal: Option<String>,
    ca_path: Option<PathBuf>,
    source_address: Option<String>,
}

impl Draft {
    fn take(&mut self, word: &str, rest: &str) -> Result<(), String> {
        if rest.is_empty() {
            return Err(format!("{word} with no value"));
        }
        let twice = |set: bool| if set { Err(format!("{word} twice in one route")) } else { Ok(()) };
        match word {
            "upstream" => {
                twice(self.upstream.is_some())?;
                self.upstream = Some(upstream(rest)?);
            }
            "host-key" => {
                twice(self.host_key.is_some())?;
                self.host_key = Some(public_key(rest)?);
            }
            "key" => {
                if self.keys.len() >= MOST_KEYS {
                    return Err(format!("more than {MOST_KEYS} keys in one route"));
                }
                self.keys.push(public_key(rest)?);
            }
            "principal" => {
                twice(self.principal.is_some())?;
                self.principal = Some(principal(rest)?);
            }
            "ca-key" => {
                twice(self.ca_path.is_some())?;
                self.ca_path = Some(PathBuf::from(rest));
            }
            "source-address" => {
                twice(self.source_address.is_some())?;
                // The certificate's own check of the list, so both agree.
                let mut request = crate::cert::Request::new("", false);
                request.option(&format!("source-address={rest}"))?;
                self.source_address = Some(rest.to_string());
            }
            other => {
                return Err(format!(
                    "{other} is not a part of a route: upstream, host-key, key, principal, ca-key or source-address"
                ));
            }
        }
        Ok(())
    }

    /// The route, once each part that it needs is there; its CA key read.
    fn close(
        self,
        dir: &Path,
        read: &mut HashMap<PathBuf, Arc<PrivateKey>>,
        ca: &mut dyn FnMut(&Path) -> Result<PrivateKey, String>,
    ) -> Result<Route, String> {
        let at = |why: &str| format!("line {}: route {} has no {why}", self.line, self.pattern);
        let (host, port) = self.upstream.ok_or_else(|| at("upstream HOST:PORT"))?;
        let host_key = self.host_key.ok_or_else(|| at("host-key: each route pins its upstream's key"))?;
        let principal = self.principal.ok_or_else(|| at("principal"))?;
        let given = self.ca_path.ok_or_else(|| at("ca-key FILE"))?;
        if self.keys.is_empty() {
            return Err(at("key: a route that no key may take refuses each login"));
        }
        let ca_path = if given.is_absolute() { given } else { dir.join(given) };
        let key = match read.get(&ca_path) {
            Some(key) => key.clone(),
            None => {
                let key = Arc::new(ca(&ca_path).map_err(|why| format!("line {}: ca-key {why}", self.line))?);
                read.insert(ca_path.clone(), key.clone());
                key
            }
        };
        Ok(Route {
            pattern: self.pattern,
            host,
            port,
            host_key,
            keys: self.keys,
            principal,
            ca: key,
            ca_path,
            source_address: self.source_address,
            line: self.line,
        })
    }
}

/// A route's pattern: one word of printable ASCII.
fn pattern(rest: &str) -> Result<String, String> {
    if rest.is_empty() {
        return Err("route with no pattern: give route PATTERN, as alice or team-*".into());
    }
    if rest.contains(char::is_whitespace) || !rest.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!("route {rest:?}: a pattern is one word of printable ASCII"));
    }
    Ok(rest.to_string())
}

/// `HOST[:PORT]`, an IPv6 address in brackets; 22 with no port.
fn upstream(rest: &str) -> Result<(String, u16), String> {
    let wrong = || format!("upstream {rest:?}: give HOST:PORT, [IPv6]:PORT or HOST");
    if rest.contains(char::is_whitespace) {
        return Err(wrong());
    }
    let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
        let (host, after) = inner.split_once(']').ok_or_else(wrong)?;
        match after {
            "" => (host, None),
            _ => (host, Some(after.strip_prefix(':').ok_or_else(wrong)?)),
        }
    } else {
        match rest.split_once(':') {
            Some((_, after)) if after.contains(':') => return Err(wrong()),
            Some((host, port)) => (host, Some(port)),
            None => (rest, None),
        }
    };
    if host.is_empty() {
        return Err(wrong());
    }
    let port = match port {
        None => 22,
        Some(port) => match port.parse::<u16>() {
            Ok(port) if port != 0 => port,
            _ => return Err(format!("upstream {rest:?}: {port:?} is not a TCP port")),
        },
    };
    Ok((host.to_string(), port))
}

/// A public key as a line of authorized_keys gives it: `TYPE BASE64
/// [COMMENT]`, with no options.
fn public_key(rest: &str) -> Result<PublicKey, String> {
    PublicKey::from_openssh(rest).map_err(|e| format!("not a public key, TYPE BASE64 [COMMENT]: {e}"))
}

/// A principal: one word, no comma (OpenSSH splits a list of them on it).
fn principal(rest: &str) -> Result<String, String> {
    let fits = rest.len() <= MOST_PRINCIPAL
        && !rest.starts_with('-')
        && rest.bytes().all(|b| b.is_ascii_graphic() && b != b',');
    if !fits {
        return Err(format!("principal {rest:?}: one user name of printable ASCII, with no comma"));
    }
    Ok(rest.to_string())
}

#[cfg(test)]
#[path = "routes_tests.rs"]
mod tests;
