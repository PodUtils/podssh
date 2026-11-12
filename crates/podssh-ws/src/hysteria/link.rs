//! A Hysteria 2 server as its share link names it, the form of Hysteria's own
//! documents ("URI Scheme") that its clients and panels give out:
//! `hysteria2://AUTH@HOST[:PORT]/?sni=&pinSHA256=&insecure=&obfs=&obfs-password=#NAME`,
//! or `hy2://`. AUTH is the credential (a password, or `USER:PASSWORD` for a
//! server of `userpass`), and so is Salamander's password: the link is read
//! from a private file, and nothing that podssh shows holds either. A setting
//! that podssh does not follow (several ports, another obfuscation, ECH, a
//! realm) is refused by its name, never ignored.

use std::fmt;

use zeroize::Zeroizing;

/// The least length of Salamander's password, as Hysteria's own
/// obfuscator refuses a shorter one (`extras/obfs/salamander.go`).
pub const SALAMANDER_LEAST: usize = 4;

/// The credential of `Hysteria-Auth`, kept apart so that no `Debug` shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct Auth(Zeroizing<String>);

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Auth(<redacted>)")
    }
}

impl Auth {
    pub fn text(&self) -> &str {
        &self.0
    }
}

/// Salamander's pre-shared key, as its bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct ObfsKey(Zeroizing<Vec<u8>>);

impl fmt::Debug for ObfsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ObfsKey(<redacted>)")
    }
}

impl ObfsKey {
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// What the server's certificate is checked against.
#[derive(Clone, PartialEq, Eq)]
pub enum Check {
    /// The roots of podssh's trust (`--ca-file`), for the name of `sni`.
    Roots,
    /// The SHA-256 of the server's own certificate (`pinSHA256`): that
    /// certificate alone passes, with no root and no name asked.
    Pin([u8; 32]),
}

impl fmt::Debug for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Check::Roots => f.write_str("Roots"),
            Check::Pin(pin) => write!(f, "Pin({})", hex(pin)),
        }
    }
}

/// A server of the file: where QUIC goes, what TLS checks, what it sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub auth: Auth,
    /// The address that UDP goes to.
    pub host: String,
    pub port: u16,
    /// The name that TLS asks for: `sni`, else HOST.
    pub sni: String,
    pub check: Check,
    /// Salamander's key, when the link names `obfs=salamander`.
    pub obfs: Option<ObfsKey>,
    /// The link's fragment, its name in a panel.
    pub name: Option<String>,
}

impl Server {
    /// `hysteria2://HOST:PORT`, with no credential.
    pub fn shown(&self) -> String {
        let salamander = if self.obfs.is_some() { " (Salamander)" } else { "" };
        format!("hysteria2://{}{salamander}", crate::dial::authority(&self.host, self.port))
    }

    /// A share link. A refusal names the setting, never the credential.
    pub fn parse(link: &str) -> Result<Server, String> {
        let link = link.trim();
        let rest = ["hysteria2://", "hy2://"]
            .iter()
            .find_map(|scheme| link.get(..scheme.len()).filter(|s| s.eq_ignore_ascii_case(scheme)).map(|s| s.len()))
            .map(|at| &link[at..]);
        let Some(rest) = rest else {
            if link.get(..15).is_some_and(|s| s.eq_ignore_ascii_case("hysteria2+realm")) {
                return Err("a realm (hysteria2+realm://) is not spoken: podssh dials the server itself".into());
            }
            return Err("a line is hysteria2://AUTH@HOST[:PORT]/?sni=&pinSHA256=&obfs=... or hy2://".into());
        };
        let (rest, name) = match rest.split_once('#') {
            Some((rest, name)) => (rest, crate::proxy::percent_decode(name).ok().map(|n| crate::text::one_line(&n))),
            None => (rest, None),
        };
        let (before, query) = rest.split_once('?').unwrap_or((rest, ""));
        let before = before.trim_end_matches('/');
        let (auth, hostport) = before.rsplit_once('@').ok_or("the link has no AUTH@ before its host")?;
        let auth = Zeroizing::new(crate::proxy::percent_decode(auth).map_err(|_| "AUTH is not percent-encoded")?);
        if auth.is_empty() {
            return Err("AUTH is empty".into());
        }
        let (host, port) = host_port(hostport)?;
        let params = Params::parse(query)?;
        let check = check(&params)?;
        let obfs = obfs(&params)?;
        if params.get("ech").is_some_and(|v| !v.is_empty()) {
            return Err("ech is not spoken over QUIC here: podssh would send the name that it hides".into());
        }
        let sni = params.get("sni").filter(|s| !s.is_empty()).unwrap_or(host.as_str()).to_string();
        crate::dial::check_name(&sni).map_err(|e| format!("sni: {e}"))?;
        Ok(Server { auth: Auth(auth), host, port, sni, check, obfs, name })
    }
}

/// HOST and its one port (443 when none); several ports, Hysteria's port
/// hopping, are refused by their name.
fn host_port(hostport: &str) -> Result<(String, u16), String> {
    let tail = hostport.rsplit_once(']').map_or(hostport, |(_, after)| after);
    if tail.contains(',') || tail.rsplit_once(':').is_some_and(|(_, ports)| ports.contains('-')) {
        return Err("several ports (port hopping) are not spoken: give the server's one port".into());
    }
    let (host, port) = crate::dial::split_host_port(hostport)?;
    if host.is_empty() {
        return Err("the link names no host".into());
    }
    crate::dial::check_name(&host).map_err(|e| e.to_string())?;
    match port.unwrap_or(443) {
        0 => Err("port 0 is no port".into()),
        port => Ok((host, port)),
    }
}

/// The check of the certificate: a pin, else the roots. A certificate that
/// is not checked (`insecure=1` with no pin) is a server that anybody can be.
fn check(params: &Params) -> Result<Check, String> {
    let insecure = params.get("insecure").is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    match params.get("pinsha256").filter(|v| !v.is_empty()) {
        Some(text) => Ok(Check::Pin(pin(text)?)),
        None if insecure => Err("insecure=1 with no pinSHA256 is refused: podssh checks the server's certificate; \
             give its pinSHA256, or --ca-file names a CA of yours"
            .into()),
        None => Ok(Check::Roots),
    }
}

/// 64 hex digits, in either case, with `:` or `-` between them or not, as
/// Hysteria's client reads them (`normalizeCertHash`).
pub fn pin(text: &str) -> Result<[u8; 32], String> {
    let digits: Vec<u8> = text.bytes().filter(|b| !matches!(b, b':' | b'-')).collect();
    let bad = || "pinSHA256 is the 64 hex digits of the SHA-256 of the server's certificate".to_string();
    if digits.len() != 64 {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (i, pair) in digits.chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| bad())?;
        out[i] = u8::from_str_radix(text, 16).map_err(|_| bad())?;
    }
    Ok(out)
}

/// Lower-case hex, as a pin is shown.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Salamander's key, or none; another obfuscation is refused by its name.
fn obfs(params: &Params) -> Result<Option<ObfsKey>, String> {
    let kind = params.get("obfs").unwrap_or("").to_ascii_lowercase();
    match kind.as_str() {
        "" | "plain" | "none" => Ok(None),
        "salamander" => {
            let key = params.get("obfs-password").unwrap_or("").as_bytes().to_vec();
            if key.len() < SALAMANDER_LEAST {
                return Err(format!("obfs-password: Salamander's password has {SALAMANDER_LEAST} bytes at least"));
            }
            Ok(Some(ObfsKey(Zeroizing::new(key))))
        }
        other => Err(format!("obfs={other} is not spoken: podssh's Hysteria has Salamander alone")),
    }
}

/// The link's query, each value percent-decoded, each key in lower case.
struct Params(Vec<(String, Zeroizing<String>)>);

impl Params {
    fn parse(query: &str) -> Result<Params, String> {
        let mut out = Vec::new();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            // A `+` is a space, as Go's `url.ParseQuery`, which Hysteria's
            // client reads its links with, takes it.
            let value = crate::proxy::percent_decode(&value.replace('+', " "))
                .map_err(|_| format!("the value of {key} is not percent-encoded"))?;
            out.push((key.to_ascii_lowercase(), Zeroizing::new(value)));
        }
        Ok(Params(out))
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

#[cfg(test)]
#[path = "link_tests.rs"]
mod tests;
