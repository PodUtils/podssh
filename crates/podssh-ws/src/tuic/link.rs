//! A TUIC server as its share link names it, the form that clients of
//! mihomo, sing-box and v2rayN give out:
//! `tuic://UUID:PASSWORD@HOST:PORT?sni=&alpn=h3&congestion_control=bbr&udp_relay_mode=native#NAME`.
//! The UUID and the password are the credential: the link is read from a
//! private file, and nothing that podssh shows holds either. A setting that
//! changes what podssh trusts (`allow_insecure`) or a version other than 5 is
//! refused by its name, never ignored. `congestion_control` is the sender's
//! own (no peer reads it), `udp_relay_mode` names a way for UDP, which this
//! road does not carry, and `disable_sni` and `reduce_rtt` shape a handshake
//! that the server takes either way: each passes.

use std::fmt;

use zeroize::Zeroizing;

/// A TUIC user's UUID: its 16 bytes are `Authenticate`'s first field and the
/// label of the token's exporter.
#[derive(Clone, PartialEq, Eq)]
pub struct Uuid(pub [u8; 16]);

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Uuid(<redacted>)")
    }
}

impl Uuid {
    /// The 36 characters with hyphens, or the 32 hex digits alone, in either
    /// case, as servers read it.
    pub fn parse(text: &str) -> Result<Uuid, String> {
        let hex: Vec<u8> = text.bytes().filter(|b| *b != b'-').collect();
        let hyphens = text.len() - hex.len();
        let shaped = (hyphens == 0 && text.len() == 32)
            || (hyphens == 4 && text.len() == 36 && [8, 13, 18, 23].iter().all(|&i| text.as_bytes()[i] == b'-'));
        if !shaped || hex.len() != 32 {
            return Err("the user is not a UUID".into());
        }
        let mut out = [0u8; 16];
        for (i, pair) in hex.chunks(2).enumerate() {
            let digit = |b: u8| (b as char).to_digit(16).ok_or("the user is not a UUID");
            out[i] = (digit(pair[0])? * 16 + digit(pair[1])?) as u8;
        }
        Ok(Uuid(out))
    }
}

/// A TUIC user's password, the context of the token's exporter: the raw
/// bytes, which go to no line and no log, and are wiped when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct Password(Zeroizing<Vec<u8>>);

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

impl Password {
    pub fn new(password: &str) -> Password {
        Password(Zeroizing::new(password.as_bytes().to_vec()))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The ALPN that TUIC's clients offer when a link names none: `h3`, which
/// sing-box, mihomo and Itsusinn's tuic serve by default.
pub const ALPN: &str = "h3";

/// A server of the file: where UDP goes, what TLS checks, what it offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub uuid: Uuid,
    pub password: Password,
    /// The address that the probe and QUIC go to, over UDP.
    pub host: String,
    pub port: u16,
    /// The name that TLS asks for and checks: `sni`, else `peer`, else HOST.
    pub sni: String,
    /// The protocols that TLS offers by ALPN, in order.
    pub alpn: Vec<String>,
    /// The link's fragment, its name in a panel.
    pub name: Option<String>,
}

impl Server {
    /// `tuic://HOST:PORT`, with no UUID and no password.
    pub fn shown(&self) -> String {
        format!("tuic://{}", crate::dial::authority(&self.host, self.port))
    }

    /// A share link. A refusal names the setting, never the UUID or the
    /// password.
    pub fn parse(link: &str) -> Result<Server, String> {
        let link = link.trim();
        let rest = match link.get(..7) {
            Some(scheme) if scheme.eq_ignore_ascii_case("tuic://") => &link[7..],
            _ => return Err("a line is tuic://UUID:PASSWORD@HOST:PORT?sni=&alpn=...".into()),
        };
        let (rest, name) = match rest.split_once('#') {
            Some((rest, name)) => (rest, crate::proxy::percent_decode(name).ok().map(|n| crate::text::one_line(&n))),
            None => (rest, None),
        };
        let (before, query) = rest.split_once('?').unwrap_or((rest, ""));
        let before = before.trim_end_matches('/');
        let (user, hostport) = before.rsplit_once('@').ok_or("the link has no UUID:PASSWORD@ before its host")?;
        // The UUID holds no colon, so the first one ends it; a password may
        // hold more.
        let (uuid, password) = user.split_once(':').ok_or("the link has no :PASSWORD after its UUID")?;
        let uuid = crate::proxy::percent_decode(uuid).map_err(|_| "the user is not a UUID")?;
        let uuid = Uuid::parse(&uuid)?;
        let password = crate::proxy::percent_decode(password).map_err(|_| "the password is not percent-encoded")?;
        if password.is_empty() {
            return Err("the password is empty".into());
        }
        let password = Password::new(&Zeroizing::new(password));
        let (host, port) = crate::dial::split_host_port(hostport)?;
        if host.is_empty() {
            return Err("the link names no host".into());
        }
        crate::dial::check_name(&host).map_err(|e| e.to_string())?;
        // A TUIC server has no port of its own: a link names it.
        let port = port.ok_or("the link names no port")?;
        if port == 0 {
            return Err("port 0 is no port".into());
        }
        let params = Params::parse(query)?;
        params.refuse_unspoken()?;
        let sni = params.get("sni").or(params.get("peer")).filter(|s| !s.is_empty()).unwrap_or(host.as_str());
        crate::dial::check_name(sni).map_err(|e| format!("sni: {e}"))?;
        let sni = sni.to_string();
        let alpn: Vec<String> = match params.get("alpn") {
            Some(list) => list.split(',').map(str::trim).filter(|a| !a.is_empty()).map(String::from).collect(),
            None => Vec::new(),
        };
        let alpn = if alpn.is_empty() { vec![ALPN.to_string()] } else { alpn };
        Ok(Server { uuid, password, host, port, sni, alpn, name })
    }
}

/// The link's query, each value percent-decoded.
struct Params(Vec<(String, String)>);

impl Params {
    fn parse(query: &str) -> Result<Params, String> {
        let mut out = Vec::new();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = crate::proxy::percent_decode(&value.replace('+', " "))
                .map_err(|_| format!("the value of {key} is not percent-encoded"))?;
            out.push((key.to_ascii_lowercase(), value));
        }
        Ok(Params(out))
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// The settings whose bytes or whose trust podssh does not take.
    fn refuse_unspoken(&self) -> Result<(), String> {
        // A certificate that is not checked is a server that anybody can be,
        // and the token would then go to whoever answers.
        let insecure = ["allow_insecure", "allowinsecure", "insecure", "skip-cert-verify"]
            .iter()
            .filter_map(|k| self.get(k))
            .any(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        if insecure {
            return Err(
                "allow_insecure is refused: podssh checks the server's certificate; --ca-file names a CA of yours"
                    .into(),
            );
        }
        // Version 4 sends the token in another form, which podssh does not
        // speak; 5 is the one of the specification.
        match self.get("version") {
            None | Some("5") | Some("") => {}
            Some(other) => return Err(format!("version={other} is not spoken: podssh speaks TUIC version 5")),
        }
        if let Some(cc) = self.get("congestion_control").or(self.get("congestion-controller")) {
            if !matches!(cc.to_ascii_lowercase().as_str(), "" | "cubic" | "bbr" | "new_reno" | "newreno") {
                return Err(format!("congestion_control={cc} is no controller: cubic, new_reno or bbr"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "link_tests.rs"]
mod tests;
