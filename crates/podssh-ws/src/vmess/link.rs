//! A VMess server as its share link names it: `vmess://` and the base64 of
//! a JSON object (v2rayN's form, which the public lists carry): `add`,
//! `port`, `id`, `aid`, `scy`, `net`, `type`, `host`, `path`, `tls`, `sni`,
//! `ps`. Numbers may come as strings. podssh takes the AEAD form over a
//! WebSocket: `aid` above 0 is the MD5 form, and another `net` another
//! transport, each refused by its name. The ID is the credential, and no
//! line that podssh shows holds it.

use base64::Engine as _;
use serde_json::Value;

use super::body::Cipher;
pub use crate::vless::link::Id;

/// A VMess server over a WebSocket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub id: Id,
    /// The address that TCP dials.
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// The name that TLS asks for and checks: `sni`, else `host`, else `add`.
    pub sni: String,
    /// `Host`: `host`, else `sni`, else `add`.
    pub authority: String,
    /// The WebSocket's path, from `/`, with its query.
    pub path: String,
    pub cipher: Cipher,
    /// The link's `ps`, on one line.
    pub name: Option<String>,
}

impl Server {
    /// `vmess://HOST:PORT/PATH`: no ID.
    pub fn shown(&self) -> String {
        let path = self.path.split('?').next().unwrap_or("/");
        format!("vmess://{}{path}", crate::dial::authority(&self.host, self.port))
    }

    /// A share link. A refusal names the setting, never the ID.
    pub fn parse(link: &str) -> Result<Server, String> {
        let link = link.trim();
        let body = match link.get(..8) {
            Some(scheme) if scheme.eq_ignore_ascii_case("vmess://") => &link[8..],
            _ => return Err("a line is vmess:// and the base64 of a JSON object".into()),
        };
        let body = body.split('#').next().unwrap_or_default();
        let json = decode(body).ok_or("the link is not the base64 of a JSON object")?;
        let fields: Value = serde_json::from_slice(&json).map_err(|_| "the link's JSON does not parse")?;
        let text = |key: &str| -> String {
            match fields.get(key) {
                Some(Value::String(s)) => s.trim().to_string(),
                Some(Value::Number(n)) => n.to_string(),
                _ => String::new(),
            }
        };
        let host = text("add");
        if host.is_empty() {
            return Err("the link names no address (add)".into());
        }
        let port: u16 = text("port").parse().map_err(|_| "the link's port is not a port")?;
        let id = Id::parse(&text("id"))?;
        match text("aid").as_str() {
            "" | "0" => {}
            other => return Err(format!("aid={other}: the MD5 form of VMess, which podssh does not speak")),
        }
        let net = text("net").to_ascii_lowercase();
        if net != "ws" {
            let net = if net.is_empty() { "tcp".to_string() } else { net };
            return Err(format!("net={net}: podssh takes VMess over a WebSocket alone"));
        }
        match text("type").to_ascii_lowercase().as_str() {
            "" | "none" => {}
            other => return Err(format!("type={other}: a disguise of the header that podssh does not send")),
        }
        let tls = match text("tls").to_ascii_lowercase().as_str() {
            "tls" => true,
            "" | "none" => false,
            other => return Err(format!("tls={other}: a security that podssh does not speak")),
        };
        let cipher = Cipher::parse(&text("scy"))?;
        let (sni_field, host_field) = (text("sni"), text("host"));
        let pick = |a: &str, b: &str| {
            if !a.is_empty() {
                a.to_string()
            } else if !b.is_empty() {
                b.to_string()
            } else {
                host.clone()
            }
        };
        let path = match text("path") {
            p if p.is_empty() => "/".to_string(),
            p if p.starts_with('/') => p,
            p => format!("/{p}"),
        };
        let name = Some(text("ps")).filter(|n| !n.is_empty()).map(|n| crate::text::one_line(&n));
        Ok(Server {
            id,
            sni: pick(&sni_field, &host_field),
            authority: pick(&host_field, &sni_field),
            host,
            port,
            tls,
            path,
            cipher,
            name,
        })
    }
}

/// Base64 of either alphabet, padded or not, with no spaces.
fn decode(body: &str) -> Option<Vec<u8>> {
    let url: String = body
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD_INDIFFERENT.decode(url.as_bytes()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn link(json: &str) -> String {
        format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(json))
    }

    const ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn a_link_of_a_list_is_read() {
        let json = format!(
            r#"{{"v":"2","ps":"a node","add":"203.0.113.9","port":"443","id":"{ID}","aid":"0","scy":"auto",
            "net":"ws","type":"none","host":"cdn.example","path":"/vm?ed=2048","tls":"tls","sni":""}}"#
        );
        let s = Server::parse(&link(&json)).unwrap();
        assert_eq!((s.host.as_str(), s.port, s.tls), ("203.0.113.9", 443, true));
        assert_eq!((s.sni.as_str(), s.authority.as_str()), ("cdn.example", "cdn.example"));
        assert_eq!(s.path, "/vm?ed=2048");
        assert_eq!(s.cipher, Cipher::Aes128Gcm);
        assert_eq!(s.shown(), "vmess://203.0.113.9:443/vm");
        assert!(!format!("{s:?}").contains("550e8400"), "no line holds the ID");
        // Numbers as numbers, and the URL-safe alphabet with no padding.
        let json = format!(r#"{{"add":"n.example","port":443,"id":"{ID}","aid":0,"net":"ws","tls":"tls"}}"#);
        let url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let s = Server::parse(&format!("vmess://{url}")).unwrap();
        assert_eq!((s.sni.as_str(), s.path.as_str()), ("n.example", "/"));
    }

    #[test]
    fn each_form_that_podssh_does_not_speak_is_refused_by_its_name() {
        let with = |extra: &str| {
            let json = format!(r#"{{"add":"n.example","port":"443","id":"{ID}","tls":"tls",{extra}}}"#);
            Server::parse(&link(&json)).unwrap_err()
        };
        assert!(with(r#""net":"ws","aid":"64""#).contains("MD5 form"));
        assert!(with(r#""net":"tcp""#).contains("net=tcp"));
        assert!(with(r#""net":"grpc""#).contains("net=grpc"));
        assert!(with(r#""net":"ws","type":"http""#).contains("type=http"));
        assert!(with(r#""net":"ws","scy":"none""#).contains("in clear"));
        assert!(with(r#""net":"ws","tls":"reality""#).contains("tls=reality"));
        assert!(Server::parse("vmess://not-base64!!").is_err());
        assert!(Server::parse("vless://x").is_err());
    }
}
