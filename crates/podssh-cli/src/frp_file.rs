//! The file of the frp road (T-498), which the node (`podssh node NAME
//! TARGET --frp FILE`) and its clients (`PODSSH_FRP=FILE podssh ssh
//! node://NAME`) share: frps, its token, and the secret of the node's STCP
//! service, a line each. The token and the secret are credentials, so the
//! file is the user's own and no one else may read it, as a key's; neither
//! goes on argv, in a line or in a URL.
//!
//! ```text
//! # frps behind the user's TLS front end, or frp's own TCP with TLS
//! server wss://frps.example
//! token the-frps-token
//! secret the-stcp-secret-of-this-node
//! ```
//!
//! `name NAME` names the service, where it is not the node's label.
//! `user USER` is frpc's `user`: the road logs in as USER, the node's
//! service is `USER.NAME` on frps, as frpc names its proxies, and a visitor
//! logs in as USER too, so that frps checks it against a service's
//! `allowUsers`. A visitor's file alone may hold `owner USER`, frpc's
//! visitor's `serverUser` (the service is `OWNER.NAME`), and `plain`, a line
//! with no value: the service is a real frpc's of a plain TCP service, an
//! sshd, which `podssh ssh node://NAME` reaches with SSH on the visit
//! itself, with no end-to-end channel and no resumable layer.

use std::path::Path;
use std::sync::Arc;

use podssh_ws::frp::node::Road;
use podssh_ws::frp::Server;
use podssh_ws::Trust;
use zeroize::Zeroizing;

use crate::relay_settings::Refusal;

/// The variable that names the file for a client, or for a node with no
/// `--frp`.
pub const ENV: &str = "PODSSH_FRP";

/// The road of the file, and the service's name in it.
pub struct Frp {
    pub road: Road,
    pub name: Option<String>,
    /// The `plain` line: a real frpc's service of plain TCP, reached with
    /// no end-to-end channel.
    pub plain: bool,
}

/// The keys of a file, for the words of a key that it does not have.
const KEYS: &str = "server, token, secret, name, user, owner, plain";

/// The words of one file: each line `KEY VALUE`, or `plain` alone; `#`
/// starts a comment.
pub fn parse(text: &str, trust: Trust) -> Result<Frp, String> {
    let (mut server, mut token, mut secret, mut name) = (None, None, None, None);
    let (mut user, mut owner, mut plain) = (None, None, false);
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let at = n + 1;
        let (key, value) = line.split_once(char::is_whitespace).map(|(k, v)| (k, v.trim())).unwrap_or((line, ""));
        if key == "plain" {
            if !value.is_empty() {
                return Err(format!("line {at}: plain takes no value"));
            }
            if plain {
                return Err(format!("line {at}: plain is given twice"));
            }
            plain = true;
            continue;
        }
        let slot = match key {
            "server" => &mut server,
            "token" => &mut token,
            "secret" => &mut secret,
            "name" => &mut name,
            "user" => &mut user,
            "owner" => &mut owner,
            // The line's number, never its text, which may hold a secret.
            _ => return Err(format!("line {at}: a key that the file does not have ({KEYS})")),
        };
        if value.is_empty() {
            return Err(format!("line {at}: {key} names nothing"));
        }
        if slot.is_some() {
            return Err(format!("line {at}: {key} is given twice"));
        }
        if matches!(key, "user" | "owner") && !is_user(value) {
            return Err(format!("line {at}: {key} is frp's user: 1 to 64 of A-Z, a-z, 0-9, '-' and '_'"));
        }
        *slot = Some(value.to_string());
    }
    let server = server.ok_or("no server line: frp://HOST[:PORT] or wss://HOST[:PORT][/PATH]")?;
    let server = Server::parse(&server)?;
    let token = token.ok_or("no token line: frps's auth.token")?;
    let secret = secret.ok_or("no secret line: the secret of the node's STCP service")?;
    if let Some(name) = &name {
        crate::pairs::check_label(name).map_err(|r| format!("name: {}", r.message))?;
    }
    let (token, secret) = (Arc::new(Zeroizing::new(token)), Arc::new(Zeroizing::new(secret)));
    let (user, owner) = (user.unwrap_or_default(), owner.unwrap_or_default());
    let road = Road { server, token, secret, trust, user, owner };
    Ok(Frp { road, name, plain })
}

/// A user of frp as this file takes one: no dot, which would make
/// `USER.NAME` read as another user's service, and nothing that a line or
/// a name of frps would carry badly.
fn is_user(value: &str) -> bool {
    (1..=64).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The file at `path`, read as a private file of the user's.
pub fn read(path: &str, trust: Trust, at: &str) -> Result<Frp, Refusal> {
    let text =
        podssh_relay::cache::read_private(Path::new(path)).map_err(|why| Refusal::config(format!("{at}: {why}")))?;
    let text = Zeroizing::new(text);
    parse(&text, trust).map_err(|why| Refusal::config(format!("{at}: {why}")))
}

/// The file that `PODSSH_FRP` names, if it names one.
pub fn from_env(trust: Trust) -> Result<Option<Frp>, Refusal> {
    match std::env::var(ENV).ok().filter(|v| !v.trim().is_empty()) {
        Some(path) => read(path.trim(), trust, &format!("{ENV}={path}")).map(Some),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_names_frps_its_token_and_the_secret_and_never_says_them() {
        let text = "# the road\nserver frp://frps.example\ntoken T0KEN-of-the-test\nsecret s3cret-of-the-test\n";
        let frp = parse(text, Trust::Default).unwrap();
        assert_eq!(frp.road.server.shown(), "frp://frps.example:7000");
        assert_eq!((frp.road.token.as_str(), frp.road.secret.as_str()), ("T0KEN-of-the-test", "s3cret-of-the-test"));
        assert_eq!(frp.name, None);
        assert!(!frp.plain);
        assert_eq!((frp.road.user.as_str(), frp.road.owner.as_str()), ("", ""), "no user: frpc's default");
        for (bad, why) in [
            ("server frp://f.example\ntoken t\n", "no secret"),
            ("server ws://f.example\ntoken t\nsecret s\n", "ws://"),
            ("server frp://f.example\ntoken t\ntoken u\nsecret s\n", "twice"),
            ("server frp://f.example\npassword hunter2\n", "line 2"),
        ] {
            let e = parse(bad, Trust::Default).err().unwrap();
            assert!(e.contains(why), "{bad}: {e}");
            assert!(!e.contains("hunter2"), "{e}");
        }
    }

    #[test]
    fn a_visitor_s_file_names_its_user_the_service_s_owner_and_a_plain_service() {
        let text = "server wss://edge.example\ntoken t\nsecret s\nname sshd\nuser guest\nowner lab\nplain\n";
        let frp = parse(text, Trust::Default).unwrap();
        assert!(frp.plain);
        assert_eq!((frp.road.user.as_str(), frp.road.owner.as_str()), ("guest", "lab"));
        assert_eq!(frp.road.visited(frp.name.as_deref().unwrap()), "lab.sshd", "frpc's serverUser.NAME");
        let node = parse("server frp://f.example\ntoken t\nsecret s\nuser alice\n", Trust::Default).unwrap();
        assert_eq!(node.road.registered("lab"), "alice.lab", "frpc's user.NAME");
        let base = "server frp://f.example\ntoken t\nsecret s\n";
        for (bad, why) in [
            ("plain yes\n", "line 4: plain takes no value"),
            ("plain\nplain\n", "line 5: plain is given twice"),
            ("user a.b\n", "line 4: user is frp's user"),
            ("owner \u{e9}\n", "line 4: owner is frp's user"),
            ("user\n", "line 4: user names nothing"),
            ("user a\nuser b\n", "line 5: user is given twice"),
        ] {
            let e = parse(&format!("{base}{bad}"), Trust::Default).err().unwrap();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
    }
}
