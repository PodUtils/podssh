//! `--tuic FILE` (T-581, the operator's ruling Q82): TUIC servers that the
//! user runs (sing-box, mihomo, shoes, Itsusinn's tuic), in place of the
//! relay, so that a server of the user's own is a road with no relay where
//! UDP passes. FILE is private, as a pair file is
//! (`podssh_relay::cache::read_private`): each line is a share link,
//! `tuic://UUID:PASSWORD@HOST:PORT?sni=&alpn=...`, whose UUID and password
//! never go to argv, a log or a message; `#` starts a comment. The servers
//! are tried in the order of the file, each after its probe of UDP
//! (`podssh_ws::tuic`). The host key of SSH protects the session, as on each
//! road: the server sees the target's name and SSH's encrypted bytes.

pub mod reach;

use std::path::Path;

use podssh_ws::tuic::Server;
use zeroize::Zeroizing;

use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{Resolved, Transport};

/// The servers of a run, in the order of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Servers {
    pub servers: Vec<Server>,
}

/// The file of `--tuic`: refused (78) when it is not this user's private
/// file, or when a line cannot go.
pub fn read(path: &str) -> Result<Servers, Refusal> {
    let text =
        podssh_relay::cache::read_private(Path::new(path)).map_err(|why| Refusal::config(format!("--tuic: {why}")))?;
    let text = Zeroizing::new(text);
    parse(&text, path).map_err(Refusal::config)
}

/// The lines of the file named `file`. A refusal names the file and the
/// line's number, never the line: it holds a UUID and a password.
pub fn parse(text: &str, file: &str) -> Result<Servers, String> {
    let mut servers = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        servers.push(Server::parse(line).map_err(|why| format!("--tuic {file}:{}: {why}", i + 1))?);
    }
    if servers.is_empty() {
        return Err(format!("--tuic {file}: it has no tuic:// line"));
    }
    Ok(Servers { servers })
}

/// The road of a run that resolved to the relay: the servers of the file
/// when `--tuic` names one, with the relay's trust for their TLS; else the
/// road as it was. It goes first of the servers' roads, so each other
/// server's flag beside it is named here, and each other road's `check`
/// names `--tuic`.
pub fn or_relay(args: &SshArgs, transport: Transport) -> Result<Transport, Refusal> {
    let Some(path) = args.tuic.as_deref() else { return Ok(transport) };
    let (trust, family) = match transport {
        Transport::Relay { trust, family, .. } => (trust, family),
        other => return Ok(other),
    };
    let others = [
        ("--relay-host", args.relay_host.is_some()),
        ("--relay-failover", args.relay_failover.is_some()),
        ("--forwarder", args.forwarder.is_some()),
        ("--shadowsocks", args.shadowsocks.is_some()),
        ("--via", args.via.is_some()),
        ("--vless", args.vless.is_some()),
        ("--trojan", args.trojan.is_some()),
        ("--wstunnel", args.wstunnel.is_some()),
        ("--chisel", args.chisel.is_some()),
    ];
    if let Some((flag, _)) = others.into_iter().find(|(_, given)| *given) {
        return Err(Refusal::usage(format!("--tuic and {flag} name two roads; a run has one")));
    }
    if family.is_some() {
        return Err(Refusal::usage(
            "-4 and -6 choose the family that the relay dials; a TUIC server dials as it chooses",
        ));
    }
    Ok(Transport::Tuic { servers: read(path)?, trust })
}

/// `--tuic` beside a road of its own, which [`or_relay`] never took: a
/// usage error.
pub fn check(args: &SshArgs, resolved: &Resolved) -> Result<(), Refusal> {
    if args.tuic.is_none() {
        return Ok(());
    }
    let other = match &resolved.transport {
        Transport::Tuic { .. } => return Ok(()),
        other => crate::ssh::servers::road_name(other),
    };
    Err(Refusal::usage(format!("--tuic cannot go with {other}, which is a road of its own; a run has one road")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Built from its parts: a scanner of secrets takes a whole link with a
    // password for a credential.
    fn line(rest: &str) -> String {
        ["tuic://", "123e4567-e89b-12d3-a456-426614174000", ":", "s3cr3t", "-pw@", rest, "\n"].concat()
    }

    #[test]
    fn a_file_holds_links_and_comments_and_a_refusal_names_the_line_never_its_credential() {
        let (first, second) = (line("a.example:8443?sni=a.example"), line("b.example:443?alpn=h3"));
        let servers = parse(&format!("# mine\n\n{first}{second}"), "t.list").unwrap();
        assert_eq!(servers.servers.len(), 2);
        assert_eq!(servers.servers[1].shown(), "tuic://b.example:443");
        let shown = format!("{servers:?}");
        assert!(!shown.contains("s3cr3t") && !shown.contains("123e4567"), "{shown}");
        let bad = parse(&format!("\n{}", line("a.example:443?allow_insecure=1")), "f").unwrap_err();
        assert!(bad.starts_with("--tuic f:2: allow_insecure") && !bad.contains("s3cr3t"), "{bad}");
        let other = parse("trojan://secret@h:443\n", "f").unwrap_err();
        assert!(other.starts_with("--tuic f:1: a line is tuic://") && !other.contains("secret"), "{other}");
        assert!(parse("# only\n", "f").unwrap_err().contains("no tuic:// line"));
    }
}
