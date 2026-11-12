//! `--hysteria FILE` (T-580, the operator's ruling Q82): Hysteria 2 servers
//! that the user runs (`apernet/hysteria`), in place of the relay, where UDP
//! passes. FILE is private, as a pair file is
//! (`podssh_relay::cache::read_private`): each line is a share link,
//! `hysteria2://AUTH@HOST[:PORT]/?sni=&pinSHA256=&obfs=salamander&...`, or
//! `hy2://`, whose credential never goes to argv, a log or a message; `#`
//! starts a comment. The servers are tried in the order of the file, as the
//! relay hosts are (T-220), each after a probe of UDP to its port, with no
//! wait for QUIC where it gets no answer (`podssh_ws::hysteria`). No HTTP
//! proxy carries UDP: a server whose host has a proxy set is not tried, and
//! its line names `NO_PROXY`, which lets UDP go straight to it.
//! The host key of SSH protects the session, as on each road: the server
//! sees the target's name and SSH's encrypted bytes.

pub mod pipe;
pub mod reach;

use std::path::Path;

use podssh_ws::hysteria::Server;
use zeroize::Zeroizing;

use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{Resolved, Transport};

/// The servers of a run, in the order of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Servers {
    pub servers: Vec<Server>,
}

/// The file of `--hysteria`: refused (78) when it is not this user's
/// private file, or when a line cannot go.
pub fn read(path: &str) -> Result<Servers, Refusal> {
    let text = podssh_relay::cache::read_private(Path::new(path))
        .map_err(|why| Refusal::config(format!("--hysteria: {why}")))?;
    let text = Zeroizing::new(text);
    parse(&text, path).map_err(Refusal::config)
}

/// The lines of the file named `file`. A refusal names the file and the
/// line's number, never the line: it holds a credential.
pub fn parse(text: &str, file: &str) -> Result<Servers, String> {
    let mut servers = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        servers.push(Server::parse(line).map_err(|why| format!("--hysteria {file}:{}: {why}", i + 1))?);
    }
    if servers.is_empty() {
        return Err(format!("--hysteria {file}: it has no hysteria2:// line"));
    }
    Ok(Servers { servers })
}

/// The road of a run that resolved to the relay: the servers of the file
/// when `--hysteria` names one, with the relay's trust for their TLS; else
/// the road as it was. A road that another flag already took is refused by
/// [`check`], in that road's words.
pub fn or_relay(args: &SshArgs, transport: Transport) -> Result<Transport, Refusal> {
    let Some(path) = args.hysteria.as_deref() else { return Ok(transport) };
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
        ("--tuic", args.tuic.is_some()),
        ("--wstunnel", args.wstunnel.is_some()),
        ("--chisel", args.chisel.is_some()),
    ];
    if let Some((flag, _)) = others.into_iter().find(|(_, given)| *given) {
        return Err(Refusal::usage(format!("--hysteria and {flag} name two roads; a run has one")));
    }
    if family.is_some() {
        return Err(Refusal::usage(
            "-4 and -6 choose the family that the relay dials; a Hysteria 2 server dials as it chooses",
        ));
    }
    Ok(Transport::Hysteria { servers: read(path)?, trust })
}

/// `--hysteria` beside a road of its own, which [`or_relay`] never took: a
/// usage error.
pub fn check(args: &SshArgs, resolved: &Resolved) -> Result<(), Refusal> {
    if args.hysteria.is_none() {
        return Ok(());
    }
    let other = match &resolved.transport {
        Transport::Hysteria { .. } => return Ok(()),
        other => crate::ssh::servers::road_name(other),
    };
    Err(Refusal::usage(format!("--hysteria cannot go with {other}, which is a road of its own; a run has one road")))
}

/// The servers that `podssh doctor --hysteria FILE` checks.
pub fn for_doctor(path: Option<&str>) -> Result<Option<Servers>, Refusal> {
    path.map(read).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Built from its parts: a scanner of secrets takes a whole link with a
    // credential for one.
    fn line(rest: &str) -> String {
        ["hysteria2://", "s3cr3t", "-pw@", rest, "\n"].concat()
    }

    #[test]
    fn a_file_holds_links_and_comments_and_a_refusal_names_the_line_never_its_credential() {
        let (first, second) = (line("a.example:443"), line("b.example:8443/?obfs=salamander&obfs-password=k3y-k3y"));
        let servers = parse(&format!("# mine\n\n{first}{second}"), "h.list").unwrap();
        assert_eq!(servers.servers.len(), 2);
        assert_eq!(servers.servers[1].shown(), "hysteria2://b.example:8443 (Salamander)");
        assert!(!format!("{servers:?}").contains("s3cr3t") && !format!("{servers:?}").contains("k3y"));
        let bad = parse(&format!("\n{}", line("a.example?insecure=1")), "f").unwrap_err();
        assert!(bad.starts_with("--hysteria f:2: insecure=1") && !bad.contains("s3cr3t"), "{bad}");
        let other = parse("trojan://secret@t.example\n", "f").unwrap_err();
        assert!(other.starts_with("--hysteria f:1: a line is hysteria2://") && !other.contains("secret"), "{other}");
        assert!(parse("# only\n", "f").unwrap_err().contains("no hysteria2:// line"));
    }
}
