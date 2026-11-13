//! What the options of a key line allow (T-114): whether the key may log in
//! now and from where (`expiry-time=`, `from=`), with which flags of a
//! security key's signature (`no-touch-required`, `verify-required`, T-774),
//! and, once it did, whether a pty, a forward, or which program a request
//! gets (`no-pty`, `no-port-forwarding`, `permitopen=`, `command=`). Each
//! refusal is a line in words that names the option, for the client and
//! for serve's log.

use std::net::IpAddr;

use super::options::{cidr, Rules};
use crate::known_hosts::wildcard;

/// OpenSSH's name of its SFTP server in the process: a forced command of
/// that name serves SFTP, as sshd does.
pub const INTERNAL_SFTP: &str = "internal-sftp";

/// The bits of a security key's flags that sshd reads (OpenSSH's `sk-api.h`,
/// `SSH_SK_USER_PRESENCE_REQD` and `SSH_SK_USER_VERIFICATION_REQD`).
pub const SK_USER_PRESENCE: u8 = 0x01;
pub const SK_USER_VERIFIED: u8 = 0x04;

/// Why a security key's signature with no touch is refused.
const NO_TOUCH: &str =
    "the security key signed with no touch of the user (its flag of presence is clear), and the line does not say \
     no-touch-required";

/// What an authentication knows of its client.
#[derive(Debug, Clone, Copy)]
pub struct Context {
    /// The client's address, where serve's stream has one: a TCP socket on
    /// stdin. None for a pipe, which a ProxyCommand and the relay give.
    pub peer: Option<IpAddr>,
    /// Now, in seconds since 1970.
    pub now: i64,
}

impl Context {
    pub fn now(peer: Option<IpAddr>) -> Context {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        Context { peer, now }
    }
}

/// What a channel asked to run.
#[derive(Debug, Clone, Copy)]
pub enum Asked<'a> {
    Exec(&'a [u8]),
    Shell,
    /// The `sftp` subsystem: each other name is refused before this.
    Sftp,
}

/// What serve does for an [`Asked`] under a key's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Run this command with `SHELL -c`; the second is the value of
    /// `SSH_ORIGINAL_COMMAND`, set where a forced command replaced one.
    Command(Vec<u8>, Option<Vec<u8>>),
    /// The login shell.
    Shell,
    /// SFTP in the process.
    Sftp,
    /// Refused, with the words for the client's stderr.
    Refuse(String),
}

impl Rules {
    /// Whether the key may log in under `at`: Err names the option that
    /// refuses it.
    pub fn admits(&self, at: &Context) -> Result<(), String> {
        // sshd refuses a key whose time is before now, so the second named
        // is still in.
        if let Some(expiry) = self.expiry.filter(|e| *e < at.now) {
            return Err(format!("expiry-time: the key expired at {}", crate::sshsig::format_time(expiry)));
        }
        if let Some(patterns) = self.from.as_deref() {
            let Some(peer) = at.peer else {
                return Err(format!(
                    "from=\"{patterns}\": serve knows no address of this client (its stream is a pipe), so no \
                     pattern can match"
                ));
            };
            if !from_matches(patterns, peer) {
                return Err(format!("from=\"{patterns}\": {peer} does not match"));
            }
        }
        Ok(())
    }

    /// Why a verified signature does not log in, or None: for a security
    /// key (`sk` true), the flags that it signed, as sshd's
    /// `userauth_pubkey` reads them after the signature. Bit 0 (the
    /// touch) is needed unless `no-touch-required`; bit 2 (the user
    /// verified) where `verify-required`. A security key's signature with
    /// no flags (None) is read as all bits clear, so it never passes for
    /// one with a touch.
    pub fn sk_refusal(&self, sk: bool, flags: Option<u8>) -> Option<String> {
        if !sk {
            return None;
        }
        let flags = flags.unwrap_or(0);
        if flags & SK_USER_PRESENCE == 0 && !self.no_touch_required {
            return Some(NO_TOUCH.into());
        }
        if flags & SK_USER_VERIFIED == 0 && self.verify_required {
            return Some("verify-required: the security key did not verify the user (no PIN, no finger)".into());
        }
        None
    }

    /// Why a pty is refused, or None.
    pub fn pty_refusal(&self) -> Option<String> {
        self.no_pty.then(|| "no-pty: this key gets no pty".to_string())
    }

    /// Why a forward to `host:port` is refused, or None: `no-port-forwarding`
    /// (or `restrict`) refuses each, and a `permitopen` list each target
    /// that it does not name, compared as OpenSSH compares them: the host
    /// as written, with no name lookup.
    pub fn forward_refusal(&self, host: &str, port: u16) -> Option<String> {
        if self.no_port_forwarding {
            return Some("no-port-forwarding: this key opens no forward".into());
        }
        if self.permit_open.is_empty() {
            return None;
        }
        let allowed =
            self.permit_open.iter().any(|p| (p.host == "*" || p.host == host) && p.port.is_none_or(|n| n == port));
        let shown = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
        (!allowed).then(|| format!("permitopen: {shown} is not one of this key's targets"))
    }

    /// What to run for `asked`. A forced command runs in place of each
    /// request, as sshd runs it: the client's command in
    /// `SSH_ORIGINAL_COMMAND`, a shell with none, and the `sftp` subsystem
    /// as the command `internal-sftp`. A forced `internal-sftp` serves SFTP
    /// alone.
    pub fn plan(&self, asked: Asked<'_>) -> Plan {
        let Some(forced) = self.command.as_deref() else {
            return match asked {
                Asked::Exec(command) => Plan::Command(command.to_vec(), None),
                Asked::Shell => Plan::Shell,
                Asked::Sftp => Plan::Sftp,
            };
        };
        if let Some(args) = internal_sftp(forced) {
            return match asked {
                // Its flags (-R, -d, -P...) would limit the server: one
                // that dropped them would allow more than the line says.
                Asked::Sftp if args.is_empty() => Plan::Sftp,
                Asked::Sftp => Plan::Refuse(format!(
                    "command=\"{forced}\": serve's SFTP server takes no arguments of internal-sftp, and does not \
                     serve this key without them"
                )),
                _ => Plan::Refuse(format!("command=\"{forced}\": this key is for SFTP alone")),
            };
        }
        let original = match asked {
            Asked::Exec(command) if command.contains(&0) => {
                return Plan::Refuse("the command holds a NUL byte, which no variable takes".into())
            }
            Asked::Exec(command) => Some(command.to_vec()),
            Asked::Shell => None,
            Asked::Sftp => Some(INTERNAL_SFTP.as_bytes().to_vec()),
        };
        Plan::Command(forced.as_bytes().to_vec(), original)
    }
}

/// The arguments after `internal-sftp` when `command` is that name, else
/// None, as sshd's `IS_INTERNAL_SFTP` tells it: the name, then the end or
/// a blank.
fn internal_sftp(command: &str) -> Option<&str> {
    let rest = command.strip_prefix(INTERNAL_SFTP)?;
    if rest.is_empty() {
        return Some("");
    }
    rest.starts_with([' ', '\t']).then(|| rest.trim_matches([' ', '\t']))
}

/// Whether `peer` matches a `from=` list, as sshd's `match_host_and_ip`
/// with no name lookup (`UseDNS no`, its default): each pattern is a CIDR
/// block, or a wildcard pattern of the address in words; a negated one
/// that matches refuses, whatever else matched. A pattern of a host name
/// matches nothing, as serve looks up no name.
pub fn from_matches(patterns: &str, peer: IpAddr) -> bool {
    let peer = peer.to_canonical();
    let text = peer.to_string();
    let mut matched = false;
    for pattern in patterns.split(',') {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, pattern),
        };
        let hit = if pattern.contains('/') {
            // Read when the line was: an unreadable block refused it then.
            cidr(pattern).is_ok_and(|(net, bits)| in_block(peer, net, bits))
        } else {
            wildcard(pattern.to_ascii_lowercase().as_bytes(), text.as_bytes())
        };
        if hit && negated {
            return false;
        }
        matched |= hit;
    }
    matched
}

/// Whether `addr` is in the block `net/bits`; an address of the other
/// family is not.
fn in_block(addr: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (addr, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - u32::from(bits)) };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - u32::from(bits)) };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}
