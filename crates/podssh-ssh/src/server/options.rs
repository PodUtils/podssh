//! The options of a line of `authorized_keys` (T-114), read as OpenSSH's
//! sshd reads them (sshd(8), "AUTHORIZED_KEYS FILE FORMAT"; the parser is
//! `sshauthopt_parse` of OpenSSH's `auth-options.c`): options separated by
//! commas up to the first blank outside quotes, names in any case, a value
//! in double quotes where `\"` is a quote and each other byte is itself.
//!
//! **Fail closed.** An option that podssh does not know, one that it knows
//! but cannot honour, and a malformed one each make the whole line an
//! error: the caller never uses the key without the option. Accepted with
//! no change: `no-agent-forwarding`, `no-X11-forwarding` and `no-user-rc`
//! (serve offers no agent, no X11 and runs no `~/.ssh/rc`), and
//! `no-touch-required`, which asks for less than serve checks.

use std::net::IpAddr;

/// The rules of one key line: what the key may do once it logged in, and
/// when it may log in at all. The default is a line with no options:
/// everything that serve offers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    /// `command="..."`: run in place of each command, shell and subsystem.
    pub command: Option<String>,
    pub no_pty: bool,
    pub no_port_forwarding: bool,
    pub no_agent_forwarding: bool,
    pub no_x11_forwarding: bool,
    pub no_user_rc: bool,
    /// Each `permitopen="host:port"`, in order; none allows each target.
    pub permit_open: Vec<Permit>,
    /// `from="pattern-list"`: the client's address must match it.
    pub from: Option<String>,
    /// `expiry-time=`: seconds since 1970, after which the key is refused.
    pub expiry: Option<i64>,
}

/// One `permitopen` target: a literal host (`*` for any) and a port (None
/// for `*`, any port), as OpenSSH compares them, with no name lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permit {
    pub host: String,
    pub port: Option<u16>,
}

/// The options that podssh knows and refuses, each with why: a key line
/// that has one is not used.
const REFUSED: &[(&str, &str)] = &[
    ("environment", "serve sets no variable from a key line: the names a client may set are --accept-env's"),
    ("principals", "serve takes no certificate"),
    ("permitlisten", "serve listens for no client (-R)"),
    ("tunnel", "serve opens no tun device"),
];

/// Split a line into its options and the rest, as sshd's
/// `sshkey_advance_past_options`: the options end at the first blank
/// outside double quotes, and `\"` never ends a quote. Err: a quote that is
/// never closed.
pub fn split(line: &str) -> Result<(&str, &str), String> {
    let b = line.as_bytes();
    let (mut i, mut quoted) = (0, false);
    while i < b.len() && (quoted || (b[i] != b' ' && b[i] != b'\t')) {
        if b[i] == b'\\' && b.get(i + 1) == Some(&b'"') {
            i += 1;
        } else if b[i] == b'"' {
            quoted = !quoted;
        }
        i += 1;
    }
    if quoted {
        return Err("a quote that is never closed".into());
    }
    let i = i.min(b.len());
    Ok((&line[..i], line[i..].trim_start_matches([' ', '\t'])))
}

/// Read the options field of a key line. Err names the option and why;
/// the line is then not used.
pub fn parse(field: &str) -> Result<Rules, String> {
    let mut rules = Rules::default();
    let mut at = field;
    while !at.is_empty() && !at.starts_with([' ', '\t']) {
        at = one(at, &mut rules)?;
        if at.is_empty() || at.starts_with([' ', '\t']) {
            break;
        }
        let Some(rest) = at.strip_prefix(',') else {
            return Err(format!("unknown key option at {}", head(at)));
        };
        if rest.is_empty() {
            return Err("unexpected end of the options after a comma".into());
        }
        at = rest;
    }
    Ok(rules)
}

/// Read one option at the start of `at` into `rules`; the rest after it.
/// The order is OpenSSH's, as a flag is matched by its prefix there too.
fn one<'a>(at: &'a str, rules: &mut Rules) -> Result<&'a str, String> {
    if let Some((rest, _)) = flag(at, "restrict", false) {
        // Each permission off; a later option turns one on again.
        rules.no_port_forwarding = true;
        rules.no_agent_forwarding = true;
        rules.no_x11_forwarding = true;
        rules.no_pty = true;
        rules.no_user_rc = true;
        return Ok(rest);
    }
    if flag(at, "cert-authority", false).is_some() {
        return Err("cert-authority: serve takes no certificate".into());
    }
    if let Some((rest, on)) = flag(at, "port-forwarding", true) {
        rules.no_port_forwarding = !on;
        return Ok(rest);
    }
    if let Some((rest, on)) = flag(at, "agent-forwarding", true) {
        rules.no_agent_forwarding = !on;
        return Ok(rest);
    }
    if let Some((rest, on)) = flag(at, "x11-forwarding", true) {
        rules.no_x11_forwarding = !on;
        return Ok(rest);
    }
    // serve does not read the flags of a security key's signature: a line
    // that asks for a touch or a PIN asks for a check that serve does not
    // make, and one that waives it asks for nothing.
    if let Some((rest, on)) = flag(at, "touch-required", true) {
        let why = "touch-required: serve does not check the touch of a security key";
        return if on { Err(why.into()) } else { Ok(rest) };
    }
    if let Some((rest, on)) = flag(at, "verify-required", true) {
        let why = "verify-required: serve does not check the PIN of a security key";
        return if on { Err(why.into()) } else { Ok(rest) };
    }
    if let Some((rest, on)) = flag(at, "pty", true) {
        rules.no_pty = !on;
        return Ok(rest);
    }
    if let Some((rest, on)) = flag(at, "user-rc", true) {
        rules.no_user_rc = !on;
        return Ok(rest);
    }
    if let Some(rest) = named(at, "command") {
        if rules.command.is_some() {
            return Err("command= twice".into());
        }
        let (value, rest) = dequote(rest).map_err(|why| format!("command=: {why}"))?;
        rules.command = Some(value);
        return Ok(rest);
    }
    if let Some(rest) = named(at, "from") {
        if rules.from.is_some() {
            return Err("from= twice".into());
        }
        let (value, rest) = dequote(rest).map_err(|why| format!("from=: {why}"))?;
        check_from(&value).map_err(|why| format!("from=\"{value}\": {why}"))?;
        rules.from = Some(value);
        return Ok(rest);
    }
    if let Some(rest) = named(at, "expiry-time") {
        let (value, rest) = dequote(rest).map_err(|why| format!("expiry-time=: {why}"))?;
        let time = crate::sshsig::parse_time(&value)
            .filter(|t| *t > 0)
            .ok_or_else(|| format!("expiry-time=\"{value}\": not a time of YYYYMMDD[HHMM[SS]][Z]"))?;
        // Of two, the earlier holds, as in sshd.
        rules.expiry = Some(rules.expiry.map_or(time, |was| was.min(time)));
        return Ok(rest);
    }
    if let Some(rest) = named(at, "permitopen") {
        let (value, rest) = dequote(rest).map_err(|why| format!("permitopen=: {why}"))?;
        let permit = permit(&value).map_err(|why| format!("permitopen=\"{value}\": {why}"))?;
        rules.permit_open.push(permit);
        return Ok(rest);
    }
    for (name, why) in REFUSED {
        if named(at, name).is_some() {
            return Err(format!("{name}=: {why}"));
        }
    }
    Err(format!("unsupported option {}", head(at)))
}

/// A flag at the start of `at`, matched by its prefix in any case, as
/// OpenSSH's `opt_flag`: the rest, and false when it came after `no-`.
fn flag<'a>(at: &'a str, name: &str, negatable: bool) -> Option<(&'a str, bool)> {
    let (body, on) = match strip_prefix_nocase(at, "no-") {
        Some(body) if negatable => (body, false),
        _ => (at, true),
    };
    strip_prefix_nocase(body, name).map(|rest| (rest, on))
}

/// `NAME=` at the start of `at`, in any case: what follows the `=`.
fn named<'a>(at: &'a str, name: &str) -> Option<&'a str> {
    strip_prefix_nocase(at, name)?.strip_prefix('=')
}

fn strip_prefix_nocase<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.as_bytes().get(..prefix.len())?;
    // A match of ASCII bytes ends on a character's edge.
    head.eq_ignore_ascii_case(prefix.as_bytes()).then(|| &text[prefix.len()..])
}

/// A value in double quotes at the start of `at`, as OpenSSH's
/// `opt_dequote`: `\"` is a quote, and every other byte is itself (a
/// backslash before anything else stays). The value, and the rest.
pub fn dequote(at: &str) -> Result<(String, &str), String> {
    let Some(body) = at.strip_prefix('"') else { return Err("a value must start with a double quote".into()) };
    let b = body.as_bytes();
    let (mut out, mut i) = (Vec::with_capacity(b.len()), 0);
    while i < b.len() && b[i] != b'"' {
        if b[i] == b'\\' && b.get(i + 1) == Some(&b'"') {
            i += 1;
        }
        out.push(b[i]);
        i += 1;
    }
    if i == b.len() {
        return Err("no closing double quote".into());
    }
    // Only ASCII backslashes were dropped, so the bytes stay UTF-8.
    let value = String::from_utf8(out).map_err(|_| "not UTF-8".to_string())?;
    Ok((value, &body[i + 1..]))
}

/// `host:port` of `permitopen`, as OpenSSH's `hpdelim2` splits it: a host
/// in brackets for IPv6, then `:` or `/`, then a port of 1 to 65535 or `*`.
fn permit(value: &str) -> Result<Permit, String> {
    let (host, port) = if let Some(inner) = value.strip_prefix('[') {
        let end = inner.find(']').ok_or("an IPv6 address with no closing bracket")?;
        let after = &inner[end + 1..];
        let port = after.strip_prefix([':', '/']).ok_or("no port after the host")?;
        (&inner[..end], port)
    } else {
        let at = value.find([':', '/']).ok_or("no port after the host")?;
        (&value[..at], &value[at + 1..])
    };
    if host.is_empty() {
        return Err("no host".into());
    }
    if host.len() >= 1025 {
        return Err("a host name past 1024 bytes".into());
    }
    let port = match port {
        "*" => None,
        digits => match digits.parse::<u16>() {
            Ok(p) if p != 0 && digits.bytes().all(|b| b.is_ascii_digit()) => Some(p),
            _ => return Err(format!("{digits:?} is not a port of 1 to 65535 or *")),
        },
    };
    Ok(Permit { host: host.to_string(), port })
}

/// Whether each address pattern of a `from=` list can be read: a CIDR
/// block (`ADDRESS/BITS`) must be one, as sshd refuses the key otherwise.
fn check_from(patterns: &str) -> Result<(), String> {
    for pattern in patterns.split(',') {
        let pattern = pattern.strip_prefix('!').unwrap_or(pattern);
        if pattern.is_empty() {
            return Err("an empty pattern".into());
        }
        if pattern.contains('/') {
            cidr(pattern)?;
        }
    }
    Ok(())
}

/// `ADDRESS/BITS`: the address and the length of its prefix.
pub fn cidr(pattern: &str) -> Result<(IpAddr, u8), String> {
    let (addr, bits) = pattern.split_once('/').ok_or("not ADDRESS/BITS")?;
    let addr: IpAddr = addr.parse().map_err(|_| format!("{addr:?} is not an address"))?;
    let most = if addr.is_ipv4() { 32 } else { 128 };
    match bits.parse::<u8>() {
        Ok(n) if n <= most && bits.bytes().all(|b| b.is_ascii_digit()) => Ok((addr, n)),
        _ => Err(format!("{bits:?} is not a prefix length of 0 to {most}")),
    }
}

/// The start of `at` for a message: the option's name, bounded.
fn head(at: &str) -> String {
    let end = at.find([',', ' ', '\t', '=']).unwrap_or(at.len());
    let name: String = at[..end].chars().take(64).collect();
    format!("\"{name}\"")
}

#[cfg(test)]
#[path = "options_tests.rs"]
mod tests;
