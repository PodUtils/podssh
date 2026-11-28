//! The credentials of Cloudflare Access (T-264, T-718): each from its
//! variable, or from the file that its `_FILE` variable names, so that a
//! secret need not sit in the environment, where `/proc` and each child read
//! it; a service's `--install` carries the paths alone. The `_FILE` names of
//! the service token are also keywords of the settings file. A file is read
//! as the token's is: a cap, a trim, and no value in any message.
//!
//! The hosts that the user named for the credentials (`--access-host`, or
//! `AccessHost` in the settings) get them on a road that podssh builds
//! itself ([`podssh_ws::access`]); `cf://HOST` names its HOST by itself. No
//! host of a pool or of a public fallback gets them.

use std::io::Read;

use podssh_ws::access::Named;
use zeroize::Zeroizing;

use crate::relay_settings::Refusal;
use crate::settings::Defaults;

/// The files of a service token of Cloudflare Access.
pub const CLIENT_ID_FILE_ENV: &str = "PODSSH_CF_ACCESS_CLIENT_ID_FILE";
pub const CLIENT_SECRET_FILE_ENV: &str = "PODSSH_CF_ACCESS_CLIENT_SECRET_FILE";
/// The flag that names a host for the credentials.
pub const HOST_FLAG: &str = "--access-host";
/// The longest credential: a token of Access is about 1 KiB.
pub const MAX_VALUE: usize = 8192;

/// A variable of the credentials as this process has it; for a `_FILE`
/// of the service token, else the keyword of the settings file.
pub fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty()).or_else(|| setting(name, crate::settings::here()))
}

/// The keyword of `file` that stands for the variable `name`.
pub fn setting(name: &str, file: &Defaults) -> Option<String> {
    let value = match name {
        CLIENT_ID_FILE_ENV => file.access_client_id_file.as_ref(),
        CLIENT_SECRET_FILE_ENV => file.access_client_secret_file.as_ref(),
        _ => None,
    };
    value.map(|v| v.text.clone())
}

/// Whether `value` of `name` can be a credential: printable, no space, at
/// most [`MAX_VALUE`] bytes. The refusal names the variable alone.
pub fn check(name: &str, value: &str) -> Result<(), String> {
    if value.len() > MAX_VALUE || !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(format!(
            "{name} is not a credential of Cloudflare Access: 1 to {MAX_VALUE} printable characters, with no space"
        ));
    }
    Ok(())
}

/// The credential in the file of `path`, which the variable `name` gives,
/// trimmed. Each refusal names the variable and the path, never the value.
pub fn secret_file(name: &str, path: &str) -> Result<Zeroizing<String>, String> {
    let mut text = Zeroizing::new(String::with_capacity(MAX_VALUE + 1));
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_VALUE as u64 + 1).read_to_string(&mut text))
        .map_err(|e| format!("{name}: {path}: {}", podssh_ws::text::said(&e)))?;
    let value = text.trim();
    if value.is_empty() {
        return Err(format!("{name}: {path} holds no credential"));
    }
    check(name, value)?;
    Ok(Zeroizing::new(value.to_string()))
}

/// The value of the variable `name` as `read` gives it, else the credential
/// in the file of the variable `file`; none when neither is set.
pub fn value_or_file(
    read: &dyn Fn(&str) -> Option<String>,
    name: &str,
    file: &str,
) -> Result<Option<Zeroizing<String>>, String> {
    if let Some(raw) = read(name).map(Zeroizing::new) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            check(name, trimmed)?;
            return Ok(Some(Zeroizing::new(trimmed.to_string())));
        }
    }
    read(file).filter(|p| !p.trim().is_empty()).map(|p| secret_file(file, p.trim())).transpose()
}

/// Whether `host` is a host name or an IP address, with no port and no
/// scheme.
fn a_host(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && !host.starts_with(['-', '.'])
}

/// The hosts named for the credentials: each `--access-host` (a list
/// `HOST[,...]` too), else each `AccessHost` line of `file`.
pub fn hosts(flags: &[String], file: &Defaults) -> Result<Vec<String>, String> {
    let (said, lines): (&str, Vec<&str>) = if flags.is_empty() {
        ("AccessHost", file.access_host.iter().map(|v| v.text.as_str()).collect())
    } else {
        (HOST_FLAG, flags.iter().map(String::as_str).collect())
    };
    let mut out = Vec::new();
    for host in lines.iter().flat_map(|line| line.split(',')).map(str::trim).filter(|h| !h.is_empty()) {
        if !a_host(host) {
            return Err(format!("{said} {host:?}: a host name or an IP address, with no port and no scheme"));
        }
        out.push(host.to_string());
    }
    Ok(out)
}

/// The credentials for the hosts of `flags` (or of the settings): none
/// named, none sent. A host named with no credential set is refused (78),
/// as nothing would go to it; the line names the variables.
pub fn named(flags: &[String]) -> Result<Named, Refusal> {
    let hosts = hosts(flags, crate::settings::here()).map_err(Refusal::usage)?;
    if hosts.is_empty() {
        return Ok(Named::default());
    }
    let access = crate::ssh::cloudflare::access_from(&var).map_err(Refusal::config)?;
    if podssh_ws::access::is_empty(&access) {
        return Err(Refusal::config(format!(
            "{HOST_FLAG} names {} for Cloudflare Access, but no credential is set: set {} and {}, or {} and {}",
            hosts.join(","),
            crate::ssh::cloudflare::CLIENT_ID_ENV,
            crate::ssh::cloudflare::CLIENT_SECRET_ENV,
            CLIENT_ID_FILE_ENV,
            CLIENT_SECRET_FILE_ENV,
        )));
    }
    Ok(Named::new(hosts, access))
}

/// The hosts of `AccessHost` in the settings, with their credentials, for
/// each road of this process (pod-ws's headers, podcrates `v0.68.0`): the
/// relay's roads, a pair's and the forwarders. None named, none sent. A
/// host named with no credential set sends nothing here; the command that
/// names it says why ([`named`]).
pub fn install() {
    if crate::settings::here().access_host.is_empty() {
        return;
    }
    if let Ok(named) = named(&[]) {
        podssh_ws::access::set_process(named);
    }
}

/// The hosts of `--access-host` of a command whose roads are pod-ws's
/// (`ssh`, T-718), with their credentials, in the place of the settings';
/// none given changes nothing. A host named with no credential is refused
/// (78), as nothing would go to it.
pub fn take_flags(flags: &[String]) -> Result<(), Refusal> {
    if flags.is_empty() {
        return Ok(());
    }
    podssh_ws::access::set_process(named(flags)?);
    Ok(())
}

/// Bound on the one-shot probe that distinguishes a Cloudflare Access refusal
/// from a relay's own 403 of a stopped pair when a node ends with `Forbidden`.
const PROBE_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Whether `body` names Cloudflare Access itself (its banner, its login path,
/// or its header names), so a body mentioning "token" is never taken for the
/// relay's own refusal.
pub fn body_names_access(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("cloudflare access")
        || lower.contains(podssh_ws::cloudflare::LOGIN_PATH)
        || lower.contains("cf-access-")
}

/// Whether an HTTP refusal `(status, body)` from a relay host is Cloudflare
/// Access refusing the connection rather than the relay refusing the pair or a
/// generic proxy blocking WebSocket upgrades.
///
/// `named` is whether this process sends Access credentials to that host
/// (`--access-host` or `AccessHost`).
pub fn is_access_refusal(status: u16, body: &str, named: bool) -> bool {
    if (300..400).contains(&status) {
        return body.contains(podssh_ws::cloudflare::LOGIN_PATH);
    }
    if !matches!(status, 401 | 403) {
        return false;
    }
    if body_names_access(body) {
        return true;
    }
    if !named {
        return false;
    }
    // This host is named for Access: a 401/403 that is not the relay's own
    // refusal (such as `reverse: forbidden`) came from Access before the relay
    // saw the pair.
    let probe = podssh_ws::ConnectError::Refused { status: 403, body: body.to_string() };
    podssh_relay::piping::probe::upgrade_refused(&probe)
}

/// Whether `why` from `pod_piping::probe::upgrade`'s `Probe::Refused` is a
/// Cloudflare Access refusal rather than a proxy blocking WebSocket upgrades.
pub fn probe_is_access_refusal(host: &str, why: &str) -> bool {
    probe_is_access_refusal_for(why, podssh_ws::access::process_names(host))
}

/// Pure helper of [`probe_is_access_refusal`], tested without global state.
pub(crate) fn probe_is_access_refusal_for(why: &str, named: bool) -> bool {
    if body_names_access(why) {
        return true;
    }
    named && (why.contains("HTTP 401") || why.contains("HTTP 403"))
}

/// One line explaining a Cloudflare Access refusal on `host`, naming the
/// variables and files to check (never a credential value). `body` must
/// already be masked against the credentials sent.
pub fn refusal_line(host: &str, status: u16, body: &str, named: bool) -> String {
    use crate::ssh::cloudflare::{CLIENT_ID_ENV, CLIENT_SECRET_ENV};
    let shown = podssh_ws::text::one_line(body);
    let detail = if shown.is_empty() { String::new() } else { format!(": {shown}") };
    if named {
        format!(
            "Cloudflare Access refused the connection to {host} (HTTP {status}{detail}): check {CLIENT_ID_ENV} and \
             {CLIENT_SECRET_ENV}, or the files of {CLIENT_ID_FILE_ENV} and {CLIENT_SECRET_FILE_ENV}"
        )
    } else {
        format!(
            "Cloudflare Access refused the connection to {host} (HTTP {status}{detail}): name {host} with {HOST_FLAG} \
             (or AccessHost) and set {CLIENT_ID_ENV} and {CLIENT_SECRET_ENV}, or the files of {CLIENT_ID_FILE_ENV} \
             and {CLIENT_SECRET_FILE_ENV}"
        )
    }
}

/// After a node's pair road returned `Exit::Forbidden`, probe `/v1/node/<name>`
/// once with no `X-Relay-Token` and with this process's Access headers for
/// `relay.host` to distinguish a Cloudflare Access refusal from the relay
/// refusing the pair itself.
pub async fn node_forbidden_line(
    relay: &podssh_relay::relay::Relay,
    pair_name: &str,
    trust: &podssh_ws::Trust,
    proxy: &podssh_ws::ProxyChoice,
) -> Option<String> {
    if podssh_ws::names::check_node_name(pair_name).is_err() {
        return None;
    }
    let way = podssh_ws::client::way(proxy);
    let extra = way.extra(&relay.host).ok()?;
    let (tls, _) = way.open_tls(&relay.host, relay.port, &relay.host, trust, PROBE_LIMIT, &[]).await.ok()?;
    let key = podssh_ws::handshake::generate_key().ok()?;
    let host = match relay.port {
        443 => relay.host.clone(),
        port => podssh_ws::dial::authority(&relay.host, port),
    };
    let agent = podssh_ws::text::one_line(&way.user_agent);
    let mut req = Zeroizing::new(
        format!("GET /v1/node/{pair_name} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {agent}\r\n").into_bytes(),
    );
    extra.write(&mut req);
    req.extend_from_slice(b"Upgrade: websocket\r\nConnection: Upgrade\r\n");
    req.extend_from_slice(format!("Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").as_bytes());
    let answer = tokio::time::timeout(PROBE_LIMIT, podssh_ws::client::upgrade_with(tls, &req, &key)).await;
    let err = match answer {
        Ok(Err(e)) => extra.masked(e),
        _ => return None,
    };
    let named = podssh_ws::access::process_names(&relay.host);
    match err {
        podssh_ws::ConnectError::Refused { status, body } if is_access_refusal(status, &body, named) => {
            Some(refusal_line(&relay.host, status, &body, named))
        }
        _ => None,
    }
}

/// For [`podssh_relay::reverse::Exit::Forbidden`], probe once to distinguish a
/// Cloudflare Access refusal from a stopped or invalid pair; `None` otherwise.
pub(crate) async fn node_exit_why(
    exit: &podssh_relay::reverse::Exit,
    pair: &podssh_relay::pair::Pair,
    trust: &podssh_ws::Trust,
    proxy: &podssh_ws::ProxyChoice,
) -> Option<String> {
    match exit {
        podssh_relay::reverse::Exit::Forbidden => node_forbidden_line(&pair.relay, &pair.name, trust, proxy).await,
        _ => None,
    }
}

/// [`crate::node::ended`], with a diagnosed Cloudflare Access refusal in place
/// of the generic pair refusal on [`podssh_relay::reverse::Exit::Forbidden`].
pub(crate) fn ended_with(
    label: &str,
    exit: podssh_relay::reverse::Exit,
    access_why: Option<String>,
) -> Option<(crate::exitmap::Fault, String)> {
    match (exit, access_why) {
        (podssh_relay::reverse::Exit::Forbidden, Some(why)) => Some((crate::exitmap::Fault::Auth, why)),
        (exit, _) => crate::node::ended(label, exit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Value;

    fn file(at: &str, text: &str) -> String {
        let path = std::env::temp_dir().join(format!("podssh-access-{}-{at}", std::process::id()));
        std::fs::write(&path, text).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn a_credential_comes_from_its_file_and_the_variable_wins() {
        let path = file("id", "  id.from-the-file\n");
        let read = |var: Option<&'static str>| {
            let path = path.clone();
            move |name: &str| match name {
                CLIENT_ID_FILE_ENV => Some(path.clone()),
                "ID" => var.map(str::to_string),
                _ => None,
            }
        };
        let got = value_or_file(&read(None), "ID", CLIENT_ID_FILE_ENV).unwrap();
        assert_eq!(got.as_deref().map(String::as_str), Some("id.from-the-file"));
        let got = value_or_file(&read(Some("id.of-the-variable")), "ID", CLIENT_ID_FILE_ENV).unwrap();
        assert_eq!(got.as_deref().map(String::as_str), Some("id.of-the-variable"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_bad_file_names_its_variable_and_never_the_value() {
        let missing = secret_file(CLIENT_SECRET_FILE_ENV, "no-such-file-of-this-test").unwrap_err();
        assert!(missing.contains(CLIENT_SECRET_FILE_ENV) && missing.contains("no-such-file"), "{missing}");
        let spaced = file("spaced", "a secret with spaces\n");
        let why = secret_file(CLIENT_SECRET_FILE_ENV, &spaced).unwrap_err();
        assert!(why.contains(CLIENT_SECRET_FILE_ENV) && !why.contains("with spaces"), "{why}");
        let empty = file("empty", " \n");
        assert!(secret_file(CLIENT_SECRET_FILE_ENV, &empty).unwrap_err().contains("holds no credential"));
        let long = file("long", &"x".repeat(MAX_VALUE + 1));
        let why = secret_file(CLIENT_SECRET_FILE_ENV, &long).unwrap_err();
        assert!(why.contains(CLIENT_SECRET_FILE_ENV) && !why.contains("xxxx"), "{why}");
        for p in [spaced, empty, long] {
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn the_hosts_come_from_the_flags_else_from_the_settings() {
        let mut d = Defaults::default();
        d.access_host.push(Value { text: "a.example, b.example".into(), at: "f:1".into() });
        assert_eq!(hosts(&[], &d).unwrap(), ["a.example", "b.example"]);
        let flags = ["edge.example".to_string(), "127.0.0.1,[::1]".to_string()];
        assert_eq!(hosts(&flags, &d).unwrap(), ["edge.example", "127.0.0.1", "[::1]"], "the flags beat the file");
        for bad in ["edge.example:443", "https://edge.example", "-x", "a b"] {
            let why = hosts(&[bad.to_string()], &d).unwrap_err();
            assert!(why.contains(HOST_FLAG), "{bad}: {why}");
        }
        assert!(hosts(&[], &Defaults::default()).unwrap().is_empty());
    }

    #[test]
    fn a_file_of_the_settings_stands_for_its_variable() {
        let d = Defaults {
            access_client_secret_file: Some(Value { text: "/run/secret".into(), at: "f:2".into() }),
            ..Defaults::default()
        };
        assert_eq!(setting(CLIENT_SECRET_FILE_ENV, &d).as_deref(), Some("/run/secret"));
        assert_eq!(setting(crate::ssh::cloudflare::CLIENT_SECRET_ENV, &d), None, "never a secret itself");
    }

    #[test]
    fn access_refusals_are_distinguished_from_relay_and_proxy_refusals() {
        let cases = [
            // Relay's own pair/token refusals stay pair refusals even on a named Access host.
            (403, "reverse: forbidden", true, false),
            (403, "reverse: forbidden", false, false),
            (403, "missing or wrong token", true, false),
            (401, "reverse: missing or wrong token", true, false),
            // Access gate banners are recognized whether or not the host was named.
            (403, "Forbidden: this application is behind Cloudflare Access", true, true),
            (403, "Forbidden: this application is behind Cloudflare Access", false, true),
            // Access messages mentioning "token" must not be misread as the relay's own.
            (403, "Cloudflare Access: invalid service token", true, true),
            (401, "invalid Cf-Access-Client-Secret token", false, true),
            // Terse 401/403 is Access when this host was named for Access, else a way refusal.
            (401, "Unauthorized", true, true),
            (401, "", true, true),
            (403, "Forbidden", true, true),
            (403, "Forbidden", false, false),
            (403, "Forbidden: WebSocket upgrades are not allowed by policy", false, false),
            // Access login redirect.
            (302, "a redirect to https://team.cloudflareaccess.com/cdn-cgi/access/login/r.test", false, true),
            (302, "a redirect to https://other.example/login", true, false),
            // Transient or conflict statuses are never Access auth refusals.
            (409, "reverse: already connected", true, false),
            (502, "Bad Gateway", true, false),
            (503, "Service Unavailable", true, false),
        ];
        for (status, body, named, want) in cases {
            assert_eq!(is_access_refusal(status, body, named), want, "{status} {body:?} named={named}");
        }
    }

    #[test]
    fn probe_refusals_keep_access_on_the_pair_road_and_proxies_on_piping() {
        let access_banner =
            "the relay refused the session: HTTP 403: Forbidden: this application is behind Cloudflare Access";
        assert!(probe_is_access_refusal_for(access_banner, true));
        assert!(probe_is_access_refusal_for(access_banner, false));
        let terse = "the relay refused the session: HTTP 403: Forbidden";
        assert!(probe_is_access_refusal_for(terse, true));
        assert!(!probe_is_access_refusal_for(terse, false));
        let proxy = "the relay refused the session: HTTP 403: Forbidden: WebSocket upgrades are not allowed by policy";
        assert!(!probe_is_access_refusal_for(proxy, false));
        let upgrade = "the relay refused the session: HTTP 426: Upgrade Required";
        assert!(!probe_is_access_refusal_for(upgrade, true));
    }

    #[test]
    fn refusal_lines_and_node_exit_keep_77_and_name_the_variables() {
        use crate::exitmap::Fault;
        use podssh_relay::reverse::Exit;

        let named_line = refusal_line("relay-a.test", 403, "Forbidden\nline 2", true);
        assert!(named_line.contains("Cloudflare Access") && named_line.contains("relay-a.test"), "{named_line}");
        assert!(named_line.contains("HTTP 403: Forbidden line 2"), "{named_line}");
        assert!(named_line.contains(CLIENT_ID_FILE_ENV) && named_line.contains(CLIENT_SECRET_FILE_ENV), "{named_line}");
        assert!(!named_line.contains(HOST_FLAG), "{named_line}");

        let unnamed_line = refusal_line("relay-a.test", 401, "", false);
        assert!(unnamed_line.contains("HTTP 401)") && unnamed_line.contains(HOST_FLAG), "{unnamed_line}");
        assert!(unnamed_line.contains("AccessHost") && unnamed_line.contains(CLIENT_SECRET_FILE_ENV), "{unnamed_line}");

        let (fault, why) = ended_with("box", Exit::Forbidden, Some(named_line.clone())).unwrap();
        assert_eq!((fault, fault.code(), why), (Fault::Auth, 77, named_line));

        // Without an Access diagnosis, Forbidden stays the pair's refusal (77).
        let (fault, why) = ended_with("box", Exit::Forbidden, None).unwrap();
        assert_eq!((fault, fault.code()), (Fault::Auth, 77));
        assert!(why.contains("the relay refused the pair (403)"), "{why}");

        // An expired pair stays PairExpired (77) and never blames Access.
        let (fault, why) = ended_with("box", Exit::PairExpired, Some("ignored".into())).unwrap();
        assert_eq!((fault, fault.code()), (Fault::PairExpired, 77));
        assert!(why.contains("the pair expired") && !why.contains("ignored"), "{why}");
    }
}
