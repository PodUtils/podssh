//! The name of a node's tunnel, as Pinggy gives it: the list of `GET /urls`
//! at port 4300 of Pinggy's end of the session, `{"urls": [...]}`, which
//! "also works for TCP, TLS, TLSTCP, and UDP tunnels"
//! (<https://pinggy.io/docs/api/web_debugger_api/>, read 2026-11-09); else
//! the text that Pinggy writes on the session's channel, where the same
//! addresses stand among words and a terminal's escapes
//! (<https://pinggy.io/docs/>, read 2026-11-09). Each address is reduced to
//! its host; a host of Pinggy's own (its server, its dashboard) is passed
//! over, as it is no tunnel's.
//!
//! The form of a TLS tunnel's address is Inferred: the documents show a
//! tunnel of HTTP's, `https://NAME.run.pinggy-free.link`, and a TLS tunnel's
//! edge under `*.a.pinggy.link`; whatever the scheme, the host is the name.

/// The bound of the list's answer: a few addresses.
pub const MOST: usize = 64 * 1024;

/// The request of the list, over a `direct-tcpip` channel to the port.
pub fn request() -> Vec<u8> {
    format!(
        "GET /urls HTTP/1.0\r\nHost: localhost:{}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        super::URLS_PORT
    )
    .into_bytes()
}

/// The addresses of an answer of HTTP/1.x to [`request`]: a status of 200
/// and a body `{"urls": [...]}`; else why not.
pub fn response(bytes: &[u8]) -> Result<Vec<String>, String> {
    let at = bytes.windows(4).position(|w| w == b"\r\n\r\n").ok_or("the answer of /urls has no end of its head")?;
    let head = String::from_utf8_lossy(&bytes[..at]);
    let status = head.lines().next().unwrap_or_default();
    let mut words = status.split_whitespace();
    let (version, code) = (words.next().unwrap_or_default(), words.next().unwrap_or_default());
    if !version.starts_with("HTTP/1.") {
        return Err("the answer of /urls is not HTTP/1.x".into());
    }
    if code != "200" {
        return Err(format!("/urls answered {code}"));
    }
    let body: serde_json::Value =
        serde_json::from_slice(&bytes[at + 4..]).map_err(|e| format!("the body of /urls is not JSON: {e}"))?;
    let urls = body.get("urls").and_then(|u| u.as_array()).ok_or("the body of /urls has no list urls")?;
    Ok(urls.iter().filter_map(|u| u.as_str().map(str::to_string)).collect())
}

/// The host of `address`: `SCHEME://HOST[:PORT][/...]` or `HOST[:PORT]`, in
/// lower case, when it is a name of two labels or more, each of
/// `[a-z0-9-]`; an address of IP is no tunnel's name.
pub fn host_of(address: &str) -> Option<String> {
    let rest = address.trim().split_once("://").map_or(address.trim(), |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        Some(_) => return None,
        None => authority,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    is_name(&host).then_some(host)
}

/// A DNS name of two labels or more, each of 1 to 63 of `[a-z0-9-]` that
/// neither begins nor ends with `-`, the last one not all digits.
pub fn is_name(text: &str) -> bool {
    let labels: Vec<&str> = text.split('.').collect();
    let label_ok = |label: &&str| {
        !label.is_empty()
            && label.len() <= 63
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    let top_ok = labels.last().is_some_and(|top| !top.bytes().all(|b| b.is_ascii_digit()));
    text.len() <= 253 && labels.len() >= 2 && labels.iter().all(label_ok) && top_ok
}

/// The names of `addresses` that are no host of `skip`, in their order,
/// once each.
pub fn names(addresses: &[String], skip: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for host in addresses.iter().filter_map(|a| host_of(a)) {
        if !skip.iter().any(|s| s.eq_ignore_ascii_case(&host)) && !out.contains(&host) {
            out.push(host);
        }
    }
    out
}

/// The addresses that `text` holds, `SCHEME://...` words with a terminal's
/// escapes taken out.
pub fn in_text(text: &str) -> Vec<String> {
    let plain = strip_escapes(text);
    plain
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | ','))
        .filter(|word| word.contains("://"))
        .map(|word| word.trim_end_matches(['.', ';']).to_string())
        .collect()
}

/// `text` with each escape sequence of a terminal (CSI and OSC) taken out,
/// as Pinggy's rich interface draws with them.
fn strip_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.next() {
            // CSI: to its final byte, from '@' to '~'.
            Some('[') => {
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            // OSC: to BEL, or to ESC '\'.
            Some(']') => {
                while let Some(c) = chars.next() {
                    if c == '\u{7}' || (c == '\u{1b}' && chars.peek() == Some(&'\\')) {
                        if c == '\u{1b}' {
                            chars.next();
                        }
                        break;
                    }
                }
            }
            _ => {}
        }
        out.push(' ');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sample of Pinggy's document of its API, as it stands there.
    const SAMPLE: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\n  \"urls\": [\n    \
        \"http://rnckk-2405-201-9018-a834-e551-ccf2-398f-130d.run.pinggy-free.link\",\n    \
        \"https://rnckk-2405-201-9018-a834-e551-ccf2-398f-130d.run.pinggy-free.link\"\n  ]\n}";

    #[test]
    fn the_list_of_the_api_gives_the_tunnel_s_name_once() {
        let urls = response(SAMPLE.as_bytes()).unwrap();
        assert_eq!(urls.len(), 2);
        let names = names(&urls, &["free.pinggy.io", "dashboard.pinggy.io"]);
        assert_eq!(names, vec!["rnckk-2405-201-9018-a834-e551-ccf2-398f-130d.run.pinggy-free.link".to_string()]);
        assert!(std::str::from_utf8(&request()).unwrap().starts_with("GET /urls HTTP/1.0\r\nHost: localhost:4300\r\n"));
    }

    #[test]
    fn an_answer_that_is_not_the_list_is_refused_with_why() {
        assert!(response(b"HTTP/1.1 404 Not Found\r\n\r\n").unwrap_err().contains("404"));
        assert!(response(b"SSH-2.0-x\r\n\r\n").is_err());
        assert!(response(b"HTTP/1.1 200 OK\r\n\r\n{\"other\":[]}").unwrap_err().contains("no list urls"));
        assert!(response(b"HTTP/1.1 200 OK\r\n").is_err());
    }

    #[test]
    fn a_host_is_a_name_and_never_an_address_or_a_port_alone() {
        assert_eq!(host_of("tls://Abc-1.A.Pinggy.Link:443/").as_deref(), Some("abc-1.a.pinggy.link"));
        assert_eq!(host_of("abc.a.pinggy.link").as_deref(), Some("abc.a.pinggy.link"));
        for not in ["https://127.0.0.1", "tcp://localhost:4300", "https://-a.b", "https://a.b:x", "https://a..b", ""] {
            assert_eq!(host_of(not), None, "{not}");
        }
    }

    #[test]
    fn the_session_s_text_gives_its_addresses_through_a_terminal_s_escapes() {
        let text = "\u{1b}[2J\u{1b}[1;1HYou can access local server via following URL(s):\r\n\
                    \u{1b}[32mtls://xyzzy-12.a.free.pinggy.link\u{1b}[0m\r\n\
                    \u{1b}]8;;https://dashboard.pinggy.io\u{7}dashboard\u{1b}]8;;\u{7} \
                    https://dashboard.pinggy.io.\r\n";
        let found = in_text(text);
        let names = names(&found, &["dashboard.pinggy.io"]);
        assert_eq!(names, vec!["xyzzy-12.a.free.pinggy.link".to_string()], "{found:?}");
    }
}
