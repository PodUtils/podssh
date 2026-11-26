//! The shape of the role's event lines (T-1016). The event's own words come
//! first, as before, so that an owner greps them and a harness counts them;
//! its fields follow, each one `KEY=VALUE` with no space in it: `client=`
//! the client's address (`-` where the role does not know it, as on the
//! owner's control socket or behind a tunnel that names no visitor), then
//! `target=HOST:PORT` where the event has one. `podssh relay serve` ends
//! each line on its stdout with `at=` its time in UTC ([`stamped`]). A
//! reader takes the words with [`words`] and a field with [`field`]; a line
//! of the stand-in relay, which has no fields, reads the same way.

use std::net::IpAddr;

/// The keys of the fields that end a line, in their order.
pub const KEYS: [&str; 3] = ["client", "target", "at"];

/// Whom a connection's lines are of: its client and, once its request
/// named one, its target.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Of {
    pub client: Option<IpAddr>,
    pub target: Option<String>,
}

impl Of {
    /// A connection of `client`, with no target yet.
    pub fn client(client: Option<IpAddr>) -> Of {
        Of { client, target: None }
    }

    /// The same client, to `target` (`HOST:PORT`, as the policy shows it).
    pub fn to(&self, target: &str) -> Of {
        Of { client: self.client, target: Some(target.to_string()) }
    }

    /// `WORDS client=ADDR[ target=HOST:PORT]`.
    pub fn line(&self, words: &str) -> String {
        let client = self.client.map_or_else(|| "-".to_string(), |ip| ip.to_canonical().to_string());
        match &self.target {
            Some(target) => format!("{words} client={client} target={}", one_token(target)),
            None => format!("{words} client={client}"),
        }
    }
}

/// `line` with its time, `at=TIME` (an RFC 3339 time in UTC), last.
pub fn stamped(line: &str, time: &str) -> String {
    format!("{line} at={}", one_token(time))
}

/// The event's own words of `line`: the line with its fields gone.
pub fn words(line: &str) -> &str {
    let mut rest = line.trim_end();
    while let Some((before, last)) = rest.rsplit_once(' ') {
        if !is_field(last) {
            break;
        }
        rest = before.trim_end();
    }
    rest
}

/// The value of the field `key` of `line`, if the line has it.
pub fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let fields = line.trim_end().get(words(line).len()..)?;
    fields.split(' ').find_map(|token| token.strip_prefix(key)?.strip_prefix('='))
}

/// Whether `token` is a field of the line's end.
fn is_field(token: &str) -> bool {
    KEYS.iter().any(|key| token.strip_prefix(key).is_some_and(|rest| rest.starts_with('=')))
}

/// `value` as one token: a space or a control character in a target, which
/// a client wrote, would split the field, so it is shown as `?`.
fn one_token(value: &str) -> String {
    let shown: String = value.chars().map(|c| if c.is_whitespace() || c.is_control() { '?' } else { c }).collect();
    if shown.is_empty() {
        "-".to_string()
    } else {
        shown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_holds_its_words_then_its_fields_and_reads_back() {
        let client: IpAddr = "203.0.113.7".parse().unwrap();
        let of = Of::client(Some(client)).to("github.com:22");
        // (words, of, the line, the target read back)
        let cases: [(&str, Of, &str, Option<&str>); 6] = [
            ("upgrade", of.clone(), "upgrade client=203.0.113.7 target=github.com:22", Some("github.com:22")),
            ("h2", Of::client(Some(client)), "h2 client=203.0.113.7", None),
            ("mint", Of::client(None), "mint client=-", None),
            (
                "end gone: the client went with no Close",
                of.clone(),
                "end gone: the client went with no Close client=203.0.113.7 target=github.com:22",
                Some("github.com:22"),
            ),
            (
                "end close 1000 target closed",
                Of::client(Some("2001:db8::1".parse().unwrap())).to("[2001:db8::2]:22"),
                "end close 1000 target closed client=2001:db8::1 target=[2001:db8::2]:22",
                Some("[2001:db8::2]:22"),
            ),
            ("upgrade", Of::client(None).to("a b\n:22"), "upgrade client=- target=a?b?:22", Some("a?b?:22")),
        ];
        for (said, of, line, target) in cases {
            assert_eq!(of.line(said), line);
            assert_eq!(words(line), said, "{line}");
            assert_eq!(field(line, "target"), target, "{line}");
            let at = stamped(line, "2026-11-26T10:00:00Z");
            assert_eq!(words(&at), said, "{at}");
            assert_eq!(field(&at, "at"), Some("2026-11-26T10:00:00Z"), "{at}");
            assert_eq!(field(&at, "client"), field(line, "client"), "{at}");
        }
    }

    #[test]
    fn a_line_with_no_fields_is_its_words() {
        // The stand-in relay's lines, and the role's lines that have none.
        for line in ["upgrade", "mint", "close 1000", "reverse node gone", "refused h:22: no address: x=y z"] {
            assert_eq!(words(line), line);
            assert_eq!(field(line, "client"), None);
        }
        // An IPv4 client of a socket of both families is shown as IPv4.
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(Of::client(Some(mapped)).line("h2"), "h2 client=192.0.2.1");
    }
}
