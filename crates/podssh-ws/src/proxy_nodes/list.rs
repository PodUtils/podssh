//! A list's body as an aggregator serves it (T-574): lines of share links,
//! or base64 of such lines, as a subscription is. The lines that podssh
//! speaks, `vless://`, `trojan://` and `vmess://` (T-739), are parsed, the
//! filters of Q79 ([`super::filter`]) keep some, and the rest is counted for
//! one line of what was left out. A line of another scheme (Shadowsocks,
//! ...), or VMess's MD5 form, is counted as one that podssh does not speak.

use std::collections::{BTreeMap, HashSet};

use base64::Engine;

use super::filter::{judge, Skip};
use super::Node;
use crate::trojan;
use crate::vless;
use crate::vmess;

/// The largest list that is read.
pub const MAX_BODY: usize = 4 << 20;
/// The kept nodes of one list: the rest of a list of thousands is not read,
/// as no run tries so many.
pub const MAX_KEPT: usize = 32;

/// A list as it was read.
#[derive(Default)]
pub struct Listed {
    /// The nodes that the filters kept, in the list's order, each once.
    pub nodes: Vec<Node>,
    /// The line of each kept node, as the list gave it, for the cache.
    pub lines: Vec<String>,
    /// Each reason, and how many nodes it left out.
    pub skipped: BTreeMap<Skip, usize>,
    /// Lines that podssh does not speak, or cannot read.
    pub others: usize,
}

// The kept lines hold each node's ID or password, a credential: a debug
// print counts them and never shows them.
impl std::fmt::Debug for Listed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listed")
            .field("nodes", &self.nodes)
            .field("lines", &self.lines.len())
            .field("skipped", &self.skipped)
            .field("others", &self.others)
            .finish()
    }
}

impl Listed {
    /// One line of what was left out, or `None` when nothing was.
    pub fn note(&self) -> Option<String> {
        let mut parts: Vec<String> = self.skipped.iter().map(|(why, n)| format!("{n} with {}", why.words())).collect();
        if self.others > 0 {
            parts.push(format!("{} of kinds that podssh does not speak", self.others));
        }
        (!parts.is_empty()).then(|| format!("left out: {}", parts.join("; ")))
    }
}

/// The text of a body: itself where it holds links, else the text that its
/// base64 gives.
fn text_of(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    if text.contains("://") {
        return Some(text.to_string());
    }
    let url: String = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD_INDIFFERENT.decode(url.as_bytes()).ok()?;
    String::from_utf8(bytes).ok().filter(|t| t.contains("://"))
}

/// The nodes of `body`, as [`Listed`] says. A body that is neither links nor
/// base64 of them is an error.
pub fn parse(body: &[u8]) -> Result<Listed, String> {
    let text = text_of(body).ok_or("the list is neither lines of share links nor base64 of them")?;
    let mut listed = Listed::default();
    let mut seen = HashSet::new();
    for line in text.lines().map(str::trim) {
        let scheme = line.split("://").next().unwrap_or_default().to_ascii_lowercase();
        let node = match (scheme.as_str(), line.contains("://")) {
            ("vless", true) => vless::Server::parse(line).map(Node::Vless),
            ("trojan", true) => trojan::Server::parse(line).map(Node::Trojan),
            ("vmess", true) => vmess::Server::parse(line).map(Node::Vmess),
            (_, true) => {
                listed.others += 1;
                continue;
            }
            _ => continue,
        };
        let Ok(node) = node else {
            listed.others += 1;
            continue;
        };
        if let Err(why) = judge(&node) {
            *listed.skipped.entry(why).or_default() += 1;
            continue;
        }
        // One node twice, under two names, is one node.
        if listed.nodes.len() < MAX_KEPT && seen.insert(key(&node)) {
            listed.nodes.push(node);
            listed.lines.push(line.to_string());
        }
    }
    Ok(listed)
}

/// What makes two lines one node.
fn key(node: &Node) -> String {
    let (host, port) = node.address();
    format!("{}|{host}|{port}|{}", node.road(), node.shown())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vless(rest: &str) -> String {
        ["vless://550e8400-e29b-41d4", "-a716-446655440000@", rest, "\n"].concat()
    }
    fn trojan(rest: &str) -> String {
        ["trojan://", "a-list-pw", "@", rest, "\n"].concat()
    }
    /// v2rayN's line: the base64 of the JSON, `aid` as given.
    fn vmess(add: &str, aid: &str) -> String {
        let json = format!(
            r#"{{"add":"{add}","port":"443","id":"550e8400-e29b-41d4-a716-446655440000","aid":"{aid}","net":"ws","tls":"tls"}}"#
        );
        format!("vmess://{}\n", base64::engine::general_purpose::STANDARD.encode(json))
    }

    fn body() -> String {
        [
            vless("a.example.com:443?type=ws&security=tls#one"),
            vless("a.example.com:443?type=ws&security=tls#the-same-again"),
            vless("front.example.com:443?type=ws&security=tls&sni=victim.example.org"),
            vless("b.state.edu:443?type=ws&security=tls"),
            vless("c.example.com:8443?type=ws&security=tls"),
            trojan("t.example.com:443?security=tls"),
            "vmess://eyJ2IjoiMiJ9\n".into(),
            vmess("v.example.com", "0"),
            vmess("md5.example.com", "64"),
            "ss://abc@h.example:1\n".into(),
            "# a comment\n\n".into(),
            "vless://not-a-link\n".into(),
        ]
        .concat()
    }

    #[test]
    fn a_list_of_links_gives_the_kept_nodes_once_each_and_counts_the_rest() {
        let listed = parse(body().as_bytes()).unwrap();
        let shown: Vec<String> = listed.nodes.iter().map(Node::shown).collect();
        assert_eq!(shown, ["vless://a.example.com:443/", "trojan://t.example.com:443", "vmess://v.example.com:443/"]);
        assert_eq!(listed.lines.len(), 3);
        assert_eq!(listed.skipped[&Skip::Fronts], 1);
        assert_eq!(listed.skipped[&Skip::Institution], 1);
        assert_eq!(listed.skipped[&Skip::Port], 1);
        assert_eq!(
            listed.others, 4,
            "a VMess line with no address, VMess's MD5 form, ss and a line that does not read"
        );
        let note = listed.note().unwrap();
        assert!(note.starts_with("left out: ") && note.contains("kinds that podssh does not speak"), "{note}");
        assert!(!format!("{listed:?}").contains("550e8400"), "no ID in a debug print");
    }

    #[test]
    fn a_base64_list_reads_as_its_lines() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(body());
        let listed = parse(encoded.as_bytes()).unwrap();
        assert_eq!(listed.nodes.len(), 3);
        let wrapped: String =
            encoded.as_bytes().chunks(60).map(|c| format!("{}\n", String::from_utf8_lossy(c))).collect();
        assert_eq!(parse(wrapped.as_bytes()).unwrap().nodes.len(), 3);
    }

    #[test]
    fn a_body_that_is_no_list_is_an_error_and_a_long_list_is_cut() {
        assert!(parse(b"<html>blocked</html>").unwrap_err().contains("neither lines of share links"));
        assert!(parse(&[0xff, 0xfe]).is_err());
        let many: String = (0..100).map(|i| vless(&format!("n{i}.example.com:443?type=ws&security=tls"))).collect();
        assert_eq!(parse(many.as_bytes()).unwrap().nodes.len(), MAX_KEPT);
    }
}
