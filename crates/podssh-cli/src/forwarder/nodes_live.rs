//! Q90's live check of the nodes that the binary ships (T-574): each one
//! alone carries a session to GitHub's SSH endpoint, whose version line
//! comes back, as `pod-services`' watch of the kind `proxy-node` asks. One
//! short probe a node; a node that fails is named, so that the catalog drops
//! it. Ignored outside its workflow (`proxy-nodes-live.yml`).

use std::time::Duration;

use podssh_ws::proxy_nodes::{carry, list, Dial};
use podssh_ws::vless::AtEnd;
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::AsyncReadExt;

use super::nodes::{NODE_WAIT, PLAN};

/// The node's session to `github.com:22`, and SSH's version line through it.
async fn version_line(node: &podssh_ws::proxy_nodes::Node) -> Result<String, String> {
    let trust = Trust::Default;
    let dial = Dial {
        trust: &trust,
        proxy: &ProxyChoice::FromEnvironment,
        timeout: NODE_WAIT - Duration::from_secs(4),
        answer: NODE_WAIT - Duration::from_secs(4),
        silence_is_ready: false,
        at_end: AtEnd::Now,
    };
    let mut quiet = |_: &str| {};
    let carried = carry(std::slice::from_ref(node), "github.com", 22, &dial, (NODE_WAIT, 1), &mut quiet)
        .await
        .map_err(|why| why.join("; "))?;
    let mut stream = carried.stream;
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(15), stream.read(&mut buf))
        .await
        .map_err(|_| "no byte of SSH within 15 s".to_string())?
        .map_err(|e| e.to_string())?;
    let line = String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or_default().to_string();
    if line.starts_with("SSH-2.0-") {
        Ok(line)
    } else {
        Err(format!("the first bytes were no version line of SSH: {line:?}"))
    }
}

/// A line of the check on stderr; a write that fails is no failure of it.
fn say(line: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{line}");
}

#[tokio::test]
#[ignore = "live: each node of the binary, to github.com:22 (proxy-nodes-live.yml)"]
async fn live_each_node_of_the_binary_carries_a_session_to_github() {
    let listed = list::parse(PLAN.built_in.join("\n").as_bytes()).expect("the binary's nodes read");
    assert!(!listed.nodes.is_empty(), "the binary ships no node");
    let mut failed = Vec::new();
    for node in &listed.nodes {
        match version_line(node).await {
            // The node's address is a public node's of a public list; its ID or password is not printed.
            Ok(line) => say(&format!("ok    the {} node {}: {line}", node.road(), node.shown())),
            Err(why) => {
                say(&format!("FAIL  the {} node {}: {why}", node.road(), node.shown()));
                failed.push(node.shown());
            }
        }
    }
    assert!(failed.is_empty(), "drop from the catalog (Q90): {failed:?}");
}
