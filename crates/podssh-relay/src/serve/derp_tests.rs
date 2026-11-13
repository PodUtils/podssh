//! The DERP route's parts that need no node: the file of keys, the frames,
//! the 101, and the hub's forwarding between two keys. The handshake with a
//! real node, the fork's, is `crates/podssh-cli/tests/ts_two_nodes.rs`'s.

use std::path::PathBuf;

use super::hub::lock;
use super::*;
use crate::derp::frame::{kind, MAX_PACKET};

const A: &str = "nodekey:0101010101010101010101010101010101010101010101010101010101010101";

fn hub() -> Hub {
    Hub::new(Secret::from_bytes([7; 32]), PathBuf::from("/nonexistent/derp-keys"))
}

#[test]
fn a_file_of_keys_takes_nodekey_lines_hex_comments_and_blanks() {
    let text = format!("# the two nodes\n{A}\n\n  {}  \r\n", "02".repeat(32));
    let keys = parse_keys(&text).unwrap();
    assert_eq!(keys, vec![Key([1; 32]), Key([2; 32])]);
    assert_eq!(parse_keys("").unwrap(), vec![]);
}

#[test]
fn a_line_that_is_no_key_is_named_and_admits_nobody() {
    let bads = ["nodekey:01".to_string(), "mkey:0101".to_string(), "zz".repeat(32), format!("{A}0")];
    for bad in &bads {
        let why = parse_keys(&format!("{A}\n{bad}\n")).expect_err(bad);
        assert!(why.starts_with("line 2: "), "{bad}: {why}");
    }
}

#[test]
fn a_frame_is_its_kind_its_length_and_its_body() {
    assert_eq!(framed(kind::PONG, &[1, 2]), vec![kind::PONG, 0, 0, 0, 2, 1, 2]);
    assert_eq!(framed(kind::KEEP_ALIVE, &[]), vec![kind::KEEP_ALIVE, 0, 0, 0, 0]);
}

#[test]
fn the_101_of_the_http_upgrade_names_derp_its_version_and_the_key() {
    let text = String::from_utf8(switching_raw(&Key([0xab; 32]))).unwrap();
    assert!(text.starts_with("HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\n"), "{text}");
    assert!(text.contains("\r\nDerp-Version: 2\r\n"), "{text}");
    assert!(text.ends_with(&format!("\r\nDerp-Public-Key: {}\r\n\r\n", "ab".repeat(32))), "{text}");
}

#[test]
fn the_101_names_the_subprotocol_derp() {
    let text = String::from_utf8(switching("dGhlIHNhbXBsZSBub25jZQ==")).unwrap();
    assert!(text.starts_with("HTTP/1.1 101 "), "{text}");
    // RFC 6455's own example of a key and its accept.
    assert!(text.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"), "{text}");
    assert!(text.ends_with("\r\nSec-WebSocket-Protocol: derp\r\n\r\n"), "{text}");
}

#[tokio::test]
async fn a_packet_goes_to_the_key_that_it_names_with_its_sender() {
    let hub = hub();
    let (a, b) = (Key([1; 32]), Key([2; 32]));
    let (_, _a_waits) = hub.join(a);
    let (_, mut b_waits) = hub.join(b);
    hub.forward(&a, &[&b.0[..], b"wg"].concat());
    let got = b_waits.recv().await.unwrap();
    assert_eq!(got, framed(kind::RECV_PACKET, &[&a.0[..], b"wg"].concat()));
    // To a key that is not up: lost, and nothing panics.
    hub.forward(&a, &[&[9u8; 32][..], b"wg"].concat());
    // Too short to name a key, or past DERP's largest packet: lost.
    hub.forward(&a, &[1, 2, 3]);
    hub.forward(&a, &[&b.0[..], &vec![0u8; MAX_PACKET + 1][..]].concat());
    assert!(b_waits.try_recv().is_err());
}

#[tokio::test]
async fn a_newer_connection_of_a_key_takes_its_queue() {
    let hub = hub();
    let a = Key([1; 32]);
    let (old, mut old_waits) = hub.join(a);
    let (new, _new_waits) = hub.join(a);
    // The older one's sender is gone: its writer says so and ends.
    assert!(old_waits.recv().await.is_none());
    // The older one's end leaves the newer one in place.
    hub.leave(&a, old);
    assert!(lock(&hub.clients).get(&a).is_some_and(|c| c.id == new));
    hub.leave(&a, new);
    assert!(lock(&hub.clients).is_empty());
}

#[test]
fn a_file_that_cannot_be_read_admits_nobody() {
    let why = hub().admits(&Key([1; 32])).expect_err("a missing file");
    assert!(why.starts_with("/nonexistent/derp-keys: "), "{why}");
}

#[test]
fn the_file_admits_its_keys_alone_and_a_key_added_without_a_restart() {
    let dir = std::env::temp_dir().join(format!("podssh-derp-keys-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("keys");
    std::fs::write(&path, format!("{A}\n")).unwrap();
    let hub = Hub::new(Secret::from_bytes([7; 32]), path.clone());
    assert_eq!(hub.admits(&Key([1; 32])), Ok(true), "a listed key");
    assert_eq!(hub.admits(&Key([2; 32])), Ok(false), "a key that the file does not list");
    std::fs::write(&path, format!("{A}\n{}\n", "02".repeat(32))).unwrap();
    assert_eq!(hub.admits(&Key([2; 32])), Ok(true), "read again at each login");
    let _ = std::fs::remove_dir_all(&dir);
}
