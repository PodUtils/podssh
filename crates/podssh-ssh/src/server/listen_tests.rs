//! The caps of a listener and the bytes of a refusal (T-124).

use super::*;

/// The packet of a refusal, read back as a client reads it: the length
/// and the padding of RFC 4253, then the DISCONNECT's fields.
fn read_packet(bytes: &[u8]) -> (u32, String) {
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert_eq!(bytes.len(), 4 + length, "one packet, whole");
    assert_eq!((4 + length) % CLEAR_BLOCK, 0, "rounded to the block");
    let padding = bytes[4] as usize;
    assert!((4..4 + CLEAR_BLOCK).contains(&padding), "padding of 4 to 11 bytes: {padding}");
    let payload = &bytes[5..4 + length - padding];
    assert_eq!(payload[0], MSG_DISCONNECT);
    let code = u32::from_be_bytes(payload[1..5].try_into().unwrap());
    let len = u32::from_be_bytes(payload[5..9].try_into().unwrap()) as usize;
    let reason = String::from_utf8(payload[9..9 + len].to_vec()).unwrap();
    let tag = u32::from_be_bytes(payload[9 + len..13 + len].try_into().unwrap());
    assert_eq!(tag, 0, "an empty language tag");
    assert_eq!(payload.len(), 13 + len, "nothing after the language tag");
    (code, reason)
}

/// Each length of a reason rounds to the block with a padding in bounds,
/// one rule for the whole family; the code is russh's own.
#[test]
fn a_disconnect_packet_of_each_length_reads_back() {
    assert_eq!(TOO_MANY_CONNECTIONS, russh::Disconnect::TooManyConnections as u32);
    for n in 0..64 {
        let reason = "r".repeat(n);
        let (code, read) = read_packet(&disconnect_packet(TOO_MANY_CONNECTIONS, &reason));
        assert_eq!((code, read.as_str()), (TOO_MANY_CONNECTIONS, reason.as_str()), "length {n}");
    }
}

#[test]
fn a_refusal_is_the_version_line_then_the_packet() {
    let why = Why::Connections(3);
    let bytes = refusal(&why.told());
    let text = String::from_utf8_lossy(&bytes);
    let (line, rest) = text.split_once("\r\n").expect("a version line");
    assert!(line.starts_with("SSH-2.0-podssh_"), "{line}");
    let (code, reason) = read_packet(&bytes[line.len() + 2..]);
    assert_eq!(code, TOO_MANY_CONNECTIONS);
    assert!(reason.starts_with("podssh serve: 3 connections"), "{reason}");
    assert!(reason.contains("--max-connections"), "{reason}");
    assert!(!rest.is_empty());
}

/// The cap lets in its number, refuses the next, drops past the refusals'
/// own cap, and gives each place back as its holder drops.
#[test]
fn the_cap_lets_in_its_number_and_gives_places_back() {
    let gate = Gate::new(Limits { connections: 2 });
    let first = gate.enter();
    let second = gate.enter();
    assert!(matches!((&first, &second), (Entry::Admitted(_), Entry::Admitted(_))));
    assert_eq!(gate.open(), 2);
    let mut refused = Vec::new();
    for _ in 0..REFUSING {
        match gate.enter() {
            Entry::Full(full) => {
                assert_eq!(full.why, Why::Connections(2));
                refused.push(full);
            }
            other => panic!("a refusal, not {other:?}"),
        }
    }
    assert!(matches!(gate.enter(), Entry::Dropped(Why::Connections(2))), "past the refusals' cap");
    refused.pop();
    assert!(matches!(gate.enter(), Entry::Full(_)), "a refusal's place comes back");
    drop(first);
    assert_eq!(gate.open(), 1);
    assert!(matches!(gate.enter(), Entry::Admitted(_)), "a connection's place comes back");
}

#[test]
fn a_cap_out_of_bounds_is_held_in_them() {
    assert_eq!(Gate::new(Limits { connections: 0 }).limits().connections, 1);
    assert_eq!(Gate::new(Limits { connections: usize::MAX }).limits().connections, CAP_MAX);
}

/// A refusal over a pipe: the client reads the words, and the refusal ends
/// at the client's end with no wait for [`REFUSE_LIMIT`].
#[tokio::test]
async fn a_refusal_ends_at_the_clients_end() {
    let gate = Gate::new(Limits { connections: 1 });
    let _held = gate.enter();
    let Entry::Full(full) = gate.enter() else { panic!("a refusal") };
    let (mut near, far) = tokio::io::duplex(1 << 16);
    let refusing = tokio::spawn(refuse(far, full));
    near.write_all(b"SSH-2.0-OpenSSH_9.9\r\n").await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), near.read_to_end(&mut got)).await.expect("in time").unwrap();
    assert_eq!(got, refusal(&Why::Connections(1).told()));
    drop(near);
    tokio::time::timeout(Duration::from_secs(5), refusing).await.expect("the refusal ends").unwrap();
    assert!(matches!(gate.enter(), Entry::Full(_)), "the refusal's place came back");
}
