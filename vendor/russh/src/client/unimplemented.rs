//! The client's SSH_MSG_UNIMPLEMENTED in answer to a message number that
//! russh names no message of, after the login (RFC 4253, section 11.4),
//! with the packet's sequence number; each named message that it passes
//! over is still passed over. Before the login, such a message ends the
//! connection, as before. podssh's patch (vendor/patches/russh/, T-854).
#![allow(clippy::unwrap_used)] // as in the test suite

use std::num::Wrapping;

use super::tests::{TestHandler, keyboard_interactive_session};
use crate::msg;
use crate::session::EncryptedState;
use crate::sshbuffer::IncomingSshPacket;

/// The bytes that a packet of `number` alone adds to the session's write
/// buffer, read through the loop's `reply` as packet `seqn` of the server.
async fn written(number: u8, seqn: u32) -> Vec<u8> {
    let (mut session, _sender, _replies) = keyboard_interactive_session();
    session.common.encrypted.as_mut().unwrap().state = EncryptedState::Authenticated;
    let before = session.common.encrypted.as_ref().unwrap().write.len();
    // The loop's count is one past the packet's own, as after read().
    let mut pkt = IncomingSshPacket {
        buffer: vec![number],
        seqn: Wrapping(seqn.wrapping_add(1)),
    };
    super::reply(&mut session, &mut TestHandler, &mut None, &mut pkt)
        .await
        .unwrap();
    session.common.encrypted.as_ref().unwrap().write[before..].to_vec()
}

/// UNIMPLEMENTED for the packet `seqn`, framed as `push_packet!` frames it.
fn unimplemented(seqn: u32) -> Vec<u8> {
    let mut packet = 5u32.to_be_bytes().to_vec();
    packet.push(msg::UNIMPLEMENTED);
    packet.extend_from_slice(&seqn.to_be_bytes());
    packet
}

#[tokio::test]
async fn an_unknown_number_is_answered_and_a_named_one_is_passed_over() {
    #[rustfmt::skip]
    let table: &[(u8, bool)] = &[
        (8, true), (62, true), (101, true), (128, true), (200, true), (255, true),
        (msg::IGNORE, false), (msg::SERVICE_REQUEST, false), (msg::SERVICE_ACCEPT, false),
        (msg::USERAUTH_REQUEST, false), (msg::USERAUTH_SUCCESS, false),
    ];
    for &(number, answered) in table {
        let seqn = 41 + u32::from(number);
        let expected = if answered { unimplemented(seqn) } else { Vec::new() };
        assert_eq!(written(number, seqn).await, expected, "{number}");
    }
    // The count wraps: the packet before a count of 0 is u32::MAX.
    assert_eq!(written(200, u32::MAX).await, unimplemented(u32::MAX));
}
