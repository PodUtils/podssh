//! SSH_MSG_UNIMPLEMENTED in answer to a message number that russh names no
//! message of (RFC 4253, section 11.4), with the packet's sequence number,
//! before the login and after it; each named message is passed over as
//! before. podssh's patch (vendor/patches/russh/, T-854), in the way of
//! the crafted packets of `tests::raw_no_crypto`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // as in the test suite

use std::time::Duration;

use crate::msg;
use crate::tests::raw_no_crypto::{RawSession, read_packet};

/// A number that no message has: the probe that follows each row that
/// expects no answer, so that silence is read as the order of the replies
/// and not as a wait.
const PROBE: u8 = 200;

/// Each number after the login, and whether the server answers it. The
/// numbers that RFC 4250 assigns and russh names (`msg.rs`) are passed over,
/// in their place or out of it; each other is answered, in each range of
/// RFC 4250, section 4.1.2: transport (8 to 19), kex (22 to 29, 35 to 49),
/// userauth (54 to 59, 62, 67 to 79), connection (83 to 89, 101 to 127), the
/// client protocols (128 to 191) and the local extensions (192 to 255).
#[rustfmt::skip]
const AFTER_LOGIN: &[(u8, bool)] = &[
    (msg::IGNORE, false), (msg::UNIMPLEMENTED, false), (msg::DEBUG, false),
    (msg::SERVICE_REQUEST, false), (msg::SERVICE_ACCEPT, false), (msg::EXT_INFO, false),
    (8, true), (9, true), (19, true),
    (22, true), (29, true), (35, true), (49, true),
    (msg::USERAUTH_REQUEST, false), (msg::USERAUTH_SUCCESS, false), (60, false),
    (54, true), (59, true), (62, true), (67, true), (79, true),
    (83, true), (89, true),
    (msg::CHANNEL_SUCCESS, false), (msg::CHANNEL_FAILURE, false),
    (101, true), (127, true), (128, true), (191, true), (192, true), (255, true),
];

/// Each number before the login (after the service request), where a
/// named message out of its place is passed over too.
#[rustfmt::skip]
const BEFORE_LOGIN: &[(u8, bool)] = &[
    (msg::IGNORE, false), (msg::SERVICE_REQUEST, false), (msg::GLOBAL_REQUEST, false),
    (msg::CHANNEL_OPEN, false),
    (8, true), (62, true), (101, true), (128, true), (255, true),
];

/// The next packet of the server, within a bound.
async fn next(session: &mut RawSession) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(3), read_packet(&mut session.stream))
        .await
        .expect("a packet of the server within 3 s")
        .unwrap()
}

/// UNIMPLEMENTED for the packet `seqn`, as its bytes.
fn unimplemented(seqn: u32) -> Vec<u8> {
    let mut packet = vec![msg::UNIMPLEMENTED];
    packet.extend_from_slice(&seqn.to_be_bytes());
    packet
}

/// Sends each row, the client's packet `first` the first, and gives each
/// row whose answer was not the table's.
async fn rows(session: &mut RawSession, table: &[(u8, bool)], first: u32) -> Vec<String> {
    let mut wrong = Vec::new();
    let mut seqn = first;
    for &(number, answered) in table {
        session.send_packet(&[number]).await.unwrap();
        let mut expected = seqn;
        seqn += 1;
        if !answered {
            session.send_packet(&[PROBE]).await.unwrap();
            expected = seqn;
            seqn += 1;
        }
        let got = next(session).await;
        if got != unimplemented(expected) {
            wrong.push(format!(
                "{number}: answered {answered:?} expected UNIMPLEMENTED for {expected}, got {got:?}"
            ));
        }
    }
    wrong
}

#[tokio::test]
async fn an_unknown_number_after_the_login_gets_unimplemented_with_its_sequence_number() {
    let mut session = RawSession::connect().await;
    // KEXINIT took 0 and NEWKEYS 1; the service request 2 and the login 3.
    session.auth_none().await.unwrap();
    let wrong = rows(&mut session, AFTER_LOGIN, 4).await;
    assert!(wrong.is_empty(), "{} rows wrong:\n{}", wrong.len(), wrong.join("\n"));
}

#[tokio::test]
async fn an_unknown_number_before_the_login_gets_unimplemented_too() {
    let mut session = RawSession::connect().await;
    session.service_request().await.unwrap();
    let wrong = rows(&mut session, BEFORE_LOGIN, 3).await;
    assert!(wrong.is_empty(), "{} rows wrong:\n{}", wrong.len(), wrong.join("\n"));
}

/// The table's rule is `msg::is_known`: each named number is in it.
#[test]
fn the_named_numbers_are_the_known_ones() {
    for (number, answered) in AFTER_LOGIN.iter().chain(BEFORE_LOGIN) {
        assert_eq!(msg::is_known(*number), !answered, "{number}");
    }
}
