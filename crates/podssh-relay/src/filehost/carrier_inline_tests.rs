//! The writes that ride in their notes (T-773): a write that fits a note
//! goes on the board alone and no host sees it; a larger one goes to a
//! host; a write's number orders both kinds; a host's pace, an hour here,
//! delays no note, so a handshake's round trip ends within its limit.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use super::carrier::INLINE_MOST;
use super::carrier_tests::{digest, ends, linked, pattern};
use super::host::Host;
use super::keys::{LinkId, Way, OVERHEAD};
use super::standin::{Counter, StandInHost};

const LINK: LinkId = LinkId([6; 16]);
const WAIT: Duration = Duration::from_secs(60);
/// The limit of each handshake above the road (`pod_session`'s and
/// `pod_e2e`'s, 30 s).
const HANDSHAKE: Duration = Duration::from_secs(30);

#[tokio::test(start_paused = true)]
async fn a_write_that_fits_a_note_rides_in_it_and_no_host_sees_it() {
    let counter = Counter::default();
    let host = Arc::new(StandInHost::new("files.stand-in.test", None, counter.clone()).never_deletes());
    let ends = ends(vec![host.clone()], &counter);
    let room = ends.client.room();
    assert_eq!(room, INLINE_MOST - OVERHEAD, "the stand-in board's 64 000 bytes are over the cap");
    let fits = pattern(room, 20);
    ends.client.send(Way::Up, &LINK, 0, &fits).await.unwrap();
    ends.client.send(Way::Up, &LINK, 1, b"").await.unwrap();
    assert_eq!(host.uploads(), 0, "no host saw a write that fits a note");
    for (_, note) in ends.board.kept() {
        assert!(!note.windows(64).any(|w| w == &fits[..64]), "no plaintext on the board");
    }
    assert_eq!(ends.node.receive(Way::Up, &LINK, 0, WAIT).await.unwrap(), fits);
    assert_eq!(ends.node.receive(Way::Up, &LINK, 1, WAIT).await.unwrap(), Vec::<u8>::new(), "the end of a way");
    assert!(ends.board.kept().is_empty(), "each note cleared once read");
    // One byte more is a piece, on a host.
    let over = pattern(room + 1, 21);
    ends.client.send(Way::Up, &LINK, 2, &over).await.unwrap();
    assert_eq!(host.uploads(), 1, "a write over a note's room went to a host");
    assert_eq!(host.kept()[0].len(), over.len() + OVERHEAD);
    assert_eq!(ends.node.receive(Way::Up, &LINK, 2, WAIT).await.unwrap(), over);
}

#[tokio::test(start_paused = true)]
async fn a_writes_number_orders_notes_and_pieces_alike() {
    let counter = Counter::default();
    let host = Arc::new(StandInHost::new("files.stand-in.test", None, counter.clone()));
    let ends = ends(vec![host.clone()], &counter);
    let room = ends.client.room();
    let sizes = [10, 40 * 1024, 300, 1, 70 * 1024, room, room + 1, 5];
    let writes: Vec<Vec<u8>> = sizes.iter().enumerate().map(|(i, len)| pattern(*len, 30 + i as u32)).collect();
    for (n, write) in writes.iter().enumerate() {
        ends.client.send(Way::Up, &LINK, n as u64, write).await.unwrap();
    }
    let hosted = sizes.iter().filter(|len| **len > room).count();
    assert_eq!(host.uploads(), hosted, "the pieces alone went to the host");
    for (n, write) in writes.iter().enumerate() {
        let got = ends.node.receive(Way::Up, &LINK, n as u64, WAIT).await.unwrap();
        assert_eq!(digest(&got), digest(write), "write {n}, of {} bytes", write.len());
    }
    assert!(host.kept().is_empty() && ends.board.kept().is_empty(), "each piece deleted, each note cleared");
}

#[tokio::test(start_paused = true)]
async fn a_hosts_pace_delays_no_note() {
    let counter = Counter::default();
    // One upload an hour.
    let host = Arc::new(StandInHost::new("slow.stand-in.test", Some(1), counter.clone()));
    let ends = ends(vec![host.clone()], &counter);
    let room = ends.client.room();
    ends.client.send(Way::Up, &LINK, 0, &pattern(room + 1, 40)).await.unwrap();
    assert_eq!(host.uploads(), 1, "the host's turn of the hour");
    let started = Instant::now();
    ends.client.send(Way::Up, &LINK, 1, b"a handshake's message").await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(1), "a note waited {:?}", started.elapsed());
    let next = tokio::time::timeout(Duration::from_secs(60), ends.client.ready(room + 1)).await;
    assert!(next.is_err(), "the next piece waits for the host's next turn");
    assert_eq!(ends.node.receive(Way::Up, &LINK, 1, WAIT).await.unwrap(), b"a handshake's message");
}

#[tokio::test(start_paused = true)]
async fn a_link_s_small_writes_make_a_round_trip_within_a_handshake_s_limit_while_its_host_waits() {
    let counter = Counter::default();
    let host = Arc::new(StandInHost::new("slow.stand-in.test", Some(1), counter.clone()));
    let shared: Arc<dyn Host> = host.clone();
    let ends = ends(vec![shared], &counter);
    let (mut client, mut node) = linked(&ends).await;
    for ask in [&b"the layer's hello"[..], b"the channel's hello"] {
        let started = Instant::now();
        client.write_all(ask).await.unwrap();
        let mut got = vec![0u8; ask.len()];
        node.read_exact(&mut got).await.unwrap();
        assert_eq!(got, ask);
        node.write_all(b"its answer").await.unwrap();
        let mut answer = [0u8; 10];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"its answer");
        assert!(started.elapsed() < HANDSHAKE, "a round trip took {:?}", started.elapsed());
    }
    assert_eq!(host.uploads(), 0, "no host saw a small write");
    // A piece takes the host's one turn of the hour; a small write after it
    // waits for no other turn.
    let piece = pattern(64 * 1024, 41);
    client.write_all(&piece).await.unwrap();
    let mut got = vec![0u8; piece.len()];
    node.read_exact(&mut got).await.unwrap();
    assert_eq!(digest(&got), digest(&piece));
    let started = Instant::now();
    client.write_all(b"a key").await.unwrap();
    let mut key = [0u8; 5];
    node.read_exact(&mut key).await.unwrap();
    assert_eq!(&key, b"a key");
    assert!(started.elapsed() < HANDSHAKE, "a small write behind a piece took {:?}", started.elapsed());
    assert_eq!(host.uploads(), 1, "one piece, in the host's one turn");
}

#[tokio::test(start_paused = true)]
async fn a_link_keeps_the_order_of_small_and_large_writes() {
    let counter = Counter::default();
    let host = Arc::new(StandInHost::new("files.stand-in.test", None, counter.clone()));
    let shared: Arc<dyn Host> = host.clone();
    let ends = ends(vec![shared], &counter);
    let (mut client, mut node) = linked(&ends).await;
    let parts = [pattern(100, 50), pattern(40 * 1024, 51), pattern(7, 52), pattern(300, 53), pattern(90 * 1024, 54)];
    let reading = tokio::spawn(async move {
        let mut got = Vec::new();
        node.read_to_end(&mut got).await.unwrap();
        got
    });
    for part in &parts {
        client.write_all(part).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    client.shutdown().await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(30 * 60), reading).await.unwrap().unwrap();
    assert_eq!(digest(&got), digest(&parts.concat()), "each byte once, in order");
    assert_eq!(host.uploads(), 2, "the two large writes as pieces, the small ones in notes");
}

#[tokio::test(start_paused = true)]
async fn a_client_s_link_waits_until_the_node_takes_its_hello() {
    let counter = Counter::default();
    let host: Arc<dyn Host> = Arc::new(StandInHost::new("files.stand-in.test", None, counter.clone()));
    let ends = ends(vec![host], &counter);
    let hello = ends.client.knock(&LINK).await.unwrap();
    let alone = ends.client.knocked(&hello, HANDSHAKE).await.unwrap_err();
    assert!(alone.contains("took no hello"), "{alone}");
    let client = ends.client.clone();
    let waiting = tokio::spawn(async move { client.knocked(&hello, WAIT).await });
    assert_eq!(ends.node.answer(Duration::from_secs(10)).await.unwrap(), LINK);
    waiting.await.unwrap().unwrap();
}
