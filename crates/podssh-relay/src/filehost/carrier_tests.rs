//! The carrier and its links against the in-process stand-ins: a client and
//! a node move their bytes each way, one request of the road at a time; a
//! host keeps ciphertext alone; a busy host hands the next piece to the
//! next one; a stranger's notes and hellos open nothing.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::board::Board;
use super::carrier::Carrier;
use super::host::Host;
use super::keys::{Keys, Kind, LinkId, Way, OVERHEAD};
use super::link;
use super::pace::Gate;
use super::standin::{Counter, StandInBoard, StandInHost};
use super::Say;
use crate::session::OsEntropy;

const TOKEN: &str = "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr";
const LINK: LinkId = LinkId([5; 16]);

fn keys() -> Arc<Keys> {
    Arc::new(Keys::of_pair("relay-pair-name", TOKEN))
}

fn sayer(lines: &Arc<Mutex<Vec<String>>>) -> Say {
    let lines = lines.clone();
    Arc::new(move |line| lines.lock().unwrap().push(line))
}

/// `len` bytes that no two calls of another `seed` share.
fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect()
}

fn digest(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

struct Ends {
    client: Arc<Carrier>,
    node: Arc<Carrier>,
    board: Arc<StandInBoard>,
    lines: Arc<Mutex<Vec<String>>>,
}

/// A client and a node of one pair over `hosts` and one board, under one
/// gate, as two carriers of one process share it.
fn ends(hosts: Vec<Arc<dyn Host>>, counter: &Counter) -> Ends {
    let board = Arc::new(StandInBoard::new(counter.clone()));
    let lines = Arc::new(Mutex::new(Vec::new()));
    let gate = Gate::default();
    let shared: Arc<dyn Board> = board.clone();
    let say = sayer(&lines);
    let carrier =
        |hosts: Vec<Arc<dyn Host>>| Arc::new(Carrier::new(keys(), hosts, shared.clone(), gate.clone(), say.clone()));
    let (client, node) = (carrier(hosts.clone()), carrier(hosts));
    Ends { client, node, board, lines }
}

/// Write `bytes` in four parts a minute apart, end the way, and read the
/// other way to its end.
async fn exchange(link: &mut link::Link, bytes: &[u8]) -> Vec<u8> {
    for part in bytes.chunks(bytes.len().div_ceil(4)) {
        link.write_all(part).await.unwrap();
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
    link.shutdown().await.unwrap();
    let mut got = Vec::new();
    link.read_to_end(&mut got).await.unwrap();
    got
}

async fn linked(ends: &Ends) -> (link::Link, link::Link) {
    let accepting = tokio::spawn(link::accept(ends.node.clone()));
    let client = link::dial(ends.client.clone()).await.unwrap();
    let node = accepting.await.unwrap().unwrap();
    assert_eq!(client.id, node.id, "the node took the client's link");
    (client, node)
}

#[tokio::test(start_paused = true)]
async fn a_client_and_a_node_move_256_kib_each_way_one_request_at_a_time_and_leave_nothing() {
    let counter = Counter::default();
    let host = Arc::new(StandInHost::new("files.stand-in.test", Some(200), counter.clone()));
    let ends = ends(vec![host.clone()], &counter);
    let (mut client, mut node) = linked(&ends).await;
    let (up, down) = (pattern(256 * 1024, 1), pattern(256 * 1024, 2));
    let (at_node, at_client) = tokio::join!(exchange(&mut node, &down), exchange(&mut client, &up));
    assert_eq!(digest(&at_node), digest(&up), "the up way");
    assert_eq!(digest(&at_client), digest(&down), "the down way");
    assert_eq!(counter.most(), 1, "never two requests of the road at once");
    assert!(host.uploads() >= 4, "the parts a minute apart went in pieces: {}", host.uploads());
    assert!(host.kept().is_empty(), "each piece deleted once read");
    assert_eq!(host.deleted().len(), host.uploads());
    assert!(ends.board.kept().is_empty(), "each note and the hello cleared");
    let lines = ends.lines.lock().unwrap().clone();
    let told = lines.iter().filter(|l| l.contains("files.stand-in.test") && l.contains("nobody vouches for"));
    assert_eq!(told.count(), 2, "each end says the line once, before its first upload: {lines:?}");
}

#[tokio::test(start_paused = true)]
async fn a_host_and_a_board_keep_ciphertext_alone() {
    let counter = Counter::default();
    let host = Arc::new(StandInHost::new("files.stand-in.test", None, counter.clone()).never_deletes());
    let ends = ends(vec![host.clone()], &counter);
    let piece = pattern(64 * 1024, 3);
    let board_before = ends.board.puts();
    ends.client.send(Way::Up, &LINK, 0, &piece).await.unwrap();
    assert_eq!(ends.board.puts(), board_before + 1, "one note");
    let kept = host.kept();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].len(), piece.len() + OVERHEAD, "a seal of the piece");
    assert!(!kept[0].windows(64).any(|w| w == &piece[..64]), "no plaintext on the host");
    for (topic, note) in ends.board.kept() {
        assert!(topic.starts_with("pf") && !topic.contains("relay"), "{topic}");
        let text = String::from_utf8_lossy(&note);
        assert!(!text.contains("https://") && !text.contains("stand-in"), "no URL in clear on the board");
    }
    let got = ends.node.receive(Way::Up, &LINK, 0, Duration::from_secs(60)).await.unwrap();
    assert_eq!(digest(&got), digest(&piece));
    assert_eq!(host.kept().len(), 1, "a host that deletes nothing keeps it for its shortest life");
    assert!(ends.board.kept().is_empty(), "the note cleared once read");
}

#[tokio::test(start_paused = true)]
async fn a_busy_host_rests_and_the_next_host_serves_the_next_piece() {
    let counter = Counter::default();
    let busy = Arc::new(StandInHost::new("busy.stand-in.test", None, counter.clone()).busy_from(1));
    let next = Arc::new(StandInHost::new("next.stand-in.test", None, counter.clone()));
    let ends = ends(vec![busy.clone(), next.clone()], &counter);
    let pieces: Vec<Vec<u8>> = (0..3).map(|n| pattern(1024, 10 + n)).collect();
    for (n, piece) in pieces.iter().enumerate() {
        ends.client.send(Way::Up, &LINK, n as u64, piece).await.unwrap();
    }
    assert_eq!((busy.uploads(), next.uploads()), (1, 2), "the first piece on the first host, then the next");
    for (n, piece) in pieces.iter().enumerate() {
        let got = ends.node.receive(Way::Up, &LINK, n as u64, Duration::from_secs(60)).await.unwrap();
        assert_eq!(&got, piece, "piece {n}");
    }
    let lines = ends.lines.lock().unwrap().clone();
    assert!(lines.iter().any(|l| l.contains("busy.stand-in.test is busy")), "{lines:?}");
    assert!(lines.iter().any(|l| l.contains("next.stand-in.test") && l.contains("Q78")), "the next host's line");
}

#[tokio::test(start_paused = true)]
async fn a_strangers_note_or_one_of_another_host_is_passed_over_and_a_changed_piece_ends_the_read() {
    let counter = Counter::default();
    let host = Arc::new(StandInHost::new("files.stand-in.test", None, counter.clone()));
    let ends = ends(vec![host.clone()], &counter);
    let topic = keys().topic(Way::Up, &LINK, 0);
    ends.board.plant(&topic, b"a stranger's bytes");
    let short = ends.node.receive(Way::Up, &LINK, 0, Duration::from_secs(10)).await.unwrap_err();
    assert!(short.contains("no piece 0"), "{short}");
    // A note under the pair's key that names a host of no list is not
    // fetched.
    let note = br#"{"h":"elsewhere.test","u":"https://elsewhere.test/1/piece.bin","t":null}"#;
    let sealed = keys().seal(Kind::Note, Way::Up, &LINK, 0, note, &mut OsEntropy).unwrap();
    ends.board.plant(&topic, &sealed);
    assert!(ends.node.receive(Way::Up, &LINK, 0, Duration::from_secs(10)).await.is_err());
    // The right note comes after them, and is read.
    ends.client.send(Way::Up, &LINK, 0, b"piece zero").await.unwrap();
    assert_eq!(ends.node.receive(Way::Up, &LINK, 0, Duration::from_secs(10)).await.unwrap(), b"piece zero");
    // A host that changes a byte is caught.
    ends.client.send(Way::Up, &LINK, 1, b"piece one").await.unwrap();
    host.spoil();
    let spoiled = ends.node.receive(Way::Up, &LINK, 1, Duration::from_secs(10)).await.unwrap_err();
    assert!(spoiled.contains("does not open"), "{spoiled}");
}

#[tokio::test(start_paused = true)]
async fn a_hello_played_back_opens_no_second_link() {
    let counter = Counter::default();
    let host: Arc<dyn Host> = Arc::new(StandInHost::new("files.stand-in.test", None, counter.clone()));
    let ends = ends(vec![host], &counter);
    ends.client.knock(&LINK).await.unwrap();
    let hello = ends.board.kept();
    assert_eq!(hello.len(), 1, "the hello waits at the door");
    assert_eq!(ends.node.answer(Duration::from_secs(10)).await.unwrap(), LINK);
    assert!(ends.board.kept().is_empty(), "the door cleared");
    let (door, bytes) = &hello[0];
    ends.board.plant(door, bytes);
    assert!(ends.node.answer(Duration::from_secs(10)).await.is_err(), "a hello already taken");
    let stranger = Keys::from_bytes([1; 32]);
    let theirs = stranger.seal(Kind::Hello, Way::Up, &LinkId([0; 16]), 0, &[9; 16], &mut OsEntropy).unwrap();
    ends.board.plant(door, &theirs);
    assert!(ends.node.answer(Duration::from_secs(10)).await.is_err(), "a hello of another key");
}
