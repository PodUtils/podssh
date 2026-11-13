//! The carrier of one pair: a piece goes up as one sealed upload to a host,
//! and its note (the host, the URL, the delete token), sealed, goes to the
//! board under the piece's topic; the far end polls the topic, fetches the
//! piece, opens it, deletes it where the host lets it, and clears the topic.
//! Each request is made under the road's gate, one at a time, and each
//! upload at its host's pace ([`super::pace`]).
//!
//! A note opens only under the pair's key, at its own topic, so a stranger
//! on a public board can neither read one nor plant one that is taken; a
//! note names a host by its id, and the reader fetches only from a host of
//! its own list, at a URL that the host serves.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::time::Instant;

use super::board::Board;
use super::host::{Host, Refusal, Stored};
use super::keys::{Keys, Kind, LinkId, Way, OVERHEAD};
use super::pace::{Gate, Hosts, REST};
use super::{third_party_line, Say, PIECE_MOST};
use crate::session::OsEntropy;

/// The first pause between two polls of a topic, and the longest: the poll
/// slows while nothing comes, so that an idle link asks the board little.
pub const POLL_FIRST: Duration = Duration::from_secs(2);
pub const POLL_MOST: Duration = Duration::from_secs(15);
/// The longest pause between two polls of a node's door: a node waits there
/// for as long as it runs, so its idle polls are what the road asks of a
/// public board most, and a client's first link waits this long at worst.
pub const DOOR_POLL_MOST: Duration = Duration::from_secs(60);
/// How many times a note is put again when the board fails.
const PUT_TRIES: u32 = 3;
/// How many times a piece whose note was read is fetched again: a host may
/// serve an upload a moment after its answer.
const FETCH_TRIES: u32 = 3;

/// The road of one pair over its hosts and its board.
pub struct Carrier {
    keys: Arc<Keys>,
    board: Arc<dyn Board>,
    hosts: Mutex<Hosts>,
    gate: Gate,
    say: Say,
    /// The hosts whose line was said.
    told: Mutex<HashSet<String>>,
    /// The links that a hello opened: a hello played back opens none.
    seen: Mutex<HashSet<LinkId>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Carrier {
    /// The carrier of `keys`' pair over `hosts`, in order, and `board`. Its
    /// gate is its own, or one that more carriers of a process share.
    pub fn new(keys: Arc<Keys>, hosts: Vec<Arc<dyn Host>>, board: Arc<dyn Board>, gate: Gate, say: Say) -> Carrier {
        Carrier {
            keys,
            board,
            hosts: Mutex::new(Hosts::new(hosts, Instant::now())),
            gate,
            say,
            told: Mutex::new(HashSet::new()),
            seen: Mutex::new(HashSet::new()),
        }
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// Wait until a host may take an upload of `size` bytes; at once when
    /// none takes it, as [`Carrier::send`] then says why.
    pub async fn ready(&self, size: usize) {
        let when = lock(&self.hosts).pick(size + OVERHEAD, Instant::now());
        if let Some((_, when)) = when {
            tokio::time::sleep_until(when).await;
        }
    }

    /// Piece `n` of `way` of `link`: sealed, uploaded to the first host that
    /// takes it, and its note put on the board.
    pub async fn send(&self, way: Way, link: &LinkId, n: u64, piece: &[u8]) -> Result<(), String> {
        if piece.len() > PIECE_MOST {
            return Err(format!("a piece of {} bytes is over {PIECE_MOST}", piece.len()));
        }
        let sealed = self.keys.seal(Kind::Piece, way, link, n, piece, &mut OsEntropy).map_err(|e| e.to_string())?;
        let (host, stored) = self.upload(sealed).await?;
        let note = json!({ "h": host.name(), "u": stored.url, "t": stored.token }).to_string();
        let note = self.keys.seal(Kind::Note, way, link, n, note.as_bytes(), &mut OsEntropy);
        let note = note.map_err(|e| e.to_string())?;
        let (most, board) = (self.board.most(), self.board.name());
        if note.len() > most {
            return Err(format!("a note of {} bytes is over the {most} of {board}", note.len()));
        }
        let topic = self.keys.topic(way, link, n);
        let mut tries = 0;
        loop {
            let put = {
                let _one = self.gate.hold().await;
                self.board.put(&topic, note.clone()).await
            };
            match put {
                Ok(()) => return Ok(()),
                Err(why) if tries + 1 >= PUT_TRIES => return Err(format!("{}: {why}", self.board.name())),
                Err(_) => {
                    tries += 1;
                    tokio::time::sleep(POLL_FIRST).await;
                }
            }
        }
    }

    /// `sealed` on the first host, in order, that takes it: a host that
    /// refuses rests, and the next one is tried, each at its pace.
    async fn upload(&self, sealed: Vec<u8>) -> Result<(Arc<dyn Host>, Stored), String> {
        let tries = lock(&self.hosts).len() * 2;
        let mut missed = Vec::new();
        for _ in 0..tries {
            let picked = lock(&self.hosts).pick(sealed.len(), Instant::now());
            let Some((i, when)) = picked else {
                return Err(format!("no file host takes a piece of {} bytes", sealed.len()));
            };
            tokio::time::sleep_until(when).await;
            let Some(host) = lock(&self.hosts).host(i) else { break };
            self.tell(host.as_ref());
            let answer = {
                let _one = self.gate.hold().await;
                host.upload(sealed.clone()).await
            };
            let now = Instant::now();
            match answer {
                Ok(stored) if host.owns(&stored.url) => {
                    lock(&self.hosts).sent(i, now);
                    return Ok((host, stored));
                }
                Ok(_) => {
                    missed.push(format!("{}: an answer that names a URL of another host", host.name()));
                    lock(&self.hosts).refused(i, now, REST);
                }
                Err(Refusal::Busy(wait)) => {
                    (self.say)(format!("{} is busy; the next file host takes the piece", host.name()));
                    missed.push(format!("{}: {}", host.name(), Refusal::Busy(wait)));
                    lock(&self.hosts).refused(i, now, wait.unwrap_or(REST));
                }
                Err(Refusal::Failed(why)) => {
                    missed.push(format!("{}: {why}", host.name()));
                    lock(&self.hosts).refused(i, now, REST);
                }
            }
        }
        Err(format!("no file host took the piece: {}", missed.join("; ")))
    }

    /// The third party's line, once for each host, before its first upload.
    fn tell(&self, host: &dyn Host) {
        if lock(&self.told).insert(host.name().to_string()) {
            (self.say)(third_party_line(host.name(), host.one_person()));
        }
    }

    /// Piece `n` of `way` of `link`, polled for within `wait`: fetched,
    /// opened, deleted where its host lets the reader, and its topic cleared.
    pub async fn receive(&self, way: Way, link: &LinkId, n: u64, wait: Duration) -> Result<Vec<u8>, String> {
        let topic = self.keys.topic(way, link, n);
        let deadline = Instant::now() + wait;
        let mut pause = POLL_FIRST;
        loop {
            let taken = {
                let _one = self.gate.hold().await;
                self.board.take(&topic).await
            };
            // A board that failed once is asked again at the next poll.
            if let Ok(Some(sealed)) = taken {
                if let Some(piece) = self.read_note(way, link, n, &sealed).await? {
                    let _one = self.gate.hold().await;
                    let _ = self.board.clear(&topic).await;
                    return Ok(piece);
                }
            }
            if Instant::now() >= deadline {
                return Err(format!("no piece {n} within {} s", wait.as_secs()));
            }
            tokio::time::sleep(pause.min(deadline.saturating_duration_since(Instant::now()))).await;
            pause = (pause * 2).min(POLL_MOST);
        }
    }

    /// The piece of a note: `None` for a note that does not open (a
    /// stranger's, or one of another place) or names no host of this list,
    /// as the right one may come after it; an error for a piece that was
    /// fetched and does not open, as a host changed it.
    async fn read_note(&self, way: Way, link: &LinkId, n: u64, sealed: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let Some(note) = self.keys.open(Kind::Note, way, link, n, sealed) else { return Ok(None) };
        let Some((name, stored)) = parse_note(&note) else { return Ok(None) };
        let Some(host) = lock(&self.hosts).named(&name) else { return Ok(None) };
        if !host.owns(&stored.url) {
            return Ok(None);
        }
        let mut tries = 0;
        let bytes = loop {
            let fetched = {
                let _one = self.gate.hold().await;
                host.fetch(&stored.url, PIECE_MOST + OVERHEAD).await
            };
            match fetched {
                Ok(bytes) => break bytes,
                Err(why) if tries + 1 >= FETCH_TRIES => return Err(format!("{}: piece {n}: {why}", host.name())),
                Err(_) => {
                    tries += 1;
                    tokio::time::sleep(POLL_FIRST).await;
                }
            }
        };
        let Some(piece) = self.keys.open(Kind::Piece, way, link, n, &bytes) else {
            return Err(format!("{}: piece {n} does not open: the host changed it", host.name()));
        };
        // The host keeps nothing once read where it lets the reader delete;
        // a delete that fails leaves the piece to its shortest life.
        if stored.token.is_some() {
            let _one = self.gate.hold().await;
            let _ = host.delete(&stored).await;
        }
        Ok(Some(piece))
    }

    /// Put a client's hello for `link` at the node's door.
    pub async fn knock(&self, link: &LinkId) -> Result<(), String> {
        let hello = self.keys.seal(Kind::Hello, Way::Up, &DOOR_LINK, 0, &link.0, &mut OsEntropy);
        let hello = hello.map_err(|e| e.to_string())?;
        let _one = self.gate.hold().await;
        self.board.put(&self.keys.door(), hello).await.map_err(|why| format!("{}: {why}", self.board.name()))
    }

    /// The link of the next client's hello at the door, within `wait`; a
    /// hello of another key, or one already taken, opens none.
    pub async fn answer(&self, wait: Duration) -> Result<LinkId, String> {
        let door = self.keys.door();
        let deadline = Instant::now() + wait;
        let mut pause = POLL_FIRST;
        loop {
            let taken = {
                let _one = self.gate.hold().await;
                self.board.take(&door).await
            };
            let opened = taken.ok().flatten().and_then(|h| self.keys.open(Kind::Hello, Way::Up, &DOOR_LINK, 0, &h));
            if let Some(id) = opened.and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok()) {
                let link = LinkId(id);
                // The lock ends here, before the awaits of the clear.
                let fresh = lock(&self.seen).insert(link);
                if fresh {
                    let _one = self.gate.hold().await;
                    let _ = self.board.clear(&door).await;
                    return Ok(link);
                }
            }
            if Instant::now() >= deadline {
                return Err(format!("no client's hello within {} s", wait.as_secs()));
            }
            tokio::time::sleep(pause.min(deadline.saturating_duration_since(Instant::now()))).await;
            pause = (pause * 2).min(DOOR_POLL_MOST);
        }
    }
}

/// The place of a hello's seal: the door belongs to no link.
const DOOR_LINK: LinkId = LinkId([0; 16]);

/// The host's id, the URL and the token of a note.
fn parse_note(note: &[u8]) -> Option<(String, Stored)> {
    let value: Value = serde_json::from_slice(note).ok()?;
    let name = value.get("h")?.as_str()?.to_string();
    let url = value.get("u")?.as_str()?.to_string();
    let token = value.get("t").and_then(Value::as_str).map(str::to_string);
    Some((name, Stored { url, token }))
}
