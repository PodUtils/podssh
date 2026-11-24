//! T-862's measure of the writer lease of a shared shell, not a check of
//! the gate: two scripted typists log in under the `rw-` name of one shell
//! under `cat` (no echo, no line buffer, so the shell's output is the pty's
//! input in the order the lease let it in) and type words with human gaps,
//! from a fixed seed, for each idle span of the lease. It counts the words
//! that the other typist's bytes broke, and each wait of a held writer.
//!
//! ```sh
//! cargo test -p podssh-ssh --test share_lease_measure -- --ignored --nocapture
//! ```
//!
//! `PODSSH_MEASURE_SECS` sets the typing of each span (default 60 s).

#![cfg(unix)]

mod share_harness;

use std::time::Duration;

use podssh_ssh::server::share_measure;
use share_harness::{have_pty, key, owner, Seat, Server};
use tokio::time::Instant;

/// The spans of the entry, and two past the longest gap between keys
/// (400 ms), for the margin of the choice.
const SPANS_MS: [u64; 6] = [100, 200, 400, 500, 600, 800];

/// A small seeded generator (xorshift64*): a run is the same each time.
struct Dice(u64);

impl Dice {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A number in `lo..=hi`.
    fn within(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
}

/// One step of a typist's script: wait, then send one byte.
type Script = Vec<(Duration, u8)>;

/// A typist's script of `secs` seconds: words of 3 to 8 letters of
/// `letters`, each ended by `end`; 100 to 400 ms between keys, 400 to
/// 1500 ms between words, and a pause of 2 to 4 s before one word in eight.
fn script(seed: u64, letters: &[u8], end: u8, secs: u64) -> Script {
    let mut dice = Dice(seed);
    let mut steps = Script::new();
    let mut spent = Duration::ZERO;
    while spent < Duration::from_secs(secs) {
        let mut gap = Duration::from_millis(dice.within(400, 1500));
        if dice.within(0, 7) == 0 {
            gap = Duration::from_millis(dice.within(2000, 4000));
        }
        let len = dice.within(3, 8);
        for i in 0..=len {
            let key = if i == len { end } else { letters[dice.within(0, letters.len() as u64 - 1) as usize] };
            let wait = if i == 0 { gap } else { Duration::from_millis(dice.within(100, 400)) };
            spent += wait;
            steps.push((wait, key));
        }
    }
    steps
}

/// Words of a typist (letters of `mine`, ended by `end`) that a byte of the
/// other typist broke, in the order that the pty took the bytes; and the
/// words.
fn broken(taken: &[u8], mine: impl Fn(u8) -> bool, end: u8) -> (usize, usize) {
    let (mut inside, mut hit, mut broken, mut words) = (false, false, 0, 0);
    for &b in taken {
        if b == end {
            words += 1;
            broken += usize::from(hit);
            (inside, hit) = (false, false);
        } else if mine(b) {
            inside = true;
        } else if inside && (b.is_ascii_alphabetic() || b == b'.' || b == b',') {
            hit = true;
        }
    }
    (broken, words)
}

/// Run each script against one shell with the lease's span `idle`.
async fn one_span(idle: Duration, secs: u64) -> String {
    let server = Server::new(true);
    let (owner, write, _) = owner(&server).await;
    owner.send(b"stty -echo -icanon min 1 time 0; echo GO_$((1+2)); exec cat\r").await;
    owner.reads("GO_3").await;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let mark = owner.seen.lock().unwrap().out.len();
    let a = Seat::shell(server.login(&write, &key()).await.expect("a writer"), 80, 24).await;
    let b = Seat::shell(server.login(&write, &key()).await.expect("a second writer"), 80, 24).await;
    let scripts = [
        script(0x5eed_0001, b"abcdefghijklmnopqrstuvwxyz", b'.', secs),
        script(0x5eed_0002, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b',', secs),
    ];
    let sent: usize = scripts.iter().map(Vec::len).sum();
    share_measure::measure(Some(idle));
    let started = Instant::now();
    let mut typing = Vec::new();
    for (seat, steps) in [a, b].into_iter().zip(scripts) {
        typing.push(tokio::spawn(async move {
            let mut at = Instant::now();
            for (wait, key) in steps {
                at += wait;
                tokio::time::sleep_until(at).await;
                seat.send(&[key]).await;
            }
            seat
        }));
    }
    let mut seats = Vec::new();
    for task in typing {
        seats.push(task.await.expect("a typist"));
    }
    let typed = started.elapsed();
    let done = |seen: &share_harness::Seen| {
        seen.out[mark..].iter().filter(|b| b.is_ascii_alphabetic() || **b == b'.' || **b == b',').count() >= sent
    };
    owner.until("each byte through cat", done).await;
    let waits = share_measure::take_waits();
    share_measure::measure(None);
    let taken: Vec<u8> = owner.seen.lock().unwrap().out[mark..].to_vec();
    let (broken_a, words_a) = broken(&taken, |b| b.is_ascii_lowercase(), b'.');
    let (broken_b, words_b) = broken(&taken, |b| b.is_ascii_uppercase(), b',');
    let total: Duration = waits.iter().sum();
    let mut sorted = waits.clone();
    sorted.sort();
    let pick = |q: usize| sorted.get((sorted.len() * q / 100).min(sorted.len().saturating_sub(1))).copied();
    let ms = |d: Option<Duration>| d.map_or(0, |d| d.as_millis());
    drop(seats);
    format!(
        "| {:>4} ms | {:>5.1} s | {:>3} + {:<3} | {:>2} + {:<2} | {:>4} | {:>6.1} s | {:>4} ms | {:>4} ms | {:>4} ms |",
        idle.as_millis(),
        typed.as_secs_f64(),
        words_a,
        words_b,
        broken_a,
        broken_b,
        waits.len(),
        total.as_secs_f64(),
        ms(pick(50)),
        ms(pick(95)),
        ms(sorted.last().copied()),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measure of about eight minutes (T-862): run with --ignored --nocapture"]
async fn the_writer_lease_with_two_people_typing() {
    if !have_pty() {
        return;
    }
    let secs = std::env::var("PODSSH_MEASURE_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(60);
    let mut rows = Vec::new();
    for span in SPANS_MS {
        let row = one_span(Duration::from_millis(span), secs).await;
        eprintln!("{row}");
        rows.push(row);
    }
    println!("| Lease | Typed | Words (a + b) | Broken (a + b) | Waits | Waited | Median | 95th | Longest |");
    println!("| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    for row in rows {
        println!("{row}");
    }
}
