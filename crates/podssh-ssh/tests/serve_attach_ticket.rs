//! Who may join a kept shell, and replay or reset (T-833), with russh's
//! client over pipes in memory: the ticket of a kept shell is its key and
//! its name, so another key and a wrong name are refused alike; a client
//! that gives the offset that it has (`count@podssh`) gets the output from
//! there; one whose offset the ring no longer holds, or that asks for a
//! reset (`reset@podssh`), gets a line that says so and the last output
//! from a clean boundary, never more than the ring; the client's count from
//! that line's offset is the far end's (T-895). One attach at a time is
//! `kept.rs`'s unit test; a later one that takes the shell is
//! `serve_keep.rs`'s. Each case needs a pty; a host with none says so.

#![cfg(unix)]

mod kept_harness;
mod share_harness;

use std::time::Duration;

use kept_harness::{detach, list, server, shell_with};
use podssh_ssh::keep_count::{listed_offset, Counter};
use podssh_ssh::server::RING;
use share_harness::{have_pty, key};

/// The offset of a detached shell in the list of `shells@podssh`.
fn offset_of(lines: &str, name: &str) -> u64 {
    let line = lines.lines().find(|l| l.starts_with(&format!("{name} detached "))).expect("the shell's line");
    line.rsplit(' ').next().and_then(|n| n.parse().ok()).expect("an offset")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_ticket_is_the_key_and_the_name() {
    if !have_pty() {
        return;
    }
    let (owner, other) = (key(), key());
    let server = server(Duration::from_secs(600), &[&owner, &other]);
    let seat = shell_with(&server, &owner, &[]).await;
    assert!(detach(&seat, "work").await);
    let cases = [(&other, "work", "no kept shell named work"), (&owner, "play", "no kept shell named play")];
    for (login, name, words) in cases {
        let refused = shell_with(&server, login, &[("attach@podssh", name)]).await;
        refused.until("the refusal's end", |seen| seen.closed).await;
        let seen = refused.seen.lock().unwrap();
        assert_eq!(seen.status, Some(1), "{words}: {seen:?}");
        assert!(String::from_utf8_lossy(&seen.err).contains(words), "{words}: {seen:?}");
    }
    let back = shell_with(&server, &owner, &[("attach@podssh", "work")]).await;
    back.send(b"exit 0\r").await;
    back.until("the shell's end", |seen| seen.closed).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_count_in_the_ring_replays_from_there() {
    if !have_pty() {
        return;
    }
    let owner = key();
    let server = server(Duration::from_secs(600), &[&owner]);
    let seat = shell_with(&server, &owner, &[]).await;
    seat.send(b"echo MARK_$((7*7))_END\r").await;
    seat.reads("MARK_49_END").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(detach(&seat, "work").await);
    seat.until("the channel's close", |seen| seen.closed).await;
    // The client's count: each byte that it got; the mark's place in them.
    let out = seat.seen.lock().unwrap().out.clone();
    let mark = out.windows(11).rposition(|w| w == b"MARK_49_END").expect("the mark") as u64;
    let detached = offset_of(&list(&server, &owner).await, "work");
    assert!(detached >= out.len() as u64, "the detach's offset {detached} counts each byte sent");

    let count = mark.to_string();
    let back = shell_with(&server, &owner, &[("count@podssh", count.as_str()), ("attach@podssh", "work")]).await;
    back.reads("MARK_49_END").await;
    {
        let seen = back.seen.lock().unwrap();
        assert!(seen.out.starts_with(b"MARK_49_END"), "the replay starts at the count: {seen:?}");
        assert!(!String::from_utf8_lossy(&seen.err).contains("reset"), "no reset: {seen:?}");
    }
    back.send(b"exit 0\r").await;
    back.until("the shell's end", |seen| seen.closed).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_count_older_than_the_ring_or_a_reset_asked_gives_the_last_output() {
    if !have_pty() {
        return;
    }
    let owner = key();
    let server = server(Duration::from_secs(600), &[&owner]);
    let seat = shell_with(&server, &owner, &[]).await;
    assert!(detach(&seat, "work").await);
    // A client makes the shell write more than the ring holds.
    let busy = shell_with(&server, &owner, &[("attach@podssh", "work")]).await;
    busy.send(b"yes ABCDEFGHIJKLMNOPQRSTUVWXYZ | head -n 20000; echo FILLED_$((8*8))_END\r").await;
    busy.reads("FILLED_64_END").await;
    assert!(detach(&busy, "work").await);

    for first in [("count@podssh", "0"), ("reset@podssh", "yes")] {
        let asks = [first, ("attach@podssh", "work")];
        let back = shell_with(&server, &owner, &asks).await;
        back.until("the reset's line", |seen| String::from_utf8_lossy(&seen.err).contains("a reset")).await;
        back.reads("FILLED_64_END").await;
        // The ring, and room for a prompt that comes after it.
        let got = back.seen.lock().unwrap().out.len();
        assert!(got <= RING + 1024, "{asks:?}: about the ring at most: {got} bytes");
        // The client's count (T-895): the reset's offset on stderr and each
        // byte since, which is where the output stands once the shell is
        // quiet.
        back.send(b"echo QUIET_$((5*5))_END\r").await;
        back.reads("QUIET_25_END").await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let counted = {
            let seen = back.seen.lock().unwrap();
            let counter = Counter::starting(None);
            counter.stderr(&seen.err);
            counter.data(seen.out.len());
            counter.at()
        };
        let listed = listed_offset(&list(&server, &owner).await, "work");
        assert!(counted.is_some(), "{asks:?}: the reset's line gives its offset");
        assert_eq!(counted, listed, "{asks:?}: the client's count is the far end's offset");
        assert!(detach(&back, "work").await, "{asks:?}");
    }
    let last = shell_with(&server, &owner, &[("attach@podssh", "work")]).await;
    last.send(b"exit 0\r").await;
    last.until("the shell's end", |seen| seen.closed).await;
}
