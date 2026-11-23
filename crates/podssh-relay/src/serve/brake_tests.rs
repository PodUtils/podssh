//! The brake of T-454: a sliding minute for each address, its bound, the
//! paths that it counts, and the role's `429` as podssh's own client reads
//! it, on a clock that the test sets.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use podssh_ws::http::{exchange, Response};

use super::super::tokens::Tokens;
use super::super::{serve_from, Config, Events, Mint};
use super::*;

/// A clock that the test sets, and the brake's reading of it.
fn set_clock() -> (Arc<AtomicU64>, Clock) {
    let now = Arc::new(AtomicU64::new(0));
    let read = now.clone();
    let clock: Clock = Arc::new(move || read.load(Ordering::SeqCst));
    (now, clock)
}

fn ip(text: &str) -> Who {
    Who::of(Some(text.parse().unwrap()))
}

#[test]
fn the_121st_request_of_an_address_waits_until_its_oldest_is_a_minute_old() {
    let brake = Brake::new(PER_MINUTE, WINDOW_MS, ADDRESSES, monotonic());
    let a = ip("192.0.2.1");
    for i in 0..120u64 {
        assert_eq!(brake.take_at(a, i * 100), Ok(()), "request {i}");
    }
    // The oldest, at 0, leaves the minute at 60 000: 48 s after 12 000.
    assert_eq!(brake.take_at(a, 12_000), Err(Braked { wait_s: 48, first: true }));
    assert_eq!(brake.take_at(a, 59_001), Err(Braked { wait_s: 1, first: false }), "not counted, not said again");
    assert_eq!(brake.take_at(ip("198.51.100.7"), 12_000), Ok(()), "another address");
    assert_eq!(brake.take_at(a, 60_000), Ok(()), "the oldest left the minute");
    // A sliding minute, not one that starts again: the next oldest is at 100.
    assert_eq!(brake.take_at(a, 60_000), Err(Braked { wait_s: 1, first: true }));
    assert_eq!(brake.take_at(a, 60_100), Ok(()));
}

#[test]
fn an_ipv6_address_counts_by_its_64_and_a_mapped_ipv4_one_as_its_ipv4() {
    assert_eq!(ip("2001:db8:1:2::1"), ip("2001:db8:1:2:ffff::9"), "one /64");
    assert_ne!(ip("2001:db8:1:2::1"), ip("2001:db8:1:3::1"));
    assert_eq!(ip("::ffff:192.0.2.1"), ip("192.0.2.1"));
    assert_eq!(Who::of(None), Who::Unknown);
    let brake = Brake::new(2, WINDOW_MS, ADDRESSES, monotonic());
    assert!(brake.take_at(ip("2001:db8:1:2::1"), 0).is_ok());
    assert!(brake.take_at(ip("2001:db8:1:2::2"), 0).is_ok());
    assert!(brake.take_at(ip("2001:db8:1:2::3"), 0).is_err(), "a third address of the same /64");
    assert!(brake.take_at(Who::Unknown, 0).is_ok() && brake.take_at(Who::Unknown, 0).is_ok());
    assert!(brake.take_at(Who::Unknown, 0).is_err(), "the requests with no address share one count");
}

#[test]
fn the_counts_keep_so_many_addresses_and_forget_the_least_lately_heard_first() {
    let brake = Brake::new(1, WINDOW_MS, 3, monotonic());
    let (a, b, c, d) = (ip("192.0.2.1"), ip("192.0.2.2"), ip("192.0.2.3"), ip("192.0.2.4"));
    for (who, at) in [(a, 0), (b, 10), (c, 20)] {
        assert!(brake.take_at(who, at).is_ok());
    }
    // A refusal does not count: a was last let through at 0.
    assert!(brake.take_at(a, 30).is_err());
    assert!(brake.take_at(d, 40).is_ok(), "a fourth address takes the place of the least lately heard");
    assert_eq!(brake.len(), 3, "the bound");
    assert!(brake.take_at(a, 50).is_ok(), "a was forgotten, and counts again from nothing, in the place of b");
    assert!(brake.take_at(d, 60).is_err(), "d is still counted");
    assert!(brake.take_at(c, 60).is_err(), "and c");
    // Past the minute of each, the counts that hold nothing go at once.
    assert!(brake.take_at(b, 200_000).is_ok());
    assert_eq!(brake.len(), 1);
}

#[test]
fn the_paths_braked_and_the_visitor_that_the_edge_names() {
    assert!(braked("POST", "/v1/mint") && braked("POST", "/v1/pair") && braked("GET", "/v1/pair"));
    let unbraked = [
        ("GET", "/v1/mint"),
        ("GET", "/health"),
        ("GET", "/relays.json"),
        ("GET", "/connect/github.com/22"),
        ("GET", "/v1/node/p-a"),
        ("GET", "/v1/connect/p-a"),
        ("POST", "/v1/stop/p-a"),
    ];
    for (method, path) in unbraked {
        assert!(!braked(method, path), "{method} {path}");
    }
    assert_eq!(edge_visitor(Some(" 203.0.113.9 ")), Some("203.0.113.9".parse().unwrap()));
    assert_eq!(edge_visitor(Some("2001:db8::1")), Some("2001:db8::1".parse().unwrap()));
    assert_eq!(edge_visitor(Some("203.0.113.9, 10.0.0.1")), None, "one address, never a list");
    assert_eq!(edge_visitor(None), None);
    let clock = monotonic();
    let first = clock();
    assert!(clock() >= first, "the role's clock does not go back");
}

/// The role on the clock `clock`, minting for anyone, and the lines it said.
fn role(clock: Clock) -> (Arc<Config>, Arc<Mutex<Vec<String>>>) {
    let said = Arc::new(Mutex::new(Vec::new()));
    let lines = said.clone();
    let say: Events = Box::new(move |line: &str| lines.lock().unwrap().push(line.to_string()));
    let cfg = Config {
        version: "test".into(),
        mint: Mint::Anyone,
        tokens: Tokens::new([6; 32]),
        policy: Default::default(),
        egress: Default::default(),
        limits: Default::default(),
        pairs: Default::default(),
        resumes: Default::default(),
        answered: Default::default(),
        brake: Brake::new(PER_MINUTE, WINDOW_MS, ADDRESSES, clock),
        usage: Default::default(),
        cover: None,
        events: Some(say),
    };
    (Arc::new(cfg), said)
}

/// One request of a client at `from` to the role, sent and read by podssh's
/// own client of HTTP/1.1: the answer as podssh reads it.
async fn ask(cfg: &Arc<Config>, method: &str, path: &str, from: &str) -> Response {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let from: IpAddr = from.parse().unwrap();
    let body = if method == "POST" { b"{}".as_slice() } else { b"".as_slice() };
    let (_, answer) = tokio::join!(
        serve_from(server, cfg.clone(), None, Some(from)),
        exchange(&mut client, method, "relay-a.test", path, &[], body, 16 * 1024),
    );
    answer.expect("an answer")
}

#[tokio::test]
async fn a_mint_past_120_of_an_address_in_a_minute_is_a_429_until_the_minute_passes() {
    let (now, clock) = set_clock();
    let (cfg, said) = role(clock);
    let a = "192.0.2.1";
    for i in 0..PER_MINUTE {
        let minted = ask(&cfg, "POST", "/v1/mint", a).await;
        assert_eq!(minted.status, 200, "mint {i}: {}", minted.body_text(200));
    }
    let braked = ask(&cfg, "POST", "/v1/mint", a).await;
    assert_eq!(braked.status, 429, "{}", braked.body_text(200));
    // podssh's client says "the relay is rate-limiting token minting; retry
    // in 60 s" from this header (`crate::token`).
    assert_eq!(braked.header_text("retry-after", 64).as_deref(), Some("60"));
    assert_eq!(ask(&cfg, "POST", "/v1/mint", "198.51.100.7").await.status, 200, "another address");
    // A pair shares the count of the mints, as on the default relay.
    let pair = ask(&cfg, "POST", "/v1/pair", a).await;
    assert_eq!((pair.status, pair.header_text("retry-after", 64).as_deref()), (429, Some("60")));
    // /health is not braked; an upgrade of an address whose minute is full
    // waits before its token is read (T-806).
    assert_eq!(ask(&cfg, "GET", "/health", a).await.status, 200);
    let connect = ask(&cfg, "GET", "/connect/github.com/22", a).await;
    assert_eq!(connect.status, 429, "{}", connect.body_text(200));
    let lines = said.lock().unwrap().iter().filter(|line| line.contains("braked")).count();
    assert_eq!(lines, 1, "one line for the address, not one for each request");
    now.store(WINDOW_MS, Ordering::SeqCst);
    assert_eq!(ask(&cfg, "POST", "/v1/mint", a).await.status, 200, "the first after the minute");
    assert_eq!(ask(&cfg, "POST", "/v1/pair", a).await.status, 200, "and a pair");
}

/// An upgrade of a client at `from` with the token `token`, if any.
async fn upgrade(cfg: &Arc<Config>, path: &str, from: &str, token: Option<&str>) -> Response {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let from: IpAddr = from.parse().unwrap();
    let headers: Vec<(&str, &str)> = token.map(|t| ("X-Relay-Token", t)).into_iter().collect();
    let (_, answer) = tokio::join!(
        serve_from(server, cfg.clone(), None, Some(from)),
        exchange(&mut client, "GET", "relay-a.test", path, &headers, b"", 16 * 1024),
    );
    answer.expect("an answer")
}

#[tokio::test]
async fn past_120_wrong_tokens_of_an_address_in_a_minute_its_upgrades_wait() {
    let (now, clock) = set_clock();
    let (cfg, _) = role(clock);
    let a = "192.0.2.1";
    for i in 0..PER_MINUTE {
        let wrong = if i % 2 == 0 { None } else { Some("ephm1.9.forward.AAAA") };
        let refused = upgrade(&cfg, "/connect/github.com/22", a, wrong).await;
        assert_eq!(refused.status, 403, "try {i}: {}", refused.body_text(200));
    }
    let braked = upgrade(&cfg, "/connect/github.com/22", a, None).await;
    assert_eq!(braked.status, 429, "{}", braked.body_text(200));
    assert_eq!(braked.header_text("retry-after", 64).as_deref(), Some("60"));
    // Its good token waits too, and so do its mints, which share the count.
    let (token, _) = cfg.tokens.mint(super::super::tokens::now_ms(), 60_000);
    assert_eq!(upgrade(&cfg, "/connect/github.com/22", a, Some(&token)).await.status, 429);
    assert_eq!(ask(&cfg, "POST", "/v1/mint", a).await.status, 429);
    assert_eq!(upgrade(&cfg, "/v1/layer/github.com/22", a, None).await.status, 429, "the layer's road");
    // Another address is not braked.
    assert_eq!(upgrade(&cfg, "/connect/github.com/22", "198.51.100.7", None).await.status, 403);
    // A good token that a later check refuses (no upgrade here) is no strike.
    let b = "203.0.113.9";
    for i in 0..PER_MINUTE + 10 {
        let refused = upgrade(&cfg, "/connect/github.com/22", b, Some(&token)).await;
        assert_ne!(refused.status, 429, "try {i}: {}", refused.body_text(200));
    }
    now.store(WINDOW_MS, Ordering::SeqCst);
    assert_eq!(upgrade(&cfg, "/connect/github.com/22", a, None).await.status, 403, "the minute passed");
}

#[test]
fn the_upgrades_that_need_a_token() {
    for (method, path) in [
        ("GET", "/connect/github.com/22"),
        ("GET", "/v1/layer/github.com/22"),
        ("POST", "/v1/http/open/github.com/22"),
        ("POST", "/v1/http/one-layer/github.com/22"),
    ] {
        assert!(needs_token(method, path), "{method} {path}");
    }
    for (method, path) in [("POST", "/v1/mint"), ("GET", "/health"), ("POST", "/v1/http/send/k"), ("GET", "/trace")] {
        assert!(!needs_token(method, path), "{method} {path}");
    }
    let brake = Brake::new(2, WINDOW_MS, ADDRESSES, monotonic());
    let a = ip("192.0.2.1");
    brake.strike_at(a, 0);
    assert!(brake.held_at(a, 0).is_ok(), "one strike of two");
    brake.strike_at(a, 1);
    assert_eq!(brake.held_at(a, 2), Err(Braked { wait_s: 60, first: true }));
    assert!(brake.held_at(ip("192.0.2.2"), 2).is_ok());
    assert!(brake.held_at(a, WINDOW_MS).is_ok(), "the first strike left the minute");
}
