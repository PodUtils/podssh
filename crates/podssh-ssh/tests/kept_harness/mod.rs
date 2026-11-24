//! The harness of `tests/serve_keep.rs` and `tests/serve_attach_ticket.rs`
//! (T-159, T-833): a server whose shells are kept, a login shell after
//! podssh's `env` requests, the list of `shells@podssh`, `~d`'s request, a
//! job in the shell's group, and the numbers that the shell prints.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::russh::keys::PrivateKey;
use podssh_ssh::server::{Authorized, Control, Keys, PtyMode, Settings};

use crate::share_harness::{Seat, Seen, Server};

/// A server whose shells run on a pty of the kernel, kept for `lease`,
/// with each key of `keys` authorized; the first is the owner.
pub fn server(lease: Duration, keys: &[&PrivateKey]) -> Server {
    let mut authorized = Authorized::new();
    for key in keys {
        authorized.add(key.public_key().key_data().clone());
    }
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
    let base: Vec<(OsString, OsString)> = vec![("PATH".into(), path)];
    let settings = Settings { base_env: Some(base), pty: PtyMode::No, keep_lease: lease, ..Settings::default() };
    let owner = keys[0].clone();
    Server { keys: Keys::new(authorized), control: Control::new(), settings: Arc::new(settings), owner }
}

/// The number after `tag` and before `_END` in the output: the echo of
/// the typed line holds `$`, not digits, so only the shell's answer counts.
pub fn after(seen: &Seen, tag: &str, hex: bool) -> Option<String> {
    let text = seen.text();
    text.split(tag).skip(1).find_map(|rest| {
        let digits: String =
            rest.chars().take_while(|c| if hex { c.is_ascii_hexdigit() } else { c.is_ascii_digit() }).collect();
        (!digits.is_empty() && rest[digits.len()..].starts_with("_END")).then_some(digits)
    })
}

/// Wait for `tag`'s number in the output of `seat`.
pub async fn read_after(seat: &Seat, tag: &str, hex: bool) -> String {
    seat.until(tag, |seen| after(seen, tag, hex).is_some()).await;
    after(&seat.seen.lock().unwrap(), tag, hex).unwrap()
}

/// Whether the process `pid` runs (or is a zombie not yet reaped).
pub fn runs(pid: i32) -> bool {
    // SAFETY: a signal of 0 checks the process and sends nothing.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Wait until `pid` is gone, within `limit`.
pub async fn gone_within(pid: i32, limit: Duration) -> bool {
    let end = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < end {
        if !runs(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// A login shell of `login` on a pty, after the `env` requests `asks`.
pub async fn shell_with(server: &Server, login: &PrivateKey, asks: &[(&str, &str)]) -> Seat {
    let handle = server.login("user", login).await.expect("the key logs in");
    let seat = Seat::open(handle).await;
    seat.write.request_pty(true, "vt100", 80, 24, 0, 0, &[]).await.unwrap();
    for (name, value) in asks {
        seat.write.set_env(true, *name, *value).await.unwrap();
    }
    seat.write.request_shell(true).await.unwrap();
    seat.until("each reply", |seen| seen.replies.len() > asks.len() + 1).await;
    seat
}

/// Each line of `shells@podssh` without its offset (T-833): the name and
/// the state.
pub async fn states(server: &Server, login: &PrivateKey) -> Vec<String> {
    let lines = list(server, login).await;
    lines.lines().map(|line| line.split(' ').take(2).collect::<Vec<_>>().join(" ")).collect()
}

/// The lines of `shells@podssh` for `login`.
pub async fn list(server: &Server, login: &PrivateKey) -> String {
    let handle = server.login("user", login).await.expect("the key logs in");
    let seat = Seat::open(handle).await;
    seat.write.request_subsystem(true, "shells@podssh").await.unwrap();
    seat.until("the list's end", |seen| seen.closed).await;
    let seen = seat.seen.lock().unwrap();
    assert_eq!(seen.status, Some(0), "{seen:?}");
    seen.text()
}

/// Ask the far end to keep the shell of `seat` as `name`: its reply.
pub async fn detach(seat: &Seat, name: &str) -> bool {
    let before = seat.seen.lock().unwrap().replies.len();
    seat.write.set_env(true, "detach@podssh", name).await.unwrap();
    seat.until("the detach's reply", |seen| seen.replies.len() > before).await;
    let replies = seat.seen.lock().unwrap().replies.clone();
    replies[before]
}

/// A job in the shell's own process group (`set +m`), and a line that the
/// shell prints after `later` seconds: the job's pid. `$!` is read where a
/// space follows it: bash's history expansion (macOS's `sh`) takes `!_END`
/// for an event and prints no pid.
pub async fn start_job(seat: &Seat, later: u32) -> i32 {
    seat.send(b"set +m; sleep 600 & p=$! ; echo PID_${p}_END\r").await;
    let pid: i32 = read_after(seat, "PID_", false).await.parse().unwrap();
    let line = format!("(sleep {later}; echo LATER_$((6*7))_END) &\r");
    seat.send(line.as_bytes()).await;
    pid
}
