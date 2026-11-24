//! Shells that outlive their client (T-159), with russh's client over pipes
//! in memory, several connections to one server: a login shell on a pty
//! starts a job, prints a line later, and is detached with `~d`'s request;
//! the job runs on, the list names the shell, and a new login of the same
//! key joins it by name, gets the line that came with no client, and finds
//! the job. A second client is refused unless it takes the shell, which
//! ends the first one's channel; an attach from inside the shell and one of
//! another key are refused. A lease of 2 s ends the shell's process group.
//! A shell left with no detach ends as before, and one kept at its login
//! (`keep@podssh`) waits after a lost connection. A server with a lease of
//! 0 refuses each request. Each case needs a pty; a host with none says so.

#![cfg(unix)]

mod share_harness;

use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::russh::keys::PrivateKey;
use podssh_ssh::russh::{client, Disconnect};
use podssh_ssh::server::{Authorized, Control, Keys, PtyMode, Settings};
use share_harness::{have_pty, key, Seat, Seen, Server, Trusting, LIMIT};

/// A server whose shells run on a pty of the kernel, kept for `lease`,
/// with each key of `keys` authorized; the first is the owner.
fn server(lease: Duration, keys: &[&PrivateKey]) -> Server {
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
fn after(seen: &Seen, tag: &str, hex: bool) -> Option<String> {
    let text = seen.text();
    text.split(tag).skip(1).find_map(|rest| {
        let digits: String =
            rest.chars().take_while(|c| if hex { c.is_ascii_hexdigit() } else { c.is_ascii_digit() }).collect();
        (!digits.is_empty() && rest[digits.len()..].starts_with("_END")).then_some(digits)
    })
}

/// Wait for `tag`'s number in the output of `seat`.
async fn read_after(seat: &Seat, tag: &str, hex: bool) -> String {
    seat.until(tag, |seen| after(seen, tag, hex).is_some()).await;
    after(&seat.seen.lock().unwrap(), tag, hex).unwrap()
}

/// Whether the process `pid` runs (or is a zombie not yet reaped).
fn runs(pid: i32) -> bool {
    // SAFETY: a signal of 0 checks the process and sends nothing.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Wait until `pid` is gone, within `limit`.
async fn gone_within(pid: i32, limit: Duration) -> bool {
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
async fn shell_with(server: &Server, login: &PrivateKey, asks: &[(&str, &str)]) -> Seat {
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

/// The lines of `shells@podssh` for `login`.
async fn list(server: &Server, login: &PrivateKey) -> String {
    let handle = server.login("user", login).await.expect("the key logs in");
    let seat = Seat::open(handle).await;
    seat.write.request_subsystem(true, "shells@podssh").await.unwrap();
    seat.until("the list's end", |seen| seen.closed).await;
    let seen = seat.seen.lock().unwrap();
    assert_eq!(seen.status, Some(0), "{seen:?}");
    seen.text()
}

/// Ask the far end to keep the shell of `seat` as `name`: its reply.
async fn detach(seat: &Seat, name: &str) -> bool {
    let before = seat.seen.lock().unwrap().replies.len();
    seat.write.set_env(true, "detach@podssh", name).await.unwrap();
    seat.until("the detach's reply", |seen| seen.replies.len() > before).await;
    let replies = seat.seen.lock().unwrap().replies.clone();
    replies[before]
}

/// A job in the shell's own process group (`set +m`), and a line that the
/// shell prints after `later` seconds: the job's pid.
async fn start_job(seat: &Seat, later: u32) -> i32 {
    seat.send(b"set +m; sleep 600 & echo PID_$!_END\r").await;
    let pid: i32 = read_after(seat, "PID_", false).await.parse().unwrap();
    let line = format!("(sleep {later}; echo LATER_$((6*7))_END) &\r");
    seat.send(line.as_bytes()).await;
    pid
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kept_shell_keeps_its_job_and_is_joined_again_by_name() {
    if !have_pty() {
        return;
    }
    let (owner, other) = (key(), key());
    let server = server(Duration::from_secs(600), &[&owner, &other]);
    let first = shell_with(&server, &owner, &[]).await;
    assert_eq!(first.seen.lock().unwrap().replies, vec![true, true], "the pty, then the shell");
    let pid = start_job(&first, 2).await;
    first.send(b"echo SID_${PODSSH_SHELL_ID}_END\r").await;
    let id = read_after(&first, "SID_", true).await;
    assert_eq!(id.len(), 32, "128 bits in hex: {id}");
    assert!(detach(&first, "work").await, "the far end keeps the shell");
    first.until("the channel's close", |seen| seen.closed).await;
    assert!(runs(pid), "the job runs on with no client");
    assert_eq!(list(&server, &owner).await, "work detached\n");
    assert_eq!(list(&server, &other).await, "", "another key's list names no shell of this one");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // The same key joins by name, and gets what came with no client.
    let second = shell_with(&server, &owner, &[("attach@podssh", "work")]).await;
    assert_eq!(second.seen.lock().unwrap().replies, vec![true, true, true]);
    second.reads("LATER_42_END").await;
    second.send(format!("kill -0 {pid} && echo ALIVE_$((1+1))_END\r").as_bytes()).await;
    second.reads("ALIVE_2_END").await;
    assert_eq!(list(&server, &owner).await, "work attached\n");

    // A second client is refused, as is one inside the shell, and another
    // key, each with its words and the status 1.
    let refusals = [
        (&owner, vec![("attach@podssh", "work")], "has a client"),
        (&owner, vec![("from@podssh", id.as_str()), ("take@podssh", "yes"), ("attach@podssh", "work")], "inside"),
        (&other, vec![("attach@podssh", "work")], "no kept shell named work"),
    ];
    for (login, asks, words) in refusals {
        let refused = shell_with(&server, login, &asks).await;
        refused.until("the refusal's end", |seen| seen.closed).await;
        let seen = refused.seen.lock().unwrap();
        assert_eq!(seen.status, Some(1), "{words}: {seen:?}");
        assert!(String::from_utf8_lossy(&seen.err).contains(words), "{words}: {seen:?}");
    }

    // --take: the third client has the shell, and the second one's channel
    // ends with a line.
    let third = shell_with(&server, &owner, &[("take@podssh", "yes"), ("attach@podssh", "work")]).await;
    second.until("the taken channel's close", |seen| seen.closed).await;
    assert!(String::from_utf8_lossy(&second.seen.lock().unwrap().err).contains("took the kept shell work"));
    third.send(b"echo THIRD_$((3*3))_END\r").await;
    third.reads("THIRD_9_END").await;
    third.send(b"exit 0\r").await;
    third.until("the shell's end", |seen| seen.closed).await;
    assert_eq!(third.seen.lock().unwrap().status, Some(0), "the shell's status goes to the client that has it");
    assert_eq!(list(&server, &owner).await, "", "an ended shell is no kept shell");
    // SAFETY: a signal to the test's own job; one gone gives ESRCH.
    unsafe { libc::kill(pid, libc::SIGKILL) };
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lease_that_runs_out_ends_the_process_group() {
    if !have_pty() {
        return;
    }
    let owner = key();
    let server = server(Duration::from_secs(2), &[&owner]);
    let seat = shell_with(&server, &owner, &[]).await;
    let pid = start_job(&seat, 600).await;
    assert!(detach(&seat, "short").await);
    assert!(runs(pid), "the job runs within the lease");
    let ended = gone_within(pid, Duration::from_secs(2) + podssh_ssh::server::KILL_AFTER + LIMIT / 3).await;
    // SAFETY: a signal to the test's own job; one gone gives ESRCH.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    assert!(ended, "the lease's end hangs up the shell's process group");
    assert_eq!(list(&server, &owner).await, "", "a shell whose lease ran out is no kept shell");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shell_is_kept_only_when_its_client_asked() {
    if !have_pty() {
        return;
    }
    let owner = key();
    let server = server(Duration::from_secs(600), &[&owner]);

    // No ~d and no keep@podssh: a lost connection hangs the shell up.
    let plain = shell_with(&server, &owner, &[]).await;
    let pid = start_job(&plain, 600).await;
    let _ = plain.kept.disconnect(Disconnect::ByApplication, "", "").await;
    let ended = gone_within(pid, LIMIT).await;
    // SAFETY: a signal to the test's own job; one gone gives ESRCH.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    assert!(ended, "a shell never kept ends with its client, as before");

    // keep@podssh at the login: a lost connection keeps the shell.
    let kept = shell_with(&server, &owner, &[("keep@podssh", "lab")]).await;
    let pid = start_job(&kept, 600).await;
    let _ = kept.kept.disconnect(Disconnect::ByApplication, "", "").await;
    let listed = tokio::time::timeout(LIMIT, async {
        loop {
            let lines = list(&server, &owner).await;
            if lines == "lab detached\n" {
                return lines;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(listed.is_ok(), "the shell kept at its login waits for a client");
    assert!(runs(pid));
    let back = shell_with(&server, &owner, &[("attach@podssh", "lab")]).await;
    back.send(format!("kill -0 {pid} && echo BACK_$((2+2))_END\r").as_bytes()).await;
    back.reads("BACK_4_END").await;
    server.control.stop();
    // SAFETY: a signal to the test's own job; one gone gives ESRCH.
    unsafe { libc::kill(pid, libc::SIGKILL) };
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_that_keeps_no_shells_refuses_each_request() {
    if !have_pty() {
        return;
    }
    let owner = key();
    let server = server(Duration::ZERO, &[&owner]);
    let seat = shell_with(&server, &owner, &[]).await;
    assert!(!detach(&seat, "work").await, "a detach is refused, and the session goes on");
    seat.send(b"echo STILL_$((5+5))_END\r").await;
    seat.reads("STILL_10_END").await;
    let asked = shell_with(&server, &owner, &[("attach@podssh", "work")]).await;
    assert!(!asked.seen.lock().unwrap().replies[1], "attach@podssh is refused");
    let handle: client::Handle<Trusting> = server.login("user", &owner).await.expect("the key logs in");
    let lister = Seat::open(handle).await;
    lister.write.request_subsystem(true, "shells@podssh").await.unwrap();
    lister.until("the reply", |seen| !seen.replies.is_empty()).await;
    assert_eq!(lister.seen.lock().unwrap().replies, vec![false], "the list is refused");
    for shell in [&seat, &asked] {
        shell.send(b"exit 0\r").await;
        shell.until("the shell's end", |seen| seen.closed).await;
    }
}
