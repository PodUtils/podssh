//! A live shell shared by name (T-837), with russh's client over pipes in
//! memory, several connections to one server with `--share`: the owner's
//! login shell on a pty is told two names on its stderr; a login under the
//! `ro-` name, with a key that the server does not know, reads the owner's
//! output, and none of its bytes (a paste before its shell request, keys
//! typed after, extended data) reaches the pty, while its window change
//! does; two logins under the `rw-` name type, and the lease keeps the
//! line of one from the line of the other; a deleted name refuses a new
//! login and leaves the seat that it opened; a name runs nothing else; the
//! names die with the shell, whose seats then exit 0; without `--share`, a
//! name is a wrong key. The owner rotates and deletes a name by the
//! subsystem `share@podssh` (T-860), which a seat of a name and another
//! connection of the owner's key may not use. The watcher, the writers and
//! the end of the names run on each tty that the host gives (T-861): the
//! kernel's pty, serve's line discipline, and the tty that serve answers by
//! seccomp; a tty that the host does not give is said, and its cases do
//! not run.

#![cfg(unix)]

mod share_harness;

use std::time::Duration;

use podssh_ssh::server::share;
use share_harness::{ask, have_pty, key, owner, Seat, Server, Tty};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_watcher_reads_and_none_of_its_bytes_reach_the_tty() {
    for tty in Tty::here() {
        watcher_on(tty).await;
    }
}

async fn watcher_on(tty: Tty) {
    let server = Server::on(tty);
    let (owner, _, read) = owner(&server).await;
    let handle = server.login(&read, &key()).await.expect("the name lets an unknown key in");
    let viewer = Seat::open(handle).await;
    // The second path to the tty: bytes before the attach, kept for the
    // program that a channel runs.
    viewer.send(b"EARLY_PASTE\r").await;
    viewer.write.request_pty(true, "xterm", 100, 30, 0, 0, &[]).await.unwrap();
    viewer.write.request_shell(true).await.unwrap();
    viewer.until("both replies", |seen| seen.replies.len() >= 2).await;
    assert_eq!(viewer.seen.lock().unwrap().replies, vec![true, true], "{tty:?}: a name's pty and shell");
    viewer.send(b"VIEWER_KEYS\r").await;
    viewer.write.extended_data(1, &b"VIEWER_EXT\r"[..]).await.unwrap();
    viewer.write.window_change(40, 10, 0, 0).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // On the line discipline the shell has no tty, and stty only fails.
    owner.send(b"stty size; echo OWNER_$((1+1))\r").await;
    owner.reads("OWNER_2").await;
    viewer.reads("OWNER_2").await;
    let (seen, watched) = (owner.seen.lock().unwrap().text(), viewer.seen.lock().unwrap().text());
    if tty.sized() {
        let sized = seen.lines().any(|l| l.trim_end_matches('\r') == "10 40");
        assert!(sized, "{tty:?}: the watcher's size counts: {seen}");
    }
    for word in ["EARLY_PASTE", "VIEWER_KEYS", "VIEWER_EXT"] {
        assert!(!seen.contains(word) && !watched.contains(word), "{tty:?}: {word} reached the tty: {seen}");
    }

    // A name runs nothing else.
    let other = Seat::open(server.login(&read, &key()).await.expect("again")).await;
    other.write.exec(true, "echo RAN").await.unwrap();
    other.until("the refusal", |seen| !seen.replies.is_empty()).await;
    assert_eq!(other.seen.lock().unwrap().replies, vec![false], "{tty:?}");
    assert!(String::from_utf8_lossy(&other.seen.lock().unwrap().err).contains("shared shell"), "{tty:?}");

    // A deleted name lets no one new in, and the seat that it opened stays.
    assert!(server.control.unshare(&read));
    assert!(server.login(&read, &key()).await.is_none(), "{tty:?}: a deleted name is a wrong key");
    owner.send(b"echo AFTER_$((2+3))\r").await;
    viewer.reads("AFTER_5").await;
    owner.send(b"exit 0\r").await;
    owner.until("the owner's end", |seen| seen.closed).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writers_take_turns_and_no_line_interleaves() {
    for tty in Tty::here() {
        writers_on(tty).await;
    }
}

async fn writers_on(tty: Tty) {
    let server = Server::on(tty);
    let (owner, write, _) = owner(&server).await;
    // The shell answers, then becomes cat; the owner's lease passes.
    owner.send(b"echo GO_$((1+2))\r").await;
    owner.reads("GO_3").await;
    owner.send(b"exec cat\r").await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let first = Seat::shell(server.login(&write, &key()).await.expect("a writer"), 80, 24).await;
    let second = Seat::shell(server.login(&write, &key()).await.expect("a second writer"), 80, 24).await;
    first.send(b"aaa").await;
    owner.reads("aaa").await;
    // Sent while the first writer holds the lease: held, not mixed in.
    second.send(b"bbbbbb\r").await;
    tokio::time::sleep(Duration::from_millis(40)).await;
    first.send(b"aaa\r").await;
    owner.until("cat's copy of each line", |seen| seen.text().matches("bbbbbb").count() >= 2).await;
    // Whatever draws the line (the kernel, the discipline and its prompt),
    // no byte of one writer sits beside a byte of the other.
    let text = owner.seen.lock().unwrap().text();
    // From the first writer's own bytes: a shell's line editor may redraw the
    // typed command (`exec ca`, an erase, `t` on macOS), and a prompt can hold
    // `ab` (the host's name), so neither marks where the writers begin.
    let typed = &text[text.find("aaa").unwrap_or(0)..];
    assert!(typed.matches("aaaaaa").count() >= 2, "{tty:?}: the first writer's line is whole: {typed:?}");
    assert!(!typed.contains("ab") && !typed.contains("ba"), "{tty:?}: interleaved: {typed:?}");
    if tty != Tty::Line {
        let lines = owner.seen.lock().unwrap().lines();
        let typed = lines.iter().filter(|l| l.contains("aaa") || l.contains("bbb"));
        assert!(typed.clone().all(|l| l == "aaaaaa" || l == "bbbbbb"), "{tty:?}: interleaved: {lines:?}");
        assert_eq!(typed.count(), 4, "{tty:?}: the echo and cat's copy of each line: {lines:?}");
    }
    second.reads("aaaaaa").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_names_die_with_the_shell_and_each_seat_exits_0() {
    for tty in Tty::here() {
        let server = Server::on(tty);
        let (owner, write, read) = owner(&server).await;
        assert_eq!(server.control.shared(), 2, "{tty:?}");
        let viewer = Seat::shell(server.login(&read, &key()).await.expect("a watcher"), 80, 24).await;
        owner.send(b"exit 3\r").await;
        owner.until("the owner's end", |seen| seen.closed).await;
        viewer.until("the seat's end", |seen| seen.closed).await;
        assert_eq!(viewer.seen.lock().unwrap().status, Some(0), "{tty:?}");
        assert_eq!(server.control.shared(), 0, "{tty:?}");
        for name in [&write, &read] {
            assert!(server.login(name, &key()).await.is_none(), "{tty:?}: {name} died with its shell");
        }
        assert!(server.control.reshare(&read).is_none(), "{tty:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_share_a_name_is_a_wrong_key() {
    if !have_pty() {
        return;
    }
    let server = Server::new(false);
    let handle = server.login("owner", &server.owner).await.expect("the owner's key logs in");
    let seat = Seat::shell(handle, 80, 24).await;
    seat.send(b"echo READY_$((3+4))\r").await;
    seat.reads("READY_7").await;
    assert!(seat.seen.lock().unwrap().err.is_empty(), "no names told");
    assert_eq!(server.control.shared(), 0);
    assert!(server.login("rw-00000000000000000000000000000000", &key()).await.is_none());
    let lease = share::LEASE_IDLE;
    // T-862's measure: past the gaps between a person's keys.
    assert!(lease >= Duration::from_millis(350) && lease <= Duration::from_millis(450), "{lease:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_owner_rotates_and_deletes_a_name_and_the_open_seats_stay() {
    // The kernel's pty where one opens, else the line discipline.
    let server = Server::on(Tty::here()[0]);
    let (owner, write, read) = owner(&server).await;
    let writer = Seat::shell(server.login(&write, &key()).await.expect("a writer"), 80, 24).await;
    let viewer = Seat::shell(server.login(&read, &key()).await.expect("a watcher"), 80, 24).await;

    let rotated = ask(&owner.kept, "rotate rw\n").await;
    assert_eq!((rotated.replies.clone(), rotated.status), (vec![true], Some(0)), "{rotated:?}");
    let fresh = rotated.text().trim_end().to_string();
    assert!(fresh.starts_with("rw-") && fresh.len() == 35 && fresh != write, "{rotated:?}");
    assert!(server.login(&write, &key()).await.is_none(), "the old name is a wrong key");
    let newcomer = Seat::shell(server.login(&fresh, &key()).await.expect("the new name lets in"), 80, 24).await;
    // The seat that the old name opened still types; the other name stays.
    writer.send(b"echo OLD_SEAT_$((2+2))\r").await;
    owner.reads("OLD_SEAT_4").await;
    newcomer.reads("OLD_SEAT_4").await;
    assert!(server.login(&read, &key()).await.is_some(), "the ro- name is left alone");

    let deleted = ask(&owner.kept, &format!("delete {read}\n")).await;
    assert_eq!(deleted.status, Some(0), "{deleted:?}");
    assert!(deleted.text().contains(&read), "{deleted:?}");
    assert!(server.login(&read, &key()).await.is_none(), "a deleted name is a wrong key");
    assert_eq!(server.control.shared(), 1);
    owner.send(b"echo STILL_$((3+3))\r").await;
    viewer.reads("STILL_6").await;

    // A name that is gone, a line that is not a verb: one line and status 1.
    for line in [format!("rotate {read}\n"), "delete ro\n".into(), "rename rw\n".into()] {
        let refused = ask(&owner.kept, &line).await;
        assert_eq!(refused.status, Some(1), "{line}: {refused:?}");
        let err = String::from_utf8_lossy(&refused.err).into_owned();
        assert!(err.starts_with("podssh serve: ") && err.lines().count() == 1, "{line}: {err}");
        assert!(refused.out.is_empty(), "{line}: {refused:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_connection_that_owns_the_shell_rotates_a_name() {
    // The kernel's pty where one opens, else the line discipline.
    let server = Server::on(Tty::here()[0]);
    let (_owner, write, read) = owner(&server).await;
    // A seat of a name: refused, as each request of a name but its shell.
    let writer = Seat::shell(server.login(&write, &key()).await.expect("a writer"), 80, 24).await;
    // Another connection of the owner's own key holds no seat of the shell.
    let other = server.login("owner", &server.owner).await.expect("the owner's key again");
    for (who, handle) in [("a seat of a name", &writer.kept), ("another connection", &other)] {
        let refused = ask(handle, "rotate rw\n").await;
        assert_eq!(refused.replies, vec![false], "{who}: {refused:?}");
        assert!(refused.closed && refused.status.is_none(), "{who}: {refused:?}");
        assert!(String::from_utf8_lossy(&refused.err).starts_with("podssh serve: "), "{who}: {refused:?}");
    }
    for name in [&write, &read] {
        assert!(server.login(name, &key()).await.is_some(), "{name} is unchanged");
    }
}
