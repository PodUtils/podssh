//! The rules of a shared shell (T-837) apart from SSH: the lease, the
//! names, the least size. `tests/serve_share.rs` holds them through russh.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::AsyncWrite;
use tokio::time::Instant;

use super::*;

/// A pty that keeps what it was given, in order.
#[derive(Clone, Default)]
struct Kept(Arc<Mutex<Vec<u8>>>);

impl AsyncWrite for Kept {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn size(cols: u32, rows: u32) -> Size {
    Size { cols, rows, px_width: 0, px_height: 0 }
}

/// A shell whose pty is `kept` and whose sizes go to `sizes`.
fn shell(table: &Shares, kept: &Kept, sizes: &Arc<Mutex<Vec<Size>>>) -> Arc<Seat> {
    let seen = sizes.clone();
    Hub::open(table, Box::new(kept.clone()), Box::new(move |s| seen.lock().unwrap().push(s)), size(80, 24))
}

#[test]
fn the_lease_lets_its_holder_and_a_silence_past_its_deadline_write() {
    let now = Instant::now();
    let later = now + LEASE_IDLE;
    // (holder, until, seat, now) and whether that seat must wait.
    type Case = (Option<u64>, Option<Instant>, u64, Instant, bool);
    let cases: &[Case] = &[
        (None, None, 1, now, false),
        (Some(1), Some(later), 1, now, false),
        (Some(1), Some(later), 2, now, true),
        (Some(1), Some(later), 2, later, false),
        (Some(1), Some(later), 2, later + Duration::from_millis(1), false),
    ];
    for &(holder, until, seat, at, waits) in cases {
        let lease = Lease { holder, until, generation: 0 };
        assert_eq!(lease.busy(seat, at).is_some(), waits, "{holder:?} until {until:?}, seat {seat}");
    }
    let mut lease = Lease::default();
    lease.take(1, now);
    lease.take(1, now);
    assert_eq!((lease.holder, lease.generation), (Some(1), 1), "the holder's own write is no new generation");
    lease.take(2, later);
    assert_eq!((lease.holder, lease.generation, lease.until), (Some(2), 2, Some(later + LEASE_IDLE)));
}

#[test]
fn a_name_is_128_random_bits_and_dies_with_its_shell() {
    let (table, kept, sizes) = (Shares::default(), Kept::default(), Arc::new(Mutex::new(Vec::new())));
    let owner = shell(&table, &kept, &sizes);
    let names = table.mint(&owner.hub).expect("random bytes");
    for (name, prefix, mode) in [(&names.write, "rw-", Mode::Write), (&names.read, "ro-", Mode::Read)] {
        let bits = name.strip_prefix(prefix).expect("its prefix");
        assert!(bits.len() == 32 && bits.bytes().all(|b| b.is_ascii_hexdigit()), "{name}");
        assert_eq!(table.find(name).map(|pass| pass.mode), Some(mode));
    }
    assert_ne!(names.write[3..], names.read[3..], "two draws");
    assert!(table.find("ro-").is_none() && table.find("").is_none() && table.find(&names.read[3..]).is_none());
    assert!(names.told().contains(&names.write) && names.told().contains(&names.read));

    // A new read name leaves the write name alone; the old read name is out.
    let fresh = table.reshare(&names.read).expect("a running shell");
    assert!(fresh.starts_with("ro-") && fresh != names.read);
    assert!(table.find(&names.read).is_none() && table.find(&fresh).is_some() && table.find(&names.write).is_some());
    assert!(table.unshare(&fresh) && !table.unshare(&fresh), "deleted once");
    assert_eq!(table.len(), 1);

    owner.hub.end();
    assert!(table.find(&names.write).is_none(), "a name dies with its shell");
    assert_eq!(table.len(), 0);
    assert!(table.reshare(&names.write).is_none() && owner.hub.subscribe().is_none());
}

#[test]
fn the_pty_takes_the_least_size_of_the_seats_that_live() {
    let (table, kept, sizes) = (Shares::default(), Kept::default(), Arc::new(Mutex::new(Vec::new())));
    let owner = shell(&table, &kept, &sizes);
    let wide = owner.hub.seat(Some(size(200, 60)));
    let narrow = owner.hub.seat(Some(size(40, 50)));
    assert_eq!(sizes.lock().unwrap().last(), Some(&size(40, 24)), "field by field");
    drop(narrow);
    assert_eq!(sizes.lock().unwrap().last(), Some(&size(80, 24)), "a seat that leaves holds nothing down");
    wide.resize(size(30, 10));
    assert_eq!(sizes.lock().unwrap().last(), Some(&size(30, 10)));
    let none: [Size; 0] = [];
    assert_eq!(least(none.iter()), None);
}

#[tokio::test(start_paused = true)]
async fn a_second_writer_waits_for_the_first_ones_silence() {
    let (table, kept, sizes) = (Shares::default(), Kept::default(), Arc::new(Mutex::new(Vec::new())));
    let owner = shell(&table, &kept, &sizes);
    let (first, second) = (owner.hub.seat(None), owner.hub.seat(None));
    assert!(owner.hub.write_leased(first.id, b"aaa").await);
    let hub = owner.hub.clone();
    let id = second.id;
    let waiting = tokio::spawn(async move { hub.write_leased(id, b"bbb\n").await });
    tokio::time::sleep(LEASE_IDLE / 2).await;
    assert!(!waiting.is_finished(), "held while the first writer holds the lease");
    assert!(owner.hub.write_leased(first.id, b"aaa\n").await, "the holder goes on");
    assert!(waiting.await.unwrap());
    assert_eq!(kept.0.lock().unwrap().as_slice(), b"aaaaaa\nbbb\n", "no interleaving");
    let lease = owner.hub.lease().await;
    assert_eq!((lease.holder, lease.generation), (Some(second.id), 2));
    owner.hub.end();
    assert!(!owner.hub.write_leased(first.id, b"late").await, "no write after the end");
}
