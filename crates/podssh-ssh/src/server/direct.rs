//! direct-tcpip into the cage (T-109): OpenSSH's `-W`, `-L` and `-J`
//! through `podssh serve`. The server dials the asked host and port from its
//! own host, through the proxy that its environment names (the loopback and
//! the names of `NO_PROXY` go directly), as podssh's client dials, and
//! carries the bytes both ways. A dial that fails is refused with its
//! reason in words (the errno, or the proxy's status and reason), so that
//! the client says why instead of "administratively prohibited".
//!
//! Each dial runs on a task of its own: the handler answers at once, and
//! the connection's other channels go on while a dial waits.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::dial::{self, ProxyChoice};
use russh::server::{ChannelOpenHandle, Msg};
use russh::{Channel, ChannelMsg, ChannelOpenFailure, ChannelReadHalf};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::oneshot;

/// How long a dial may take, a proxy's answer included.
pub const DIAL_LIMIT: Duration = Duration::from_secs(20);

/// The most forwards open at once on one connection: past it a new one is
/// refused with `ResourceShortage`, so one client cannot spend each
/// descriptor of the cage.
pub const MAX_FORWARDS: usize = 256;

/// RFC 4254's reason codes (section 5.1) that a refusal here carries with
/// words of its own; russh's named ones carry fixed words.
const PROHIBITED: u32 = 1;
const CONNECT_FAILED: u32 = 2;

/// The longest reason sent: a proxy's reason phrase is the far side's text.
const MOST_WORDS: usize = 512;

/// The forwards of one connection: how many are open, and the bound.
#[derive(Debug, Clone)]
pub(super) struct Slots {
    open: Arc<AtomicUsize>,
    most: usize,
}

/// One open forward's place, given back when it is dropped.
#[derive(Debug)]
pub(super) struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Slots {
    pub(super) fn new(most: usize) -> Slots {
        Slots { open: Arc::new(AtomicUsize::new(0)), most }
    }

    /// A place for one more forward, or None at the bound.
    pub(super) fn take(&self) -> Option<Slot> {
        let most = self.most;
        self.open.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < most).then_some(n + 1)).ok()?;
        Some(Slot(self.open.clone()))
    }
}

/// A refusal of code 2, with `words` as its reason: the client prints them
/// (OpenSSH: `open failed: connect failed: WORDS`).
pub(super) fn connect_failed(words: &str) -> ChannelOpenFailure {
    ChannelOpenFailure::Other { code: CONNECT_FAILED, reason: bounded(&format!("podssh serve: {words}")) }
}

/// A refusal of code 1, administratively prohibited, with `words` as its
/// reason: a key's rule that refuses the forward (T-114).
pub(super) fn prohibited(words: &str) -> ChannelOpenFailure {
    ChannelOpenFailure::Other { code: PROHIBITED, reason: bounded(&format!("podssh serve: {words}")) }
}

/// `words` cut at [`MOST_WORDS`] bytes, on a character's edge.
fn bounded(words: &str) -> String {
    if words.len() <= MOST_WORDS {
        return words.to_string();
    }
    let mut end = MOST_WORDS;
    while !words.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &words[..end])
}

/// Whether a forward to `host:port` may be dialed: forwarding not turned
/// off, and the port a TCP port. Any host, as OpenSSH's sshd allows by
/// default: whoever holds an authorized key is the cage's owner, and the
/// limits of one key are its rules (`Rules::forward_refusal`, T-114). `Ok`
/// is the port.
pub(super) fn check(no_forwarding: bool, host: &str, port: u32) -> Result<u16, ChannelOpenFailure> {
    if no_forwarding {
        return Err(ChannelOpenFailure::Other {
            code: PROHIBITED,
            reason: "podssh serve: --no-forwarding: this server opens no forward".into(),
        });
    }
    match u16::try_from(port) {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(connect_failed(&format!("{}: port {port} is not a TCP port", bounded(host)))),
    }
}

/// Dial `host:port` on a task of its own, then accept the channel and carry
/// it, or refuse it with the dial's error in words. `slot` is held until
/// the forward ends.
pub(super) fn open(channel: Channel<Msg>, host: String, port: u16, reply: ChannelOpenHandle, slot: Slot) {
    tokio::spawn(async move {
        let _slot = slot;
        match dial::dial(&host, port, &ProxyChoice::FromEnvironment, DIAL_LIMIT).await {
            Ok(tcp) => {
                reply.accept().await;
                carry(channel, tcp).await;
            }
            Err(e) => reply.reject(connect_failed(&e.to_string())).await,
        }
    });
}

/// What ended the client's side of a forward.
enum Up {
    /// The client closed the channel, or the connection ended: russh has
    /// answered the close.
    Gone,
    /// A write to the target failed.
    Failed,
}

/// The client's side: its data to the target, its EOF as TCP's half-close
/// (said on `eof`), until it closes the channel.
async fn client_side(mut read: ChannelReadHalf, mut to_far: OwnedWriteHalf, eof: oneshot::Sender<()>) -> Up {
    let mut eof = Some(eof);
    while let Some(message) = read.wait().await {
        match message {
            ChannelMsg::Data { data } => {
                if to_far.write_all(&data).await.is_err() {
                    return Up::Failed;
                }
            }
            ChannelMsg::Eof => {
                let _ = to_far.shutdown().await;
                if let Some(eof) = eof.take() {
                    let _ = eof.send(());
                }
            }
            ChannelMsg::Close => return Up::Gone,
            _ => {}
        }
    }
    Up::Gone
}

/// Carry `channel` and `tcp` both ways. An EOF in one direction keeps the
/// other open, as sshd does: the target's end is the channel's EOF, the
/// client's EOF the target's half-close, and the channel closes once both
/// ended, or when a side fails. A client that closes the channel ends the
/// TCP connection with it, so no connection outlives its channel.
///
/// The bytes for the target are written as they come: russh keeps 100 of a
/// channel's messages unread before the whole connection waits, and the
/// window of each channel apart is T-118's.
pub(super) async fn carry(channel: Channel<Msg>, tcp: TcpStream) {
    // Each keystroke of a forwarded session goes at once.
    let _ = tcp.set_nodelay(true);
    let (read, write) = channel.split();
    let (mut from_far, to_far) = tcp.into_split();
    let (eof_tx, mut eof_rx) = oneshot::channel();
    let mut up = tokio::spawn(client_side(read, to_far, eof_tx));
    let mut writer = write.make_writer();
    let down = async move { tokio::io::copy(&mut from_far, &mut writer).await.is_ok() };
    tokio::pin!(down);
    let (mut down_done, mut client_eof, mut eof_known) = (false, false, false);
    loop {
        tokio::select! {
            ended = &mut up => {
                if matches!(ended, Ok(Up::Gone)) {
                    return;
                }
                break;
            }
            said = &mut eof_rx, if !eof_known => {
                eof_known = true;
                client_eof = said.is_ok();
                if client_eof && down_done {
                    break;
                }
            }
            clean = &mut down, if !down_done => {
                down_done = true;
                let _ = write.eof().await;
                if !clean || client_eof {
                    break;
                }
            }
        }
    }
    up.abort();
    let _ = write.close().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(refusal: &ChannelOpenFailure) -> (u32, String) {
        (refusal.code(), refusal.description().to_string())
    }

    #[test]
    fn no_forwarding_refuses_each_target_and_names_the_flag() {
        let (code, why) = words(&check(true, "127.0.0.1", 22).unwrap_err());
        assert_eq!(code, 1);
        assert!(why.contains("--no-forwarding"), "{why}");
    }

    #[test]
    fn a_port_that_is_no_tcp_port_is_refused_with_its_number() {
        for port in [0, 65_536, u32::MAX] {
            let (code, why) = words(&check(false, "db", port).unwrap_err());
            assert_eq!(code, 2, "{port}");
            assert!(why.contains(&format!("port {port} is not a TCP port")), "{why}");
        }
        assert_eq!(check(false, "db", 5432).unwrap(), 5432);
        assert_eq!(check(false, "127.0.0.1", 65_535).unwrap(), 65_535);
    }

    #[test]
    fn the_words_of_a_failed_dial_are_code_2_and_bounded() {
        let (code, why) = words(&connect_failed("could not connect to 127.0.0.1:1: Connection refused"));
        assert_eq!(code, 2);
        assert_eq!(why, "podssh serve: could not connect to 127.0.0.1:1: Connection refused");
        let long = "é".repeat(MOST_WORDS);
        let (_, why) = words(&connect_failed(&long));
        assert!(why.len() <= MOST_WORDS + 3 && why.ends_with("..."), "{}", why.len());
    }

    #[test]
    fn the_slots_stop_at_their_bound_and_free_each_place_on_drop() {
        let slots = Slots::new(2);
        let (a, b) = (slots.take().expect("one"), slots.take().expect("two"));
        assert!(slots.take().is_none(), "a third forward past the bound");
        drop(a);
        let c = slots.take().expect("a place again");
        assert!(slots.take().is_none());
        drop((b, c));
        let both = (slots.take(), slots.take());
        assert!(both.0.is_some() && both.1.is_some(), "each place came back");
    }
}
