//! The meeting point that carries each piece's note: a board of topics that
//! keeps the last message of each topic until it is cleared. No file host
//! lets the uploader name the path, so the far end learns each URL here.
//!
//! A public MQTT broker is one (T-737's, of `pod-services`' kind
//! `mqtt-broker`): a retained message is the one that it keeps for each
//! topic, a subscription gets it at once, and an empty retained message
//! clears it (MQTT 3.1.1, section 3.3.1.3). So an end reaches the board on a
//! connection of its own for each step, and closes it before the next: one
//! connection of the road at a time, where a subscription held open would
//! sit beside each upload. A topic is public and a message is at most 64 KB
//! there, so a note is sealed ([`super::keys`]) and small. ntfy.sh (T-496)
//! and Nostr's relays (T-545) keep messages too, and can be boards when
//! their entries are done.

use std::future::Future;
use std::pin::Pin;

/// One call of a board, in flight.
pub type Posting<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

/// A meeting point that keeps the last message of each topic.
pub trait Board: Send + Sync {
    /// Its name, for a line.
    fn name(&self) -> &str;
    /// The most bytes of one message.
    fn most(&self) -> usize;
    /// Keep `payload` as the message of `topic`, in the place of the one
    /// before.
    fn put<'a>(&'a self, topic: &'a str, payload: Vec<u8>) -> Posting<'a, ()>;
    /// The message that `topic` keeps now, if any, without waiting for one.
    fn take<'a>(&'a self, topic: &'a str) -> Posting<'a, Option<Vec<u8>>>;
    /// Clear `topic`, so that the board keeps nothing of a piece once read.
    fn clear<'a>(&'a self, topic: &'a str) -> Posting<'a, ()>;
}
