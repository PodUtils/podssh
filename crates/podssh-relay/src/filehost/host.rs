//! A file host, as the carrier sees one: it takes one sealed piece and
//! names its URL, serves it back, and deletes it where its form lets the
//! uploader. The hosts themselves, their forms and limits, are the services
//! of `pod-services` ([`super::form::Form`] holds what one says); a test
//! gives a stand-in. Each call is one request on one connection, made under
//! the road's gate ([`super::pace::Gate`]), so that the road never holds two
//! connections at once.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// One call of a host, in flight.
pub type Doing<'a, T> = Pin<Box<dyn Future<Output = Result<T, Refusal>> + Send + 'a>>;

/// Where a host keeps a piece: its URL, and the token that deletes it where
/// the host gives one. The token is a credential of the upload: never shown.
#[derive(Clone, PartialEq, Eq)]
pub struct Stored {
    pub url: String,
    pub token: Option<String>,
}

impl fmt::Debug for Stored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = self.token.as_ref().map(|_| "<redacted>");
        f.debug_struct("Stored").field("url", &self.url).field("token", &token).finish()
    }
}

/// Why a host did not do what it was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Too many requests (429), or a host that says it is busy: it rests
    /// this long, or the road's own rest when it says nothing.
    Busy(Option<Duration>),
    /// Any other failure, in words for a line.
    Failed(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Busy(Some(wait)) => write!(f, "busy: asked to wait {} s", wait.as_secs()),
            Refusal::Busy(None) => f.write_str("busy"),
            Refusal::Failed(why) => f.write_str(why),
        }
    }
}

/// A public file host.
pub trait Host: Send + Sync {
    /// Its name, as `pod-services` gives it and the line shows it.
    fn name(&self) -> &str;
    /// The most bytes of one upload.
    fn most(&self) -> usize;
    /// The uploads an hour that the host publishes for each user, if any.
    fn per_hour(&self) -> Option<u32>;
    /// Whether the host says that one person runs it (0x0 asks that its
    /// users be told).
    fn one_person(&self) -> bool;
    /// Whether `url` is one that this host serves: a note that names a URL
    /// of another place is not fetched, sealed or not.
    fn owns(&self, url: &str) -> bool;
    /// Upload `sealed` with the host's shortest life.
    fn upload(&self, sealed: Vec<u8>) -> Doing<'_, Stored>;
    /// The whole of the upload at `url`, at most `most` bytes.
    fn fetch<'a>(&'a self, url: &'a str, most: usize) -> Doing<'a, Vec<u8>>;
    /// Delete the upload, where the host lets its uploader; `Ok` where it
    /// cannot, as its life ends it.
    fn delete<'a>(&'a self, stored: &'a Stored) -> Doing<'a, ()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_debug_shows_a_delete_token() {
        let stored = Stored { url: "https://h.test/abc".into(), token: Some("SECRET".into()) };
        let shown = format!("{stored:?}");
        assert!(shown.contains("h.test/abc") && !shown.contains("SECRET"), "{shown}");
        assert_eq!(Refusal::Busy(Some(Duration::from_secs(60))).to_string(), "busy: asked to wait 60 s");
    }
}
