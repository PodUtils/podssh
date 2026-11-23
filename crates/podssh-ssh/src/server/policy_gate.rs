//! An algorithm policy on a client (T-838): `podssh serve --policy FILE`
//! judges the client's first KEXINIT as its bytes pass, before any
//! authentication, with the same `evaluate` that judges a server's for
//! `podssh ssh --policy`. A mismatch, or a KEXINIT that does not read, ends
//! the connection as a reload's revoke does: a disconnect with the reason,
//! and one line in serve's log that names the client's address and each
//! mismatch. A connection ended here logs in no key (`handler.rs`).
//!
//! It reads; it never changes a byte. The record is the client side's own
//! reader of a handshake (`handshake_side.rs`), so its bounds hold: a KEXINIT
//! of more than 64 KiB is not kept, and is refused here as no reading.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::live::Conn;
use super::Settings;
use crate::handshake::side::Side;
use crate::policy::{evaluate, observe_client, Mismatch, Policy};

/// What the client is told: the policy's name, never its lines.
pub(super) fn told(policy: &Policy) -> String {
    format!("podssh serve: this client's algorithms do not meet the policy {:?}", policy.name)
}

/// The judge of one connection, until its verdict.
struct Gate {
    policy: Arc<Policy>,
    conn: Conn,
    settings: Arc<Settings>,
    side: Side,
}

/// The stream of one connection, its client's bytes read by the gate until
/// the verdict; with no policy, the stream as it is.
pub(super) struct Gated<S> {
    inner: S,
    gate: Option<Box<Gate>>,
}

impl<S> Gated<S> {
    pub(super) fn new(inner: S, conn: &Conn, settings: &Arc<Settings>) -> Gated<S> {
        let gate = settings.policy.clone().map(|policy| {
            Box::new(Gate { policy, conn: conn.clone(), settings: settings.clone(), side: Side::default() })
        });
        Gated { inner, gate }
    }
}

impl Gate {
    /// Read the client's next bytes; true once the verdict is made.
    fn feed(&mut self, data: &[u8]) -> bool {
        self.side.feed(data);
        if self.side.kexinit.is_none() && !self.side.sealed() {
            return false;
        }
        if let Some(why) = self.verdict() {
            let who = self.settings.peer.map_or_else(|| "with no address (a pipe)".to_string(), |ip| ip.to_string());
            self.settings.say(&format!("client {who}: refused before authentication: {why}"));
            self.conn.end(told(&self.policy));
        }
        true
    }

    /// None when the client passed; else why it is refused, in one line.
    fn verdict(&self) -> Option<String> {
        let name = &self.policy.name;
        let Some(payload) = self.side.kexinit.as_deref() else {
            return Some(format!("no verdict of the policy {name:?}: the client's KEXINIT was not read whole"));
        };
        let observed = match observe_client(payload, self.side.version.clone(), self.side.other.clone()) {
            Ok(observed) => observed,
            Err(why) => return Some(format!("no verdict of the policy {name:?}: {why}")),
        };
        let verdict = evaluate(&self.policy, &observed);
        if verdict.passed() {
            return None;
        }
        let each: Vec<String> = verdict.mismatches.iter().map(words).collect();
        Some(format!("{}: {}", verdict.line(), each.join("; ")))
    }
}

/// One mismatch in words: the field, what was expected, what came.
pub(super) fn words(m: &Mismatch) -> String {
    let list = |names: &[String]| if names.is_empty() { "none".to_string() } else { names.join(",") };
    format!("{} expected {}, got {}", m.field, list(&m.expected), list(&m.actual))
}

impl<S: AsyncRead + Unpin> AsyncRead for Gated<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        let this = &mut *self;
        // The verdict falls in the read that brings the KEXINIT's last byte,
        // before russh reads a message after it.
        if let Some(gate) = this.gate.as_mut() {
            if gate.feed(&buf.filled()[before..]) {
                this.gate = None;
            }
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Gated<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "policy_gate_tests.rs"]
mod tests;
