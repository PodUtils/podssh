//! The allocation kept while its data connection lives (RFC 6062, 4.4): the
//! control connection stays open, and a Refresh on it before the lifetime
//! ends, as the server closes each data connection of an allocation that
//! expired. The stream of the road owns the keeper, so that the end of the
//! session ends the allocation too, by the close of its control connection.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use super::client::{self, Answer, Auth};
use super::msg::{self, LIFETIME, NONCE, REFRESH};
use super::Note;
use crate::url::Stream;

/// The wait for a Refresh's answer.
const ANSWER_WAIT: Duration = Duration::from_secs(30);

/// When to refresh an allocation of `lifetime` seconds: a minute before its
/// end, or at its half when it is two minutes or less, never sooner than
/// 5 s, as a server may give a short lifetime.
pub fn refresh_after(lifetime: u32) -> Duration {
    let secs = if lifetime > 120 { lifetime - 60 } else { lifetime / 2 };
    Duration::from_secs(u64::from(secs.max(5)))
}

/// The tasks of an allocation, aborted when the road's stream is dropped.
struct Keep {
    tasks: Vec<AbortHandle>,
}

impl Drop for Keep {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// The data connection of a TURN road: the target's bytes, as they are,
/// with the allocation's keeper.
pub struct TurnStream {
    inner: Stream,
    _keep: Keep,
}

/// Keep the allocation of `control` for `data`, refreshed by `auth` each
/// time before `lifetime` ends; `note` says why the allocation ended.
pub fn keep(control: Stream, data: Stream, auth: Auth, lifetime: u32, note: Note) -> TurnStream {
    let (read, write) = tokio::io::split(control);
    let (answers, inbox) = mpsc::channel(4);
    let reader = tokio::spawn(read_control(read, answers, note.clone()));
    let refresher = tokio::spawn(refresh(write, inbox, auth, lifetime, note));
    TurnStream { inner: data, _keep: Keep { tasks: vec![reader.abort_handle(), refresher.abort_handle()] } }
}

/// Each message of the control connection, to the refresher; its end said
/// once, as the server's close of it ends the allocation.
async fn read_control(mut read: ReadHalf<Stream>, answers: mpsc::Sender<Vec<u8>>, note: Note) {
    loop {
        match client::read_message(&mut read).await {
            Ok(bytes) => {
                // An indication (a peer's ConnectionAttempt) asks nothing of
                // a client that dials out.
                if answers.send(bytes).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                note(&format!("the TURN server ended the allocation's control connection: {e}"));
                return;
            }
        }
    }
}

/// A Refresh before each end of the lifetime, until one fails.
async fn refresh(
    mut write: WriteHalf<Stream>,
    mut inbox: mpsc::Receiver<Vec<u8>>,
    mut auth: Auth,
    mut lifetime: u32,
    note: Note,
) {
    loop {
        tokio::time::sleep(refresh_after(lifetime)).await;
        match refresh_once(&mut write, &mut inbox, &mut auth).await {
            Ok(next) => lifetime = next,
            Err(why) => {
                note(&format!("the TURN server did not refresh the allocation: {why}"));
                return;
            }
        }
    }
}

/// One Refresh with the allocation's credential, a stale nonce tried again
/// once: the lifetime that the server gave, or why there is none.
async fn refresh_once(
    write: &mut WriteHalf<Stream>,
    inbox: &mut mpsc::Receiver<Vec<u8>>,
    auth: &mut Auth,
) -> Result<u32, String> {
    for round in 0..2 {
        let id = client::transaction_id().map_err(|e| e.to_string())?;
        let request = auth.sign(REFRESH, &id, &[]);
        write.write_all(&request).await.map_err(|e| format!("a write failed: {e}"))?;
        write.flush().await.map_err(|e| format!("a write failed: {e}"))?;
        let answer = tokio::time::timeout(ANSWER_WAIT, wait_for(inbox, &id))
            .await
            .map_err(|_| format!("no answer in {} s", ANSWER_WAIT.as_secs()))??;
        let answer = client::checked(answer, &auth.key[..]).map_err(|e| e.to_string())?;
        if answer.is_success() {
            // A success with no LIFETIME keeps the server's default, 600 s.
            return Ok(answer.attribute(LIFETIME).and_then(|v| msg::u32_of(&v)).unwrap_or(600));
        }
        let (code, reason) = answer.error();
        if code == 438 && round == 0 {
            if let Some(nonce) = answer.attribute(NONCE) {
                auth.nonce = nonce;
                continue;
            }
        }
        return Err(format!("{code} {reason}"));
    }
    Err("a second stale nonce".into())
}

/// The answer of `id` among the messages of the control connection.
async fn wait_for(inbox: &mut mpsc::Receiver<Vec<u8>>, id: &[u8; 12]) -> Result<Answer, String> {
    while let Some(bytes) = inbox.recv().await {
        let kind = u16::from_be_bytes([bytes[0], bytes[1]]);
        if bytes[8..20] == id[..] && kind & msg::ERROR != msg::INDICATION && kind & msg::ERROR != 0 {
            return Ok(Answer { bytes });
        }
    }
    Err("the control connection closed".into())
}

impl AsyncRead for TurnStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TurnStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The note of a road that says nothing: a pipe whose end speaks for it.
pub fn silent() -> Note {
    Arc::new(|_: &str| {})
}
