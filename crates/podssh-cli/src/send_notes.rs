//! The notes of an opener that wants a `Send` sink (`pod-relay`'s `open`,
//! its last road over cleartext, a layer's link), said by a caller whose own
//! sink is not `Send` (a `&mut dyn Write`, a closure that holds one). Each
//! note crosses a channel and is said while the opener runs, in its order,
//! so that a user sees each failover as it happens, not at the end.

use std::future::Future;

use tokio::sync::mpsc::{self, UnboundedSender};

/// The `Send` end that an opener's notes go to.
pub type Notes = UnboundedSender<String>;

/// Run `open` with a [`Notes`] end, and say each note it sends through `say`
/// as it comes; the result once the opener ended and each note was said.
pub async fn said<T, F, Fut>(open: F, say: &mut dyn FnMut(&str)) -> T
where
    F: FnOnce(Notes) -> Fut,
    Fut: Future<Output = T>,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    // The opener owns the only sender: its end closes the channel, which
    // ends the loop below once the last note was said.
    let opening = open(tx);
    let saying = async {
        while let Some(note) = rx.recv().await {
            say(&note);
        }
    };
    let (out, ()) = tokio::join!(opening, saying);
    out
}

/// A note sent to `notes`; a closed channel loses nothing that a user asked
/// for, as the caller's loop ended with its run.
pub fn send(notes: &Notes, note: &str) {
    let _ = notes.send(note.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn each_note_is_said_in_its_order_and_the_result_comes_back() {
        let mut heard = Vec::new();
        let out = said(
            |notes| async move {
                send(&notes, "first");
                tokio::task::yield_now().await;
                send(&notes, "second");
                7
            },
            &mut |n: &str| heard.push(n.to_string()),
        )
        .await;
        assert_eq!(out, 7);
        assert_eq!(heard, ["first", "second"]);
    }
}
