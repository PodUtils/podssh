//! russh's loop in small, with no russh, for the tests of each wait beside
//! a channel (T-780, T-923): a loop that puts each message into a channel's
//! queue of 2, inline, and takes the pump's writes from a queue of 1, which
//! one write fills already, only after them.

use std::future::Future;

use russh::{ChannelMsg, ChannelReadHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::Source;

impl Source for mpsc::Receiver<Vec<u8>> {
    type Msg = Vec<u8>;

    fn wait(&mut self) -> impl Future<Output = Option<Vec<u8>>> + Send + '_ {
        self.recv()
    }

    fn size(msg: &Vec<u8>) -> usize {
        msg.len()
    }
}

impl Source for mpsc::Receiver<ChannelMsg> {
    type Msg = ChannelMsg;

    fn wait(&mut self) -> impl Future<Output = Option<ChannelMsg>> + Send + '_ {
        self.recv()
    }

    fn size(msg: &ChannelMsg) -> usize {
        <ChannelReadHalf as Source>::size(msg)
    }
}

/// The channel's queue, the loop's queue of writes, and the loop.
pub(crate) type Model<M> = (mpsc::Receiver<M>, mpsc::Sender<&'static str>, JoinHandle<Vec<&'static str>>);

/// The loop: it puts each of `msgs` into the channel's queue of 2, each
/// awaited inline, and only then takes the pump's writes, from a queue of 1
/// that one write fills already. It gives the writes that it took, up to the
/// EOF; the channel ends behind its messages.
pub(crate) fn model<M: Send + 'static>(msgs: Vec<M>) -> Model<M> {
    let (chan_tx, chan_rx) = mpsc::channel(2);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
    cmd_tx.try_send("data").expect("an empty queue of 1");
    let looping = tokio::spawn(async move {
        for msg in msgs {
            if chan_tx.send(msg).await.is_err() {
                break;
            }
        }
        drop(chan_tx);
        let mut took = Vec::new();
        while let Some(cmd) = cmd_rx.recv().await {
            took.push(cmd);
            if cmd == "eof" {
                break;
            }
        }
        took
    });
    (chan_rx, cmd_tx, looping)
}
