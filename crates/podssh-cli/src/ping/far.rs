//! The measures of `podssh ping` through a destination (T-053): the echo of
//! single bytes through `cat`, and the throughput down with `head -c SIZE
//! /dev/zero` and up with `cat > /dev/null`. These programs are an
//! assumption about the far host, so they run only when the user names a
//! destination, and the output names them; one that the host lacks ends the
//! run with its status (127), never with a hang: each wait has a limit.
//! Each write goes beside the channel's reads: russh's loop takes a write
//! only after it put each message into the channel's bounded queue (T-923).

use std::time::{Duration, Instant};

use podssh_ssh::handler::Client;
use podssh_ssh::io::beside::{self, beside, Backlog, Source};
use podssh_ssh::russh::client::{Handle, Msg};
use podssh_ssh::russh::{Channel, ChannelMsg};

/// The limit on each wait of a measure.
pub(super) const STEP: Duration = Duration::from_secs(60);
/// The size of each write up.
const CHUNK: usize = 32 * 1024;

/// Why a measure has no number.
#[derive(Debug)]
pub enum Failed {
    /// The program ended with this status: 127 when the host lacks it.
    Status(String, i32),
    /// The channel or the connection broke, or a wait passed its limit.
    Broke(String),
}

impl Failed {
    /// The program's status, when it ended with one.
    pub fn status(&self) -> Option<i32> {
        match self {
            Failed::Status(_, status) => Some(*status),
            Failed::Broke(_) => None,
        }
    }
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failed::Status(command, 127) => write!(f, "{command}: the host has no such program (exit 127)"),
            Failed::Status(command, status) => write!(f, "{command}: exit {status}"),
            Failed::Broke(why) => f.write_str(why),
        }
    }
}

/// A session channel running `command`, once the server took it.
pub(super) async fn open(handle: &Handle<Client>, command: &str) -> Result<Channel<Msg>, Failed> {
    let broke = |what: &str, e: &dyn std::fmt::Display| Failed::Broke(format!("{command}: {what}: {e}"));
    let mut channel = match handle.channel_open_session().await {
        Ok(channel) => channel,
        // A refusal told from a connection that ended first (T-464).
        Err(e) => {
            let read = podssh_ssh::unopened::read(&e, handle).await;
            return Err(Failed::Broke(format!("{command}: {}", read.words("a session", false))));
        }
    };
    channel.exec(true, command.as_bytes()).await.map_err(|e| broke("not sent", &e))?;
    // A program that is not there can end before the server's reply comes.
    let mut status = None;
    loop {
        match tokio::time::timeout(STEP, channel.wait()).await {
            Ok(Some(ChannelMsg::Success)) => return Ok(channel),
            Ok(Some(ChannelMsg::Failure)) => {
                return Err(Failed::Broke(format!("{command}: the server refused to run it")))
            }
            Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                status = Some(i32::try_from(exit_status).unwrap_or(255))
            }
            Ok(Some(_)) => continue,
            Ok(None) => {
                return Err(match status {
                    Some(status) if status != 0 => Failed::Status(command.into(), status),
                    _ => Failed::Broke(format!("{command}: the channel closed")),
                })
            }
            Err(_) => return Err(Failed::Broke(format!("{command}: no answer within {} s", STEP.as_secs()))),
        }
    }
}

/// The rest of a channel's messages, those taken beside a write first: its
/// exit status, if one came.
pub(super) async fn status_of<S: Source<Msg = ChannelMsg>>(
    reader: &mut S,
    aside: &mut Backlog<ChannelMsg>,
) -> Option<i32> {
    let mut status = None;
    while let Ok(Some(msg)) = tokio::time::timeout(STEP, beside::next(reader, aside)).await {
        match msg {
            ChannelMsg::ExitStatus { exit_status } => status = Some(i32::try_from(exit_status).unwrap_or(255)),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    status
}

/// `count` round trips of one byte through `cat`, after one that is not
/// counted: the first byte can wait for the remote shell to start `cat`.
pub async fn echo(handle: &Handle<Client>, count: usize) -> Result<Vec<Duration>, Failed> {
    const COMMAND: &str = "cat";
    let channel = open(handle, COMMAND).await?;
    let (mut reader, writer) = channel.split();
    let mut aside = Backlog::default();
    let mut samples = Vec::with_capacity(count);
    for round in 0..=count {
        let started = Instant::now();
        if beside(writer.data_bytes(vec![b'x']), &mut reader, &mut aside, &|| {}).await.is_err() {
            return Err(gone(COMMAND, &mut reader, &mut aside).await);
        }
        loop {
            match tokio::time::timeout(STEP, beside::next(&mut reader, &mut aside)).await {
                Ok(Some(ChannelMsg::Data { data })) if !data.is_empty() => break,
                Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                    return Err(Failed::Status(COMMAND.into(), i32::try_from(exit_status).unwrap_or(255)))
                }
                Ok(Some(ChannelMsg::Close)) | Ok(None) => return Err(Failed::Broke(format!("{COMMAND}: closed"))),
                Ok(Some(_)) => {}
                Err(_) => return Err(Failed::Broke(format!("{COMMAND}: no echo within {} s", STEP.as_secs()))),
            }
        }
        if round > 0 {
            samples.push(started.elapsed());
        }
    }
    let _ = tokio::time::timeout(STEP, beside(writer.eof(), &mut reader, &mut aside, &|| {})).await;
    let _ = status_of(&mut reader, &mut aside).await;
    Ok(samples)
}

/// Why a write failed: the program's status when it ended, else a break.
async fn gone<S: Source<Msg = ChannelMsg>>(command: &str, reader: &mut S, aside: &mut Backlog<ChannelMsg>) -> Failed {
    match status_of(reader, aside).await {
        Some(status) if status != 0 => Failed::Status(command.into(), status),
        _ => Failed::Broke(format!("{command}: the channel closed")),
    }
}

/// `size` bytes down, from `head -c SIZE /dev/zero`: the time, and the
/// command that ran.
pub async fn down(handle: &Handle<Client>, size: u64) -> (String, Result<Duration, Failed>) {
    let command = format!("head -c {size} /dev/zero");
    let result = async {
        let (mut reader, _writer) = open(handle, &command).await?.split();
        let started = Instant::now();
        let mut got = 0u64;
        let mut status = None;
        loop {
            match tokio::time::timeout(STEP, reader.wait()).await {
                Ok(Some(ChannelMsg::Data { data })) => got += data.len() as u64,
                Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                    status = Some(i32::try_from(exit_status).unwrap_or(255))
                }
                Ok(Some(ChannelMsg::Close)) | Ok(None) => break,
                Ok(Some(_)) => {}
                Err(_) => return Err(Failed::Broke(format!("{command}: no byte within {} s", STEP.as_secs()))),
            }
        }
        let took = started.elapsed();
        match status {
            Some(0) if got == size => Ok(took),
            Some(0) | None => Err(Failed::Broke(format!("{command}: {got} of {size} bytes came"))),
            Some(other) => Err(Failed::Status(command.clone(), other)),
        }
    }
    .await;
    (command, result)
}

/// `size` bytes up, into `cat > /dev/null`: the time until it exited, and
/// the command that ran.
pub async fn up(handle: &Handle<Client>, size: u64) -> (String, Result<Duration, Failed>) {
    let command = "cat > /dev/null".to_string();
    let result = async {
        let channel = open(handle, &command).await?;
        let (mut reader, writer) = channel.split();
        // What cat says while the bytes go (its error), read after them.
        let mut aside = Backlog::default();
        let started = Instant::now();
        let mut sent = 0u64;
        while sent < size {
            let n = CHUNK.min((size - sent) as usize);
            let write = writer.data_bytes(vec![0u8; n]);
            match tokio::time::timeout(STEP, beside(write, &mut reader, &mut aside, &|| {})).await {
                Ok(Ok(())) => sent += n as u64,
                Ok(Err(_)) => return Err(gone(&command, &mut reader, &mut aside).await),
                Err(_) => {
                    return Err(Failed::Broke(format!("{command}: the window stayed shut for {} s", STEP.as_secs())))
                }
            }
        }
        if tokio::time::timeout(STEP, beside(writer.eof(), &mut reader, &mut aside, &|| {})).await.is_err() {
            return Err(Failed::Broke(format!("{command}: the end of its input waited {} s", STEP.as_secs())));
        }
        match status_of(&mut reader, &mut aside).await {
            Some(0) => Ok(started.elapsed()),
            Some(other) => Err(Failed::Status(command.clone(), other)),
            None => Err(Failed::Broke(format!("{command}: no exit status"))),
        }
    }
    .await;
    (command, result)
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;

    use super::*;

    /// A channel's queue, in small.
    struct Queue(mpsc::Receiver<ChannelMsg>);

    impl Source for Queue {
        type Msg = ChannelMsg;

        fn wait(&mut self) -> impl std::future::Future<Output = Option<ChannelMsg>> + Send + '_ {
            self.0.recv()
        }

        fn size(msg: &ChannelMsg) -> usize {
            match msg {
                ChannelMsg::Data { data } => data.len(),
                _ => 0,
            }
        }
    }

    /// russh's loop, in small: cat's output, its status and its close, each
    /// put into the channel's queue of 2 inline; only then the writes, from
    /// a queue of 1 that one write fills already.
    fn model() -> (Queue, mpsc::Sender<&'static str>, JoinHandle<()>) {
        let (chan_tx, chan_rx) = mpsc::channel(2);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(1);
        cmd_tx.try_send("data").expect("an empty queue of 1");
        let looping = tokio::spawn(async move {
            let output = (0..6u8).map(|i| ChannelMsg::Data { data: vec![i; 10].into() });
            for msg in output.chain([ChannelMsg::ExitStatus { exit_status: 3 }, ChannelMsg::Close]) {
                if chan_tx.send(msg).await.is_err() {
                    return;
                }
            }
            drop(chan_tx);
            while cmd_rx.recv().await.is_some() {}
        });
        (Queue(chan_rx), cmd_tx, looping)
    }

    /// The end of a measure's input goes beside the channel's output, and
    /// the status is read from what its wait took (T-923); awaited alone,
    /// the end waits for ever on a loop that waits on it (the control).
    #[tokio::test(start_paused = true)]
    async fn the_end_of_input_goes_beside_the_output_and_its_status_is_kept() {
        let (chan, cmd, looping) = model();
        assert!(tokio::time::timeout(STEP, cmd.send("eof")).await.is_err(), "the control");
        looping.abort();
        drop(chan);

        let (mut chan, cmd, _looping) = model();
        let mut aside = Backlog::default();
        let sent = tokio::time::timeout(STEP, beside(cmd.send("eof"), &mut chan, &mut aside, &|| {})).await;
        assert!(matches!(sent, Ok(Ok(()))), "the end went beside the output");
        assert_eq!(status_of(&mut chan, &mut aside).await, Some(3), "the status, from what the wait took");
    }
}
