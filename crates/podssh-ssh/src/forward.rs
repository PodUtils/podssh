//! `-W HOST:PORT`, or `-W /PATH` (T-040): the server opens a TCP connection,
//! or one to a Unix socket on it, and podssh's stdin and stdout become that
//! stream. Nothing listens locally, which is why this is the forwarding
//! podssh offers. Also how `-J` reaches each next hop.

use russh::client::Handle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::handler::Client;
use crate::log::Log;
use crate::options::StdioTarget;

/// Open `host:port` from the server; the caller wraps the channel in a stream.
pub async fn open(
    handle: &Handle<Client>,
    host: &str,
    port: u16,
) -> Result<russh::ChannelStream<russh::client::Msg>, String> {
    handle.channel_open_direct_tcpip(host, u32::from(port), "127.0.0.1", 0).await.map(|c| c.into_stream()).map_err(
        |e| format!("the server could not open a connection to {}: {e}", podssh_ws::dial::authority(host, port)),
    )
}

/// Open `target` from the server: a TCP connection, or a Unix socket on it.
pub async fn open_target(
    handle: &Handle<Client>,
    target: &StdioTarget,
) -> Result<russh::ChannelStream<russh::client::Msg>, String> {
    open_raw(handle, target).await.map_err(|e| refusal_words(target, &e))
}

/// [`open_target`], with russh's error, whose reason `-W`'s state keeps
/// (T-840).
async fn open_raw(
    handle: &Handle<Client>,
    target: &StdioTarget,
) -> Result<russh::ChannelStream<russh::client::Msg>, russh::Error> {
    match target {
        StdioTarget::Tcp { host, port } => {
            handle.channel_open_direct_tcpip(host, u32::from(*port), "127.0.0.1", 0).await.map(|c| c.into_stream())
        }
        StdioTarget::Socket(path) => {
            handle.channel_open_direct_streamlocal(path.as_str()).await.map(|c| c.into_stream())
        }
    }
}

/// The line of a target that the server did not open, as [`open`] says it.
fn refusal_words(target: &StdioTarget, e: &russh::Error) -> String {
    match target {
        StdioTarget::Tcp { host, port } => {
            format!("the server could not open a connection to {}: {e}", podssh_ws::dial::authority(host, *port))
        }
        StdioTarget::Socket(path) => format!("the server could not open a connection to the socket {path}: {e}"),
    }
}

/// The name of the forward of `-W`, as its counts and `--result-file`
/// give it: one name from before the link to its end (T-866).
pub fn stdio_name(target: &StdioTarget) -> String {
    format!("-W {}", target.shown())
}

/// Copy stdin to the stream and the stream to stdout until the far side
/// closes. Returns the exit code: 0 for a normal close.
pub async fn stdio(handle: &Handle<Client>, target: &StdioTarget, log: &Log) -> i32 {
    let name = stdio_name(target);
    let counts = crate::tally::of(&name);
    let stream = match open_raw(handle, target).await {
        Ok(s) => s,
        Err(e) => {
            counts.failed();
            // The forward is its one channel: one that did not open is a
            // refusal, with the server's reason (T-840).
            counts.set_state(&name, crate::tally::State::Refused, Some(&crate::local::open_failure(&e)), None);
            log.error(&refusal_words(target, &e));
            crate::outcome::failed("forward");
            return crate::run::EXIT_FAILURE;
        }
    };
    counts.set_state(&name, crate::tally::State::Up, None, None);
    let _connection = counts.connection();
    let stream = crate::tally::Counted::down(stream, &counts);
    let (mut from_far, mut to_far) = tokio::io::split(stream);
    let up = async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    // Behind a key that waits for its echo (T-661).
                    crate::pace::turn().await;
                    if to_far.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                    counts.add_up(n as u64);
                    crate::outcome::stdin(n);
                }
            }
        }
        // End of stdin: send EOF and keep receiving.
        let _ = to_far.shutdown().await;
    };
    let down = async move {
        let mut stdout = tokio::io::stdout();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match from_far.read(&mut buf).await {
                Ok(0) => return 0,
                Ok(n) => {
                    if stdout.write_all(&buf[..n]).await.is_err() || stdout.flush().await.is_err() {
                        return 0;
                    }
                    crate::outcome::output(n, false);
                }
                Err(e) => {
                    log.error(&format!("the forwarded connection failed: {e}"));
                    crate::outcome::failed("forward");
                    return crate::run::EXIT_FAILURE;
                }
            }
        }
    };
    tokio::pin!(up);
    tokio::pin!(down);
    let mut sending = true;
    let code = loop {
        tokio::select! {
            _ = &mut up, if sending => sending = false,
            code = &mut down => break code,
        }
    };
    // russh ends a channel's stream the same way whether the far side closed
    // it or the whole connection died; only the second is a failure.
    if code == 0 && handle.is_closed() {
        let cause = crate::handler::take_last_error().map(|c| format!(": {c}")).unwrap_or_default();
        log.error(&format!("the connection was lost while forwarding to {}{cause}", target.shown()));
        return crate::run::EXIT_FAILURE;
    }
    code
}
