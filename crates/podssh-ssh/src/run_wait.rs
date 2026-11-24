//! The wait of `-N` (T-026, T-038, T-039), apart from `run.rs` for its
//! length. It ends when the server or the network ends the connection, when
//! a control master ends the run, or at Ctrl-C (T-866): the run then ends
//! as interrupted, with 130, so that its `--result-file` is written. Before,
//! SIGINT's default action killed podssh, and no file was written.

use std::sync::Arc;

use russh::client::Handle;

use crate::handler::Client;
use crate::log::Log;
use crate::options::Options;
use crate::terminal::interrupt::{Interrupt, INTERRUPTED};

/// The wait of `-N` on the destination's connection, the last of
/// `handles`: the run's exit code, or the words of its loss. The caller
/// closes each connection after it.
pub(super) async fn nothing(
    handles: &mut [Handle<Client>],
    opts: &Options,
    log: &Arc<Log>,
    host: &str,
) -> Result<i32, String> {
    // No handler with `--no-signal`, or where SIGINT was ignored at start:
    // Ctrl-C then keeps OpenSSH's way, as for a command.
    let mut interrupt = Interrupt::for_session(opts.interrupt_signal);
    tokio::select! {
        ended = until_end(handles, opts, log, host) => ended,
        _ = Interrupt::next(&mut interrupt) => {
            crate::outcome::ended(&crate::io::End::Interrupted);
            log.verbose("Ctrl-C: the run of -N ends");
            Ok(INTERRUPTED)
        }
    }
}

/// The wait itself: -L, -D and a control master serve while it runs; a
/// master may end the run, with 0.
async fn until_end(handles: &mut [Handle<Client>], opts: &Options, log: &Arc<Log>, host: &str) -> Result<i32, String> {
    let Some(handle) = handles.last_mut() else {
        return Err(format!("no connection to {host}"));
    };
    if !opts.local_forwards.is_empty() || super::masters(opts) {
        let wait = crate::local::alongside(&*handle, &opts.local_forwards, log, crate::local::closed(&*handle));
        let closed = super::with_master(
            &*handle,
            opts,
            log,
            async {
                wait.await;
                true
            },
            false,
        )
        .await;
        if !closed {
            return Ok(0);
        }
    }
    let ended = (&mut *handle).await;
    // -N ends only when the server or the network ends it, never as a
    // success: OpenSSH says so too, with 255 (T-026).
    match ended {
        Ok(()) => {
            crate::outcome::ended(&crate::io::End::Lost);
            let said = crate::handler::take_last_disconnect().map(|s| format!(": {s}")).unwrap_or_default();
            log.error(&format!("the server ended the connection to {host}{said}"));
            Ok(super::EXIT_FAILURE)
        }
        Err(e) => Err(format!(
            "connection to {host} lost: {}",
            crate::handler::take_last_error().unwrap_or_else(|| super::describe(&e))
        )),
    }
}
