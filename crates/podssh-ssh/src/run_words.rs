//! russh's errors in words that a user can act on, for `run`'s lines: kept
//! apart so that `run.rs` stays within 500 lines.

/// Whether `e` is the end of the stream, as [`describe`] calls it closed.
pub(crate) fn closed(e: &russh::Error) -> bool {
    use russh::Error;
    match e {
        Error::Disconnect | Error::HUP | Error::RecvError | Error::SendError => true,
        Error::IO(io) => io.kind() == std::io::ErrorKind::UnexpectedEof,
        _ => false,
    }
}

/// russh's errors, in words a user can act on.
pub fn describe(e: &russh::Error) -> String {
    use russh::Error;
    match e {
        Error::Disconnect | Error::HUP | Error::RecvError | Error::SendError => {
            "the connection closed unexpectedly".into()
        }
        Error::IO(io) if io.kind() == std::io::ErrorKind::UnexpectedEof => "the connection closed unexpectedly".into(),
        Error::Version => "the server did not answer with an SSH version line (is this an SSH server?)".into(),
        Error::NoCommonAlgo { kind, ours, theirs } => format!(
            "no {kind:?} algorithm in common with the server (podssh offers {}; the server offers {})",
            ours.join(","),
            theirs.join(",")
        ),
        Error::KeepaliveTimeout => "the server stopped answering keepalives".into(),
        Error::ConnectionTimeout | Error::InactivityTimeout => "the connection timed out".into(),
        Error::StrictKeyExchangeViolation { .. } => {
            format!("{e} (the connection was tampered with, or the server is broken)")
        }
        // russh's words alone named no side (GitHub #83).
        Error::SshEncoding(inner) => format!("podssh could not read a message of the server: {inner}"),
        other => other.to_string(),
    }
}
