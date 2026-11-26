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
            "no {} algorithm in common with the server (podssh offers {}; the server offers {})",
            kind_words(kind),
            ours.join(","),
            theirs.join(",")
        ),
        Error::KeepaliveTimeout => "the server stopped answering keepalives".into(),
        Error::ConnectionTimeout | Error::InactivityTimeout => "the connection timed out".into(),
        Error::StrictKeyExchangeViolation { .. } => {
            format!("{} (the connection was tampered with, or the server is broken)", podssh_ws::text::said(&e))
        }
        // russh's words alone named no side (GitHub #83).
        Error::SshEncoding(inner) => format!("podssh could not read a message of the server: {inner}"),
        // russh's own words name its enum's variant (`ConnectFailed`): the
        // server's reason as OpenSSH says it, for each channel.
        Error::ChannelOpenFailure(reason) => format!("open failed: {}", crate::unopened::reason_text(reason)),
        other => podssh_ws::text::said(other),
    }
}

/// The kind of a list of algorithms as `ssh_config` names it, not as
/// russh's enum spells it ("Key").
fn kind_words(kind: &russh::AlgorithmKind) -> &'static str {
    use russh::AlgorithmKind;
    match kind {
        AlgorithmKind::Kex => "key exchange",
        AlgorithmKind::Key => "host key",
        AlgorithmKind::Cipher => "cipher",
        AlgorithmKind::Compression => "compression",
        AlgorithmKind::Mac => "MAC",
    }
}

#[cfg(test)]
mod tests {
    use super::describe;

    /// Each kind of a failed negotiation is named in words, with both sides'
    /// lists; an error of the system has no "(os error N)".
    #[test]
    fn a_failed_negotiation_names_its_kind_and_both_lists() {
        use russh::AlgorithmKind;
        for (kind, words) in [
            (AlgorithmKind::Kex, "no key exchange algorithm"),
            (AlgorithmKind::Key, "no host key algorithm"),
            (AlgorithmKind::Cipher, "no cipher algorithm"),
            (AlgorithmKind::Compression, "no compression algorithm"),
            (AlgorithmKind::Mac, "no MAC algorithm"),
        ] {
            let e = russh::Error::NoCommonAlgo { kind, ours: vec!["a".into(), "b".into()], theirs: vec!["c".into()] };
            let said = describe(&e);
            assert!(said.starts_with(words), "{said}");
            assert!(said.contains("podssh offers a,b; the server offers c"), "{said}");
        }
        let io = russh::Error::IO(std::io::Error::from_raw_os_error(111));
        assert!(!describe(&io).contains("os error"), "{}", describe(&io));
    }
}
