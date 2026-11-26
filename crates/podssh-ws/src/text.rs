//! Text that came from a peer, made safe to print on a terminal.
//!
//! A relay's error body, a WebSocket close reason, a proxy's status line or an
//! SSH banner can carry ESC, BEL or a bare CR, which repaint the line, ring the
//! bell or overwrite what the user is reading. Everything podssh prints from a
//! peer goes through one of these two functions, so there is one definition of
//! "safe" (a sibling project ended up with two that disagreed).

/// For a one-line message: control characters (C0, DEL, C1) and bidirectional
/// formatting characters are dropped, and every run of whitespace, line breaks
/// included, becomes one space. Leading and trailing whitespace is removed.
pub fn one_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut space = false;
    for c in text.chars() {
        if c.is_whitespace() {
            space = true;
        } else if c.is_control() || is_bidi_control(c) {
            continue;
        } else {
            if space && !out.is_empty() {
                out.push(' ');
            }
            space = false;
            out.push(c);
        }
    }
    out
}

/// For text that is meant to span lines (an SSH banner, a keyboard-interactive
/// instruction): CR LF and a lone CR become LF, tabs stay, and every other
/// control or bidirectional formatting character is dropped.
pub fn multi_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            '\n' | '\t' => out.push(c),
            c if c.is_control() || is_bidi_control(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// Characters that reorder how a terminal displays the text around them
/// (the "Trojan Source" set), plus the Arabic letter mark.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// `text` without each ` (os error N)` that Rust's `io::Error` adds to the
/// system's words: a line says what happened once, in the system's words
/// (one helper for each crate of podssh).
pub fn plain(text: &str) -> String {
    const MARK: &str = " (os error ";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(MARK) {
        let tail = &rest[at + MARK.len()..];
        let digits = tail.bytes().take_while(|b| b.is_ascii_digit() || *b == b'-').count();
        if digits > 0 && tail[digits..].starts_with(')') {
            out.push_str(&rest[..at]);
            rest = &tail[digits + 1..];
        } else {
            out.push_str(&rest[..at + 1]);
            rest = &rest[at + 1..];
        }
    }
    out.push_str(rest);
    out
}

/// [`plain`] of an error: what a user line shows of an `io::Error`.
pub fn said(e: &dyn std::fmt::Display) -> String {
    plain(&e.to_string())
}

/// What a user line shows of an error on a file that a flag names: "no such
/// file", or the directory that is missing where the file's own is, or
/// [`said`] of the rest. One set of words for each file flag.
pub fn file_said(path: &std::path::Path, e: &std::io::Error) -> String {
    if e.kind() != std::io::ErrorKind::NotFound {
        return said(e);
    }
    match path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        // A file under a directory that is not there: the directory is what
        // the user must make.
        Some(dir) if !dir.exists() => format!("the directory {} does not exist", dir.display()),
        _ => "no such file".to_string(),
    }
}

/// A line of a name that did not resolve, in plain words: pod-dns says each
/// source's failure, DNS over HTTPS's in the TLS library's words. The user
/// line keeps what the system's resolver said, and whether DNS over HTTPS
/// could not be reached or found no address; the source's own words are the
/// detail, for -v. `None` for a line with no DNS over HTTPS in it (T-1054).
pub fn unresolved(line: &str) -> Option<(String, String)> {
    const DOH: &str = "DNS over HTTPS: ";
    let at = line.find(DOH)?;
    let doh = &line[at + DOH.len()..];
    let head = line[..at].trim_end().trim_end_matches(';').trim_end();
    let head = plain(&head.replacen("system resolver: ", "the system's resolver said: ", 1));
    // An answer with no address is a name that is not there; each other
    // failure is a resolver that this host could not reach.
    let none = doh.trim() == "no answer" || doh.contains("no address");
    let doh_said = if none { "DNS over HTTPS found no address" } else { "DNS over HTTPS could not be reached" };
    let head = if head.is_empty() { String::new() } else { format!("{head}; ") };
    Some((format!("{head}{doh_said}"), plain(&format!("{DOH}{doh}"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name that did not resolve: the system's words and one plain clause
    /// of DNS over HTTPS, the TLS library's words for -v alone (T-1054).
    #[test]
    fn a_name_that_did_not_resolve_is_said_in_plain_words() {
        let system = "could not resolve nosuch.invalid: system resolver: failed to lookup address information: \
                      Name or service not known";
        let tls = "each of 6 resolvers failed: TLS: invalid peer certificate: UnknownIssuer";
        for (doh, said) in
            [(tls, "DNS over HTTPS could not be reached"), ("no answer", "DNS over HTTPS found no address")]
        {
            let line = format!("{system}; DNS over HTTPS: {doh}");
            let (shown, detail) = unresolved(&line).expect("a line of DNS over HTTPS");
            let want = "could not resolve nosuch.invalid: the system's resolver said: failed to lookup address \
                        information: Name or service not known; ";
            assert_eq!(shown, format!("{want}{said}"));
            assert!(!shown.contains("TLS") && !shown.contains("..."), "{shown}");
            assert_eq!(detail, format!("DNS over HTTPS: {doh}"));
        }
        assert_eq!(unresolved("could not resolve x: system resolver: no answer"), None);
    }

    #[test]
    fn plain_text_is_unchanged() {
        assert_eq!(one_line("403 missing or wrong token"), "403 missing or wrong token");
        assert_eq!(multi_line("Welcome.\nNo shell here.\n"), "Welcome.\nNo shell here.\n");
        assert_eq!(one_line("naïve — ok"), "naïve — ok");
    }

    #[test]
    fn terminal_controls_are_removed() {
        // ESC sequences, BEL, a bare CR that would overwrite the line, and the
        // 8-bit CSI (U+009B). The CR is whitespace, so one line shows a space.
        let hostile = "ok\x1b[2J\x1b]0;title\x07\rFAKE\u{9b}31m";
        assert_eq!(one_line(hostile), "ok[2J]0;title FAKE31m");
        assert!(!multi_line(hostile).contains('\x1b'));
        assert!(!multi_line(hostile).contains('\x07'));
        assert!(!multi_line(hostile).contains('\u{9b}'));
    }

    #[test]
    fn bidirectional_overrides_are_removed() {
        assert_eq!(one_line("abc\u{202E}fed\u{202C}"), "abcfed");
        assert_eq!(multi_line("a\u{2066}b\u{2069}c"), "abc");
    }

    #[test]
    fn one_line_folds_whitespace_and_line_breaks() {
        assert_eq!(one_line("  a \r\n\t b\n\nc  "), "a b c");
        assert_eq!(one_line("\n\n"), "");
    }

    #[test]
    fn multi_line_normalises_line_breaks() {
        assert_eq!(multi_line("a\r\nb\rc\nd\te"), "a\nb\nc\nd\te");
    }

    /// Rust's suffix goes, and only it: the system's words stay.
    #[test]
    fn the_os_error_suffix_leaves_and_the_words_stay() {
        for (given, want) in [
            ("Connection refused (os error 111)", "Connection refused"),
            (
                "a: No such file or directory (os error 2); b: Is a directory (os error 21)",
                "a: No such file or directory; b: Is a directory",
            ),
            ("words (os error x) stay", "words (os error x) stay"),
            ("no suffix", "no suffix"),
            ("(os error 5)", "(os error 5)"),
        ] {
            assert_eq!(plain(given), want, "{given}");
        }
    }

    /// A missing file, a missing directory, and another error, each in one
    /// set of words.
    #[test]
    fn a_file_flag_says_what_is_missing() {
        use std::io::{Error, ErrorKind};
        let missing = Error::from(ErrorKind::NotFound);
        let denied = Error::from_raw_os_error(13);
        let here = std::env::temp_dir();
        let gone = here.join(format!("podssh-file-said-{}-none", std::process::id()));
        for (path, e, want) in [
            (here.join("none-such-file"), &missing, "no such file".to_string()),
            (std::path::PathBuf::from("bare"), &missing, "no such file".to_string()),
            (gone.join("a.log"), &missing, format!("the directory {} does not exist", gone.display())),
            (here.join("x"), &denied, said(&denied)),
        ] {
            assert_eq!(file_said(&path, e), want, "{}", path.display());
        }
        assert!(!file_said(&here, &denied).contains("os error"));
    }
}
