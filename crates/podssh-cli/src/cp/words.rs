//! The words of the file commands' lines: the system's words of a failure
//! without Rust's `(os error N)`, a bound as the user gave it, and the
//! partial copies that a run ended early keeps.

use std::time::Duration;

/// `text` without each ` (os error N)` that Rust's `io::Error` adds to the
/// system's words: a line says what happened once, in the system's words.
pub(crate) fn plain(text: &str) -> String {
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

/// [`plain`] of an `io::Error`.
pub(crate) fn said(e: &std::io::Error) -> String {
    plain(&e.to_string())
}

/// A bound as a line names it: whole seconds as `N s`, else `N ms`, so
/// that `--timeout 1ms` is never "0 s".
pub(crate) fn limit(bound: Duration) -> String {
    if bound.subsec_nanos() == 0 {
        format!("{} s", bound.as_secs())
    } else {
        format!("{} ms", bound.as_millis().max(1))
    }
}

/// The partial copies that a run which ended early keeps, for the end of
/// its line: each temporary file and its side file, or nothing when no copy
/// was in flight (T-297: several files at once keep one each).
pub(crate) fn kept(current: &[(String, String)]) -> String {
    match current {
        [] => String::new(),
        [(temp, side)] => {
            format!("; the partial copy stays at {temp}, and the same command goes on from it (its record: {side})")
        }
        many => {
            let (temps, sides): (Vec<&str>, Vec<&str>) =
                many.iter().map(|(temp, side)| (temp.as_str(), side.as_str())).unzip();
            format!(
                "; the partial copies stay at {}, and the same command goes on from each (their records: {})",
                temps.join(", "),
                sides.join(", ")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One rule for each line: the suffix goes, wherever it is, and text
    /// that only looks like it stays.
    #[test]
    fn the_rust_suffix_goes_and_the_system_s_words_stay() {
        let cases = [
            ("src/nope: No such file or directory (os error 2)", "src/nope: No such file or directory"),
            ("Connection refused (os error 111); try again", "Connection refused; try again"),
            ("a (os error 13) and b (os error 28)", "a and b"),
            ("Access is denied. (os error 5)", "Access is denied."),
            ("weird (os error -1)", "weird"),
            ("no number (os error )", "no number (os error )"),
            ("not closed (os error 2", "not closed (os error 2"),
            ("plain words", "plain words"),
            ("", ""),
        ];
        for (given, want) in cases {
            assert_eq!(plain(given), want, "{given:?}");
        }
        let e = std::io::Error::from_raw_os_error(2);
        assert!(!said(&e).contains("os error"), "{}", said(&e));
    }

    #[test]
    fn a_bound_is_named_as_it_was_given() {
        for (bound, want) in [
            (Duration::from_secs(2), "2 s"),
            (Duration::from_millis(1), "1 ms"),
            (Duration::from_millis(1500), "1500 ms"),
            (Duration::from_micros(10), "1 ms"),
            (Duration::ZERO, "0 s"),
        ] {
            assert_eq!(limit(bound), want, "{bound:?}");
        }
    }

    #[test]
    fn the_partial_copies_are_named_with_their_records() {
        assert_eq!(kept(&[]), "");
        let one = [("d/.f.podssh-0123456789abcdef.part".to_string(), "c/podssh-cp-1.resume".to_string())];
        assert!(kept(&one).starts_with("; the partial copy stays at d/.f.podssh-"), "{}", kept(&one));
        let two = [one[0].clone(), ("e".to_string(), "s".to_string())];
        assert!(kept(&two).contains("the partial copies stay at") && kept(&two).contains(", e"), "{}", kept(&two));
    }
}
