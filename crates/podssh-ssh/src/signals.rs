//! Signal names as SSH carries them (RFC 4254 §6.10, without "SIG"), and the
//! numbers podssh exits with: 128 + the signal number, as a shell reports a
//! process killed by a signal. Numbers are Linux's, the target platform's.

use russh::Sig;

/// The name of a signal, as SSH spells it.
pub fn name(sig: &Sig) -> String {
    match sig {
        Sig::ABRT => "ABRT".into(),
        Sig::ALRM => "ALRM".into(),
        Sig::FPE => "FPE".into(),
        Sig::HUP => "HUP".into(),
        Sig::ILL => "ILL".into(),
        Sig::INT => "INT".into(),
        Sig::KILL => "KILL".into(),
        Sig::PIPE => "PIPE".into(),
        Sig::QUIT => "QUIT".into(),
        Sig::SEGV => "SEGV".into(),
        Sig::TERM => "TERM".into(),
        Sig::USR1 => "USR1".into(),
        Sig::Custom(other) => podssh_ws::text::one_line(other),
    }
}

/// The signals that russh names, with their numbers.
fn named() -> [(Sig, i32); 12] {
    [
        (Sig::HUP, 1),
        (Sig::INT, 2),
        (Sig::QUIT, 3),
        (Sig::ILL, 4),
        (Sig::ABRT, 6),
        (Sig::FPE, 8),
        (Sig::KILL, 9),
        (Sig::USR1, 10),
        (Sig::SEGV, 11),
        (Sig::PIPE, 13),
        (Sig::ALRM, 14),
        (Sig::TERM, 15),
    ]
}

/// The other signals, by the name that SSH carries in `Sig::Custom`.
const CUSTOM: &[(&str, i32)] = &[
    ("TRAP", 5),
    ("BUS", 7),
    ("USR2", 12),
    ("STKFLT", 16),
    ("CHLD", 17),
    ("CONT", 18),
    ("STOP", 19),
    ("TSTP", 20),
    ("TTIN", 21),
    ("TTOU", 22),
    ("URG", 23),
    ("XCPU", 24),
    ("XFSZ", 25),
    ("VTALRM", 26),
    ("PROF", 27),
    ("WINCH", 28),
    ("IO", 29),
    ("PWR", 30),
    ("SYS", 31),
];

/// The name that OpenSSH's server sends for a signal with no name.
pub const UNNAMED: &str = "SIG@openssh.com";

/// The signal's number, if podssh knows it.
pub fn number(sig: &Sig) -> Option<i32> {
    if let Sig::Custom(other) = sig {
        let other = other.trim_start_matches("SIG");
        return CUSTOM.iter().find(|(name, _)| *name == other).map(|(_, n)| *n);
    }
    // Sig has no PartialEq; each of these variants carries nothing.
    let kind = std::mem::discriminant(sig);
    named().into_iter().find(|(known, _)| std::mem::discriminant(known) == kind).map(|(_, n)| n)
}

/// The signal of a number, as `podssh serve` sends it in `exit-signal`
/// (T-108): the same tables as [`number`], read the other way, so the two
/// directions cannot disagree.
pub fn from_number(n: i32) -> Sig {
    if let Some((sig, _)) = named().into_iter().find(|(_, known)| *known == n) {
        return sig;
    }
    let name = CUSTOM.iter().find(|(_, known)| *known == n).map_or(UNNAMED, |(name, _)| *name);
    Sig::Custom(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn term_is_15_so_the_exit_code_is_143() {
        assert_eq!(number(&Sig::TERM).map(|n| 128 + n), Some(143));
        assert_eq!(number(&Sig::Custom("USR2".into())), Some(12));
        assert_eq!(number(&Sig::Custom("NOPE".into())), None);
        assert_eq!(name(&Sig::KILL), "KILL");
    }

    #[test]
    fn each_number_names_its_signal_and_back() {
        for n in 1..=31 {
            let sig = from_number(n);
            assert_eq!(number(&sig), Some(n), "{n}: {}", name(&sig));
        }
        assert_eq!(name(&from_number(15)), "TERM");
        assert_eq!(name(&from_number(12)), "USR2");
        assert_eq!(name(&from_number(64)), UNNAMED);
        assert_eq!(number(&from_number(64)), None);
    }
}
