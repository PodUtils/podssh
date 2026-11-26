//! Refusals. Every one of them names a real flag, and **none of them prints
//! a usage block**.
//!
//! `docs/cli.md`, "Options of `podssh ssh`", requires an unknown flag to be *"an error that
//! names the nearest real flag"*, and the sibling half-meets that: **READ**,
//! `.tmp/dropssh/src/main.c:276-278` refuses and exits 2, **but the message
//! is only `unknown option %s`, with no nearest match**, and
//! **READ**, `src/main.c:283-287` records the class in its own words — `--json`
//! *"was accepted, set a field, and nothing read it, which is worse than
//! refusing it"*.
//!
//! **The `usage()` dump is the reason refusals live here rather than in the
//! parser.** The sibling prints a full usage block on an unknown option
//! (`src/main.c:277`), and that buries the one line the user needs. A refusal
//! here is three lines: what was given, what it means elsewhere, what to type.

use crate::flags::{FlagKind, FlagRow, VERBS};
use crate::suggest::NoSubcommand;

/// The message for an unknown flag: the flag given, and the nearest known one.
///
/// `nearest_flag` is `clap`'s own suggestion engine (the `suggestions`
/// feature, `strsim`), not the function above — and that asymmetry is
/// deliberate. `clap` searches the flags of the command actually being parsed,
/// so it can name `-p` for a typo of `-P` on `ssh`; a hand-rolled search over a
/// flat list would name a flag belonging to a different verb, which is the
/// `cp`/`ssh` `-P` split made worse.
pub fn unknown_flag(verb: &str, token: &str, suggestion: Option<&str>, given_o: bool) -> String {
    // **The last line is the same in both branches, and it was missing from
    // one.** A test caught it: with no suggestion the message ended at
    // *"Run 'podssh --help' for the flags this build accepts."* and never said
    // anything was ignored — which is precisely the reassurance a user who
    // just mistyped `-o StrictHostKeyChecking=no` needs, because the failure
    // they are afraid of is a **silent** drop, and the branch that cannot
    // suggest anything is the branch most likely to be a genuinely unknown flag.
    let last = if given_o && takes_o(verb) {
        "Nothing was ignored: the command did not run, and no -o setting was dropped."
    } else {
        // A verb with no -o has no such setting to drop (T-828), and a
        // command line with no -o has none to fear for (T-868).
        "Nothing was ignored: the command did not run."
    };
    // The verb's own name heads the line, as each other line of it (T-1010).
    let head = if verb.is_empty() { "podssh".to_string() } else { format!("podssh {verb}") };
    match suggestion {
        Some(s) => format!("{head}: unknown flag '{token}'.\n  Did you mean '{s}'?\n  {last}"),
        // The verb's own help, where its flags are (T-818).
        None => {
            format!(
                "{head}: unknown flag '{token}'.\n  Run '{head} --help' for the flags this build accepts.\n  {last}"
            )
        }
    }
}

/// Whether `verb` (or no verb: the top of the command line) takes `-o`.
fn takes_o(verb: &str) -> bool {
    let first = verb.split_whitespace().next().unwrap_or("");
    match VERBS.iter().find(|v| v.aliases.contains(&first)) {
        Some(v) => v.flags.iter().any(|f| f.short == Some('o')),
        None => true,
    }
}

/// Two flags that do not go together, and why: one table, so that each
/// such refusal says first what to do (T-868).
pub const APART: &[(&str, &str, &str)] = &[
    ("--policy", "--persist", "--policy ends a run at a mismatch, and --persist connects again"),
    ("--policy", "--upgrade", "--upgrade moves the session to an end that the policy did not judge"),
    ("--policy", "--preflight", "--policy probes with no login, and --preflight asks after one"),
    ("--upgrade", "--persist", "each keeps a session across a lost link"),
    ("--frames", "--predict", "a guess of --predict is drawn on the far end's bytes, and --frames carries none"),
];

/// The refusal of `a` beside `b`: "A and B cannot be used together: WHY",
/// with the why of [`APART`] where it has the pair.
pub fn apart(a: &str, b: &str) -> String {
    match APART.iter().find(|(x, y, _)| (*x, *y) == (a, b) || (*x, *y) == (b, a)) {
        Some((_, _, why)) => format!("{a} and {b} cannot be used together: {why}"),
        None => format!("{a} and {b} cannot be used together"),
    }
}

/// A flag that takes one value, given twice (T-818): named as the flag it
/// is, never as an unknown one.
pub fn given_twice(verb: &str, flag: &str) -> String {
    format!("podssh {verb}: {flag} is given more than once; give it once.\n  Run 'podssh {verb} --help' for each flag.")
}

/// A negative number that the parser took for a flag (T-818): it goes after
/// `=`, where it is the value.
pub fn negative_value(verb: &str, token: &str) -> String {
    format!(
        "podssh {verb}: {token} is read as a flag; a value that starts with '-' goes after '=', as --FLAG={token}.\n  \
         Run 'podssh {verb} --help' for each flag and its value."
    )
}

/// The message for a flag that parses but is refused, and it **must** name the
/// replacement. A refusal that does not say what to type instead is the
/// sibling's `unknown option %s`. One function, so that each verb, and a
/// refused flag given with no value, refuse in the same words; the third line
/// is the row's own reason.
pub fn refused(verb: &str, given: &str, instead: &str, reason: &str) -> String {
    if instead.is_empty() || instead == "no flag" {
        format!("podssh {verb}: {given} is refused. Leave it out.\n  {reason}.")
    } else {
        format!("podssh {verb}: {given} is refused.\n  Use {instead} instead.\n  {reason}.")
    }
}

/// A word after `podssh --help` or `--version` that it does not take: named,
/// never dropped (GitHub #10).
pub fn extra_word(given: &str, word: &str) -> String {
    let hint = if given == "-V" || given == "--version" {
        "Run 'podssh --version' alone."
    } else {
        "Run 'podssh --help' alone, or 'podssh --help COMMAND' for one command."
    };
    format!("podssh: {given} takes no word '{word}'.\n  {hint}")
}

/// A known flag given with no value. `clap` writes the long spelling also
/// when the short one was typed, so the message names both.
pub fn missing_value(verb: &str, row: &FlagRow) -> String {
    let both = match row.short {
        Some(c) => format!("-{c} (--{})", row.long),
        None => format!("--{}", row.long),
    };
    format!(
        "podssh {verb}: {both} needs a value: {}.\n  Run 'podssh {verb} --help' for each flag and its value.",
        row.arg.unwrap_or("VALUE")
    )
}

/// The note for `-P` on `ssh`, whose value is a Tag, which `Match tagged`
/// reads (T-045), not a port: a tag that is a number was most likely meant
/// as one, so podssh says so before it connects; another tag needs no note.
///
/// MEASURED 2026-10-02, this machine, OpenSSH_10.3p1: `ssh -G -P mytag
/// example.org` prints `tag mytag`, and without `-P` there is no `tag`
/// line. `-P` is a real OpenSSH `ssh` flag whose value is a Tag, and
/// refusing it would refuse a flag a user has memorised.
pub fn tag_notice(tag: &str) -> Option<String> {
    if tag.is_empty() || !tag.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(format!(
        "podssh ssh: -P {tag} is a Tag, which Match tagged reads, not a port.\n  \
         For a port use -p. On scp and sftp, -P is the port."
    ))
}

/// The message for an unknown verb, and it carries the whole subcommand list
/// when no guess is available — **the list is the answer, not a usage dump**,
/// because it is what the user asked for and it is three lines, not thirty.
pub fn unknown_verb(token: &str, verdict: &NoSubcommand) -> String {
    let mut m = String::new();
    match verdict {
        NoSubcommand::Destination => {
            m.push_str(&format!("podssh: '{token}' looks like a host, not a subcommand.\n"));
            m.push_str(&format!("Try: podssh ssh {token}\n"));
        }
        NoSubcommand::Typo(name) => {
            m.push_str(&format!("podssh: unknown subcommand '{token}'.\n"));
            m.push_str(&format!("Try: podssh {name}\n"));
        }
        NoSubcommand::NoMatch => {
            m.push_str(&format!("podssh: unknown subcommand '{token}'.\n"));
            m.push_str("No close subcommand, so none is guessed.\n");
        }
    }
    m.push_str("Subcommands:\n");
    for v in VERBS {
        m.push_str(&format!("  {:10} {}\n", v.name, v.about));
    }
    m.push_str("Run 'podssh --help' for the same list with flags.");
    if !matches!(verdict, NoSubcommand::Destination) {
        m.push('\n');
        m.push_str(&newer_release());
    }
    m
}

/// A subcommand that a later release added is unknown here, and a binary
/// cannot name a later release's commands: so the last line names this build
/// and the way to a newer one (T-594). A word shaped as a host gets none.
fn newer_release() -> String {
    format!("This is {}; a newer release may have it: podssh update --check", crate::version::line())
}

/// The refusal for a subcommand that parses but has no behaviour yet. It must
/// never exit 0 (the caller returns 70), and it says nothing was attempted.
pub fn not_implemented(what: &str) -> String {
    format!("podssh: '{what}' is not implemented yet; nothing was done.")
}

/// The message for `podssh` with no arguments at all. Never an implicit
/// `ssh` — `docs/decisions.md`, "Product" (2026-10-01).
pub fn no_arguments() -> String {
    let mut m = String::from(
        "podssh: no subcommand given.\n\
         podssh never guesses a destination, so it will not connect anywhere.\n\
         Subcommands:\n",
    );
    for v in VERBS {
        m.push_str(&format!("  {:10} {}\n", v.name, v.about));
    }
    m.push_str("Run 'podssh --help' for the same list with flags.");
    m
}

/// **A `clap` error that carries no offending token**: a missing value, or a
/// positional count that does not fit. It names the verb and what was
/// expected, and **never prints a usage block** — the sibling's failure
/// (`src/main.c:277`) is a full usage dump on an unknown option, which buries
/// the one line the user needs.
/// **A `clap` error that carries no offending token**: a missing value, or a
/// positional count that does not fit. It names the verb and what was
/// expected, and **never prints a usage block** — the sibling's failure
/// (`src/main.c:277`) is a full usage dump on an unknown option, which buries
/// the one line the user needs.
///
/// `given` is the offending token, empty when `clap` reported none. It is
/// only ever a token that is **not flag-shaped**: a flag-shaped one is answered
/// by [`unknown_flag`], because being told a flag does not exist when the real
/// problem is a missing positional is a message about the wrong thing.
pub fn bad_invocation(verb: &str, kind: clap::error::ErrorKind, given: &str) -> String {
    let what = match kind {
        clap::error::ErrorKind::InvalidValue => {
            format!("podssh {verb}: that value is not one this flag accepts.")
        }
        clap::error::ErrorKind::InvalidSubcommand => {
            format!("podssh {verb}: that subcommand does not exist.")
        }
        clap::error::ErrorKind::WrongNumberOfValues
        | clap::error::ErrorKind::TooFewValues
        | clap::error::ErrorKind::TooManyValues => {
            format!("podssh {verb}: the right number of arguments was not given.")
        }
        clap::error::ErrorKind::MissingRequiredArgument => {
            format!("podssh {verb}: a required argument was not given.")
        }
        clap::error::ErrorKind::NoEquals => {
            format!("podssh {verb}: that option needs its value as -o Name=Value.")
        }
        clap::error::ErrorKind::UnknownArgument => {
            format!("podssh {verb}: '{given}' is not an argument this verb takes.")
        }
        // A host or a path of bytes that are not text (T-818): named, as the
        // vague line of the default named nothing.
        clap::error::ErrorKind::InvalidUtf8 => {
            format!("podssh {verb}: an argument is not UTF-8 text, which each argument of podssh must be.")
        }
        _ => format!("podssh {verb}: that command line cannot be used."),
    };
    format!(
        "{what}\n  Run 'podssh {verb} --help' for what this verb accepts.\n  \
         Nothing has been ignored and nothing has been attempted."
    )
}

/// Whether a flag kind is one that must refuse rather than parse. One place,
/// so the parser and the table check cannot disagree about which flags refuse.
pub fn refuses(kind: FlagKind) -> bool {
    matches!(kind, FlagKind::Refused | FlagKind::NotInFirstRelease)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suggest::NoSubcommand;

    /// **A refusal is a line, not a usage dump**, and the test for that is a
    /// line-count claim rather than a substring one.
    ///
    /// **A substring test is what this check was written as first, and it is
    /// wrong**: `relay` is in the subcommand list, so a refusal that names the
    /// list would trip a naive `contains("usage")`. The defect being guarded
    /// against is **bulk** the sibling prints ~30 lines of `Usage:` and
    /// `For more information, try '--help'` (`src/main.c:277`), and that is
    /// what buries the one line the user needs.
    ///
    /// So the assertion is: every refusal is a **single short line** plus the
    /// answer. Anything approaching a usage dump fails this.
    #[test]
    fn a_refusal_is_a_line_not_a_usage_dump() {
        for token in ["example.org", "user@example.org", "sttaus", "chatr", "nonsense"] {
            let m = unknown_verb(token, &crate::suggest::diagnose_no_subcommand(token));
            assert!(!m.contains("Usage:"), "{token} printed a usage header: {m}");
            assert!(!m.contains("For more information"), "{token} printed clap's trailer: {m}");
            // A line for each verb and a few more: never a usage dump.
            let lines = m.lines().count();
            assert!(lines <= VERBS.len() + 5, "{token} produced {lines} lines: {m}");
            assert!(m.contains("Try:") || m.contains("Run 'podssh --help'"), "{token} gave no next step: {m}");
        }
    }

    /// **The other half of the same guard**: the subcommand list is allowed,
    /// and it is what a user who mistyped a verb actually needs.
    #[test]
    fn the_subcommand_list_survives_a_refusal() {
        let m = unknown_verb("example.org", &NoSubcommand::Destination);
        for v in VERBS {
            assert!(m.contains(v.name), "the list omits {}", v.name);
        }
    }

    /// **An unknown subcommand names this build and the way to a newer one**
    /// (T-594): a tester of 1.0.0 planned on `podssh exit` from the page of
    /// `main`, and the refusal named no version. A word shaped as a host is a
    /// subcommand of no release, so it gets no such line.
    #[test]
    fn an_unknown_subcommand_names_the_version_and_a_newer_release() {
        let version = crate::version::line();
        assert!(version.contains(env!("CARGO_PKG_VERSION")), "{version}");
        for token in ["exit", "sttaus", "nonsense"] {
            let m = unknown_verb(token, &crate::suggest::diagnose_no_subcommand(token));
            let last = m.lines().last().unwrap_or_default();
            assert_eq!(
                last,
                format!("This is {version}; a newer release may have it: podssh update --check"),
                "{token}: {m}"
            );
        }
        let host = unknown_verb("example.org", &NoSubcommand::Destination);
        assert!(!host.contains("update --check"), "{host}");
    }

    /// **`podssh` with no arguments says it will not guess a destination**, which
    /// is the sentence that `docs/decisions.md` ("Product", 2026-10-01) turns into behaviour.
    #[test]
    fn no_arguments_says_it_will_not_connect() {
        let m = no_arguments();
        assert!(m.contains("never guesses a destination"), "{m}");
        assert!(!m.contains("Usage:"), "{m}");
        for v in VERBS {
            assert!(m.contains(v.name), "no-arguments omits {}", v.name);
        }
    }

    /// **An unknown flag's message names both ends**: what was given and the
    /// nearest known one. Without a suggestion it still says nothing was
    /// ignored, because a silently-dropped `-o` is the spec's security bug.
    #[test]
    fn an_unknown_flag_names_the_given_and_the_nearest() {
        let with = unknown_flag("ssh", "-StricthostKeyChekcing", Some("-StrictHostKeyChecking"), false);
        assert!(with.contains("-StricthostKeyChekcing"), "{with}");
        assert!(with.contains("Did you mean"), "{with}");
        assert!(with.contains("-StrictHostKeyChecking"), "{with}");

        let without = unknown_flag("ssh", "--qqqqq", None, false);
        assert!(without.contains("--qqqqq"), "{without}");
        // Each line starts with the verb, as its other lines do (T-1010).
        assert!(with.starts_with("podssh ssh: unknown flag") && without.starts_with("podssh ssh: "), "{with}");
        assert!(unknown_flag("", "--x", None, false).starts_with("podssh: unknown flag '--x'"));
        assert!(without.contains("podssh ssh --help"), "the verb's own help: {without}");
        assert!(unknown_flag("", "--x", None, false).contains("'podssh --help'"));
        assert!(given_twice("relay serve", "--mint").contains("--mint is given more than once"));
        assert!(negative_value("play", "-1").contains("--FLAG=-1"));
        let bytes = bad_invocation("ssh", clap::error::ErrorKind::InvalidUtf8, "");
        assert!(bytes.contains("not UTF-8"), "{bytes}");
        assert!(without.contains("Nothing was ignored"), "{without}");
        // The -o of the reassurance only where the verb takes -o (T-828)
        // and the command line gave one (T-868).
        let rows = [("ssh", true, true), ("ssh", false, false), ("node", true, false), ("node", false, false)];
        for (verb, given_o, says_o) in rows {
            let m = unknown_flag(verb, "--qqqqq", None, given_o);
            assert!(m.contains("the command did not run"), "{m}");
            assert_eq!(m.contains("-o"), says_o, "{verb} given -o {given_o}: {m}");
        }
        // Four lines: the flag, the next step, the reassurance, and nothing else.
        assert!(without.lines().count() <= 4, "{without}");
    }

    /// Each pair of [`APART`] says first that its two flags do not go
    /// together, then why; a pair it lacks still says the first (T-868).
    #[test]
    fn a_pair_that_does_not_go_together_says_so_first() {
        for (a, b, why) in APART {
            let line = apart(a, b);
            assert!(line.starts_with(&format!("{a} and {b} cannot be used together: ")), "{line}");
            assert!(line.ends_with(why) && !line.contains("give one"), "{line}");
        }
        assert_eq!(apart("--x", "--y"), "--x and --y cannot be used together");
    }

    /// **A count that clap refuses is a count, never a flag.** No verb has a
    /// count for clap to refuse since `mv` takes any (T-138), so the binary
    /// cannot show this message; a verb that gains one would.
    #[test]
    fn a_wrong_count_is_named_as_one() {
        for kind in [
            clap::error::ErrorKind::TooFewValues,
            clap::error::ErrorKind::TooManyValues,
            clap::error::ErrorKind::WrongNumberOfValues,
        ] {
            let m = bad_invocation("mv", kind, "");
            assert_eq!(m.lines().next(), Some("podssh mv: the right number of arguments was not given."), "{m}");
            assert!(!m.contains("unknown flag"), "{m}");
        }
    }
}
