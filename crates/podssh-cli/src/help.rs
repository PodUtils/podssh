//! `--help`: pod-manual's help over the manual's model
//! ([`crate::man::pod_model`]).
//!
//! The help of a command is the blocks of its section of `podssh man`, so
//! the two cannot differ: the same about line, notes, usage, arguments,
//! options and examples. Nothing here writes a flag down; each flag's
//! sentence is the crate's over the row of `flags.rs`.
//!
//! **The width is fixed and is not probed.** The crate fills to 79
//! columns. `clap`'s `wrap_help` feature stays off in `Cargo.toml`: it pulls
//! `terminal_size`, a probe of a capability, and `AGENTS.md` (section 5,
//! rule 1) forbids a capability that was not probed. A fixed width also
//! keeps the parity gate a comparison of strings.

use crate::flags::{FlagRow, Verb};

/// The help of the command at `path`; the program's when it is empty.
fn render(path: &[String]) -> String {
    let manual = crate::man::pod_model::manual();
    // Each path here is the root or a verb of the model; an error is a
    // defect, shown in place of the help rather than hidden.
    pod_manual::help::render(&manual, path).unwrap_or_else(|e| format!("{e}\n"))
}

/// The help of the program: what it is, the commands by purpose, and the
/// options before a command.
pub fn top_level_help() -> String {
    render(&[])
}

/// One verb's help: its section of the manual.
pub fn verb_help(verb: &'static Verb) -> String {
    render(&[verb.name.to_string()])
}

/// **The sentence of a flag, one copy for each writer.** The crate's text
/// of the row: its help with a stop, then what its kind adds ("Accepted
/// and ignored.", "Refused. Use X."). The parity gate and the tests compare
/// each writer's text with this.
pub fn help_text(row: &FlagRow) -> String {
    pod_manual::sections::flag_text(&crate::man::pod_model::row_flag(row))
}

/// What the list of commands adds to the about line of a verb that does not
/// work here.
pub fn availability_note(verb: &Verb) -> &'static str {
    match crate::flags::availability(verb) {
        crate::flags::Availability::Works => "",
        crate::flags::Availability::NotYet => " (not implemented yet)",
        crate::flags::Availability::NotInBuild => " (not in this build)",
    }
}

// The notes that the flags of a verb cannot say, in a file of their own for
// the length of this one.
pub mod json;
mod notes;
pub use notes::{verb_notes, PROXY_OF_SSH};

/// **The usage tail, and it is public for the same reason [`help_text`] is:**
/// The manual page prints `podssh <verb> <this>`, and the parity gate asserts the
/// page carries the string `--help` prints rather than a second copy of it.
pub fn usage_tail(verb: &Verb) -> &'static str {
    match verb.name {
        "ssh" => "[OPTIONS] [--] [user@]host [COMMAND...]",
        "each" => "[OPTIONS] HOSTS [--] COMMAND...",
        "containers" => "[OPTIONS] [user@]host",
        "job" => "[OPTIONS] SUBCOMMAND HOST [ID [DIR]] [-- COMMAND...]",
        "run" => "[OPTIONS] [user@]host[:DIR] [--] COMMAND...",
        "cp" | "mv" | "scp" => "[OPTIONS] SRC... DST",
        "sftp" => "[OPTIONS] DESTINATION",
        "edit" => "[OPTIONS] [user@]host:PATH",
        "tx" => "SUBCOMMAND [FILE | DIR]",
        "chat" => "[OPTIONS] PEER",
        "man" => "[OPTIONS] [SECTION]",
        "relay" => "[OPTIONS] SUBCOMMAND [NAME | HOST PORT]",
        "node" => "[OPTIONS] NAME [TARGET] [ROUTE=TARGET]...",
        "exit" => "[OPTIONS] NAME --listen ADDR:PORT",
        "share" => "[OPTIONS] SUBCOMMAND [NAME=TARGET | NAME]",
        "funnel" => "[OPTIONS] TARGET",
        "operator" => "[OPTIONS] NAME",
        "proxy" => "[OPTIONS] [--] HOST PORT | node://NAME[/ROUTE]",
        "health" => "[OPTIONS] [user@]host",
        "play" => "[OPTIONS] FILE",
        "config" => "import FORMAT FILE",
        "session" => "SUBCOMMAND [OPTIONS] [NAME] [HOST [COMMAND...] | TEXT]",
        "detached" => "SUBCOMMAND [OPTIONS] [NAME]",
        "net" => "[OPTIONS] SUBCOMMAND [NAME [KEY] | FILE | FROM TO]",
        _ => "[OPTIONS]",
    }
}

/// The version string. Read from the manifest at compile time, so it cannot
/// drift from the crate it ships in.
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags::{FlagKind, VERBS};

    fn verb(name: &str) -> &'static Verb {
        VERBS.iter().find(|v| v.name == name).unwrap()
    }

    fn squeeze(t: &str) -> String {
        t.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn the_top_level_help_lists_every_verb() {
        let h = top_level_help();
        for v in VERBS {
            assert!(h.lines().any(|l| l.split_whitespace().next() == Some(v.name)), "help omits {}", v.name);
        }
    }

    /// The options before a command are an item each: the spellings on a
    /// line of their own, then the sentence.
    #[test]
    fn each_top_level_option_is_its_term_then_its_sentence() {
        let h = top_level_help();
        for (term, sentence) in [
            ("-h, --help", "Print help; --help COMMAND prints the help of one command."),
            ("-V, --version", "Print the version, and the commit of a release build."),
        ] {
            assert!(h.lines().any(|l| l == format!("    {term}")), "{term:?} is not a line of its own:\n{h}");
            assert!(squeeze(&h).contains(&format!("{term} {sentence}")), "{term}: {h}");
        }
    }

    #[test]
    fn help_names_the_other_names_of_a_verb() {
        assert!(squeeze(&verb_help(verb("chat"))).contains("Other names: podssh irc"));
        assert!(squeeze(&verb_help(verb("keygen"))).contains("Other names: podssh ssh-keygen"));
    }

    #[test]
    fn a_refused_flag_says_so_in_help_not_only_when_used() {
        let ssh = verb_help(verb("ssh"));
        assert!(ssh.lines().any(|l| l.trim() == "-L, --forward-local SPEC"), "{ssh}");
        let refused = crate::flags::SSH_FLAGS.iter().find(|r| r.kind == FlagKind::Refused).expect("a refused row");
        let text = help_text(refused);
        assert!(text.contains("Refused."), "{text}");
        assert!(squeeze(&ssh).contains(&squeeze(&text)), "{text}");
        assert!(squeeze(&ssh).contains("-W HOST:PORT"), "{ssh}");
    }

    /// -R needs no local listener: the server listens. Its row and its note
    /// say so, and neither borrows the cause of -L and -D nor offers -W,
    /// which carries the other direction.
    #[test]
    fn the_lines_about_r_say_that_the_server_listens() {
        let row = crate::flags::SSH_FLAGS.iter().find(|r| r.short == Some('R')).expect("-R");
        let notes: Vec<String> = verb_notes(verb("ssh")).into_iter().filter(|n| n.starts_with("-R")).collect();
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("the server listens"), "{notes:?}");
        for text in [help_text(row), notes[0].clone()] {
            for word in ["never", "local listener", "-W", "not implemented"] {
                assert!(!text.contains(word), "{word}: {text}");
            }
        }
    }

    /// Each flag's spellings and value are a line of their own: the term
    /// cannot run into its sentence, as `-W, --stdio-forward HOST:PORT` once
    /// ran into "forward stdio" in a column too narrow for it.
    #[test]
    fn no_flag_runs_into_its_description() {
        for v in VERBS.iter().filter(|v| crate::flags::availability(v) == crate::flags::Availability::Works) {
            let help = verb_help(v);
            for row in v.flags.iter().chain(std::iter::once(&crate::flags::HELP_FLAG)) {
                let term = crate::man::pod_model::row_flag(row).term();
                assert!(help.lines().any(|l| l == format!("    {term}")), "{}: {term:?}:\n{help}", v.name);
            }
        }
    }

    /// **An accepted flag says it once.** `-P`'s row once ended with the
    /// words that the kind adds, so the help said them twice. scp's `-3` is
    /// accepted; `-P` of ssh is honoured.
    #[test]
    fn an_accepted_flag_says_it_once() {
        let row = crate::flags::SCP_FLAGS.iter().find(|r| r.long == "through-this-host").expect("-3");
        assert_eq!(help_text(row).to_lowercase().matches("accepted and ignored").count(), 1, "{}", help_text(row));
        assert!(squeeze(&verb_help(verb("scp"))).contains(&squeeze(&help_text(row))));
        let tag = crate::flags::SSH_FLAGS.iter().find(|r| r.long == "tag").expect("-P, --tag");
        assert!(!help_text(tag).to_lowercase().contains("accepted and ignored"), "{}", help_text(tag));
    }

    /// A verb that the build lacks keeps its help: the sentence of the
    /// crate, and no option but `--help`.
    #[test]
    fn a_verb_that_the_build_lacks_says_so() {
        let ts = verb("ts");
        let help = squeeze(&verb_help(ts));
        assert!(help.contains("Only a build with the feature ts has this command"), "{help}");
        assert!(help.contains("Each other build exits 70."), "{help}");
        if crate::flags::availability(ts) != crate::flags::Availability::Works {
            assert!(!help.contains("--ts-auth-key-file"), "{help}");
        }
    }
}
