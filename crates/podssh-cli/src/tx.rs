//! `podssh tx send FILE` and `podssh tx receive [DIR]` (T-831): the far end
//! of the 7-bit envelope, typed in the shell of a `podssh ssh` session whose
//! terminal damages ZMODEM (tmux). The transfer is `podssh_ssh::zmodem::far`;
//! this reads the words, and gives its end one line on stderr and an exit
//! code. The frames are on the process's own terminal, never on a sink.

use std::io::Write;
use std::path::PathBuf;

use clap::ArgMatches;
use podssh_ssh::zmodem::far::{self, Failure};

use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::{EX_CANTCREAT, EX_DATAERR, EX_NOINPUT, EX_TEMPFAIL};

/// The arguments of `podssh tx`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TxArgs {
    pub subcommand: Option<String>,
    pub args: Vec<String>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl TxArgs {
    /// Read the words out of `tx`'s matches.
    pub fn from_matches(m: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> Self {
        TxArgs {
            subcommand: m.get_one::<String>("subcommand").cloned(),
            args: m.get_many::<String>("args").map(|v| v.cloned().collect()).unwrap_or_default(),
            refused,
        }
    }
}

/// What the words ask.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ask {
    Send(PathBuf),
    Receive(PathBuf),
}

/// The words, or the line of a usage error.
fn ask(args: &TxArgs) -> Result<Ask, String> {
    match (args.subcommand.as_deref(), args.args.as_slice()) {
        (Some("send"), [file]) => Ok(Ask::Send(PathBuf::from(file))),
        (Some("send"), _) => Err("send takes one file: podssh tx send FILE".to_string()),
        (Some("receive"), []) => Ok(Ask::Receive(PathBuf::from("."))),
        (Some("receive"), [dir]) => Ok(Ask::Receive(PathBuf::from(dir))),
        (Some("receive"), _) => Err("receive takes one directory at most: podssh tx receive [DIR]".to_string()),
        (Some(other), _) => Err(format!("{other:?} is not a subcommand of tx; it has send and receive")),
        (None, _) => Err("give a subcommand: podssh tx send FILE, or podssh tx receive [DIR]".to_string()),
    }
}

/// The line of `words` (the command line after `tx`) that [`ask`] refuses,
/// for a command line that the parser refused first: `send a b` gets tx's
/// own words, not the parser's (T-1019). A word that is a flag is the
/// parser's to say.
pub(crate) fn refused_words(words: &[&str]) -> Option<String> {
    if words.iter().any(|word| word.starts_with('-')) {
        return None;
    }
    let mut words = words.iter().map(|word| word.to_string());
    let args = TxArgs { subcommand: words.next(), args: words.collect(), refused: Vec::new() };
    ask(&args).err()
}

/// The exit code of each failure, as the manual's notes of `tx` give them.
fn code(failure: &Failure) -> i32 {
    match failure {
        Failure::Usage(_) => EXIT_USAGE,
        Failure::Data(_) => EX_DATAERR,
        Failure::NoInput(_) => EX_NOINPUT,
        Failure::CantCreate(_) => EX_CANTCREAT,
        Failure::Stopped(_) => EX_TEMPFAIL,
    }
}

fn line(failure: &Failure) -> &str {
    match failure {
        Failure::Usage(l) | Failure::Data(l) | Failure::NoInput(l) | Failure::CantCreate(l) | Failure::Stopped(l) => l,
    }
}

pub fn run(args: &TxArgs, err: &mut dyn Write) -> i32 {
    let outcome = match ask(args) {
        Ok(Ask::Send(file)) => far::send(&file),
        Ok(Ask::Receive(dir)) => far::receive(&dir),
        Err(why) => Err(Failure::Usage(why)),
    };
    match outcome {
        Ok(done) => {
            let _ = writeln!(err, "podssh tx: {done}");
            0
        }
        Err(failure) => {
            let _ = writeln!(err, "podssh tx: {}", line(&failure));
            code(&failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> TxArgs {
        TxArgs {
            subcommand: words.first().map(|w| w.to_string()),
            args: words.iter().skip(1).map(|w| w.to_string()).collect(),
            refused: Vec::new(),
        }
    }

    /// The words and what they ask, one table: each other shape is a usage
    /// error, before any terminal is touched.
    #[test]
    fn the_words_ask_one_thing_or_are_refused() {
        let cases: &[(&[&str], Option<Ask>)] = &[
            (&["send", "a.bin"], Some(Ask::Send("a.bin".into()))),
            (&["receive"], Some(Ask::Receive(".".into()))),
            (&["receive", "/tmp"], Some(Ask::Receive("/tmp".into()))),
            (&["send"], None),
            (&["send", "a", "b"], None),
            (&["receive", "a", "b"], None),
            (&["recv"], None),
            (&[], None),
        ];
        for (words, want) in cases {
            assert_eq!(ask(&args(words)).ok(), *want, "{words:?}");
        }
    }

    /// The help's usage shows what the parser takes: one argument at most,
    /// and the parser refuses a second one before `ask` is reached.
    #[test]
    fn the_help_shows_one_argument_and_the_parser_takes_one() {
        let verb = crate::flags::verb_for("tx").expect("the verb tx");
        let help = crate::help::verb_help(verb).split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(help.contains("Usage: podssh tx send FILE | receive [DIR]"), "{help}");
        assert!(!help.contains("[FILE | DIR]..."), "{help}");
        // Refused in tx's own words, one line (T-1019).
        let rows = [
            (["tx", "send", "a", "b"], "podssh tx: send takes one file: podssh tx send FILE"),
            (["tx", "receive", "a", "b"], "podssh tx: receive takes one directory at most: podssh tx receive [DIR]"),
        ];
        for (words, line) in rows {
            match crate::tree::parse(words) {
                crate::tree::Parsed::Usage(m) => assert_eq!(m, line, "{words:?}"),
                other => panic!("{words:?}: {other:?}"),
            }
        }
        assert!(matches!(crate::tree::parse(["tx", "receive", "a"]), crate::tree::Parsed::Tx(_)));
    }

    /// Each failure has its own documented code, none of them 0, 1 or 2.
    #[test]
    fn each_failure_has_its_code() {
        let all = [
            (Failure::Usage(String::new()), 64),
            (Failure::Data(String::new()), 65),
            (Failure::NoInput(String::new()), 66),
            (Failure::CantCreate(String::new()), 73),
            (Failure::Stopped(String::new()), 75),
        ];
        for (failure, want) in all {
            assert_eq!(code(&failure), want, "{failure:?}");
        }
    }

    /// With no terminal, nothing is sent and the run says why, with 64.
    #[test]
    fn with_no_terminal_it_is_a_usage_error() {
        // A test's stdin is no terminal; where it is one, a run would start
        // a real transfer, so nothing is run.
        if podssh_ssh::terminal::stdin_is_terminal() {
            return;
        }
        let mut err = Vec::new();
        let code = run(&args(&["receive"]), &mut err);
        let err = String::from_utf8_lossy(&err);
        assert_eq!(code, 64, "{err}");
        assert!(err.contains("must be a terminal"), "{err}");
    }
}
