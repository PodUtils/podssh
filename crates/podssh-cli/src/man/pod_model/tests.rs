//! The checks of `pod_manual::check` over podssh's manual: the rules of the
//! model, the text rules, the variables against the source, the exit codes
//! against the constants that the commands return, and the commands and
//! flags against the parser. Each check has a
//! control that plants a drift and finds it.

use super::*;
use pod_manual::check::{self, assert_none};
use pod_manual::scan;
use std::path::{Path, PathBuf};

fn crate_src(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(name).join("src")
}

/// The non-test source of the crates in this build's binary, without the
/// manual itself, which names each variable.
fn sources() -> Vec<(PathBuf, String)> {
    let mut crates = vec!["podssh-cli", "podssh-ssh", "podssh-relay", "podssh-ws"];
    // A road's crate is in the binary with its feature only. The Tor road is
    // `pod-tor` of podcrates now, which podssh-cli's glue gives its settings.
    for (on, name) in [
        (cfg!(feature = "iroh"), "podssh-iroh"),
        (cfg!(feature = "warp"), "podssh-warp"),
        (cfg!(feature = "ts"), "podssh-ts"),
        (cfg!(feature = "zerotier"), "podssh-zerotier"),
        (cfg!(feature = "gsr"), "podssh-gsr"),
    ] {
        if on {
            crates.push(name);
        }
    }
    let dirs: Vec<PathBuf> = crates.iter().map(|c| crate_src(c)).collect();
    let man = crate_src("podssh-cli").join("man");
    let mut out: Vec<(PathBuf, String)> =
        scan::rust_sources(&dirs).into_iter().filter(|(path, _)| !path.starts_with(&man)).collect();
    // The pager is pod-manual's, which podssh takes (T-820): its source, as
    // the crate gives it for this check.
    out.push((PathBuf::from("pod-manual/src/pager.rs"), pod_manual::pager::SOURCE.to_string()));
    out
}

/// Each exit code that podssh gives: 0, and each constant `EXIT_*` or
/// `EX_*` of a number in the crates that end the process. A code of the
/// payload (the remote command's status) is the row `N`.
fn given() -> Vec<i32> {
    let mut codes = vec![0];
    for (_, code) in scan::rust_sources(&[crate_src("podssh-cli"), crate_src("podssh-ssh")]) {
        for prefix in ["EXIT_", "EX_"] {
            for (_, n) in scan::exit_constants(&code, prefix) {
                if !codes.contains(&n) {
                    codes.push(n);
                }
            }
        }
    }
    codes
}

#[test]
fn the_model_keeps_its_own_rules() {
    assert_none(check::model(&manual()));
}

/// Each string of the manual and the help keeps the text rules: no
/// sentence over 25 words, no work id, no fault of a character.
#[test]
fn each_string_keeps_the_text_rules() {
    assert_none(check::texts(&manual()));
}

#[test]
fn each_variable_read_is_a_fact_and_each_fact_is_read() {
    assert_none(check::variables(&manual(), &sources(), &[]));
}

#[test]
fn each_exit_code_given_is_a_fact_and_each_fact_is_given() {
    assert_none(check::exit_codes(&manual(), &given()));
}

/// The controls of the sources and the codes: a wrong directory or a
/// reader that sees nothing would make each check above pass on nothing.
#[test]
fn the_sources_and_the_codes_are_read() {
    let read: Vec<String> = sources().iter().flat_map(|(_, code)| scan::variables_read(code)).collect();
    for name in ["PODSSH_SSH_CONFIG", "PODSSH_RELAY_TOKEN", "SSH_AUTH_SOCK"] {
        assert!(read.iter().any(|r| r == name), "no source reads {name}: {read:?}");
    }
    let codes = given();
    for code in [
        crate::exit_codes::EXIT_USAGE,
        crate::exitmap::sysexits::EX_CONFIG,
        crate::doctor::EXIT_FAILED,
        podssh_ssh::EXIT_FAILURE,
    ] {
        assert!(codes.contains(&code), "{code} is not found: {codes:?}");
    }
}

/// The drift that the entry plants: a variable that the code reads and no
/// fact names, a fact that no code reads, a code with no fact and a fact of
/// a code that nothing gives. Each is found.
#[test]
fn a_planted_drift_is_found() {
    let m = manual();
    let mut src = sources();
    src.push((PathBuf::from("planted.rs"), "fn f() { let _ = std::env::var(\"PODSSH_PLANTED_DRIFT\"); }".into()));
    let found = check::variables(&m, &src, &[]);
    assert!(found.iter().any(|f| f.at == "planted.rs" && f.what.contains("PODSSH_PLANTED_DRIFT")), "{found:?}");

    let mut unread = manual();
    unread.facts.variables[0].vars.push(pm::Var::reads(&["PODSSH_NEVER_READ"], "A planted fact."));
    let found = check::variables(&unread, &sources(), &[]);
    assert!(found.iter().any(|f| f.what.contains("PODSSH_NEVER_READ")), "{found:?}");

    let mut codes = given();
    codes.push(42);
    let found = check::exit_codes(&m, &codes);
    assert!(found.iter().any(|f| f.what.contains("gives 42")), "{found:?}");

    let mut extra = manual();
    extra.facts.exits.push(pm::Exit::new(3, "", "A planted fact."));
    let found = check::exit_codes(&extra, &given());
    assert!(found.iter().any(|f| f.what.contains("fact of 3")), "{found:?}");
}

/// The control of the text rules over this model: a long sentence in a note
/// of a command is found at that command.
#[test]
fn a_planted_long_note_is_found() {
    let mut m = manual();
    let ssh = m.commands.iter_mut().find(|c| c.path == ["ssh"]).expect("ssh");
    ssh.notes.push("word ".repeat(26));
    let found = check::texts(&m);
    assert!(found.iter().any(|f| f.at == "podssh ssh"), "{found:?}");
}

/// Each part of podssh's manual is in the model: each command with each
/// flag of a command that works, each variable, exit code, file and example,
/// and the topics that the model has no typed place for.
#[test]
fn the_model_holds_each_part_of_the_manual() {
    let m = manual();
    assert_eq!(m.commands.len(), VERBS.len() + 1, "the root and each verb");
    for verb in VERBS {
        let c = m.command(verb.name).unwrap_or_else(|| panic!("no command {}", verb.name));
        assert!(c.flag("--help").is_some(), "{}", verb.name);
        if flags::availability(verb) == Availability::Works {
            for row in verb.flags {
                let f = c.flag(&format!("--{}", row.long)).unwrap_or_else(|| panic!("{} --{}", verb.name, row.long));
                assert_eq!((f.short, f.value.as_deref(), f.help.as_str()), (row.short, row.arg, row.help));
                // Each writer's sentence of the flag is the one of `help_text`.
                assert_eq!(pm::sections::flag_text(f), crate::help::help_text(row), "{} --{}", verb.name, row.long);
            }
        }
        for alias in verb.aliases.iter().filter(|a| **a != verb.name) {
            assert_eq!(m.command(alias).map(|c| c.name()), Some(verb.name.to_string()), "{alias}");
        }
    }
    let vars: usize = m.facts.variables.iter().map(|g| g.vars.len()).sum();
    assert_eq!(vars, super::super::facts::variables().count());
    assert_eq!(m.facts.exits.len(), super::super::data::exit_codes().len());
    assert_eq!(m.facts.files.len(), super::super::data::files().len());
    assert_eq!(m.examples.len(), super::super::examples::section().blocks.len());
    assert!(!m.description.is_empty() && !m.see_also.is_empty());
    for key in ["relay-facts", "keywords", "retired-variables"] {
        let t = m.topics.iter().find(|t| t.key == key).unwrap_or_else(|| panic!("no topic {key}"));
        assert!(!t.blocks.is_empty(), "the topic {key} is empty");
    }
    // The keywords are in their topic, and their paragraphs are no notes of ssh.
    let keywords = m.topics.iter().find(|t| t.key == "keywords").expect("keywords");
    let first = crate::ssh::keywords::HONOURED[0].help;
    let item = keywords.blocks.iter().any(|b| matches!(b, pm::Block::Item { text, .. } if text == first));
    assert!(item, "{first}");
    let ssh = m.command("ssh").expect("ssh");
    let paras = keywords.blocks.iter().filter_map(|b| match b {
        pm::Block::Para { text } => Some(text),
        _ => None,
    });
    for p in paras {
        assert!(!ssh.notes.contains(p), "{p}");
    }
    assert!(m.commands.iter().any(|c| c.flags.iter().any(|f| f.repeatable)), "no flag may be repeated");
    // The keywords show inside ssh's section, and no other command holds them.
    assert_eq!(ssh.topics, [KEYWORDS_KEY], "ssh's topics");
    assert!(m.commands.iter().filter(|c| c.path != ["ssh"]).all(|c| c.topics.is_empty()));
}

/// Each kind of a row is the crate's kind: the JSON keeps what the text
/// says, and an empty reason or replacement gives the crate's short
/// sentence alone.
#[test]
fn each_kind_of_a_row_is_the_crate_s() {
    let mut seen = Vec::new();
    for row in VERBS.iter().flat_map(|v| v.flags.iter()) {
        let k = kind(row);
        let want = match (row.kind, &k) {
            (FlagKind::Supported, pm::FlagKind::Wired) => true,
            (FlagKind::Accepted, pm::FlagKind::Ignored { why }) => why.is_empty(),
            (FlagKind::Refused, pm::FlagKind::Refused { instead }) => match row.instead {
                Some("no flag") => instead.is_empty(),
                other => other == Some(instead.as_str()),
            },
            (FlagKind::NotInFirstRelease, pm::FlagKind::NotInRelease { code, .. }) => {
                *code == crate::exit_codes::EXIT_USAGE
            }
            _ => false,
        };
        assert!(want, "--{}: {:?} as {k:?}", row.long, row.kind);
        if !seen.contains(&row.kind) {
            seen.push(row.kind);
        }
    }
    // The control: the table has rows of the three kinds in use.
    for k in [FlagKind::Supported, FlagKind::Accepted, FlagKind::Refused] {
        assert!(seen.contains(&k), "no row of {k:?}");
    }
    let accepted = VERBS.iter().flat_map(|v| v.flags.iter()).find(|r| r.kind == FlagKind::Accepted).expect("a row");
    let text = crate::help::help_text(accepted);
    assert!(text.ends_with(". Accepted and ignored."), "{text}");
}

/// A verb behind a cargo feature says so in each build, with the code that
/// a build without it gives; each other verb is in each build.
#[test]
fn the_availability_of_a_verb_is_in_the_model() {
    let m = manual();
    for verb in VERBS {
        let c = m.command(verb.name).expect("a command");
        match flags::needed_feature(verb) {
            Some(name) => {
                let pm::Availability::Feature { name: n, code, why } = &c.availability else {
                    panic!("{}: {:?}", verb.name, c.availability)
                };
                assert_eq!((n.as_str(), *code), (name, crate::exit_codes::EXIT_NOT_IMPLEMENTED));
                assert!(!why.is_empty());
            }
            None => assert!(c.availability.is_always(), "{}", verb.name),
        }
        if flags::availability(verb) != Availability::Works {
            assert_eq!(c.flags.len(), 1, "{}: options other than --help", verb.name);
            assert!(c.args.is_empty() && c.about.contains("(not "), "{}", verb.name);
        }
    }
    assert!(VERBS.iter().any(|v| flags::needed_feature(v).is_some()), "no verb behind a feature");
}

/// Each verb and alias selects its section, and each topic its own; the
/// keywords select ssh's, where they are shown.
#[test]
fn each_name_selects_its_section() {
    use pm::sections::{find, sections};
    let m = manual();
    let all = sections(&m);
    for verb in VERBS {
        for name in verb.aliases {
            let s = find(&m, &all, name).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(s.command.as_deref(), Some(&[verb.name.to_string()][..]), "{name}");
        }
    }
    for key in ["relay-facts", "retired-variables", "environment", "env", "files", "exit-status", "examples"] {
        let s = find(&m, &all, key).unwrap_or_else(|| panic!("{key}"));
        assert!(s.command.is_none(), "{key}");
    }
    let keywords = find(&m, &all, KEYWORDS_KEY).expect("keywords");
    assert_eq!(keywords.command.as_deref(), Some(&["ssh".to_string()][..]));
    assert!(find(&m, &all, "relay").is_some_and(|s| s.command.is_some()), "relay is the command");
    assert!(find(&m, &all, "nonsense").is_none());
}

/// The help of the `man` section argument names each topic there is.
#[test]
fn the_section_argument_names_each_topic() {
    let m = manual();
    let help = crate::tree::verb_command(crate::flags::verb_for("man").unwrap())
        .get_positionals()
        .find_map(|a| a.get_help().map(|h| h.to_string()))
        .unwrap();
    for s in pm::sections::sections(&m).iter().filter(|s| s.command.is_none()) {
        assert!(help.contains(&s.key), "the help of SECTION does not name {:?}: {help}", s.key);
    }
}

/// The text of the manual reads in an 80-column terminal and in any log:
/// ASCII, no trailing space, and no line wider than the page but a command
/// line kept whole (an example's, a line kept as it is) or one long word.
#[test]
fn the_text_fits_the_page_and_is_ascii() {
    let m = manual();
    let page = pm::text::render(&m);
    assert!(page.is_ascii(), "the page is not ASCII");
    // A command line is kept whole, as its wrap would change it: an example's
    // (the manual's, a command's lead, a topic's) and a line kept as it is.
    let mut commands: Vec<String> = m.examples.iter().map(|e| e.command.clone()).collect();
    commands.extend(m.commands.iter().flat_map(|c| c.lead.iter().map(|e| e.command.clone())));
    for block in m.topics.iter().flat_map(|t| t.blocks.iter()) {
        match block {
            pm::Block::Example { command, .. } => commands.push(command.clone()),
            pm::Block::Line { spans } => commands.push(pm::model::plain(spans)),
            _ => {}
        }
    }
    let kept = |line: &str| {
        let shown = line.trim();
        commands.iter().any(|c| shown == c || shown.strip_prefix("$ ") == Some(c.as_str()))
    };
    for line in page.lines() {
        assert_eq!(line, line.trim_end(), "trailing space: {line:?}");
        if line.chars().count() > pm::text::WIDTH && !kept(line) {
            assert_eq!(line.split_whitespace().count(), 1, "a line of {} characters: {line:?}", line.len());
        }
    }
    assert!(page.starts_with(&format!("podssh {} - {}\n", crate::help::version(), flags::ABOUT)), "the title");
    for v in VERBS {
        assert!(page.contains(&format!("\npodssh {}\n", v.name)), "no section {}", v.name);
    }
}

/// What the parser knows of the command at `path`. The root: each option
/// before a command that `tree::parse` answers, and each verb that it
/// selects. A verb: the flags of the clap command that `tree.rs` builds.
/// A verb that does not work here exits 70 before it reads a flag, and its
/// help and the manual show `--help` alone: so does its row here.
fn parser(path: &[String]) -> Option<check::ParserCommand> {
    use crate::tree::Parsed;
    match path {
        [] => {
            let answered = |w: &str| matches!(crate::tree::parse([w]), Parsed::Help(_) | Parsed::Version);
            let rows = flags::TOP_OPTIONS
                .iter()
                .filter(|(short, long, _)| answered(short) && answered(long))
                .map(|(short, long, _)| check::ParserFlag {
                    spellings: vec![short.to_string(), long.to_string()],
                    takes_value: false,
                })
                .collect();
            let subcommands = VERBS
                .iter()
                .filter(|v| flags::verb_for(v.name).is_some_and(|f| f.name == v.name))
                .map(|v| v.name.to_string())
                .collect();
            Some(check::ParserCommand { flags: rows, subcommands })
        }
        [name] => {
            let verb = flags::verb_for(name).filter(|v| v.name == name.as_str())?;
            let works = flags::availability(verb) == Availability::Works;
            let command = crate::tree::verb_command(verb);
            let rows = command
                .get_arguments()
                .filter(|a| !a.is_positional() && !a.is_hide_set())
                .filter(|a| works || a.get_id().as_str() == flags::HELP_FLAG.long)
                .map(|a| {
                    let mut spellings: Vec<String> = a.get_short().map(|c| format!("-{c}")).into_iter().collect();
                    spellings.extend(a.get_long().map(|l| format!("--{l}")));
                    check::ParserFlag { spellings, takes_value: a.get_action().takes_values() }
                })
                .collect();
            Some(check::ParserCommand { flags: rows, subcommands: Vec::new() })
        }
        _ => None,
    }
}

#[test]
fn each_command_and_flag_is_the_parser_s() {
    assert_none(check::flags(&manual(), parser));
}

/// The controls of the check of the flags: the parser is read (the root
/// and `ssh` have their rows), and a flag in the model that the parser
/// lacks, a flag of the parser that the model lacks and a value that the
/// two read differently are each found.
#[test]
fn a_planted_drift_of_a_flag_is_found() {
    let root = parser(&[]).expect("the root");
    assert_eq!(root.flags.len(), flags::TOP_OPTIONS.len(), "{root:?}");
    assert_eq!(root.subcommands.len(), VERBS.len());
    let ssh = parser(&["ssh".to_string()]).expect("ssh");
    assert!(ssh.flags.iter().any(|f| f.spellings == ["-p", "--port"] && f.takes_value), "{ssh:?}");

    let mut m = manual();
    let c = m.commands.iter_mut().find(|c| c.path == ["ssh"]).expect("ssh");
    c.flags.push(pm::Flag::long("planted-flag", "A planted flag."));
    let port = c.flags.iter_mut().find(|f| f.long.as_deref() == Some("port")).expect("--port");
    port.value = None;
    c.flags.retain(|f| f.long.as_deref() != Some("verbose"));
    let found = check::flags(&m, parser);
    for want in ["--planted-flag", "-p, --port takes a value", "--verbose"] {
        assert!(found.iter().any(|f| f.at == "podssh ssh" && f.what.contains(want)), "{want}: {found:?}");
    }
}
