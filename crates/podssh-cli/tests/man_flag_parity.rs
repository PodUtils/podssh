//! The parity gate: `--help` and the manual must show the same flags, with
//! the same value names and the same sentences, and both must be the flag
//! table. Each side is read from the text that a user sees (the readers
//! are in `man_extract/`), in both directions, and each failure names the
//! flag. Both are pod-manual's writers over one model; the gate holds them
//! to it from the outside.

use podssh_cli::flags::{Availability, FlagRow, VERBS};
use podssh_cli::{help, man};

mod man_extract;
use man_extract::*;

/// The option that every verb takes. The parser declares it, so it is in no
/// verb's table.
const UNIVERSAL: &str = "--help";

/// A gate that read nothing would pass on nothing.
#[test]
fn the_readers_are_not_vacuous() {
    let page = man::page();
    let regions = man_regions(&page);
    assert!(regions.contains_key(""), "no region for the options before a command");
    for (name, verb) in sections() {
        let expected = tree_map(verb);
        let h = flag_map(&options(&help_text(verb)), verb);
        let m = flag_map(&options(regions.get(&name).unwrap_or_else(|| panic!("no region {name:?}"))), verb);
        assert!(h.len() >= expected.len(), "{name:?}: help gave {} flags, the table has {}", h.len(), expected.len());
        assert!(
            m.len() >= expected.len(),
            "{name:?}: the manual gave {} flags, the table has {}",
            m.len(),
            expected.len()
        );
    }
    // The flags that a careless reader loses: digits, a long-only flag, and
    // a row whose meaning differs between verbs.
    let ssh = VERBS.iter().find(|v| v.name == "ssh").unwrap();
    let items = options(regions.get("ssh").unwrap());
    let ssh_page = flag_map(&items, Some(ssh));
    for want in ["--port", "--tag", "--forward-local", "--StrictHostKeyChecking", "--ipv4-only"] {
        assert!(ssh_page.contains_key(want), "the manual reader missed {want}");
    }
    let port = items.iter().find(|i| i.flags.iter().any(|f| f == "-p")).expect("an item for -p");
    assert!(port.flags.iter().any(|f| f == "--port"), "one spelling only: {port:?}");
    assert!(!port.text.is_empty(), "no sentence for -p: {port:?}");
}

#[test]
fn each_section_shows_the_same_flags_in_help_and_in_the_manual() {
    let page = man::page();
    let regions = man_regions(&page);
    for (name, verb) in sections() {
        let h = flag_map(&options(&help_text(verb)), verb);
        let m = flag_map(&options(regions.get(&name).unwrap()), verb);
        let missing: Vec<&String> = h.keys().filter(|k| !m.contains_key(*k)).collect();
        let extra: Vec<&String> = m.keys().filter(|k| !h.contains_key(*k)).collect();
        assert!(missing.is_empty(), "{name:?}: in --help, not in the manual: {missing:?}");
        assert!(extra.is_empty(), "{name:?}: in the manual, not in --help: {extra:?}");
        assert_eq!(h, m, "{name:?}: the value names differ");
    }
}

#[test]
fn each_section_shows_the_flags_of_the_table() {
    let page = man::page();
    let regions = man_regions(&page);
    for (name, verb) in sections() {
        let expected = tree_map(verb);
        let h = flag_map(&options(&help_text(verb)), verb);
        let m = flag_map(&options(regions.get(&name).unwrap()), verb);
        for (label, got) in [("--help", &h), ("the manual", &m)] {
            let missing: Vec<&String> = expected.keys().filter(|k| !got.contains_key(*k)).collect();
            let extra: Vec<&String> = got.keys().filter(|k| !expected.contains_key(*k)).collect();
            assert!(missing.is_empty(), "{name:?}: {label} leaves out {missing:?}");
            assert!(extra.is_empty(), "{name:?}: {label} has {extra:?}, which the table does not");
            assert_eq!(&expected, got, "{name:?}: {label} shows other value names than the table");
        }
    }
}

/// Each sentence in the manual and in `--help` is the one of the row, and
/// each command's section has the usage that its `--help` has.
#[test]
fn each_description_is_the_one_help_prints() {
    let page = man::page();
    let regions = man_regions(&page);
    for (name, verb) in sections() {
        let region = regions.get(&name).unwrap();
        let want = sentences(verb);
        let help = help_text(verb);
        for (label, text) in [("--help", help.as_str()), ("the manual", region.as_str())] {
            let got = descriptions(&options(text), verb);
            for (flag, sentence) in &want {
                let shown = got.get(flag).unwrap_or_else(|| panic!("{name:?}: {label} has no {flag}"));
                assert_eq!(squeeze(shown), squeeze(sentence), "{name:?}: {label}: {flag}");
            }
        }
        if let Some(v) = verb {
            let usage = format!("Usage: podssh {} {}", v.name, help::usage_tail(v));
            assert!(squeeze(region).contains(&squeeze(&usage)), "{name}: no usage {usage:?}");
            assert!(squeeze(&help).contains(&squeeze(&usage)), "{name}: --help has another usage");
        }
    }
}

/// A command that does not work in this binary says so in both renderings
/// and in the list of commands, and neither shows an option of it.
#[test]
fn a_command_that_does_not_work_says_so_in_both() {
    let page = man::page();
    let regions = man_regions(&page);
    let top = squeeze(&help::top_level_help());
    let broken: Vec<_> = VERBS.iter().filter(|v| podssh_cli::flags::availability(v) != Availability::Works).collect();
    // Each command works in a build with the feature ts; in another, ts
    // does not, so this check has a command to check.
    #[cfg(not(feature = "ts"))]
    assert!(!broken.is_empty(), "no command to check");
    #[cfg(feature = "ts")]
    if broken.is_empty() {
        return;
    }
    for v in broken {
        let region = regions.get(v.name).unwrap_or_else(|| panic!("no section for {}", v.name));
        let own = help::verb_help(v);
        let row = format!("{} {}{}", v.name, v.about, help::availability_note(v));
        assert!(top.contains(&squeeze(&row)), "{}: the list of commands does not mark it", v.name);
        for (label, text) in [("--help", own.as_str()), ("the manual", region.as_str())] {
            assert!(squeeze(text).contains("exits 70"), "{}: {label} does not say that it exits 70", v.name);
            let items = options(text);
            assert_eq!(items.len(), 1, "{}: {label} shows options other than --help: {items:?}", v.name);
            assert!(items[0].flags.iter().any(|f| f == UNIVERSAL), "{}: {label}: {items:?}", v.name);
        }
    }
}

/// The list of options is each row of the table in its order, then
/// `--help`, each term on a line of its own four spaces in: a term that
/// ran into its sentence, or a row out of the list, fails here.
#[test]
fn the_options_are_the_rows_in_order_then_help() {
    for v in VERBS {
        let text = help::verb_help(v);
        let shown: &[FlagRow] = if podssh_cli::flags::availability(v) == Availability::Works { v.flags } else { &[] };
        let rows: Vec<&FlagRow> = shown.iter().chain(std::iter::once(&podssh_cli::flags::HELP_FLAG)).collect();
        let want: Vec<String> = rows.iter().map(|r| format!("--{}", r.long)).collect();
        let got: Vec<String> =
            options(&text).iter().map(|i| i.flags.last().map(|f| canonical(Some(v), f)).unwrap_or_default()).collect();
        assert_eq!(got, want, "{}: the options are not the rows in order", v.name);
        for row in rows {
            let mut term = match row.short {
                Some(c) => format!("-{c}, --{}", row.long),
                None => format!("--{}", row.long),
            };
            if let Some(a) = row.arg {
                term = format!("{term} {a}");
            }
            assert!(text.lines().any(|l| l == format!("    {term}")), "{}: {term:?} is not a line of its own", v.name);
        }
    }
}

/// T-1071: where a name validator refuses a leading `-`, its `--help` and
/// manual text say `not first a -` too, with the same length limit.
#[test]
fn help_and_manual_state_leading_hyphen_rule_for_session_and_detach_names() {
    let page = man::page();
    let regions = man_regions(&page);
    let session_rule = format!("letters, digits, _ and -, not first a -, {} at most", podssh_cli::session::NAME_MAX);
    let detach_rule =
        format!("letters, digits, _ and -, not first a -, {} at most", podssh_cli::detach::lock::NAME_MAX);
    let session_err = podssh_cli::session::check_name("-x").unwrap_err();
    let detach_err = podssh_cli::detach::lock::check_name("-x").unwrap_err();
    for (verb, expected, err) in [
        ("session", session_rule.as_str(), session_err.as_str()),
        ("ssh", detach_rule.as_str(), detach_err.as_str()),
        ("pipe", detach_rule.as_str(), detach_err.as_str()),
        ("node", detach_rule.as_str(), detach_err.as_str()),
    ] {
        let v = VERBS.iter().find(|v| v.name == verb).unwrap_or_else(|| panic!("no verb {verb}"));
        let help = squeeze(&help::verb_help(v));
        let region = squeeze(regions.get(verb).unwrap_or_else(|| panic!("no region {verb}")));
        assert!(err.contains(expected), "{verb}: error {err:?} does not hold {expected:?}");
        assert!(help.contains(expected), "{verb}: --help does not hold {expected:?}");
        assert!(region.contains(expected), "{verb}: manual does not hold {expected:?}");
    }
}
