//! The tests of the manual's examples (`examples.rs`): each podssh command
//! line parses with the binary's own parser.

use super::*;
use crate::tree::{parse, Parsed};

/// Shell words, with single and double quotes; stops at an operator.
fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for c in line.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => word.push(c),
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                started = true;
            }
            None if c.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            None => {
                word.push(c);
                started = true;
            }
        }
    }
    if started {
        words.push(word);
    }
    words
}

/// The parts of a command line between the operators |, <, >, ; and &&,
/// outside quotes.
fn segments(line: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut quote: Option<char> = None;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => quote = Some(c),
            None if "|<>;".contains(c) || (c == '&' && chars.peek() == Some(&'&')) => {
                if c == '&' {
                    chars.next();
                }
                out.push(String::new());
                continue;
            }
            None => {}
        }
        out.last_mut().unwrap().push(c);
    }
    out
}

/// The podssh command lines in an example: each pipeline segment that
/// runs podssh, and the ProxyCommand that OpenSSH would run.
fn podssh_lines(command: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for segment in segments(command) {
        let mut words = shell_words(&segment);
        while words.first().is_some_and(|w| w.contains('=') && !w.starts_with('-')) {
            let name = words.remove(0);
            let name = name.split('=').next().unwrap().to_string();
            let known = super::super::facts::variables().any(|(n, _)| n.contains(&name.as_str()));
            assert!(known, "{command}: {name} is not in ENVIRONMENT");
        }
        match words.first().map(String::as_str) {
            Some("podssh") => out.push(words[1..].to_vec()),
            Some("ssh") => {
                for w in &words {
                    if let Some(inner) = w.strip_prefix("ProxyCommand=") {
                        let inner = shell_words(inner);
                        assert_eq!(inner.first().map(String::as_str), Some("podssh"), "{command}");
                        out.push(inner[1..].to_vec());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

#[test]
fn each_example_parses_with_the_real_parser() {
    for (text, command) in examples() {
        let lines = podssh_lines(&command);
        assert!(!lines.is_empty(), "{text}: {command} runs no podssh");
        for argv in lines {
            let parsed = parse(argv.clone());
            assert!(!parsed.needs_refusal(), "{command}: {argv:?} is refused: {parsed:?}");
            let verb = match &parsed {
                Parsed::Command { verb, .. } => *verb,
                Parsed::Proxy { .. } => "proxy",
                Parsed::Doctor { .. } => "doctor",
                Parsed::Status { .. } => "status",
                Parsed::Ping(_) => "ping",
                Parsed::Health(_) => "health",
                Parsed::Play(_) => "play",
                Parsed::Update(_) => "update",
                Parsed::Edit(_) => "edit",
                Parsed::Each(_) => "each",
                Parsed::Containers(_) => "containers",
                Parsed::Job(_) => "job",
                Parsed::Run(_) => "run",
                Parsed::Config(_) => "config",
                Parsed::Mcp(_) => "mcp",
                Parsed::Session(_) => "session",
                Parsed::Detached(_) => "detached",
                Parsed::Net(_) => "net",
                Parsed::Exit(_) => "exit",
                Parsed::Man { .. } => "man",
                Parsed::Node(_) => "node",
                Parsed::Relay(_) => "relay",
                Parsed::Operator(_) => "operator",
                Parsed::Pipe(_) => "pipe",
                other => panic!("{command}: {other:?}"),
            };
            let v = crate::flags::verb_for(verb).unwrap();
            assert_eq!(crate::flags::availability(v), crate::flags::Availability::Works, "{command}");
        }
    }
}

/// The control: an example with a flag that does not exist is caught.
#[test]
fn a_planted_example_is_refused() {
    let argv = podssh_lines("podssh ssh --no-such-flag user@example.org").remove(0);
    assert!(parse(argv).needs_refusal());
    let argv = podssh_lines("ssh -o ProxyCommand='podssh proxy --jsonl %h %p' host").remove(0);
    assert!(parse(argv).needs_refusal());
}

#[test]
fn operators_in_quotes_do_not_split() {
    let s = segments("podssh ssh h 'cat > x' < x | y && z");
    assert_eq!(s, vec!["podssh ssh h 'cat > x' ", " x ", " y ", " z"]);
}

#[test]
fn the_start_has_the_first_steps() {
    let commands: Vec<String> = start_here()
        .into_iter()
        .filter_map(|b| match b {
            Block::Example { command, .. } => Some(command),
            _ => None,
        })
        .collect();
    assert_eq!(commands.len(), 3, "{commands:?}");
    assert!(commands[0].starts_with("podssh doctor"));
}
