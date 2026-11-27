//! `podssh pipe --install` (T-726): the service's words, the sides that a
//! service cannot have, and a unit that holds no credential.

use super::*;
use crate::pipe::PipeArgs;

fn args(a: &str, b: &str) -> PipeArgs {
    PipeArgs { a: Some(a.to_string()), b: Some(b.to_string()), ..PipeArgs::default() }
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|w| w.to_string()).collect()
}

#[test]
fn the_service_runs_the_words_but_install_with_batch_mode_and_each_client() {
    let typed = words(&["pipe", "--install", "web", "--direct", "tcp-listen:8080", "ssh:me@host:tcp:127.0.0.1:80"]);
    let got = service_words(&typed, Path::new("/e/pipe-web.env"), true);
    assert_eq!(
        got,
        words(&[
            "pipe",
            "-o",
            "BatchMode=yes",
            "--env-file",
            "/e/pipe-web.env",
            "--keep-listening",
            "--direct",
            "tcp-listen:8080",
            "ssh:me@host:tcp:127.0.0.1:80"
        ])
    );
    let typed = words(&["pipe", "--install=x", "relay:a:1", "--", "exec:cat"]);
    assert_eq!(
        service_words(&typed, Path::new("/e"), false),
        words(&["pipe", "-o", "BatchMode=yes", "--env-file", "/e", "relay:a:1", "--", "exec:cat"])
    );
}

#[test]
fn a_side_of_the_shell_or_a_credential_in_an_address_is_refused() {
    for (a, b) in [("stdio", "relay:h:22"), ("fd:3", "tcp-listen:9000"), ("tcp-listen:9000", "-")] {
        let why = prepare(&args(a, b), "x", &words(&["pipe"])).err().expect("refused");
        // Windows refuses a descriptor first, as it passes none.
        let words = if cfg!(windows) && a.starts_with("fd:") { "on Unix only" } else { "no stdin" };
        assert!(why.message.contains(words), "{a} {b}: {}", why.message);
    }
    let secret = "wss://me:the-secret-of-this-test@edge.example/x";
    let why = prepare(&args("tcp-listen:9000", secret), "x", &words(&["pipe"])).err().expect("refused");
    // The address's own check refuses it first; the service's is the second.
    assert!(!why.message.contains("the-secret"), "{}", why.message);
    assert!(credential_in(secret).unwrap().contains("user and a password"));
    assert!(credential_in("wss://edge.example/a@b").is_none(), "an @ of the path is no user");
    assert!(credential_in("tcp:host:22").is_none());
}

#[test]
fn the_unit_of_a_pipe_holds_its_words_and_no_credential() {
    let typed = words(&["pipe", "--install", "web", "tcp-listen:8080", "wss://edge.example/x"]);
    let spec = Spec {
        kind: Kind::Pipe,
        name: "web".into(),
        exe: "/usr/bin/podssh".into(),
        args: service_words(&typed, Path::new("/e/pipe-web.env"), true),
        dir: None,
        env_file: "/e/pipe-web.env".into(),
    };
    let unit = super::super::text::unit(&spec).unwrap();
    assert!(unit.starts_with("# Written by podssh pipe.\n"), "{unit}");
    assert!(unit.contains("Description=podssh pipe web"), "{unit}");
    assert!(unit.contains("--keep-listening") && unit.contains("BatchMode=yes"), "{unit}");
    // No word of the unit may be a credential: a URL with a user and a
    // password is refused before the unit is written.
    for line in unit.lines().filter(|l| l.starts_with("ExecStart=")) {
        for word in line.split_whitespace() {
            assert!(credential_in(word).is_none(), "a credential on ExecStart: {word}");
        }
    }
}
