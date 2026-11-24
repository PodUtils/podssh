//! The tests of `podssh serve`'s command line (`serve.rs`): its modes, its
//! refusals at the start, and the host key's place.

use super::*;
use crate::exitmap::sysexits::EX_CONFIG;

fn args(stdio: bool) -> ServeArgs {
    ServeArgs { stdio, ..ServeArgs::default() }
}

#[test]
fn a_run_without_stdio_is_a_usage_error() {
    let mut err = Vec::new();
    let code = run(&args(false), &mut err);
    let said = String::from_utf8_lossy(&err);
    if cfg!(windows) {
        assert_eq!(code, EXIT_NOT_IMPLEMENTED, "{said}");
    } else {
        assert_eq!(code, EXIT_USAGE, "{said}");
        assert!(said.contains("--stdio") && said.contains("NAME"), "{said}");
    }
}

/// One of --stdio, NAME and --listen, and --max-connections only with
/// --listen (T-124): one table, as the rule is one.
#[test]
fn one_mode_of_the_three_is_given() {
    let (listen, name) = (vec!["2222".to_string()], Some("lab".to_string()));
    let cases = [
        (ServeArgs { listen: listen.clone(), ..args(true) }, Some("--stdio and --listen")),
        (ServeArgs { listen: listen.clone(), name: name.clone(), ..args(false) }, Some("and --listen")),
        (ServeArgs { name: name.clone(), ..args(true) }, Some("--stdio and NAME")),
        (ServeArgs { max_connections: Some("4".into()), ..args(true) }, Some("--max-connections bounds")),
        (ServeArgs { pending_max: Some("4".into()), ..args(true) }, Some("--pending-max bounds")),
        (ServeArgs { login_timeout: Some("9".into()), name: name.clone(), ..args(false) }, Some("--login-timeout")),
        (args(false), Some("or --listen ADDR")),
        (ServeArgs { listen, max_connections: Some("4".into()), ..args(false) }, None),
        (args(true), None),
        (ServeArgs { name, ..args(false) }, None),
    ];
    for (a, words) in cases {
        match (one_mode(&a), words) {
            (Ok(()), None) => {}
            (Err(refusal), Some(words)) => {
                assert_eq!(refusal.code, EXIT_USAGE, "{}", refusal.message);
                assert!(refusal.message.contains(words), "{words}: {}", refusal.message);
            }
            (got, want) => panic!("{a:?}: {got:?}, wanted {want:?}"),
        }
    }
}

#[test]
fn a_key_with_options_is_taken_and_one_it_cannot_honour_is_refused() {
    let key = podssh_ssh::keygen::generate(podssh_ssh::keygen::KeyKind::Ed25519, "t").unwrap();
    let line = key.public_key().to_openssh().unwrap();
    let mut a = args(true);
    a.authorized_key = vec![format!("no-pty,command=\"echo hi\" {line}")];
    let found = authorized(&a, &mut Vec::new()).expect("a key with its rules");
    assert!(found.allows(key.public_key()));
    a.authorized_key = vec![format!("tunnel=\"0\" {line}")];
    let refusal = authorized(&a, &mut Vec::new()).expect_err("refused");
    assert_eq!(refusal.code, EXIT_USAGE, "{}", refusal.message);
    assert!(refusal.message.contains("tunnel="), "the option is named: {}", refusal.message);
    a.authorized_key = vec!["not a key".into()];
    assert_eq!(authorized(&a, &mut Vec::new()).expect_err("refused").code, EXIT_USAGE);
}

#[test]
fn a_named_file_that_is_missing_is_a_setup_error() {
    let mut a = args(true);
    a.authorized_keys = vec!["/nonexistent/podssh/authorized_keys".into()];
    let refusal = authorized(&a, &mut Vec::new()).expect_err("refused");
    assert_eq!(refusal.code, EX_CONFIG, "{}", refusal.message);
}

#[test]
fn a_key_given_is_enough() {
    let key = podssh_ssh::keygen::generate(podssh_ssh::keygen::KeyKind::Ed25519, "t").unwrap();
    let mut a = args(true);
    a.authorized_key = vec![key.public_key().to_openssh().unwrap()];
    let found = authorized(&a, &mut Vec::new()).expect("a key");
    assert!(found.allows(key.public_key()));
}

#[test]
fn the_temporary_places_are_known() {
    assert!(temporary(Path::new("/tmp/podssh-1000/serve_host_ed25519_key")));
    assert!(!temporary(Path::new("/home/u/.cache/podssh/serve_host_ed25519_key")));
}
