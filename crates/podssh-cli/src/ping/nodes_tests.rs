//! The tests of `ping --nodes`: the list, the bounds, the exit and the JSON.

use podssh_relay::session::race::Timed;

use super::*;
use crate::ssh::roads::probe::Measured;

fn args() -> PingArgs {
    PingArgs { nodes: Some("a".into()), ..PingArgs::default() }
}

fn measured(shown: &str, answered: bool) -> Outcome {
    let answered = if answered { Ok(()) } else { Err("the node is offline".to_string()) };
    let timed = Timed { started: Duration::ZERO, took: Duration::from_millis(12), answered };
    let won = timed.answered.is_ok().then_some(0);
    let roads = vec![Measured { road: "the pair's road", timed: Some(timed) }];
    let measures = Measures { shown: shown.into(), roads, won };
    let code = if won.is_some() { 0 } else { EX_UNAVAILABLE };
    let error = won.is_none().then(|| measures.why_none());
    Outcome { shown: shown.into(), measures: Some(measures), code, error }
}

/// The names of `--nodes`, with or without the scheme, each once in the
/// order given; an empty name is refused.
#[test]
fn the_list_takes_each_name_once_in_its_order() {
    let names = listed("lab, node://gone,lab,two").unwrap();
    assert_eq!(names, ["lab", "gone", "two"]);
    assert_eq!(listed("lab,,two").unwrap_err().code, 64);
    assert_eq!(listed("node://").unwrap_err().code, 64);
    let many: Vec<String> = (0..=MOST_NODES).map(|n| format!("n{n}")).collect();
    assert_eq!(listed(&many.join(",")).unwrap_err().code, 64);
}

/// `--parallel` is from 1 to 64; a host's flags, a destination and the two
/// lists together are refused (64), each before anything connects.
#[test]
fn the_flags_of_a_host_and_a_bad_parallel_are_refused() {
    let plan_of = |args: PingArgs| plan(&args).map(|(names, parallel, _)| (names, parallel));
    assert_eq!(plan_of(args()).unwrap(), (vec!["a".to_string()], PARALLEL));
    let with = |parallel: &str| PingArgs { parallel: Some(parallel.into()), ..args() };
    assert_eq!(plan_of(with("64")).unwrap().1, 64);
    for bad in ["0", "65", "x"] {
        assert_eq!(plan_of(with(bad)).unwrap_err().code, 64, "--parallel {bad}");
    }
    assert_eq!(plan_of(PingArgs { net: true, ..args() }).unwrap_err().code, 64);
    assert_eq!(plan_of(PingArgs { size: Some("1M".into()), ..args() }).unwrap_err().code, 64);
    assert_eq!(plan_of(PingArgs { under_load: true, ..args() }).unwrap_err().code, 64);
    let mut given = args();
    given.ssh.destination = Some("host".into());
    assert_eq!(plan_of(given).unwrap_err().code, 64);
    let stray_one = PingArgs { timeout: Some("5s".into()), ..PingArgs::default() };
    assert_eq!(stray(&stray_one), Some("--timeout"));
    assert_eq!(stray(&args()), None);
}

/// Each node's bound: the flag, else the variable, else the default; a bad
/// flag is 64, a bad variable 78, and past the run's limit is 64.
#[test]
fn each_node_s_bound_is_the_flag_then_the_variable() {
    let none = |_: &str| None;
    let var = |_: &str| Some("20s".to_string());
    assert_eq!(node_limit(None, none).unwrap(), NODE_LIMIT);
    assert_eq!(node_limit(None, var).unwrap(), Duration::from_secs(20));
    assert_eq!(node_limit(Some("5s"), var).unwrap(), Duration::from_secs(5));
    let bad = node_limit(Some("5x"), none).unwrap_err();
    assert_eq!(bad.code, 64);
    assert!(!bad.message.starts_with("podssh: "), "{}", bad.message);
    // Each bad value is one line, in the words of each command's --timeout (T-1029).
    for text in ["5x", "0s", "0"] {
        let bad = node_limit(Some(text), none).unwrap_err();
        assert_eq!(bad.code, 64, "{text:?}");
        assert!(bad.message.starts_with(&format!("bad --timeout {text:?}: ")), "{}", bad.message);
        assert!(!bad.message.contains('\n'), "{}", bad.message);
    }
    assert_eq!(node_limit(None, |_: &str| Some("x".to_string())).unwrap_err().code, 78);
    assert_eq!(node_limit(Some("11m"), none).unwrap_err().code, 64);
}

/// 0 when each node answered, 69 when none did, else 1.
#[test]
fn the_exit_is_0_1_or_69() {
    let ok = || measured("node://a", true);
    let gone = || Outcome::failed("node://b".into(), EX_TEMPFAIL, "no road answered within 5.0 s".into());
    assert_eq!(run_code(&[ok(), ok()]), 0);
    assert_eq!(run_code(&[ok(), gone(), measured("node://c", false)]), 1);
    assert_eq!(run_code(&[gone(), measured("node://c", false)]), EX_UNAVAILABLE);
}

/// The JSON holds each node in the order of the list, in the shape of one
/// node's, with its code and why it failed; the lines end with the count.
#[test]
fn the_json_has_each_node_with_its_code() {
    let outcomes = [
        measured("node://a", true),
        Outcome::failed("node://b".into(), 78, "PODSSH_X=y: yes or no".into()),
        measured("node://c", false),
    ];
    let value = json_of(&outcomes, run_code(&outcomes));
    assert_eq!((&value["schema"], &value["exit"]), (&json!(1), &json!(1)));
    let nodes = value["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 3);
    assert_eq!((&nodes[0]["name"], &nodes[0]["code"]), (&json!("node://a"), &json!(0)));
    assert_eq!(nodes[0]["won"], "the pair's road");
    assert_eq!((&nodes[0]["roads"][0]["ms"], &nodes[0]["error"]), (&json!(12.0), &Value::Null));
    assert_eq!((&nodes[1]["roads"], &nodes[1]["won"], &nodes[1]["code"]), (&json!([]), &Value::Null, &json!(78)));
    assert_eq!(nodes[1]["error"], "PODSSH_X=y: yes or no");
    assert_eq!((&nodes[2]["won"], &nodes[2]["code"]), (&Value::Null, &json!(69)));
    assert!(nodes[2]["error"].as_str().is_some_and(|why| why.starts_with("no road reached the node")));
    let lines = lines(&outcomes);
    assert_eq!(lines.last().map(String::as_str), Some("1 of 3 nodes answered"));
    assert!(lines.contains(&"node://b: PODSSH_X=y: yes or no".to_string()), "{lines:#?}");
}

/// A refusal that names its node already is said with the node once, in the
/// line and in the JSON (T-1028); another refusal keeps its words.
#[test]
fn a_node_is_named_once_in_its_line() {
    let stored = "no pair is stored under \"n1\"; make one with `podssh relay pair n1`";
    for (error, want) in [
        (format!("node://n1: {stored}"), stored.to_string()),
        (stored.to_string(), stored.to_string()),
        ("node://n2: other".to_string(), "node://n2: other".to_string()),
    ] {
        let outcome = Outcome::failed("node://n1".into(), 78, error);
        assert_eq!(outcome.error.as_deref(), Some(want.as_str()));
        assert_eq!(lines(&[outcome])[0], format!("node://n1: {want}"));
    }
}
