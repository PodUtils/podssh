//! The command line of `podssh job` (T-193, T-197), with no host: each
//! action that it reads, and each refusal (64) before anything connects.

use std::time::Duration;

use super::*;

fn args(words: &[&str], dashed: bool) -> JobArgs {
    let mut it = words.iter().map(|w| w.to_string());
    JobArgs { subcommand: it.next(), host: it.next(), words: it.collect(), dashed, ..JobArgs::default() }
}

#[test]
fn each_action_is_read_from_its_words() {
    let start = action(&args(&["start", "web1", "sleep", "300"], true)).unwrap();
    let want = Action::Start { command: "sleep 300".into(), plain: false };
    assert_eq!(start, want, "the words joined, as OpenSSH joins them");
    assert_eq!(action(&args(&["list", "web1"], false)), Ok(Action::List { json: false }));
    assert_eq!(action(&args(&["log", "web1", "ABCD1234"], false)), Ok(Action::Log("abcd1234".into())));
    assert_eq!(action(&args(&["stop", "web1", "0123abcd"], false)), Ok(Action::Stop("0123abcd".into())));
}

#[test]
fn the_queue_reads_its_flags() {
    let mut submit = args(&["submit", "web1,web2", "make"], true);
    submit.slots = Some("2".into());
    assert_eq!(action(&submit), Ok(Action::Submit { command: "make".into(), slots: Some(2), plain: false }));
    let mut wait = args(&["wait", "web1", "abcd1234"], false);
    wait.timeout = Some("30s".into());
    assert_eq!(action(&wait), Ok(Action::Wait { id: "abcd1234".into(), timeout: Some(Duration::from_secs(30)) }));
    let mut fetch = args(&["fetch", "web1", "abcd1234", "here"], false);
    fetch.files = Some("build/*.log".into());
    let want = Action::Fetch { id: "abcd1234".into(), dir: Some("here".into()), files: Some("build/*.log".into()) };
    assert_eq!(action(&fetch), Ok(want));
    let mut list = args(&["list", "web1"], false);
    list.json = true;
    assert_eq!(action(&list), Ok(Action::List { json: true }));
}

#[test]
fn a_command_line_that_names_no_job_is_refused() {
    for (words, dashed, says) in [
        (&[][..], false, "give what to do"),
        (&["run"][..], false, "not a command of podssh job"),
        (&["start"][..], false, "give the host"),
        (&["start", "web1"][..], true, "give the command after --"),
        // Without --, a word such as -l would be a flag of podssh.
        (&["start", "web1", "ls"][..], false, "so that no word of it is read as a flag"),
        (&["submit", "web1", "ls"][..], false, "so that no word of it is read as a flag"),
        (&["list", "web1", "x"][..], false, "list takes no word"),
        (&["log", "web1"][..], false, "give one ID"),
        (&["stop", "web1", "a", "b"][..], false, "give one ID"),
        (&["stop", "web1", "abcd123"][..], false, "8 hex digits"),
        (&["stop", "web1", "podssh-j"][..], false, "8 hex digits"),
        (&["wait", "web1"][..], false, "give one ID"),
        (&["fetch", "web1", "abcd1234", "a", "b"][..], false, "a directory or none"),
    ] {
        let why = action(&args(words, dashed)).expect_err("a refusal");
        assert!(why.contains(says), "{words:?}: {why}");
    }
    let newline = action(&args(&["start", "web1", "echo a\nb"], true)).expect_err("a refusal");
    assert!(newline.contains("newline"), "{newline}");
}

#[test]
fn a_flag_of_the_queue_is_refused_with_another_subcommand_or_a_bad_value() {
    let with = |words: &[&str], set: &dyn Fn(&mut JobArgs)| {
        let mut a = args(words, true);
        set(&mut a);
        action(&a).expect_err("a refusal")
    };
    let why = with(&["list", "web1"], &|a| a.slots = Some("2".into()));
    assert!(why.contains("--slots goes with podssh job submit"), "{why}");
    let why = with(&["stop", "web1", "abcd1234"], &|a| a.json = true);
    assert!(why.contains("--json goes with podssh job list"), "{why}");
    // T-481: --no-tmux goes with the two that start a job.
    let why = with(&["list", "web1"], &|a| a.no_tmux = true);
    assert!(why.contains("--no-tmux goes with podssh job start or submit, not with list"), "{why}");
    for bad in ["0", "65", "x"] {
        let why = with(&["submit", "web1", "make"], &|a| a.slots = Some(bad.into()));
        assert!(why.contains("1 to 64"), "{bad}: {why}");
    }
    let why = with(&["wait", "web1", "abcd1234"], &|a| a.timeout = Some("soon".into()));
    assert!(why.starts_with("bad --timeout"), "{why}");
    for bad in ["/etc/*", "../x", "a/../../b", " "] {
        let why = with(&["fetch", "web1", "abcd1234"], &|a| a.files = Some(bad.into()));
        assert!(why.contains("under the home directory"), "{bad}: {why}");
    }
}

/// T-481: `--no-tmux` is carried to each of the two, and nothing else
/// changes.
#[test]
fn no_tmux_makes_a_plain_start_or_submit() {
    let mut start = args(&["start", "web1", "make"], true);
    start.no_tmux = true;
    assert_eq!(action(&start), Ok(Action::Start { command: "make".into(), plain: true }));
    let mut submit = args(&["submit", "web1", "make"], true);
    submit.no_tmux = true;
    assert_eq!(action(&submit), Ok(Action::Submit { command: "make".into(), slots: None, plain: true }));
}

/// T-485: `log --follow`, with `--from-end`, `--jsonl` and `--timeout`;
/// each of the three without `--follow` is refused, and `--follow` with
/// another subcommand.
#[test]
fn log_follow_reads_its_flags_and_refuses_them_without_it() {
    let mut follow = args(&["log", "web1", "ABCD1234"], false);
    follow.follow = true;
    let want = Action::Follow { id: "abcd1234".into(), from_end: false, jsonl: false, timeout: None };
    assert_eq!(action(&follow), Ok(want));
    follow.from_end = true;
    follow.jsonl = true;
    follow.timeout = Some("2s".into());
    let timeout = Some(Duration::from_secs(2));
    let want = Action::Follow { id: "abcd1234".into(), from_end: true, jsonl: true, timeout };
    assert_eq!(action(&follow), Ok(want));
    let refused = |set: &dyn Fn(&mut JobArgs)| {
        let mut a = args(&["log", "web1", "abcd1234"], false);
        set(&mut a);
        action(&a).expect_err("a refusal")
    };
    let why = refused(&|a| a.from_end = true);
    assert!(why.contains("--from-end goes with podssh job log --follow"), "{why}");
    let why = refused(&|a| a.jsonl = true);
    assert!(why.contains("--jsonl goes with podssh job log --follow, not with log without --follow"), "{why}");
    let why = refused(&|a| a.timeout = Some("2s".into()));
    assert!(why.contains("--timeout goes with podssh job wait or log --follow"), "{why}");
    let mut stop = args(&["stop", "web1", "abcd1234"], false);
    stop.follow = true;
    let why = action(&stop).expect_err("a refusal");
    assert!(why.contains("--follow goes with podssh job log, not with stop"), "{why}");
}

#[test]
fn an_id_is_eight_hex_digits_and_new_ones_differ() {
    let a = new_id();
    assert_eq!(id(&a), Ok(a.clone()));
    assert_ne!(a, new_id(), "two IDs in a row are one in 2^32");
    assert!(now_ms() > 1_700_000_000_000, "milliseconds since 1970");
}

/// Each answer of the far script's stop, and its line (T-978): a job that
/// ended is never said to have not run.
#[test]
fn a_stop_says_what_the_job_was() {
    let id = "0123abcd";
    for (answer, says) in [
        ("stopped 0123abcd", Ok("stopped, and removed with its output")),
        ("removed 0123abcd", Ok("it was queued, and never ran")),
        ("ended 0123abcd 0", Ok("had ended (status 0); removed with its output")),
        ("ended 0123abcd 130", Ok("had ended (status 130)")),
        ("gone 0123abcd", Ok("was lost (no status, and nothing ran it)")),
        ("lost 0123abcd", Ok("its runner was gone")),
        ("stuck 0123abcd", Err("runs on after 15 s")),
        ("ended 0123abcd", Err("does not know")),
        ("ended 0123abcd x", Err("does not know")),
        ("stopped 99999999", Err("does not know")),
        ("stopped", Err("does not know")),
    ] {
        let got = stop_said(id, "web1", answer);
        match (says, &got) {
            (Ok(part), Ok(line)) | (Err(part), Err(line)) => {
                assert!(line.contains(part), "{answer}: {line}");
                assert!(!line.contains("did not run"), "{answer}: {line}");
            }
            _ => panic!("{answer}: {got:?}"),
        }
    }
}

/// T-1070: `wait`, `log --follow`, `fetch`, `stop` and the manual agree on
/// the wording for a lost job, naming neither a tmux session nor a runner
/// alone when `state` reports `lost` for either.
#[test]
fn lost_job_wording_matches_across_subcommands_and_manual() {
    let wait_and_follow = queue::lost_line("0123abcd", "web1");
    assert_eq!(
        wait_and_follow,
        "job 0123abcd on web1 is lost: no status, and nothing runs it, as after a restart of the host"
    );
    assert!(!wait_and_follow.contains("tmux") && !wait_and_follow.contains("runner"), "{wait_and_follow}");
    let fetched = fetch::lost_line("0123abcd", "web1", std::path::Path::new("out"));
    assert!(fetched.contains("no status, and nothing runs it"), "{fetched}");
    let stopped = stop_said("0123abcd", "web1", "gone 0123abcd").expect("gone");
    assert!(stopped.contains("no status, and nothing ran it"), "{stopped}");
    let notes = crate::man::notes::for_verb("job").join("\n");
    assert!(notes.contains("when no status is there and nothing runs it"), "{notes}");
}
