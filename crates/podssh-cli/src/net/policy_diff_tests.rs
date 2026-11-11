//! The questions of a net and the diff of two policies by their answers
//! (T-749), on documents made here.

use serde_json::{json, Value};

use super::*;

const OWNER: &str = include_str!("testdata/owner.pub");

/// The net home with lab (a share db), gw (an exit with a range), ci and
/// laptop, and `policy`, if one.
fn doc_with(policy: Option<Value>) -> Doc {
    let first = Doc::new("home", OWNER.trim(), 1_793_577_600, 4_102_444_800).unwrap();
    let member = |name: &str, seed: u8, roles: &[&str]| json!({"name": name, "key": format!("{seed:02x}").repeat(32), "roles": roles});
    let mut lab = member("lab", 0x21, &["node", "share"]);
    lab["shares"] = json!(["db"]);
    let mut gw = member("gw", 0x22, &["node", "exit"]);
    gw["routes"] = json!(["10.9.0.0/16"]);
    let members = json!([lab, gw, member("ci", 0x31, &["node"]), member("laptop", 0x41, &["node"])]);
    let next = first.next_whole(1_793_577_700, 4_102_444_800, |whole| {
        whole.insert("members".into(), members);
        if let Some(policy) = policy {
            whole.insert("policy".into(), policy);
        }
    });
    next.unwrap()
}

fn policy_of(rules: Value) -> Value {
    json!({"rules": rules, "tags": {"builders": ["ci"]}})
}

#[test]
fn each_question_of_the_net_is_asked_once() {
    let doc = doc_with(None);
    let asked = questions(&[&doc, &doc]);
    let of_ci: Vec<String> = asked.iter().filter(|(from, _)| from == "ci").map(|(_, to)| to.to_string()).collect();
    for want in ["lab", "lab/db", "exit:gw", "10.9.0.0", "relay:*", "laptop"] {
        assert!(of_ci.contains(&want.to_string()), "{want}: {of_ci:?}");
    }
    assert_eq!(asked.len(), 4 * of_ci.len(), "each member asks the same");
}

#[test]
fn a_policy_against_itself_and_a_reordered_one_change_nothing() {
    let rules = json!([{"from": ["tag:builders"], "to": ["lab/db"]}, {"from": ["laptop"], "to": ["lab"]}]);
    let reordered = json!([{"from": ["laptop"], "to": ["lab"]}, {"from": ["tag:builders"], "to": ["lab/db"]}]);
    let (one, two) = (doc_with(Some(policy_of(rules))), doc_with(Some(policy_of(reordered))));
    assert_eq!(diff(&one, &one), Diff::default());
    let changed = diff(&one, &two);
    assert!(changed.widened.is_empty() && changed.narrowed.is_empty(), "{changed:?}");
}

/// The block's case: a tag's line deleted, its pairs narrowed; and a first
/// policy narrows each pair that it does not name.
#[test]
fn a_deleted_tag_line_and_a_first_policy_show_their_narrowed_pairs() {
    let rules = json!([{"from": ["tag:builders"], "to": ["lab/db"]}]);
    let before = doc_with(Some(policy_of(rules.clone())));
    let after = doc_with(Some(json!({"rules": rules, "tags": {"builders": []}})));
    let lost = diff(&before, &after);
    let narrowed: Vec<String> = lost.narrowed.iter().map(|c| format!("{} -> {}", c.from, c.to)).collect();
    assert_eq!(narrowed, ["ci -> lab/db"], "{lost:?}");
    assert!(lost.widened.is_empty());
    let back = diff(&after, &before);
    assert_eq!(back.widened.len(), 1, "restored, it widens again");
    let first = diff(&doc_with(None), &before);
    assert!(first.narrowed.iter().any(|c| c.from == "laptop" && c.to.to_string() == "lab"), "{first:?}");
    assert!(first.lines(2).last().unwrap().contains("narrowed"));
}

#[test]
fn an_expectation_file_reads_its_cases_and_refuses_another_word() {
    let read = cases(&json!({"expect": [{"from": "ci", "to": "lab/db", "want": "allow", "note": "nightly"}]})).unwrap();
    assert_eq!(read[0], Case { from: "ci".into(), to: "lab/db".into(), allow: true, note: Some("nightly".into()) });
    assert!(cases(&json!({"expect": [{"from": "ci", "to": "lab", "want": "maybe"}]})).unwrap_err().contains("maybe"));
    assert!(cases(&json!({})).is_err());
}
