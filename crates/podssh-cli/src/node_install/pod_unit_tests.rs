//! What pod-unit's check of a unit makes of podssh's words (T-820): the
//! asks that held the move of the renderers back, answered in podcrates
//! `v0.82.1`. A public key and a fingerprint of `--net-owner` and
//! `--authorized-key` pass the scan of secrets; each older mark of podssh's
//! forms is a mark that pod-unit takes; a token in the words is still
//! refused, so the scan is not vacuous.

use std::path::Path;

use podssh_ssh::keygen::{generate, KeyKind};
use podssh_ssh::russh::keys::ssh_key::HashAlg;

use super::text::{cron_mark, old_cron_mark, PLIST_MARK, UNIT_MARK};
use super::Kind;

/// podssh's unit of a node of a net, or of serve with its keys, as pod-unit
/// would hold it, with each of podssh's older marks. pod-unit's mark holds
/// no `--` (a comment of XML may not), so it names no flag; the older marks
/// find what podssh wrote before, whose first lines name `--install`.
fn unit(kind: Kind, name: &str, words: &[String]) -> pod_unit::Unit {
    let mark = format!("podssh {} {name}", kind.verb());
    pod_unit::Unit::new(&format!("podssh-{}-{name}", kind.verb()), Path::new("/usr/local/bin/podssh"), &mark)
        .args(words)
        .older_mark(UNIT_MARK)
        .older_mark(PLIST_MARK)
        .older_mark(&cron_mark(kind, name))
        .older_mark(&old_cron_mark(kind, name))
}

/// Each of 50 random keys, in each form that the flags take, passes; the
/// model of `v0.82.0`'s rule refused 198 of 200 fingerprints and each key.
#[test]
fn pod_unit_passes_public_keys_fingerprints_and_podssh_s_older_marks() {
    for n in 0..50 {
        let key = generate(KeyKind::Ed25519, "owner@lab").unwrap();
        let line = key.public_key().to_openssh().unwrap();
        let print = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let words: Vec<String> = ["node", "lab", "--net-url", "https://example.test/net.json", "--net-owner", &print]
            .map(String::from)
            .into();
        unit(Kind::Node, "lab", &words).check().unwrap_or_else(|e| panic!("key {n}, the fingerprint: {e}"));
        let words: Vec<String> = ["node", "lab", "--net-owner", &line].map(String::from).into();
        unit(Kind::Node, "lab", &words).check().unwrap_or_else(|e| panic!("key {n}, the key: {e}"));
        let words: Vec<String> = ["serve", "lab", "--authorized-key", &line].map(String::from).into();
        unit(Kind::Serve, "lab", &words).check().unwrap_or_else(|e| panic!("key {n}, serve's key: {e}"));
    }
}

/// The control: a token among the words is still refused, by its rule and
/// never by its text; and an older mark shorter than 8 characters is
/// refused (T-1106), which none of podssh's is.
#[test]
fn pod_unit_still_refuses_a_token_and_a_short_older_mark() {
    let token = format!("ghp_{}", "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI2k");
    let words: Vec<String> = ["node", "lab", "--relay-addr", &token].map(String::from).into();
    let refused = unit(Kind::Node, "lab", &words).check().unwrap_err().to_string();
    assert!(refused.contains("GitHub token"), "{refused}");
    assert!(!refused.contains(&token), "the refusal names the rule, never the word: {refused}");
    let words: Vec<String> = vec!["node".into(), "lab".into()];
    let short = unit(Kind::Node, "lab", &words).older_mark("podssh").check().unwrap_err().to_string();
    assert!(short.contains("older mark"), "{short}");
}
