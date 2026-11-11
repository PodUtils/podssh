//! `podssh net policy test`, `diff` and `set --expect` and `--dry-run`
//! (T-749), a module of `tests/net.rs`, with no connection: a case that the
//! policy refuses fails `test` with its reason; a diff of a policy against
//! itself is empty; a deleted tag line shows its pair narrowed; `--expect`
//! with a false case and `--dry-run` leave `net.doc` byte for byte.

use sha2::{Digest, Sha256};

use crate::{key_hex, net, owner_key, private};

#[test]
fn a_policy_is_tested_diffed_and_set_only_when_its_cases_hold() {
    let home = private("net-policy-test");
    let doc = home.join("net.doc");
    let (owner, _) = owner_key(&home, "owner");
    let o = owner.display().to_string();
    let says = |args: &[&str]| net(&home, &doc, args);
    assert_eq!(says(&["net", "init", "home", "--owner-key", &o]).0, 0);
    for (name, seed) in [("lab", 0x21), ("ci", 0x31), ("laptop", 0x41)] {
        let (rc, _, err) = says(&["net", "add", name, &key_hex(seed), "--owner-key", &o]);
        assert_eq!(rc, 0, "{err}");
    }
    let write = |name: &str, text: &str| {
        let path = home.join(name);
        std::fs::write(&path, text).unwrap();
        path.display().to_string()
    };
    let policy =
        write("policy.json", r#"{"tags": {"builders": ["ci"]}, "rules": [{"from": ["tag:builders"], "to": ["lab"]}]}"#);
    let (rc, _, err) = says(&["net", "policy", "set", &policy, "--owner-key", &o]);
    assert_eq!(rc, 0, "{err}");
    assert!(err.contains("- laptop -> lab"), "set says what it narrows: {err}");

    // test: a true case passes; one that the policy refuses fails with its reason.
    let good = write(
        "good.json",
        r#"{"expect": [{"from": "ci", "to": "lab", "want": "allow"}, {"from": "laptop", "to": "lab", "want": "refuse"}]}"#,
    );
    let (rc, out, err) = says(&["net", "policy", "test", &good]);
    assert_eq!(rc, 0, "{out} {err}");
    let bad = write(
        "bad.json",
        r#"{"expect": [{"from": "laptop", "to": "lab", "want": "allow", "note": "the owner's laptop"}]}"#,
    );
    let (rc, out, _) = says(&["net", "policy", "test", &bad]);
    assert_eq!(rc, 65, "{out}");
    assert!(
        out.starts_with("FAIL\tlaptop -> lab: allow (the owner's laptop)") && out.contains("no rule of the net home"),
        "{out}"
    );

    // diff: against itself, nothing; with the tag's line deleted, ci -> lab narrowed.
    let (rc, out, _) = says(&["net", "policy", "diff", &policy]);
    assert!(rc == 0 && out.starts_with("0 widened, 0 narrowed"), "{out}");
    let untagged =
        write("untagged.json", r#"{"tags": {"builders": []}, "rules": [{"from": ["tag:builders"], "to": ["lab"]}]}"#);
    let (rc, out, _) = says(&["net", "policy", "diff", &untagged]);
    assert!(rc == 0 && out.contains("- ci -> lab (was rule 1") && out.contains("0 widened, 1 narrowed"), "{out}");
    let open = write("open.json", r#"{"rules": [{"from": ["*"], "to": ["*"]}]}"#);
    let (rc, out, _) = says(&["net", "policy", "diff", &open, "--exit-code"]);
    assert!(rc == 65 && out.contains("+ laptop -> lab"), "a widened pair is 65 with --exit-code: {out}");

    // set --expect with a false case, and --dry-run: net.doc stays byte for byte.
    let sum = || hex(&Sha256::digest(std::fs::read(&doc).unwrap()));
    let before = sum();
    let (rc, _, err) = says(&["net", "policy", "set", &untagged, "--expect", &good, "--owner-key", &o]);
    assert!(rc == 65 && err.contains("nothing is signed") && err.contains("FAIL\tci -> lab"), "{err}");
    let (rc, _, err) = says(&["net", "policy", "set", &open, "--dry-run", "--owner-key", &o]);
    assert!(rc == 0 && err.contains("a dry run: nothing is signed") && err.contains("+ laptop -> lab"), "{err}");
    assert_eq!(sum(), before, "net.doc byte for byte");
    let (rc, _, err) = says(&["net", "policy", "diff", &open, "--dry-run"]);
    assert_eq!(rc, 64, "--dry-run is set's: {err}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
