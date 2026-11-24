//! The verdict: a total, I/O-free judgment of what a peer offered against a
//! policy. Each mismatch has what the policy expected and what came, so the
//! verdict says why, not only whether.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::file::Policy;
use super::kexinit::key_type_of;
use super::{EXIT_MISMATCH, EXIT_NO_READING, EXIT_PASS};

/// The names of a KEXINIT's key exchange list that name no key exchange:
/// RFC 8308's extension marker and OpenSSH's strict key exchange.
const MARKERS: [&str; 4] = ["ext-info-s", "ext-info-c", "kex-strict-s-v00@openssh.com", "kex-strict-c-v00@openssh.com"];

/// Which side's KEXINIT was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Server,
    Client,
}

impl Side {
    fn word(self) -> &'static str {
        match self {
            Side::Server => "server",
            Side::Client => "client",
        }
    }
}

/// The host key that one exchange gave: the algorithm that the exchange
/// agreed (what was requested), the type of the key that actually came,
/// and its size measured on that type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeySeen {
    pub requested: String,
    pub returned: String,
    pub bits: u32,
    /// A certificate's signing key: its type and its size.
    pub ca: Option<(String, u32)>,
}

/// What a peer offered: its version line, the first line before it, its
/// four name-lists and its compressions (in the direction it sends), and
/// what was measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub side: Side,
    pub banner: Option<String>,
    pub header: Option<String>,
    pub kex: Vec<String>,
    pub host_keys: Vec<String>,
    pub ciphers: Vec<String>,
    pub macs: Vec<String>,
    pub compressions: Vec<String>,
    pub host_key: Option<HostKeySeen>,
    /// A group-exchange modulus by its key exchange, where one was measured.
    pub dh_modulus: BTreeMap<String, u32>,
}

/// One difference: the field, what the policy expected (and allowed), and
/// what came; ssh-audit's four fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    pub field: String,
    pub expected: Vec<String>,
    pub optional: Vec<String>,
    pub actual: Vec<String>,
}

impl Mismatch {
    /// One mismatch in words, the one form of doctor, serve and each other
    /// line: `FIELD: expected A,B (optional C), got D`, `nothing` for an
    /// empty list.
    pub fn line(&self) -> String {
        let names = |list: &[String]| if list.is_empty() { "nothing".to_string() } else { list.join(",") };
        let optional =
            if self.optional.is_empty() { String::new() } else { format!(" (optional {})", self.optional.join(",")) };
        format!("{}: expected {}{optional}, got {}", self.field, names(&self.expected), names(&self.actual))
    }
}

/// The judgment: each mismatch, and each check that this reading could not
/// make (a size of a host key type that the exchange did not request).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub policy: String,
    pub version: u64,
    pub mismatches: Vec<Mismatch>,
    pub unmeasured: Vec<String>,
}

impl Verdict {
    /// 0 pass, 78 a mismatch, 69 no mismatch but a check not made.
    pub fn exit(&self) -> i32 {
        if !self.mismatches.is_empty() {
            EXIT_MISMATCH
        } else if !self.unmeasured.is_empty() {
            EXIT_NO_READING
        } else {
            EXIT_PASS
        }
    }

    pub fn word(&self) -> &'static str {
        match self.exit() {
            EXIT_PASS => "pass",
            EXIT_MISMATCH => "mismatch",
            _ => "unmeasured",
        }
    }

    pub fn passed(&self) -> bool {
        self.mismatches.is_empty()
    }

    /// The verdict as one JSON object.
    pub fn json(&self) -> Value {
        let mismatches: Vec<Value> = self
            .mismatches
            .iter()
            .map(|m| json!({"field": m.field, "expected": m.expected, "optional": m.optional, "actual": m.actual}))
            .collect();
        json!({
            "schema": 1, "policy": self.policy, "version": self.version, "verdict": self.word(),
            "exit": self.exit(), "mismatches": mismatches, "unmeasured": self.unmeasured,
        })
    }

    /// One line: the verdict and its first fields.
    pub fn line(&self) -> String {
        let fields: Vec<&str> = self.mismatches.iter().map(|m| m.field.as_str()).collect();
        match self.exit() {
            EXIT_PASS => format!("the policy {:?} passed", self.policy),
            EXIT_MISMATCH => {
                format!("the policy {:?} found {} mismatch(es): {}", self.policy, fields.len(), fields.join(", "))
            }
            _ => {
                format!("the policy {:?} found no mismatch; not measured: {}", self.policy, self.unmeasured.join(", "))
            }
        }
    }
}

impl Verdict {
    /// [`Verdict::line`] with each mismatch in words ([`Mismatch::line`]) in
    /// the place of its field alone, so that no field is named twice.
    pub fn detail(&self) -> String {
        if self.exit() != EXIT_MISMATCH {
            return self.line();
        }
        let each: Vec<String> = self.mismatches.iter().map(Mismatch::line).collect();
        format!("the policy {:?} found {} mismatch(es): {}", self.policy, each.len(), each.join("; "))
    }
}

/// The verdict of `policy` on `observed`.
pub fn evaluate(policy: &Policy, observed: &Observed) -> Verdict {
    let mut out = Verdict {
        policy: policy.name.clone(),
        version: policy.version,
        mismatches: Vec::new(),
        unmeasured: Vec::new(),
    };
    let mut miss = |field: &str, expected: Vec<String>, optional: Vec<String>, actual: Vec<String>| {
        out.mismatches.push(Mismatch { field: field.to_string(), expected, optional, actual });
    };
    let judged = if policy.client_policy { Side::Client } else { Side::Server };
    if judged != observed.side {
        let (want, got) = (judged.word().to_string(), observed.side.word().to_string());
        miss("policy side", vec![want], Vec::new(), vec![got]);
    }
    for (field, want, got) in
        [("banner", &policy.banner, &observed.banner), ("header", &policy.header, &observed.header)]
    {
        if let Some(want) = want.as_ref().filter(|w| got.as_ref() != Some(*w)) {
            miss(field, vec![want.clone()], Vec::new(), got.iter().cloned().collect());
        }
    }
    if let Some(want) = policy.compressions.as_ref().filter(|w| **w != observed.compressions) {
        miss("compressions", want.clone(), Vec::new(), observed.compressions.clone());
    }
    if let Some(want) = &policy.host_keys {
        let actual: Vec<String> =
            observed.host_keys.iter().filter(|k| !policy.optional_host_keys.contains(k)).cloned().collect();
        if !lists_agree(want, &actual, policy.allow_hostkey_subset_and_reordering) {
            miss("host keys", want.clone(), policy.optional_host_keys.clone(), observed.host_keys.clone());
        }
    }
    let subset = policy.allow_algorithm_subset_and_reordering;
    // A policy that names a marker judges the list as it came, as
    // ssh-audit's own do; one that names none judges the key exchanges.
    let names_marker = policy.kex.as_ref().is_some_and(|k| k.iter().any(|n| MARKERS.contains(&n.as_str())));
    let kex: Vec<String> =
        observed.kex.iter().filter(|k| names_marker || !MARKERS.contains(&k.as_str())).cloned().collect();
    for (field, want, got) in [
        ("key exchanges", &policy.kex, &kex),
        ("ciphers", &policy.ciphers, &observed.ciphers),
        ("macs", &policy.macs, &observed.macs),
    ] {
        if let Some(want) = want.as_ref().filter(|w| !lists_agree(w, got, subset)) {
            miss(field, want.clone(), Vec::new(), got.clone());
        }
    }
    sizes(policy, observed, &mut out);
    out
}

/// In order and whole; or, where reordering is allowed, each name that came
/// is expected and at least one came.
fn lists_agree(expected: &[String], actual: &[String], subset: bool) -> bool {
    if subset {
        !actual.is_empty() && actual.iter().all(|a| expected.contains(a))
    } else {
        expected == actual
    }
}

/// A size meets its floor: equal, as ssh-audit asks, or larger where the
/// policy allows larger keys.
fn size_ok(floor: u32, bits: u32, larger: bool) -> bool {
    bits == floor || (larger && bits > floor)
}

fn mismatch(field: String, expected: String, actual: Option<String>) -> Mismatch {
    Mismatch { field, expected: vec![expected], optional: Vec::new(), actual: actual.into_iter().collect() }
}

fn sizes(policy: &Policy, observed: &Observed, out: &mut Verdict) {
    let larger = policy.allow_larger_keys;
    // A key of another type than the one requested is a mismatch with no
    // policy line for it: its size says nothing of the requested type.
    let seen = observed.host_key.as_ref();
    let typed = seen.filter(|s| {
        let want = key_type_of(&s.requested);
        let ok = s.returned == want;
        if !ok {
            out.mismatches.push(mismatch("host key type".into(), want, Some(s.returned.clone())));
        }
        ok
    });
    for (name, rule) in &policy.host_key_sizes {
        match typed.filter(|s| s.requested == *name) {
            Some(s) => {
                if !size_ok(rule.hostkey_size, s.bits, larger) {
                    let field = format!("host key size {name}");
                    out.mismatches.push(mismatch(field, rule.hostkey_size.to_string(), Some(s.bits.to_string())));
                }
                ca(name, rule, s, larger, out);
            }
            // Requested and of the wrong type: said once above.
            None if seen.is_some_and(|s| s.requested == *name) => {}
            None if observed.host_keys.contains(name) => out.unmeasured.push(format!("host key size {name}")),
            None => {}
        }
    }
    for (kex, floor) in &policy.dh_modulus_sizes {
        match observed.dh_modulus.get(kex) {
            Some(bits) if !size_ok(*floor, *bits, larger) => {
                let field = format!("DH modulus size {kex}");
                out.mismatches.push(mismatch(field, floor.to_string(), Some(bits.to_string())));
            }
            Some(_) => {}
            None if observed.kex.contains(kex) => out.unmeasured.push(format!("DH modulus size {kex}")),
            None => {}
        }
    }
}

fn ca(name: &str, rule: &super::file::SizeRule, seen: &HostKeySeen, larger: bool, out: &mut Verdict) {
    if rule.ca_key_type.is_none() && rule.ca_key_size.is_none() {
        return;
    }
    let Some((ca_type, ca_bits)) = &seen.ca else {
        let want = rule.ca_key_type.clone().unwrap_or_else(|| "a certificate".into());
        out.mismatches.push(mismatch(format!("CA key type {name}"), want, None));
        return;
    };
    if let Some(want) = rule.ca_key_type.as_ref().filter(|w| *w != ca_type) {
        out.mismatches.push(mismatch(format!("CA key type {name}"), want.clone(), Some(ca_type.clone())));
    }
    if let Some(floor) = rule.ca_key_size.filter(|f| !size_ok(*f, *ca_bits, larger)) {
        out.mismatches.push(mismatch(format!("CA key size {name}"), floor.to_string(), Some(ca_bits.to_string())));
    }
}
