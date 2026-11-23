//! The policy file: ssh-audit's grammar, read so that its files load
//! unchanged. One `KEY = VALUE` on each line; `#` starts a comment line.
//! A field that podssh does not know is refused, never ignored: a policy
//! that names a check podssh would skip must not pass for it.

use std::collections::BTreeMap;

use serde_json::Value;

/// The most bytes of a policy file: ssh-audit's own are a few KiB.
pub const MAX_BYTES: usize = 1024 * 1024;
/// The largest host key or modulus that a size may name, in bits.
const MAX_BITS: u64 = 65_536;

/// The floors of one host key algorithm, as `host_key_sizes` names them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SizeRule {
    pub hostkey_size: u32,
    /// For a certificate: the type and the size of the key that signed it.
    pub ca_key_type: Option<String>,
    pub ca_key_size: Option<u32>,
}

/// A policy, as its file gave it. A list that is `None` is not checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub name: String,
    /// The policy's own revision, ssh-audit's `version`.
    pub version: u64,
    pub changelog: Option<String>,
    pub banner: Option<String>,
    pub header: Option<String>,
    pub compressions: Option<Vec<String>>,
    pub host_keys: Option<Vec<String>>,
    pub optional_host_keys: Vec<String>,
    pub kex: Option<Vec<String>>,
    pub ciphers: Option<Vec<String>>,
    pub macs: Option<Vec<String>>,
    pub host_key_sizes: BTreeMap<String, SizeRule>,
    pub dh_modulus_sizes: BTreeMap<String, u32>,
    /// `client policy = true`: the policy judges a client's KEXINIT.
    pub client_policy: bool,
    pub allow_algorithm_subset_and_reordering: bool,
    pub allow_larger_keys: bool,
    pub allow_hostkey_subset_and_reordering: bool,
}

/// Why a policy file is refused: its line (from 1; 0 for the whole file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub line: usize,
    pub why: String,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.line == 0 {
            write!(f, "{}", self.why)
        } else {
            write!(f, "line {}: {}", self.line, self.why)
        }
    }
}

/// The policy in `bytes`, the whole file.
pub fn parse(bytes: &[u8]) -> Result<Policy, PolicyError> {
    let whole = |why: String| PolicyError { line: 0, why };
    if bytes.len() > MAX_BYTES {
        return Err(whole(format!("{} bytes, over the {MAX_BYTES} that a policy file may have", bytes.len())));
    }
    let text = std::str::from_utf8(bytes).map_err(|e| whole(format!("not UTF-8 ({e})")))?;
    let mut read = Read::default();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        read.line(line).map_err(|why| PolicyError { line: i + 1, why })?;
    }
    read.finish().map_err(whole)
}

#[derive(Default)]
struct Read {
    policy: Policy,
    name: bool,
    version: bool,
    /// Each key given, so that a second one is refused: which one wins
    /// would be a guess.
    seen: Vec<String>,
}

impl Read {
    fn line(&mut self, line: &str) -> Result<(), String> {
        let (key, value) = line.split_once('=').ok_or("no '=': each line is KEY = VALUE")?;
        let (key, value) = (key.trim(), value.trim());
        if key.is_empty() {
            return Err("a line with no key before its '='".into());
        }
        if self.seen.iter().any(|k| k == key) {
            return Err(format!("{key:?} is given twice"));
        }
        self.seen.push(key.to_string());
        let p = &mut self.policy;
        match key {
            "name" => {
                p.name = unquoted(value).to_string();
                self.name = true;
            }
            "version" => {
                p.version = value.parse().map_err(|_| format!("version {value:?} is not a whole number"))?;
                self.version = true;
            }
            "changelog" => p.changelog = Some(value.to_string()),
            "banner" => p.banner = Some(unquoted(value).to_string()),
            "header" => p.header = Some(unquoted(value).to_string()),
            "compressions" => p.compressions = Some(list(value)?),
            "host keys" => p.host_keys = Some(list(value)?),
            "optional host keys" => p.optional_host_keys = list(value)?,
            "key exchanges" => p.kex = Some(list(value)?),
            "ciphers" => p.ciphers = Some(list(value)?),
            "macs" => p.macs = Some(list(value)?),
            "host_key_sizes" => {
                for (name, rule) in host_key_sizes(value)? {
                    put_size(&mut p.host_key_sizes, &name, rule)?;
                }
            }
            "dh_modulus_sizes" => {
                for (name, bits) in dh_modulus_sizes(value)? {
                    put_modulus(&mut p.dh_modulus_sizes, &name, bits)?;
                }
            }
            "client policy" => p.client_policy = truth(key, value)?,
            "allow_algorithm_subset_and_reordering" => p.allow_algorithm_subset_and_reordering = truth(key, value)?,
            "allow_larger_keys" => p.allow_larger_keys = truth(key, value)?,
            "allow_hostkey_subset_and_reordering" => p.allow_hostkey_subset_and_reordering = truth(key, value)?,
            // ssh-audit's older forms, one key for each size.
            _ if key.starts_with("hostkey_size_") => {
                let rule = SizeRule { hostkey_size: bits(value)?, ..SizeRule::default() };
                put_size(&mut p.host_key_sizes, &key["hostkey_size_".len()..], rule)?;
            }
            _ if key.starts_with("cakey_size_") => {
                let name = &key["cakey_size_".len()..];
                let size = bits(value)?;
                let rule = p.host_key_sizes.entry(name.to_string()).or_default();
                if rule.ca_key_size.is_some_and(|s| s != size) {
                    return Err(format!("two sizes of the CA key of {name}"));
                }
                rule.ca_key_size = Some(size);
            }
            _ if key.starts_with("dh_modulus_size_") => {
                put_modulus(&mut p.dh_modulus_sizes, &key["dh_modulus_size_".len()..], bits(value)?)?;
            }
            _ => return Err(format!("a field that podssh does not know: {key:?}")),
        }
        Ok(())
    }

    fn finish(self) -> Result<Policy, String> {
        if !self.name {
            return Err("the policy has no name: a line name = \"...\"".into());
        }
        if !self.version {
            return Err("the policy has no version: a line version = N".into());
        }
        if let Some((name, _)) = self.policy.host_key_sizes.iter().find(|(_, r)| r.hostkey_size == 0) {
            return Err(format!("the CA key of {name} has a size, and its host key has none"));
        }
        Ok(self.policy)
    }
}

/// A value in double quotes, as ssh-audit takes `name`, `banner` and
/// `header`, without them.
fn unquoted(value: &str) -> &str {
    value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value)
}

/// A list of names, by commas; an empty name is a typing fault.
fn list(value: &str) -> Result<Vec<String>, String> {
    let names: Vec<String> = value.split(',').map(|n| n.trim().to_string()).collect();
    if names.iter().any(String::is_empty) {
        return Err(format!("an empty name in the list {value:?}"));
    }
    if let Some(bad) = names.iter().find(|n| n.contains(char::is_whitespace)) {
        return Err(format!("{bad:?} is no algorithm name: names are split by commas"));
    }
    Ok(names)
}

fn truth(key: &str, value: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("{key} is true or false, not {value:?}")),
    }
}

fn bits(value: &str) -> Result<u32, String> {
    let n: u64 = value.parse().map_err(|_| format!("{value:?} is not a size in bits"))?;
    in_range(n).ok_or_else(|| format!("{n} bits: a size is from 1 to {MAX_BITS}"))
}

fn in_range(n: u64) -> Option<u32> {
    (1..=MAX_BITS).contains(&n).then_some(n as u32)
}

fn json_bits(value: &Value, what: &str) -> Result<u32, String> {
    value.as_u64().and_then(in_range).ok_or_else(|| format!("{what} is {value}, not a size from 1 to {MAX_BITS}"))
}

/// `host_key_sizes`: `{"ALG": {"hostkey_size": N, "ca_key_type": T, "ca_key_size": N}}`.
fn host_key_sizes(value: &str) -> Result<Vec<(String, SizeRule)>, String> {
    let doc: Value = serde_json::from_str(value).map_err(|e| format!("host_key_sizes is not JSON: {e}"))?;
    let map = doc.as_object().ok_or("host_key_sizes is not a JSON object")?;
    let mut out = Vec::new();
    for (name, rule) in map {
        let fields = rule.as_object().ok_or_else(|| format!("host_key_sizes: {name} is not an object"))?;
        let mut size = SizeRule::default();
        for (field, v) in fields {
            match field.as_str() {
                "hostkey_size" => size.hostkey_size = json_bits(v, &format!("{name}'s hostkey_size"))?,
                "ca_key_size" => size.ca_key_size = Some(json_bits(v, &format!("{name}'s ca_key_size"))?),
                "ca_key_type" => {
                    let t = v.as_str().ok_or_else(|| format!("{name}'s ca_key_type is not a string"))?;
                    size.ca_key_type = Some(t.to_string());
                }
                other => return Err(format!("host_key_sizes: a field that podssh does not know: {other:?}")),
            }
        }
        if size.hostkey_size == 0 {
            return Err(format!("host_key_sizes: {name} has no hostkey_size"));
        }
        out.push((name.clone(), size));
    }
    Ok(out)
}

/// `dh_modulus_sizes`: `{"KEX": N}`.
fn dh_modulus_sizes(value: &str) -> Result<Vec<(String, u32)>, String> {
    let doc: Value = serde_json::from_str(value).map_err(|e| format!("dh_modulus_sizes is not JSON: {e}"))?;
    let map = doc.as_object().ok_or("dh_modulus_sizes is not a JSON object")?;
    map.iter().map(|(name, v)| json_bits(v, name).map(|bits| (name.clone(), bits))).collect()
}

fn put_size(sizes: &mut BTreeMap<String, SizeRule>, name: &str, rule: SizeRule) -> Result<(), String> {
    match sizes.get_mut(name) {
        // An older cakey_size_ line may have come first.
        Some(have) if have.hostkey_size == 0 && have.ca_key_type.is_none() => {
            let ca = have.ca_key_size;
            *have = SizeRule { ca_key_size: rule.ca_key_size.or(ca), ..rule };
            Ok(())
        }
        Some(_) => Err(format!("two sizes of the host key {name}")),
        None => {
            sizes.insert(name.to_string(), rule);
            Ok(())
        }
    }
}

fn put_modulus(sizes: &mut BTreeMap<String, u32>, name: &str, bits: u32) -> Result<(), String> {
    if sizes.insert(name.to_string(), bits).is_some() {
        return Err(format!("two modulus sizes of {name}"));
    }
    Ok(())
}
