//! The PAKE of croc's relay handshake: schollz/pake v3 (pake.go at v3.2.0)
//! on SIEC (`super::siec`), with croc's fixed weak key `[1, 2, 3]`
//! (schollz/croc:src/tcp/tcp.go at v11.6.4, `weakKey`). Party A (role 0, the
//! relay's client) sends X = pw·U + a·G; party B (role 1, the relay) answers
//! Y = pw·V + b·G; each takes Z, the other's point less its mask, times its
//! own secret, and the key is the SHA-256 of pw, X, Y and Z, each coordinate
//! in Go's bytes. The key is no secret of podssh's: the weak key and the
//! relay's password are public, so the handshake proves nothing; it is the
//! relay's door, and podssh's own proof of the pair runs after it
//! (`super::meet`).
//!
//! A message is the JSON of Go's `Pake.Public()`: each field in the struct's
//! order, the integers in decimal, the private ones null. Integers of 77
//! digits are past a float's, so the message is read by a small scanner of
//! its own, not by serde_json, which would round them.

use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::siec::{go_bytes, Curve, Point};
use crate::session::secret::{Entropy, NoRandom};

/// croc's weak key of the relay's PAKE.
pub const WEAK_KEY: &[u8] = &[1, 2, 3];
/// The longest message read, as croc's web client bounds it.
pub const MESSAGE_MOST: usize = 4096;
/// The most digits of an integer of a message, as the web client reads one.
const DIGITS_MOST: usize = 157;

/// One end of the PAKE.
pub struct Pake {
    curve: Curve,
    role: u8,
    pw: Vec<u8>,
    secret: Zeroizing<[u8; 32]>,
    x: Option<Point>,
    y: Option<Point>,
    key: Option<[u8; 32]>,
}

impl Pake {
    /// Role 0 (the client of the relay) or 1 (the relay), with a secret of
    /// `entropy`'s, as pake.go draws 32 random bytes.
    pub fn new(pw: &[u8], role: u8, entropy: &mut dyn Entropy) -> Result<Pake, NoRandom> {
        let mut secret = Zeroizing::new([0u8; 32]);
        entropy.fill(&mut secret[..])?;
        Ok(Pake::with_secret(pw, role, &secret))
    }

    /// The same with a secret given: for the vectors of a test.
    pub fn with_secret(pw: &[u8], role: u8, secret: &[u8; 32]) -> Pake {
        let curve = Curve::siec();
        let role = role.min(1);
        // A computes X at once; B computes Y when X comes.
        let x = (role == 0).then(|| curve.add(&curve.multiply(&curve.u, pw), &curve.multiply(&curve.g, secret)));
        Pake { curve, role, pw: pw.to_vec(), secret: Zeroizing::new(*secret), x, y: None, key: None }
    }

    /// This end's message: the JSON of pake.go's `Public()`.
    pub fn bytes(&self) -> Vec<u8> {
        let n = |n: Option<&BigUint>| n.map_or_else(|| "null".to_string(), |n| n.to_str_radix(10));
        let (u, v) = (&self.curve.u, &self.curve.v);
        let (x, y) = (self.x.as_ref(), self.y.as_ref());
        format!(
            "{{\"Role\":{},\"Uᵤ\":{},\"Uᵥ\":{},\"Vᵤ\":{},\"Vᵥ\":{},\"Xᵤ\":{},\"Xᵥ\":{},\"Yᵤ\":{},\"Yᵥ\":{},\
             \"P\":null,\"Pw\":null,\"Vpwᵤ\":null,\"Vpwᵥ\":null,\"Upwᵤ\":null,\"Upwᵥ\":null,\"Aα\":null,\
             \"Aαᵤ\":null,\"Aαᵥ\":null,\"Zᵤ\":null,\"Zᵥ\":null,\"K\":null}}",
            self.role,
            u.x,
            u.y,
            v.x,
            v.y,
            n(x.map(|p| &p.x)),
            n(x.map(|p| &p.y)),
            n(y.map(|p| &p.x)),
            n(y.map(|p| &p.y)),
        )
        .into_bytes()
    }

    /// The other end's message: its point, checked on the curve, then Z and
    /// the key; B computes its Y here, as pake.go's `Update` does.
    pub fn update(&mut self, peer: &[u8]) -> Result<(), String> {
        if peer.len() > MESSAGE_MOST {
            return Err(format!("a PAKE message of {} bytes, past {MESSAGE_MOST}", peer.len()));
        }
        let text = std::str::from_utf8(peer).map_err(|_| "a PAKE message that is not UTF-8".to_string())?;
        let fields = object(text)?;
        let role = integer(&fields, "Role")?;
        if role != BigUint::from(1 - self.role) {
            return Err("a PAKE message of this end's own role".into());
        }
        let prefix = if self.role == 1 { 'X' } else { 'Y' };
        let ux = integer(&fields, &format!("{prefix}ᵤ"))?;
        let uy = integer(&fields, &format!("{prefix}ᵥ"))?;
        let theirs = Point { x: ux, y: uy };
        if !self.curve.is_on_curve(&theirs) {
            return Err(format!("the PAKE's {prefix} is not on the curve"));
        }
        let c = &self.curve;
        let z = if self.role == 1 {
            let upw = c.multiply(&c.u, &self.pw);
            self.y = Some(c.add(&c.multiply(&c.v, &self.pw), &c.multiply(&c.g, &self.secret[..])));
            let z = c.add(&theirs, &c.negate(&upw));
            self.x = Some(theirs);
            c.multiply(&z, &self.secret[..])
        } else {
            let vpw = c.multiply(&c.v, &self.pw);
            let z = c.add(&theirs, &c.negate(&vpw));
            self.y = Some(theirs);
            c.multiply(&z, &self.secret[..])
        };
        let (Some(x), Some(y)) = (&self.x, &self.y) else {
            return Err("the PAKE has no X".into());
        };
        let mut hash = Sha256::new();
        hash.update(&self.pw);
        for n in [&x.x, &x.y, &y.x, &y.y, &z.x, &z.y] {
            hash.update(go_bytes(n));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash.finalize());
        self.key = Some(key);
        Ok(())
    }

    /// The session key, once the other end's message came.
    pub fn session_key(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.key.map(Zeroizing::new)
    }
}

/// A value of a message: an integer's digits, null, or another value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Number(String),
    Null,
    Other,
}

/// The integer of field `name`, refused when it is missing, null, signed,
/// written with a leading zero or longer than the web client takes.
fn integer(fields: &[(String, Value)], name: &str) -> Result<BigUint, String> {
    let digits = match fields.iter().find(|(key, _)| key == name) {
        Some((_, Value::Number(digits))) => digits,
        _ => return Err(format!("a PAKE message with no {name}")),
    };
    let canonical = digits == "0" || (!digits.starts_with('0') && digits.len() <= DIGITS_MOST);
    if !canonical || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("the PAKE's {name} is not an integer"));
    }
    BigUint::parse_bytes(digits.as_bytes(), 10).ok_or_else(|| format!("the PAKE's {name} is not an integer"))
}

/// The fields of one flat JSON object, in order.
fn object(text: &str) -> Result<Vec<(String, Value)>, String> {
    let bad = || "a PAKE message that is not a JSON object".to_string();
    let b = text.as_bytes();
    let mut i = blank(b, 0);
    if b.get(i) != Some(&b'{') {
        return Err(bad());
    }
    i = blank(b, i + 1);
    let mut out = Vec::new();
    if b.get(i) == Some(&b'}') {
        i += 1;
    } else {
        loop {
            let (key, next) = string(text, i).ok_or_else(bad)?;
            i = blank(b, next);
            if b.get(i) != Some(&b':') {
                return Err(bad());
            }
            let (value, next) = value(text, blank(b, i + 1)).ok_or_else(bad)?;
            out.push((key, value));
            i = blank(b, next);
            match b.get(i) {
                Some(b',') => i = blank(b, i + 1),
                Some(b'}') => {
                    i += 1;
                    break;
                }
                _ => return Err(bad()),
            }
        }
    }
    if blank(b, i) != b.len() {
        return Err(bad());
    }
    Ok(out)
}

fn blank(b: &[u8], mut i: usize) -> usize {
    while matches!(b.get(i), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        i += 1;
    }
    i
}

/// A string at `i`, with its escapes read, and the index after it.
fn string(text: &str, mut i: usize) -> Option<(String, usize)> {
    let b = text.as_bytes();
    if b.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;
    let mut out = String::new();
    let mut run = i;
    loop {
        match *b.get(i)? {
            b'"' => {
                out.push_str(text.get(run..i)?);
                return Some((out, i + 1));
            }
            b'\\' => {
                out.push_str(text.get(run..i)?);
                let (c, next) = escape(text, i + 1)?;
                out.push(c);
                i = next;
                run = i;
            }
            0..=0x1f => return None,
            _ => i += 1,
        }
    }
}

/// The character of an escape after its backslash, and the index after it.
fn escape(text: &str, i: usize) -> Option<(char, usize)> {
    let c = match *text.as_bytes().get(i)? {
        b'"' => '"',
        b'\\' => '\\',
        b'/' => '/',
        b'b' => '\u{8}',
        b'f' => '\u{c}',
        b'n' => '\n',
        b'r' => '\r',
        b't' => '\t',
        b'u' => {
            let unit = |at: usize| u32::from_str_radix(text.get(at..at + 4)?, 16).ok();
            let high = unit(i + 1)?;
            // A pair of surrogates is one character, as Go writes one.
            if (0xd800..0xdc00).contains(&high) && text.get(i + 5..i + 7) == Some("\\u") {
                let low = unit(i + 7)?;
                let joined = 0x10000 + ((high - 0xd800) << 10) + low.checked_sub(0xdc00)?;
                return Some((char::from_u32(joined)?, i + 11));
            }
            return Some((char::from_u32(high).unwrap_or('\u{fffd}'), i + 5));
        }
        _ => return None,
    };
    Some((c, i + 1))
}

/// A value at `i`: an integer, null, or a string, true or false, which no
/// field that is read holds; and the index after it.
fn value(text: &str, i: usize) -> Option<(Value, usize)> {
    let b = text.as_bytes();
    let rest = text.get(i..)?;
    if rest.starts_with("null") {
        return Some((Value::Null, i + 4));
    }
    for word in ["true", "false"] {
        if rest.starts_with(word) {
            return Some((Value::Other, i + word.len()));
        }
    }
    if b.get(i) == Some(&b'"') {
        let (_, next) = string(text, i)?;
        return Some((Value::Other, next));
    }
    let end =
        (i..b.len()).find(|&j| !matches!(b[j], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')).unwrap_or(b.len());
    (end > i).then(|| (Value::Number(text[i..end].to_string()), end))
}

#[cfg(test)]
#[path = "pake_tests.rs"]
mod tests;
