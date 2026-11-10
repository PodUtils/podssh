//! The PAKE of croc's relay against vectors of a Python transcription of
//! siec.go and pake.go (affine forms, one inversion at each step), which
//! shares no code with `super::siec`; and against croc's own Go, in the
//! harness of T-694's Prove (UNVERIFIED until it runs).

use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn secret(from: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = from + i as u8;
    }
    s
}

/// A's message with the secret 1..=32: its SHA-256 and its length.
const A_MESSAGE_SHA256: &str = "cffd696de54179f9f32a5fe6fe61e5fecf42334030f6a218d2cf1ae975ff4b30";
const A_MESSAGE_LEN: usize = 633;
const X: (&str, &str) = (
    "21669097853230410346930434285083229351563897339580057304732792370452304580087",
    "3756381562106614610035329127563055699476168623945875100263199596259653155920",
);
/// The key of A (secret 1..=32) and B (secret 101..=132).
const KEY: &str = "30d6497689dd7aa3740119e85e9fa61b3c9677edf113002e46bbd0ca783fc058";

#[test]
fn a_s_message_is_go_s_json_byte_for_byte() {
    let a = Pake::with_secret(WEAK_KEY, 0, &secret(1));
    let bytes = a.bytes();
    assert_eq!(bytes.len(), A_MESSAGE_LEN, "{}", String::from_utf8_lossy(&bytes));
    assert_eq!(hex(&Sha256::digest(&bytes)), A_MESSAGE_SHA256, "{}", String::from_utf8_lossy(&bytes));
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.starts_with("{\"Role\":0,\"Uᵤ\":793136080485469241208656611513609866400481671853,"), "{text}");
    assert!(text.contains(&format!("\"Xᵤ\":{},\"Xᵥ\":{},\"Yᵤ\":null", X.0, X.1)), "{text}");
    assert!(text.ends_with("\"Zᵤ\":null,\"Zᵥ\":null,\"K\":null}"), "{text}");
}

#[test]
fn both_ends_take_the_key_of_the_vector() {
    let mut a = Pake::with_secret(WEAK_KEY, 0, &secret(1));
    let mut b = Pake::with_secret(WEAK_KEY, 1, &secret(101));
    assert!(b.session_key().is_none());
    b.update(&a.bytes()).expect("B reads A's X");
    a.update(&b.bytes()).expect("A reads B's Y");
    assert_eq!(hex(&a.session_key().unwrap()[..]), KEY);
    assert_eq!(hex(&b.session_key().unwrap()[..]), KEY);
    // B's message carries A's X back, as pake.go's Public() of B does.
    let text = String::from_utf8(b.bytes()).unwrap();
    assert!(text.starts_with("{\"Role\":1,") && text.contains(X.0), "{text}");
}

#[test]
fn random_secrets_agree_and_another_password_does_not() {
    let mut entropy = crate::session::OsEntropy;
    let mut a = Pake::new(WEAK_KEY, 0, &mut entropy).unwrap();
    let mut b = Pake::new(WEAK_KEY, 1, &mut entropy).unwrap();
    b.update(&a.bytes()).unwrap();
    a.update(&b.bytes()).unwrap();
    assert_eq!(a.session_key().unwrap()[..], b.session_key().unwrap()[..]);
    let mut other = Pake::new(&[9, 9, 9], 1, &mut entropy).unwrap();
    let mut a = Pake::new(WEAK_KEY, 0, &mut entropy).unwrap();
    other.update(&a.bytes()).unwrap();
    a.update(&other.bytes()).unwrap();
    assert_ne!(a.session_key().unwrap()[..], other.session_key().unwrap()[..]);
}

#[test]
fn a_message_of_one_s_own_role_off_the_curve_or_not_json_is_refused() {
    let a = Pake::with_secret(WEAK_KEY, 0, &secret(1));
    let mut also_a = Pake::with_secret(WEAK_KEY, 0, &secret(2));
    assert!(also_a.update(&a.bytes()).unwrap_err().contains("own role"));
    let mut b = Pake::with_secret(WEAK_KEY, 1, &secret(3));
    let off = String::from_utf8(a.bytes()).unwrap().replace(X.1, "12");
    assert!(b.update(off.as_bytes()).unwrap_err().contains("not on the curve"));
    let lead = String::from_utf8(a.bytes()).unwrap().replace(&format!(":{}", X.1), &format!(":0{}", X.1));
    assert!(b.update(lead.as_bytes()).unwrap_err().contains("not an integer"));
    for bad in ["", "[]", "{\"Role\":0", "{\"Role\":0}x", "{\"Role\":-1}", "{\"Role\":1.5}"] {
        assert!(b.update(bad.as_bytes()).is_err(), "{bad}");
    }
    assert!(b.update(&vec![b' '; MESSAGE_MOST + 1]).unwrap_err().contains("past"));
}

#[test]
fn the_scanner_reads_escapes_and_skips_values_that_are_not_read() {
    let text = "{ \"a\\u0062\" : \"x\\\"y\" , \"n\":null, \"t\":true, \"Role\": 0 ,\"\\ud83d\\ude00\":1}";
    let fields = object(text).unwrap();
    assert_eq!(fields[0], ("ab".to_string(), Value::Other));
    assert_eq!(fields[1], ("n".to_string(), Value::Null));
    assert_eq!(fields[3], ("Role".to_string(), Value::Number("0".into())));
    assert_eq!(fields[4].0, "\u{1f600}");
    assert_eq!(integer(&fields, "Role").unwrap(), BigUint::from(0u32));
    assert!(integer(&fields, "n").is_err() && integer(&fields, "missing").is_err());
    assert_eq!(object("{}").unwrap(), vec![]);
}
