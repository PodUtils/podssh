//! The gate of a client's KEXINIT, as one table: a client policy, what the
//! client offered, and whether the connection ends with a line that names
//! each mismatch. The client lists are OpenSSH 9's defaults as its source
//! names them; the bytes of a live OpenSSH client are `serve_policy_openssh.rs`'s.

use std::sync::Mutex;

use tokio::io::AsyncReadExt;

use super::*;
use crate::server::{Control, Say};

const VERSION: &[u8] = b"SSH-2.0-OpenSSH_9.6p1\r\n";
const KEX: &str = "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,\
ecdh-sha2-nistp256,ext-info-c,kex-strict-c-v00@openssh.com";
const CIPHERS: &str = "chacha20-poly1305@openssh.com,aes128-ctr,aes256-gcm@openssh.com";

/// A KEXINIT payload of these ten lists.
fn kexinit(ten: [&str; 10]) -> Vec<u8> {
    let mut out = vec![20];
    out.extend_from_slice(&[7u8; 16]);
    for list in ten {
        out.extend_from_slice(&(list.len() as u32).to_be_bytes());
        out.extend_from_slice(list.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

/// `payload` as an unencrypted binary packet (RFC 4253, section 6).
fn packet(payload: &[u8]) -> Vec<u8> {
    let mut padding = 8 - (5 + payload.len()) % 8;
    if padding < 4 {
        padding += 8;
    }
    let mut out = ((1 + payload.len() + padding) as u32).to_be_bytes().to_vec();
    out.push(padding as u8);
    out.extend_from_slice(payload);
    out.resize(out.len() + padding, 0);
    out
}

/// The client's first bytes: its version line and its KEXINIT.
fn client(kex: &str, ciphers: &str) -> Vec<u8> {
    let lists = [kex, "ssh-ed25519", ciphers, ciphers, "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""];
    [VERSION.to_vec(), packet(&kexinit(lists))].concat()
}

fn policy(more: &str) -> Arc<Policy> {
    let text = format!("name = \"clients\"\nversion = 1\nclient policy = true\n{more}");
    Arc::new(crate::policy::parse(text.as_bytes()).unwrap_or_else(|e| panic!("{e}: {text}")))
}

/// What the gate did with `bytes`: what the client was told, and serve's
/// lines.
async fn gate(policy: Option<Arc<Policy>>, bytes: &[u8]) -> (Vec<u8>, Option<String>, Vec<String>) {
    let said = Arc::new(Mutex::new(Vec::new()));
    let sink = said.clone();
    let say = Say(Arc::new(move |line: &str| sink.lock().unwrap().push(line.to_string())));
    let settings = Arc::new(Settings { policy, say: Some(say), ..Settings::default() });
    let control = Control::new();
    let conn = control.live.join(None);
    let mut gated = Gated::new(bytes, &conn, &settings);
    let mut read = Vec::new();
    gated.read_to_end(&mut read).await.unwrap();
    let lines = said.lock().unwrap().clone();
    (read, conn.ended(), lines)
}

#[tokio::test]
async fn the_gate_of_each_case() {
    // (case, policy's lines, the client's key exchanges and ciphers, the
    // fields that its line must name; none passes).
    let cases: &[(&str, &str, &str, &str, &[&str])] = &[
        (
            "subset inside",
            "key exchanges = curve25519-sha256, sntrup761x25519-sha512@openssh.com, \
          curve25519-sha256@libssh.org, ecdh-sha2-nistp256\nallow_algorithm_subset_and_reordering = true",
            KEX,
            CIPHERS,
            &[],
        ),
        (
            "only one name, offered alone",
            "key exchanges = curve25519-sha256",
            "curve25519-sha256,ext-info-c",
            CIPHERS,
            &[],
        ),
        ("only one name, more offered", "key exchanges = curve25519-sha256", KEX, CIPHERS, &["key exchanges"]),
        (
            "a weak cipher",
            "ciphers = aes128-ctr, aes256-gcm@openssh.com\nallow_algorithm_subset_and_reordering = true",
            KEX,
            "aes128-ctr,3des-cbc",
            &["ciphers"],
        ),
        (
            "two fields",
            "key exchanges = curve25519-sha256\nciphers = aes128-ctr",
            KEX,
            CIPHERS,
            &["key exchanges", "ciphers"],
        ),
    ];
    for (case, more, kex, ciphers, fields) in cases {
        let bytes = client(kex, ciphers);
        let (read, ended, lines) = gate(Some(policy(more)), &bytes).await;
        assert_eq!(read, bytes, "{case}: the gate changes no byte");
        if fields.is_empty() {
            assert!(ended.is_none() && lines.is_empty(), "{case}: passes: {lines:?}");
            continue;
        }
        assert_eq!(ended.as_deref(), Some(told(&policy(more)).as_str()), "{case}: the client hears the policy");
        assert_eq!(lines.len(), 1, "{case}: one line: {lines:?}");
        assert!(lines[0].starts_with("client with no address (a pipe): refused before authentication"), "{case}");
        for field in *fields {
            assert!(lines[0].contains(&format!("{field} expected")), "{case}: names {field}: {}", lines[0]);
        }
    }
}

/// A KEXINIT that does not read, or never came before NEWKEYS, is refused
/// as no reading; with no policy, nothing is judged.
#[tokio::test]
async fn no_reading_is_refused_and_no_policy_judges_nothing() {
    let broken = [VERSION.to_vec(), packet(&[20, 1, 2, 3])].concat();
    let (_, ended, lines) = gate(Some(policy("ciphers = aes128-ctr")), &broken).await;
    assert!(ended.is_some(), "{lines:?}");
    assert!(lines[0].contains("no verdict of the policy"), "{lines:?}");

    let sealed = [VERSION.to_vec(), packet(&[21])].concat();
    let (_, ended, lines) = gate(Some(policy("ciphers = aes128-ctr")), &sealed).await;
    assert!(ended.is_some() && lines[0].contains("not read whole"), "{lines:?}");

    let (read, ended, lines) = gate(None, &client(KEX, CIPHERS)).await;
    assert_eq!(read, client(KEX, CIPHERS));
    assert!(ended.is_none() && lines.is_empty());
}

/// The verdict falls however the client's bytes are cut.
#[test]
fn the_verdict_falls_however_the_bytes_are_cut() {
    let bytes = client(KEX, CIPHERS);
    for cut in [1, 7, 64, bytes.len()] {
        let policy = Some(policy("key exchanges = curve25519-sha256"));
        let settings = Arc::new(Settings { policy, ..Settings::default() });
        let control = Control::new();
        let conn = control.live.join(None);
        let mut gate = Gated::new((), &conn, &settings).gate.expect("a gate with a policy");
        let done: Vec<bool> = bytes.chunks(cut).map(|piece| gate.feed(piece)).collect();
        assert_eq!(done.last(), Some(&true), "cut {cut}");
        assert!(done[..done.len() - 1].iter().all(|d| !d), "cut {cut}: no verdict before the last byte");
        assert!(conn.ended().is_some(), "cut {cut}");
    }
}
