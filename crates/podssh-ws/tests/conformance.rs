//! VEC-1 to VEC-5 from podssh's side: the published vectors go through
//! `pod-testkit::vectors` and the codecs that podssh's roads re-export. A
//! round trip through our own client and server would prove only that the
//! two agree; these tests are named for the proof they give, and the ones
//! that cannot give a byte-level proof say so.
//!
//! Shadowsocks: SIP004's subkey and sealed chunk, from OpenSSL and
//! RFC 5869's HKDF-SHA1. Trojan: the request's layout and SHA-224 from
//! Python's `hashlib`. VMess: `pod-testkit`'s fixture is built from the
//! published algorithm in Go, and the request header that makes it is
//! private to `pod-egress`; its byte-level run is `pod-egress`'s own
//! `vector_tests.rs`. What podssh can reach is the link's `alterId` rule,
//! and that is what its test asserts. No captured reference client or
//! Trojan server is faked here.

use base64::Engine as _;
use pod_testkit::vectors::{self, ShadowsocksCodec, TrojanCodec};
use podssh_ws::shadowsocks::{self, codec::Decoder, codec::Encoder, Method};
use podssh_ws::vmess::Server;

struct Shadowsocks;

impl ShadowsocksCodec for Shadowsocks {
    fn subkey(&self, master: &[u8], salt: &[u8]) -> Vec<u8> {
        shadowsocks::subkey(master, salt).to_vec()
    }

    fn seal(&self, method: &str, master: &[u8], salt: &[u8], plain: &[u8]) -> Vec<u8> {
        let method = Method::parse(method).expect("a method of the vectors");
        let mut out = Vec::new();
        Encoder::with_salt(method, master, salt)
            .expect("a salt of the method's length")
            .seal(plain, &mut out)
            .expect("the plain text is the vector's");
        out
    }

    fn open(&self, method: &str, master: &[u8], wire: &[u8]) -> Option<Vec<u8>> {
        let method = Method::parse(method).ok()?;
        let mut decoder = Decoder::new(method, master);
        decoder.feed(wire);
        let mut out = Vec::new();
        loop {
            match decoder.chunk() {
                Ok(Some(chunk)) => out.extend_from_slice(&chunk),
                Ok(None) => return Some(out),
                Err(_) => return None,
            }
        }
    }
}

struct Trojan;

impl TrojanCodec for Trojan {
    fn request(&self, password: &str, host: &str, port: u16) -> Result<Vec<u8>, String> {
        podssh_ws::trojan::request(password, host, port)
    }
}

/// VEC-1: each SIP004 vector's subkey, sealed first chunk and opening, in
/// `pod-testkit`'s runner, through the codec that podssh's road sends.
#[test]
fn the_published_shadowsocks_vectors_pass_through_podssh_s_shadowsocks_codec() {
    let checks = vectors::check_shadowsocks(&Shadowsocks).expect("the published vectors");
    assert_eq!(checks, 3 * vectors::SHADOWSOCKS.len());
    for vector in vectors::SHADOWSOCKS.iter() {
        assert!(!vector.source.is_empty());
    }
}

/// VEC-1: a changed byte of a sealed stream does not open, so the opening
/// that the runner checks is not a pass that any bytes would give.
#[test]
fn a_changed_shadowsocks_ciphertext_does_not_open() {
    let vector = &vectors::SHADOWSOCKS[0];
    let mut wire = vector.wire.to_vec();
    wire[vector.salt.len()] ^= 0x01;
    let opened = Shadowsocks.open(vector.method, vector.master_key, &wire);
    assert!(opened.is_none(), "a changed ciphertext does not open");
}

/// VEC-2: each published Trojan request, in `pod-testkit`'s runner, through
/// the request that podssh's road writes.
#[test]
fn the_published_trojan_requests_pass_through_podssh_s_trojan_codec() {
    let checks = vectors::check_trojan(&Trojan).expect("the published requests");
    assert_eq!(checks, vectors::TROJAN.len());
}

/// VEC-3: the fixture is the AEAD form, whose `alterId` is 0, and a link
/// with another `alterId` is refused by name. The request bytes themselves
/// are checked in `pod-egress`'s own vector test, which holds the private
/// header; podssh's test proves the rule that the two implementations
/// differ on, and says so in its name.
#[test]
fn the_vmess_link_refuses_the_md5_form_where_the_fixture_is_the_aead_form() {
    let fixture = &vectors::VMESS;
    assert_eq!(fixture.alter_id, 0, "the fixture is the AEAD form");
    assert_eq!(fixture.auth.len(), 16);
    assert!(fixture.wire.starts_with(fixture.auth));
    let id: String = fixture.id.iter().map(|b| format!("{b:02x}")).collect();
    for aid in [1u32, 64] {
        let json = format!(
            r#"{{"add":"n.example","port":"443","id":"{id}","aid":"{aid}","scy":"auto","net":"ws","tls":"tls"}}"#
        );
        let link = format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(json));
        let refused = Server::parse(&link).expect_err("the MD5 form is not spoken");
        assert!(refused.starts_with(&format!("aid={aid}: the MD5 form")), "{refused}");
    }
    let json =
        format!(r#"{{"add":"n.example","port":"443","id":"{id}","aid":"0","scy":"auto","net":"ws","tls":"tls"}}"#);
    let link = format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(json));
    assert!(Server::parse(&link).is_ok(), "the AEAD form's aid=0 parses");
}
