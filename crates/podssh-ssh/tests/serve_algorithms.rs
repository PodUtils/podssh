//! The algorithms of `podssh serve` (T-841): one stated set, held here
//! against a table of its own. The server's constant and the config that it
//! runs with must be the table, name for name; and russh's client, offering
//! one name alone of each name that podssh's client knows (its table of
//! T-505, `algorithms::spoken`), is let in when the table has the name and
//! refused by the handshake when it does not. A set, not a ranking: to
//! require a name, the client offers that one and nothing else.
//!
//! A refusal of the handshake has one reply: the server's KEXINIT, whose
//! lists the client finds no name of its own in. russh's server sends no
//! DISCONNECT for it; its connection ends with `No common ... algorithm`,
//! which is what this test reads of the server. OpenSSH's words for the same
//! refusal, and the table of the other refusals, are `podssh-cli`'s
//! `tests/serve_algorithms_openssh.rs`.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::algorithms::{spoken, Kind};
use podssh_ssh::keygen::{self, KeyKind};
use podssh_ssh::russh::keys::{Algorithm, EcdsaCurve, PrivateKey, PrivateKeyWithHashAlg};
use podssh_ssh::russh::{self, cipher, client, kex, mac, Preferred};
use podssh_ssh::server::{self, algorithms, Authorized};

/// A bound on each handshake: the largest group of DH takes a while.
const LIMIT: Duration = Duration::from_secs(30);

/// The key exchanges that serve offers: this table, not russh's default,
/// is the record. Adding a name to the constant that this table lacks
/// fails [`the_constant_is_the_table`].
const KEX: &[&str] = &[
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group17-sha512",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group15-sha512",
    "diffie-hellman-group14-sha256",
];

/// The extensions that ride in the list of key exchanges.
const KEX_EXTENSIONS: &[&str] =
    &["ext-info-c", "ext-info-s", "kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com"];

const HOST_KEYS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
];

const CIPHERS: &[&str] =
    &["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"];

const MACS: &[&str] =
    &["hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512", "hmac-sha2-256"];

const COMPRESSION: &[&str] = &["none", "zlib", "zlib@openssh.com"];

fn ed25519() -> PrivateKey {
    keygen::generate(KeyKind::Ed25519, "test").unwrap()
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|n| n.to_string()).collect()
}

#[test]
fn the_constant_is_the_table() {
    assert_eq!(algorithms::kex_names(), strings(KEX), "the key exchanges");
    assert_eq!(algorithms::names(algorithms::KEX_EXTENSIONS), strings(KEX_EXTENSIONS), "the extensions");
    assert_eq!(algorithms::host_key_names(), strings(HOST_KEYS), "the host key algorithms");
    assert_eq!(algorithms::names(algorithms::CIPHERS), strings(CIPHERS), "the ciphers");
    assert_eq!(algorithms::names(algorithms::MACS), strings(MACS), "the MACs");
    assert_eq!(algorithms::names(algorithms::COMPRESSION), strings(COMPRESSION), "the compressions");
    // And the server runs with it, not with a list of its own.
    let preferred = server::config(ed25519()).preferred;
    let kex: Vec<String> = KEX.iter().chain(KEX_EXTENSIONS).map(|n| n.to_string()).collect();
    assert_eq!(algorithms::names(&preferred.kex), kex, "the server's key exchanges");
    let keys: Vec<String> = preferred.key.iter().map(|a| a.as_str().to_string()).collect();
    assert_eq!(keys, strings(HOST_KEYS), "the server's host key algorithms");
    assert!(preferred.host_key_certificates.is_empty(), "a server offers no certificate of its own");
    assert_eq!(algorithms::names(&preferred.cipher), strings(CIPHERS), "the server's ciphers");
    assert_eq!(algorithms::names(&preferred.mac), strings(MACS), "the server's MACs");
    assert_eq!(algorithms::names(&preferred.compression), strings(COMPRESSION), "the server's compressions");
}

/// The host keys of the test, one of each type that the set can serve: a
/// row of a host key algorithm meets a server whose key is of that type,
/// so that only the set decides.
struct HostKeys {
    ed25519: PrivateKey,
    p256: PrivateKey,
    p384: PrivateKey,
    p521: PrivateKey,
    rsa: PrivateKey,
}

impl HostKeys {
    fn new() -> HostKeys {
        let ecdsa = |curve| keygen::generate(KeyKind::Ecdsa(curve), "host").unwrap();
        HostKeys {
            ed25519: ed25519(),
            p256: ecdsa(EcdsaCurve::NistP256),
            p384: ecdsa(EcdsaCurve::NistP384),
            p521: ecdsa(EcdsaCurve::NistP521),
            rsa: keygen::generate(KeyKind::Rsa(2048), "host").unwrap(),
        }
    }

    /// The key of the type that `name` (a plain name or a certificate's)
    /// signs with.
    fn for_name(&self, name: &str) -> PrivateKey {
        let key = if name.contains("nistp256") {
            &self.p256
        } else if name.contains("nistp384") {
            &self.p384
        } else if name.contains("nistp521") {
            &self.p521
        } else if name.contains("rsa") {
            &self.rsa
        } else {
            &self.ed25519
        };
        key.clone()
    }
}

/// The client's lists for one row: `name` alone of `kind`, and russh's
/// default for the rest. A MAC row takes a cipher that needs a MAC, as an
/// AEAD cipher negotiates none.
fn alone(kind: Kind, name: &str) -> Preferred {
    let mut preferred = Preferred::DEFAULT;
    match kind {
        Kind::Kex => {
            let mut list = vec![kex::Name::try_from(name).expect("a key exchange that russh knows")];
            list.extend(algorithms::KEX_EXTENSIONS.iter().copied());
            preferred.kex = Cow::Owned(list);
        }
        Kind::Ciphers => {
            preferred.cipher = Cow::Owned(vec![cipher::Name::try_from(name).expect("a cipher that russh knows")]);
        }
        Kind::Macs => {
            preferred.cipher = Cow::Owned(vec![cipher::AES_256_CTR]);
            preferred.mac = Cow::Owned(vec![mac::Name::try_from(name).expect("a MAC that russh knows")]);
        }
        Kind::HostKey => {
            let plain = Preferred::DEFAULT.key.iter().find(|a| a.as_str() == name).cloned();
            match plain {
                Some(algorithm) => preferred.key = Cow::Owned(vec![algorithm]),
                // A certificate's name: that certificate alone is asked for.
                None => {
                    let certified: Vec<Algorithm> =
                        Preferred::DEFAULT.key.iter().filter(|a| a.to_certificate_type() == name).cloned().collect();
                    assert_eq!(certified.len(), 1, "{name} names one certificate");
                    preferred.key = Cow::Owned(Vec::new());
                    preferred.host_key_certificates = Cow::Owned(certified);
                }
            }
        }
        Kind::Pubkey | Kind::CaSignature => unreachable!("not a list of the handshake"),
    }
    preferred
}

/// The word of russh's error for a list of `kind`.
fn word(kind: Kind) -> &'static str {
    match kind {
        Kind::Kex => "Kex",
        Kind::HostKey => "Key",
        Kind::Ciphers => "Cipher",
        Kind::Macs => "Mac",
        Kind::Pubkey | Kind::CaSignature => unreachable!("not a list of the handshake"),
    }
}

/// A client that takes any host key: the test checks the server's lists,
/// not the client's trust.
struct Trusting;

impl client::Handler for Trusting {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// One row: a server with `host_key` and the set; a client that offers
/// `preferred`. Ok when the login worked; Err with the server's words
/// when the connection did not get that far.
async fn row(host_key: PrivateKey, preferred: Preferred) -> Result<(), String> {
    let login = ed25519();
    let mut authorized = Authorized::new();
    authorized.add(login.public_key().key_data().clone());
    let (near, far) = tokio::io::duplex(1 << 20);
    let served = tokio::spawn(server::serve(far, host_key, Arc::new(authorized)));
    let config = Arc::new(client::Config { preferred, ..client::Config::default() });
    let mut handle = match client::connect_stream(config, near, Trusting).await {
        Ok(handle) => handle,
        Err(client_said) => {
            let server_said = match tokio::time::timeout(LIMIT, served).await {
                Ok(Ok(Err(why))) => why,
                other => format!("the server did not fail ({other:?}); the client: {client_said}"),
            };
            return Err(server_said);
        }
    };
    let signed = PrivateKeyWithHashAlg::new(Arc::new(login), None);
    let result = handle.authenticate_publickey("anyone", signed).await.map_err(|e| format!("the login: {e}"))?;
    if !result.success() {
        return Err("the login was refused".into());
    }
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "").await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_name_of_the_set_is_let_in_and_each_other_is_refused() {
    let hosts = HostKeys::new();
    let mut wrong = Vec::new();
    let mut rows = 0;
    for (kind, table) in [(Kind::Kex, KEX), (Kind::HostKey, HOST_KEYS), (Kind::Ciphers, CIPHERS), (Kind::Macs, MACS)] {
        for name in spoken(kind) {
            rows += 1;
            let in_set = table.contains(&name.as_str());
            let host_key = hosts.for_name(&name);
            let got = tokio::time::timeout(LIMIT, row(host_key, alone(kind, &name))).await;
            let got = got.unwrap_or_else(|_| Err(format!("no answer within {LIMIT:?}")));
            let refusal = format!("No common {} algorithm", word(kind));
            match (in_set, got) {
                (true, Ok(())) => {}
                (false, Err(why)) if why.contains(&refusal) => {}
                (true, Err(why)) => wrong.push(format!("{} {name}: in the set, yet refused: {why}", kind.keyword())),
                (false, Ok(())) => wrong.push(format!("{} {name}: not in the set, yet let in", kind.keyword())),
                (false, Err(why)) => {
                    wrong.push(format!("{} {name}: refused, but not by the handshake's lists: {why}", kind.keyword()))
                }
            }
        }
    }
    // Each table's names are names that the client knows: a row of each.
    for (kind, table) in [(Kind::Kex, KEX), (Kind::HostKey, HOST_KEYS), (Kind::Ciphers, CIPHERS), (Kind::Macs, MACS)] {
        let known = spoken(kind);
        for name in table {
            if !known.iter().any(|k| k == name) {
                wrong.push(format!("{} {name}: in the set, but no row tried it", kind.keyword()));
            }
        }
    }
    assert!(rows > 30, "each list of the client's table was tried: {rows} rows");
    assert!(wrong.is_empty(), "{} rows wrong:\n{}", wrong.len(), wrong.join("\n"));
}
