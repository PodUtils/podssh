//! The login probe against a russh server in this process: with its host key
//! named, the server refuses the key made for the call; with another host key
//! named, no key is offered.

use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth};

use super::*;

/// Refuses every key, as GitHub refuses a key that no account has.
struct Strict;

impl server::Handler for Strict {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::reject())
    }
}

/// A login to a [`Strict`] server; `named` says whether its own host key is
/// the one accepted.
async fn against(named: bool) -> Result<Login, String> {
    let (client_end, server_end) = tokio::io::duplex(1 << 16);
    let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key");
    let own = crate::known_hosts::fingerprint(host.public_key());
    let mut config = server::Config::default();
    config.keys.push(host);
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let config = Arc::new(config);
    tokio::spawn(async move {
        if let Ok(session) = server::run_stream(config, server_end, Strict).await {
            let _ = session.await;
        }
    });
    let other = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    let accepted = if named { vec![own] } else { vec![other] };
    login(client_end, "git", &accepted, Duration::from_secs(20)).await
}

#[tokio::test]
async fn login_with_the_named_host_key_reaches_the_refusal() {
    match against(true).await {
        Ok(Login::Refused { methods, .. }) => assert!(methods.contains(&"publickey".to_string()), "{methods:?}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn login_stops_at_a_host_key_that_was_not_named() {
    match against(false).await {
        Ok(Login::WrongHostKey { .. }) => {}
        other => panic!("{other:?}"),
    }
}

/// The policy probe against a russh server in this process, whose key
/// exchange is set to one name: a policy of that name passes, one of
/// another name is a mismatch that names the field, and a stream that
/// ends before a banner gives no reading.
#[tokio::test]
async fn the_policy_probe_judges_the_server_s_kexinit_with_no_login() {
    async fn probe(policy: &str) -> Result<crate::policy::Verdict, String> {
        let (client_end, server_end) = tokio::io::duplex(1 << 16);
        let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("a host key");
        let mut config = server::Config::default();
        config.keys.push(host);
        config.preferred.kex = std::borrow::Cow::Owned(vec![russh::kex::CURVE25519]);
        let config = Arc::new(config);
        tokio::spawn(async move {
            if let Ok(session) = server::run_stream(config, server_end, Strict).await {
                let _ = session.await;
            }
        });
        let policy = crate::policy::parse(policy.as_bytes()).expect("the policy reads");
        algorithm_policy(client_end, &policy, Duration::from_secs(20)).await
    }
    let pass = probe("name = \"one\"\nversion = 1\nkey exchanges = curve25519-sha256\n").await.expect("a reading");
    assert_eq!(pass.exit(), crate::policy::EXIT_PASS, "{pass:?}");
    let other = "name = \"two\"\nversion = 1\nkey exchanges = diffie-hellman-group14-sha256\n";
    let mismatch = probe(other).await.expect("a reading");
    assert_eq!(mismatch.exit(), crate::policy::EXIT_MISMATCH, "{mismatch:?}");
    assert_eq!(mismatch.mismatches[0].field, "key exchanges", "{mismatch:?}");

    let (client_end, server_end) = tokio::io::duplex(64);
    drop(server_end);
    let policy = crate::policy::parse(b"name = \"x\"\nversion = 1\n").expect("the policy reads");
    assert!(algorithm_policy(client_end, &policy, Duration::from_secs(5)).await.is_err());
}
