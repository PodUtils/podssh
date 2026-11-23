//! #225: every route of the relay under a cover answers the site's exact 404
//! without the cover credential, the pair mint takes it, and the live upgrade
//! verifies it: another key, another name, a lapsed window and a replay are
//! each refused.
//!
//!     cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_cover_credential
#![cfg(all(feature = "serve", feature = "plain-ws", unix))]

mod cover_harness;
mod cover_rig;
mod publish_harness;

use cover_harness::{header, Tree};
use cover_rig::{ask, ask_on, credential_for, start, target, upgrade_on, SERVER};
use pod_cover::Site;
use podssh_relay::serve::cover::{Cover, Issuer, VerifyError};
use podssh_relay::serve::surface::{self, Reach};
use podssh_relay::serve::tokens;
use podssh_ws::tls_server::HTTP1;
use publish_harness::{visit, ROLE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// T-767 (SURF-1) and #225: one unauthenticated request to every row of the
/// router gets the site's exact 404, the mint aside because it is the one
/// open route. A row added to `ROUTES` is reached by this test, so a route
/// that the cover does not gate fails here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_route_is_the_sites_404_under_a_cover() {
    let rig = start("routes", Tree::new("routes")).await;
    let mut checked = 0;
    let mut skipped = Vec::new();
    for route in surface::ROUTES {
        // A route whose feature or runtime road is off matches nothing now:
        // DERP without its feature, and the meeting point unless --relay-roads
        // named it. Its row is still in the table and its reach still checked.
        if surface::classify(route.method.as_str(), route.example).map(|r| r.id) != Some(route.id) {
            skipped.push(format!("{:?} {}", route.id, route.example));
            continue;
        }
        let (status, head, body) = ask(&rig.certs, rig.door, ROLE, route.method.as_str(), route.example, "").await;
        match route.reach {
            Reach::Open => {
                assert_ne!(status, 404, "{} is the open route: {head}", route.example);
            }
            Reach::Local | Reach::Token => {
                assert_eq!(status, 404, "{} {:?}: {head}", route.example, route.id);
                assert_eq!(header(&head, "Server").as_deref(), Some(SERVER), "{}", route.example);
                assert!(body.contains("<h1>Not here</h1>"), "{}: {body}", route.example);
            }
        }
        checked += 1;
    }
    assert!(checked >= 12, "the router's rows were reached: {checked}; skipped {skipped:?}");
    eprintln!("router rows reached: {checked}; skipped: {skipped:?}");
}

/// #225: `POST /v1/pair` mints nothing without the cover credential, and a
/// credential of the connection mints one pair.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pair_mint_takes_the_cover_credential() {
    let rig = start("pair", Tree::new("pair")).await;
    let before = rig.cfg.pairs.len();
    let (status, _, body) = ask(&rig.certs, rig.door, ROLE, "POST", "/v1/pair", "Content-Length: 2\r\n\r\n{}").await;
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("<h1>Not here</h1>"), "{body}");
    assert_eq!(rig.cfg.pairs.len(), before, "no pair was issued");

    let visit = visit(&rig.certs, rig.door, ROLE, &[HTTP1]).await.expect("the cover's TLS");
    let exporter = podssh_ws::delegated::client_exporter(visit.tls.get_ref().1).expect("an exporter");
    let credential = credential_for(rig.cfg.cover.as_ref().unwrap(), &exporter, ROLE);
    let (status, head, body) = ask_on(
        visit.tls,
        ROLE,
        "POST",
        "/v1/pair",
        &format!("X-Cover-Credential: {credential}\r\nContent-Length: 2\r\n\r\n{{}}"),
    )
    .await;
    assert_eq!(status, 200, "{head} {body}");
    let made: serde_json::Value = serde_json::from_str(&body).expect("the pair's JSON");
    let name = made["name"].as_str().expect("a pair's name");
    assert_eq!(rig.cfg.pairs.len(), before + 1, "one pair was issued");
    assert!(name.starts_with("p-"), "the pair's name: {name}");
    assert!(made["connect_token"].is_string() && made["node_token"].is_string(), "{body}");
}

/// #225: the cover credential is checked on the live upgrade. A credential
/// of this connection, its key and name opens the tunnel; another key,
/// another name, a lapsed window and a replay each get the site's 404.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_live_upgrade_refuses_each_wrong_credential() {
    let rig = start("live", Tree::new("live")).await;
    let cover = rig.cfg.cover.clone().unwrap();
    let target = target().await;
    let path = format!("/connect/127.0.0.1/{target}");
    let now = i64::try_from(tokens::now_ms() / 1000).unwrap();

    // The connection whose exporter the credential binds, and its upgrade.
    let (token, _) = rig.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let opened = visit(&rig.certs, rig.door, ROLE, &[HTTP1]).await.expect("the cover's TLS");
    let exporter = podssh_ws::delegated::client_exporter(opened.tls.get_ref().1).expect("an exporter");
    let good = credential_for(&cover, &exporter, ROLE);
    let (status, head) = upgrade_on(opened.tls, &token, Some(&good), &path).await;
    assert_eq!(status, 101, "{head}");

    // A credential of another key for the same name, connection and window.
    let (token, _) = rig.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let opened = visit(&rig.certs, rig.door, ROLE, &[HTTP1]).await.expect("the cover's TLS");
    let exporter = podssh_ws::delegated::client_exporter(opened.tls.get_ref().1).expect("an exporter");
    let wrong_key = {
        let key = podssh_ws::delegated::issuer_signing_key(&[0x44; 32]);
        let credential =
            pod_cover::Credential::issue(&key, ROLE, ROLE, now - 5, now + 300, [7; 32], Some(&exporter)).unwrap();
        podssh_ws::delegated::encode_wire(&credential)
    };
    let (status, head) = upgrade_on(opened.tls, &token, Some(&wrong_key), &path).await;
    assert_eq!(status, 404, "{head}");
    assert!(head.contains(SERVER), "{head}");

    // A credential of this key for another name.
    let (token, _) = rig.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let opened = visit(&rig.certs, rig.door, ROLE, &[HTTP1]).await.expect("the cover's TLS");
    let exporter = podssh_ws::delegated::client_exporter(opened.tls.get_ref().1).expect("an exporter");
    let wrong_name = {
        let key = podssh_ws::delegated::issuer_signing_key(&[0x11; 32]);
        let credential = pod_cover::Credential::issue(
            &key,
            "another.example",
            "another.example",
            now - 5,
            now + 300,
            [7; 32],
            Some(&exporter),
        )
        .unwrap();
        podssh_ws::delegated::encode_wire(&credential)
    };
    let (status, head) = upgrade_on(opened.tls, &token, Some(&wrong_name), &path).await;
    assert_eq!(status, 404, "{head}");
    assert!(head.contains(SERVER), "{head}");

    // A credential of this key and name whose window closed.
    let (token, _) = rig.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let opened = visit(&rig.certs, rig.door, ROLE, &[HTTP1]).await.expect("the cover's TLS");
    let exporter = podssh_ws::delegated::client_exporter(opened.tls.get_ref().1).expect("an exporter");
    let expired = {
        let key = podssh_ws::delegated::issuer_signing_key(&[0x11; 32]);
        let credential =
            pod_cover::Credential::issue(&key, ROLE, ROLE, now - 300, now - 1, [7; 32], Some(&exporter)).unwrap();
        podssh_ws::delegated::encode_wire(&credential)
    };
    let (status, head) = upgrade_on(opened.tls, &token, Some(&expired), &path).await;
    assert_eq!(status, 404, "{head}");
    assert!(head.contains(SERVER), "{head}");

    // The credential that opened the first tunnel, used again on a fresh
    // connection: the role remembers the signature it spent.
    let (token, _) = rig.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let opened = visit(&rig.certs, rig.door, ROLE, &[HTTP1]).await.expect("the cover's TLS");
    let (status, head) = upgrade_on(opened.tls, &token, Some(&good), &path).await;
    assert_eq!(status, 404, "a replayed credential is refused: {head}");
    assert!(head.contains(SERVER), "{head}");
}

/// #225: `Cover::admit` refuses a wrong key, a wrong name, an expired
/// credential and a replay, each by the name of what failed.
#[test]
fn admit_names_each_refusal() {
    let tree = Tree::new("admit");
    let site = Site::load(tree.path()).unwrap();
    let issuer = Issuer::from_seed([0x11; 32]);
    let cover = Cover::new(site, ROLE, issuer.clone(), Some(SERVER)).unwrap();
    let now = 1_800_000_000;
    let exporter = [9u8; 32];
    let good = pod_cover::Credential::issue(
        &podssh_ws::delegated::issuer_signing_key(&[0x11; 32]),
        ROLE,
        ROLE,
        now - 5,
        now + 300,
        [7; 32],
        Some(&exporter),
    )
    .unwrap();
    assert_eq!(cover.admit(&good, &exporter, now, Some(ROLE)), Ok(()));
    assert_eq!(cover.admit(&good, &exporter, now, Some(ROLE)), Err(VerifyError::Replayed));

    let wrong_key = pod_cover::Credential::issue(
        &podssh_ws::delegated::issuer_signing_key(&[0x22; 32]),
        ROLE,
        ROLE,
        now - 5,
        now + 300,
        [7; 32],
        Some(&exporter),
    )
    .unwrap();
    let what = cover.admit(&wrong_key, &exporter, now, Some(ROLE)).unwrap_err();
    assert_eq!(what, VerifyError::Credential(pod_cover::CredentialError::Signature));
    assert!(what.to_string().contains("signature"), "{what}");

    let wrong_name = pod_cover::Credential::issue(
        &podssh_ws::delegated::issuer_signing_key(&[0x11; 32]),
        "another.example",
        "another.example",
        now - 5,
        now + 300,
        [7; 32],
        Some(&exporter),
    )
    .unwrap();
    let what = cover.admit(&wrong_name, &exporter, now, Some(ROLE)).unwrap_err();
    assert!(what.to_string().contains("another name"), "{what}");

    let expired = pod_cover::Credential::issue(
        &podssh_ws::delegated::issuer_signing_key(&[0x11; 32]),
        ROLE,
        ROLE,
        now - 300,
        now - 1,
        [7; 32],
        Some(&exporter),
    )
    .unwrap();
    let what = cover.admit(&expired, &exporter, now, Some(ROLE)).unwrap_err();
    assert!(what.to_string().contains("expired"), "{what}");
}

/// #225 (SURF-1): the cleartext road beside TLS is the site too. A visitor
/// without TLS gets the page and the exact 404, never `/health`, a mint or a
/// tunnel: the cover answers before any role route on this road as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_cleartext_road_is_the_site_under_a_cover() {
    let rig = start("cleartext", Tree::new("cleartext")).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cfg = rig.cfg.clone();
    tokio::spawn(async move {
        while let Ok((tcp, peer)) = listener.accept().await {
            tokio::spawn(podssh_relay::serve::cleartext::serve(tcp, cfg.clone(), Some(peer.ip())));
        }
    });
    for (method, path, status, marker) in [
        ("GET", "/", 200, "<h1>Example</h1>"),
        ("GET", "/health", 404, "<h1>Not here</h1>"),
        ("POST", "/v1/mint?once=1", 404, "<h1>Not here</h1>"),
        ("GET", "/connect/127.0.0.1/22", 404, "<h1>Not here</h1>"),
    ] {
        let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let body = if method == "POST" { "Content-Length: 0\r\n\r\n" } else { "\r\n" };
        let request = format!("{method} {path} HTTP/1.1\r\nHost: {ROLE}\r\nConnection: close\r\n{body}");
        tcp.write_all(request.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(20), tcp.read_to_end(&mut answer)).await;
        let text = String::from_utf8_lossy(&answer).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
        assert_eq!(head.get(9..12).and_then(|s| s.parse().ok()), Some(status), "{path}: {head}");
        assert_eq!(header(head, "Server").as_deref(), Some(SERVER), "{path}: {head}");
        assert!(body.contains(marker), "{path}: {body}");
    }
}
