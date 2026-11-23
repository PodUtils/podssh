//! The cover site of a relay name (#225, T-764), the surfaces that it moves
//! (T-767), the delegated credential (T-765, T-766), and the two chains of
//! two deployments (T-768), on the loopback. The role's TLS is a leaf of the
//! test's CA; the site is a tree of the test's; the documents are asked on
//! the owner's socket and on the public listener, and each answer is read.
//!
//!     cargo test -p podssh-relay --features serve,plain-ws --test relay_serve_cover
#![cfg(all(feature = "serve", feature = "plain-ws", unix))]

mod cover_harness;
mod cover_rig;
mod publish_harness;

use std::sync::Arc;
use std::time::Duration;

use cover_harness::{header, local, local_post, Tree, LIMIT};
use cover_rig::{ask, ask_at, ask_on, start, SERVER};
use pod_cover::Site;
use podssh_relay::pair::Pair;
use podssh_relay::reverse::{self, Handler, NodeConfig, Opening, SessionId, Settings, Wire};
use podssh_relay::serve::cover::{Cover, Issuer};
use podssh_relay::serve::listener::{connection, Door};
use podssh_relay::serve::published::Published;
use podssh_relay::serve::{self, tokens, Config, Limits, Mint};
use podssh_ws::tls_server::{acceptor_for, HTTP1};
use publish_harness::{visit, Certs, ROLE, SITE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// T-764: the page, an asset, `robots.txt` and the site's own 404, with the
/// configured `Server`; an unknown `Host`, a traversal and a document each
/// get the site's 404, and no unauthenticated body names the role.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cover_name_serves_the_site_and_an_unknown_name_its_own_404() {
    let rig = start("site", Tree::new("site")).await;
    let (status, head, body) = ask(&rig.certs, rig.door, ROLE, "GET", "/", "").await;
    assert_eq!(status, 200, "{head}");
    assert_eq!(header(&head, "Server").as_deref(), Some(SERVER));
    assert!(body.contains("<h1>Example</h1>"), "{body}");

    let (status, head, body) = ask(&rig.certs, rig.door, ROLE, "GET", "/assets/style.css", "").await;
    assert_eq!(status, 200, "{head}");
    assert_eq!(header(&head, "Content-Type").as_deref(), Some("text/css; charset=utf-8"));
    assert!(body.contains("color: #222"), "{body}");

    let (status, _, body) = ask(&rig.certs, rig.door, ROLE, "GET", "/robots.txt", "").await;
    assert_eq!(status, 200);
    assert!(body.contains("User-agent"));

    // The site's own 404 page, not the role's.
    for (host, path) in [("unknown.example", "/"), (ROLE, "/no-such-page"), (ROLE, "/health")] {
        let (status, _, body) = ask(&rig.certs, rig.door, host, "GET", path, "").await;
        assert_eq!(status, 404, "{host} {path}");
        assert!(body.contains("<h1>Not here</h1>"), "{host} {path}: {body}");
    }
    // A traversal is no file of the site.
    for path in ["/../etc/passwd", "/%2e%2e/etc/passwd", "/assets/../../etc/passwd"] {
        let (status, _, body) = ask(&rig.certs, rig.door, ROLE, "GET", path, "").await;
        assert_eq!(status, 404, "{path}: the site's 404, never a file outside it");
        assert!(!body.contains("root:"), "{path}: {body}");
    }
    // Each unauthenticated body of the site is the site's: no name of the
    // role, its version or its contract (COVER-3).
    for path in ["/", "/assets/style.css", "/robots.txt", "/no-such-page", "/health", "/relays.json", "/trace"] {
        let (_, _, body) = ask(&rig.certs, rig.door, ROLE, "GET", path, "").await;
        let lower = body.to_ascii_lowercase();
        for word in ["podssh", "podutils", "podcrates", "contract", "2026-10-03-r2"] {
            assert!(!lower.contains(word), "{path} names {word}: {body}");
        }
    }
}

/// T-767 (SURF-1): under a cover the documents and the probes leave the
/// public listener, and the owner's socket answers them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_documents_move_to_the_owners_socket() {
    let rig = start("docs", Tree::new("docs")).await;
    for path in ["/health", "/relays.json", "/trace", "/llms-full.txt", "/v1/probe/drip", "/v1/probe/anything"] {
        let (status, _, body) = ask(&rig.certs, rig.door, ROLE, "GET", path, "").await;
        assert_eq!(status, 404, "{path} on the public listener: the site's 404");
        assert!(body.contains("<h1>Not here</h1>"), "{path}: {body}");
    }
    let (status, body) = local(&rig.socket, "/health").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"service\""), "{body}");
    let (status, body) = local(&rig.socket, "/relays.json").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"limits\""), "{body}");
    let (status, body) = local(&rig.socket, "/llms-full.txt").await;
    assert_eq!(status, 200);
    assert!(body.contains("2026-10-03-r2"), "the contract, kept on the socket alone");
    let (status, body) = local(&rig.socket, "/trace").await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = local(&rig.socket, "/v1/probe/drip").await;
    assert_eq!(status, 200, "/v1/probe/drip: {body}");
    let (status, body) = local_post(&rig.socket, "/v1/probe/anything", "{}").await;
    assert_eq!(status, 200, "/v1/probe/anything: {body}");
    // The socket is one request's, as the contract's roads are.
    let (status, _) = local(&rig.socket, "/no-such-page").await;
    assert_eq!(status, 404);
    assert_eq!(rig.cfg.cover.as_ref().unwrap().name, ROLE);
}

/// T-767 (SURF-2): under a cover the mint takes a POST with a body alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_mint_is_a_post_with_a_body_alone() {
    let rig = start("mint", Tree::new("mint")).await;
    let (status, head, _) = ask(&rig.certs, rig.door, ROLE, "GET", "/v1/mint", "").await;
    assert_eq!(status, 405, "{head}");
    assert_eq!(header(&head, "Allow").as_deref(), Some("POST"));
    let (status, _, body) = ask(&rig.certs, rig.door, ROLE, "POST", "/v1/mint", "Content-Length: 0\r\n").await;
    assert_eq!(status, 400, "{body}");
    let (status, head, body) = ask(&rig.certs, rig.door, ROLE, "POST", "/v1/mint", "Content-Length: 2\r\n\r\n{}").await;
    assert_eq!(status, 200, "{head} {body}");
    assert!(body.contains("\"token\""), "{body}");
}

/// T-765 and T-766: a token gets a temporary credential of the same chain
/// and name, bound to the exporter of the connection, and the client refuses
/// another issuer or a lapsed window by name; no token gets the site.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_gets_a_credential_of_the_same_chain_and_name() {
    let rig = start("deleg", Tree::new("deleg")).await;
    let (token, _) = rig.cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    // The connection whose exporter is bound.
    let visit = visit(&rig.certs, rig.door, ROLE, &[HTTP1]).await.expect("the cover's TLS");
    let exporter = podssh_ws::delegated::client_exporter(visit.tls.get_ref().1).expect("an exporter");
    let mut tls = visit.tls;
    let subject = ed25519_dalek::SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
    let body = serde_json::json!({ "subject_key": hex::encode(subject) }).to_string();
    let request = format!(
        "POST /v1/delegate HTTP/1.1\r\nHost: {ROLE}\r\nX-Relay-Token: {token}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(LIMIT, tls.read_to_end(&mut answer)).await;
    let text = String::from_utf8_lossy(&answer).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").expect("a credential");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let credential = podssh_ws::delegated::decode(body).expect("the credential's JSON");
    assert_eq!((credential.issuer.as_str(), credential.name.as_str()), (ROLE, ROLE));
    assert_eq!(credential.subject_key, subject);
    assert!(credential.exporter.is_some(), "bound to the exporter");
    let now = i64::try_from(tokens::now_ms() / 1000).unwrap();
    assert_eq!(podssh_ws::delegated::verify(&credential, ROLE, &rig.issuer.pinned(), &exporter, now), Ok(()));
    // Another issuer, and a window that lapsed, are refused by name (T-766).
    let refused =
        podssh_ws::delegated::verify(&credential, "other.example", &rig.issuer.pinned(), &exporter, now).unwrap_err();
    assert!(refused.to_string().contains("another name"), "{refused}");
    let refused =
        podssh_ws::delegated::verify(&credential, ROLE, &rig.issuer.pinned(), &exporter, credential.not_after + 1)
            .unwrap_err();
    assert!(refused.to_string().contains("expired"), "{refused}");
    assert_eq!(
        podssh_ws::delegated::verify(&credential, ROLE, &rig.issuer.pinned(), b"another connection", now),
        Err(pod_cover::CredentialError::WrongBinding)
    );
    // No token: the site, never a credential.
    let (status, _, body) =
        ask(&rig.certs, rig.door, ROLE, "POST", "/v1/delegate", "Content-Length: 2\r\n\r\n{}").await;
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("<h1>Not here</h1>"), "{body}");
}

/// T-768: two deployments present two chains and two names, and neither
/// certificate is taken for the other's name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_deployments_present_two_chains_and_two_names() {
    let a = Certs::named("two-a", "a.cover.test", "a.site.test");
    let b = Certs::named("two-b", "b.cover.test", "b.site.test");
    assert_ne!(a.role.der, b.role.der, "two chains");
    assert_ne!(a.role.cert, b.role.cert);
    async fn port_of(certs: &Certs) -> u16 {
        let served = Certs::served(&certs.role, "the name of the test", &certs.role_challenge);
        let acceptor = acceptor_for(served, &[HTTP1]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(tcp).await;
                });
            }
        });
        port
    }
    let (port_a, port_b) = (port_of(&a).await, port_of(&b).await);
    let got_a = visit(&a, port_a, "a.cover.test", &[HTTP1]).await.expect("a's chain");
    let got_b = visit(&b, port_b, "b.cover.test", &[HTTP1]).await.expect("b's chain");
    assert_eq!(got_a.chain.first().map(Vec::as_slice), Some(a.role.der.as_slice()), "a's leaf");
    assert_eq!(got_b.chain.first().map(Vec::as_slice), Some(b.role.der.as_slice()), "b's leaf");
    assert_ne!(got_a.chain, got_b.chain, "two deployments, two chains");
    // A name of one deployment is no name of the other's chain.
    assert!(visit(&b, port_b, "a.cover.test", &[HTTP1]).await.is_err());
    assert!(visit(&a, port_a, "b.cover.test", &[HTTP1]).await.is_err());
}

/// T-764: two names of one certificate, one that the role terminates and
/// serves the site for, and one that it forwards to its pair's node. Both
/// connections complete with no close before their answer; the role's two
/// names present one leaf.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_role_owns_a_name_locally_and_forwards_another_on_one_certificate() {
    const COVER2: &str = "cover.publish.test";
    let certs = Certs::named_many("own-two", &[ROLE, COVER2], SITE);
    let tree = Tree::new("own-two");
    let site = Site::load(tree.path()).unwrap();
    let issuer = Issuer::from_seed([0x22; 32]);
    let cover = Cover::new_named(site, ROLE, &[COVER2.to_string()], issuer.clone(), Some(SERVER)).unwrap();
    let node_port = publish_harness::site(&certs).await;
    let events: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let said = events.clone();
    let events_sink: serve::Events = Box::new(move |line: &str| said.lock().unwrap().push(line.to_string()));
    // The node's road is the role's own internal listener, not the public
    // cover site's. Both configurations hold the one table of pairs, with the
    // live socket the node registered, so the cover's public listener can
    // publish that name.
    let pairs = Arc::new(podssh_relay::serve::reverse::Pairs::open(None).unwrap());
    let made = pairs.make(tokens::now_ms()).unwrap();
    let cfg = Arc::new(Config {
        version: "podssh test".into(),
        mint: Mint::Anyone,
        tokens: tokens::Tokens::new([7; 32]),
        policy: Default::default(),
        egress: Default::default(),
        limits: Limits::default(),
        pairs: pairs.clone(),
        resumes: Default::default(),
        answered: Default::default(),
        brake: Default::default(),
        usage: Default::default(),
        cover: Some(cover),
        events: Some(events_sink),
    });
    // The role's plain listener of the reverse road, so that its pair names
    // the port its node dials.
    let reverse = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reverse_port = reverse.local_addr().unwrap().port();
    let heard = events.clone();
    let reverse_sink: serve::Events = Box::new(move |line: &str| heard.lock().unwrap().push(line.to_string()));
    let reverse_cfg = Arc::new(Config {
        version: "podssh test".into(),
        mint: Mint::Anyone,
        tokens: tokens::Tokens::new([7; 32]),
        policy: Default::default(),
        egress: Default::default(),
        limits: Limits::default(),
        pairs,
        resumes: Default::default(),
        answered: Default::default(),
        brake: Default::default(),
        usage: Default::default(),
        cover: None,
        events: Some(reverse_sink),
    });
    tokio::spawn(async move {
        while let Ok((tcp, peer)) = reverse.accept().await {
            serve::sockets::bound_unsent(&tcp);
            tokio::spawn(serve::serve_from(tcp, reverse_cfg.clone(), None, Some(peer.ip())));
        }
    });
    let relay = podssh_relay::relay::Relay { host: "127.0.0.1".into(), port: reverse_port };
    let body = serde_json::json!({
        "name": made.name, "node_token": made.node, "connect_token": made.connect,
        "stop_token": made.stop, "expires": made.expires_ms,
    });
    let pair: Pair = podssh_relay::pair::parse(&relay, body.to_string().as_bytes(), tokens::now_ms() as i64)
        .expect("a pair of the role's");
    let pair_name = made.name.clone();
    struct Echo {
        port: u16,
    }
    impl Handler for Echo {
        type Stream = tokio::net::TcpStream;
        fn open(&self, _id: SessionId) -> Opening<tokio::net::TcpStream> {
            let port = self.port;
            Box::pin(
                async move { tokio::net::TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| e.to_string()) },
            )
        }
    }
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (trust, proxy) = (podssh_ws::Trust::Default, podssh_ws::ProxyChoice::Direct);
        let mut config = NodeConfig {
            pair,
            label: None,
            trust: &trust,
            ctx: &podssh_relay::context::of(&proxy),
            timeout: LIMIT,
            settings: Settings::default(),
            repair: None,
            wire: Wire::PlainLoopback,
            say: None,
        };
        let _ = reverse::run(&mut config, Arc::new(Echo { port: node_port }), async {
            let _ = stopped.await;
        })
        .await;
    });
    // The published name routes to that pair.
    let served = Certs::served(&certs.role, ROLE, &certs.role_challenge);
    let acceptor = acceptor_for(served, &[HTTP1]).unwrap();
    let door = Door {
        acceptor,
        cleartext: false,
        sshd: None,
        published: Arc::new(Published::of(&[format!("{SITE}={pair_name}")]).unwrap()),
        proxy: Default::default(),
    };
    let _stop = stop;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let deadline = tokio::time::Instant::now() + LIMIT;
    while !events.lock().unwrap().iter().any(|line| line.contains("reverse node")) {
        assert!(tokio::time::Instant::now() < deadline, "the node joined: {:?}", events.lock().unwrap());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let served_cfg = cfg.clone();
    tokio::spawn(async move {
        while let Ok((tcp, peer)) = listener.accept().await {
            serve::sockets::bound_unsent(&tcp);
            tokio::spawn(connection(tcp, peer.ip(), door.clone(), served_cfg.clone()));
        }
    });

    // The role's own two names: one leaf, the site at each.
    let first = visit(&certs, port, ROLE, &[HTTP1]).await.expect("the role's first name");
    let second = visit(&certs, port, COVER2, &[HTTP1]).await.expect("the role's second name");
    assert_eq!(first.leaf, second.leaf, "one certificate for both names");
    assert_eq!(first.leaf, certs.role.der);
    for name in [ROLE, COVER2] {
        let (status, head, body) = ask_at(&certs, port, name, name, "GET", "/", "").await;
        assert_eq!(status, 200, "{name}: {head}");
        assert_eq!(header(&head, "Server").as_deref(), Some(SERVER));
        assert!(body.contains("<h1>Example</h1>"), "{name}: {body}");
    }

    // A credential of the second name is under that name, not the first:
    // the connection's name is what the client asks and checks.
    let (token, _) = cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let got = visit(&certs, port, COVER2, &[HTTP1]).await.expect("the second name's TLS");
    let exporter = podssh_ws::delegated::client_exporter(got.tls.get_ref().1).expect("an exporter");
    let mut tls = got.tls;
    let subject = ed25519_dalek::SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes();
    let body = serde_json::json!({ "subject_key": hex::encode(subject) }).to_string();
    let request = format!(
        "POST /v1/delegate HTTP/1.1\r\nHost: {COVER2}\r\nX-Relay-Token: {token}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(LIMIT, tls.read_to_end(&mut answer)).await;
    let text = String::from_utf8_lossy(&answer).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").expect("a credential");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let credential = podssh_ws::delegated::decode(body).expect("the credential's JSON");
    assert_eq!((credential.issuer.as_str(), credential.name.as_str()), (COVER2, COVER2));
    let now = i64::try_from(tokens::now_ms() / 1000).unwrap();
    assert_eq!(podssh_ws::delegated::verify(&credential, COVER2, &issuer.pinned(), &exporter, now), Ok(()));

    // An authenticated client and an unauthenticated one on the tunnel name
    // present one chain and see one surface: the token road is the site's
    // 404 with the same Server and page whether or not a credential is
    // carried.
    let (unauth_status, unauth_head, unauth_body) = ask_at(&certs, port, ROLE, ROLE, "GET", "/health", "").await;
    assert_eq!(unauth_status, 404, "{unauth_head}");
    let (token, _) = cfg.tokens.mint(tokens::now_ms(), tokens::LIFETIME_MS);
    let authed = visit(&certs, port, ROLE, &[HTTP1]).await.expect("the tunnel name's TLS");
    let one_chain = authed.chain == first.chain;
    assert!(one_chain, "one chain for an authenticated and an unauthenticated client");
    let (authed_leaf, authed_chain) = (authed.leaf.clone(), authed.chain.len());
    let mut authed_tls = authed.tls;
    let now = i64::try_from(tokens::now_ms() / 1000).unwrap();
    let (credential, _) = podssh_ws::delegated::request_and_verify(&mut authed_tls, &token, [9; 32], ROLE, now)
        .await
        .expect("the credential over the same chain");
    let wire = podssh_ws::delegated::encode_wire(&credential);
    let (authed_status, head, authed_body) =
        ask_on(authed_tls, ROLE, "GET", "/health", &format!("X-Cover-Credential: {wire}\r\n")).await;
    assert_eq!(authed_status, 404, "{head}");
    assert_eq!(authed_body, unauth_body, "the same site page for both clients");
    assert_eq!(header(&head, "Server"), header(&unauth_head, "Server"), "the same Server value");

    // The published name goes to the node's TLS, whose bytes echo back: the
    // role does not answer it and does not close it.
    let mut forwarded = match visit(&certs, port, SITE, &[HTTP1]).await {
        Ok(got) => got,
        Err(why) => panic!("{why}: {:?}", events.lock().unwrap()),
    };
    assert_eq!(forwarded.leaf, certs.site.der, "the node's own leaf");
    let sent = b"tunnel-bytes-through-the-node";
    forwarded.tls.write_all(sent).await.unwrap();
    let mut back = vec![0u8; sent.len()];
    let read = tokio::time::timeout(LIMIT, forwarded.tls.read_exact(&mut back)).await;
    assert!(matches!(read, Ok(Ok(n)) if n == sent.len()), "the forwarded connection completed: {read:?}");
    assert_eq!(&back, sent);
    let prefix = |der: &[u8]| hex::encode(&der[..16.min(der.len())]);
    eprintln!(
        "two chains: role unauth leaf={} chain_len={}; authed leaf={} chain_len={}; one_chain={}; \
         role_leaf={} site_leaf={} forwarded_leaf={} forwarded_is_site={}; statuses={}/{} \
         server={:?} same_body={}",
        prefix(&first.leaf),
        first.chain.len(),
        prefix(&authed_leaf),
        authed_chain,
        one_chain,
        prefix(&certs.role.der),
        prefix(&certs.site.der),
        prefix(&forwarded.leaf),
        forwarded.leaf == certs.site.der,
        unauth_status,
        authed_status,
        header(&head, "Server"),
        authed_body == unauth_body,
    );
}

/// The cover script of the role: its replay is the first records, the sizes
/// add up to the payload and each is within the measurement's range.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_cover_script_replays_the_first_record_sizes() {
    let script = pod_cover::Script::parse(
        "date = \"2026-11-20\"\ncover_version = \"pod-cover test\"\nseed = 7\n\
         [[record_size]]\nmin = 16\nmax = 256\ncount = 8\n\
         [[record_size]]\nmin = 1024\nmax = 4096\ncount = 2\n\
         [[timing]]\nmicros = 1000\njitter_micros = 10\ncount = 100\n\
         [split]\nmin = 16\nmax = 4096\n",
    )
    .unwrap();
    let tree = Tree::new("script");
    let site = Site::load(tree.path()).unwrap();
    let cover =
        Cover::new_covered(site, ROLE, &[], Issuer::from_seed([0x33; 32]), Some(SERVER), Some(script.clone())).unwrap();
    let records = cover.first_records(8192).expect("the script's replay");
    assert_eq!(records.iter().map(|r| r.size).sum::<usize>(), 8192);
    assert!(records.iter().all(|r| (16..=4096).contains(&r.size)), "{records:?}");
    assert_eq!(records, script.replay(8192), "the same script and length give the same records");
    let payload = vec![0u8; 4096];
    let split = script.split_payload(&payload);
    assert_eq!(split.concat(), payload);
    for part in &split[..split.len() - 1] {
        assert!((16..=4096).contains(&part.len()), "{split:?}");
    }
    assert!(split.last().is_some_and(|part| !part.is_empty() && part.len() <= 4096), "{split:?}");
}

/// The constants of the published harness's names are still the cover's.
#[test]
fn the_harness_names_the_cover_site_and_the_published_name() {
    assert_eq!((ROLE, SITE), ("relay.publish.test", "site.publish.test"));
}
