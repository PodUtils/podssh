//! The client's refusals of `--bearer`, its choice of the agent's key, and
//! the node's choice of a bearer's signer and of its check.

use super::*;
use podssh_relay::grant::Spent;

/// 2026-11-25, in seconds since the epoch.
const NOW: u64 = 1_795_564_800;

fn identity(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

/// A directory of its own for one test.
fn scratch(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-bearer-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The refusals that read nothing, and those of a signer that cannot be
/// read: each with its code, none of them kept.
#[test]
fn each_refusal_of_bearer_has_its_code() {
    let usage = crate::exit_codes::EXIT_USAGE;
    let config = crate::exitmap::sysexits::EX_CONFIG;
    let dir = scratch("refusals");
    let junk = dir.join("junk.key");
    std::fs::write(&junk, "no key in here\n").unwrap();
    let missing = dir.join("missing.key");
    let (junk, missing) = (junk.to_string_lossy().into_owned(), missing.to_string_lossy().into_owned());
    // (word, --grant, --no-e2e, code, words of the line)
    let table: &[(&str, bool, bool, i32, &str)] = &[
        ("k.key", false, true, usage, "which --no-e2e turns off"),
        ("k.key", true, false, usage, "give one of them"),
        ("agent", true, true, usage, "--no-e2e"),
        ("", false, false, usage, "takes a key file"),
        ("https://idp.example/token", false, false, usage, "never a URL"),
        ("agent:not-a-fingerprint", false, false, usage, "agent:FINGERPRINT takes"),
        (missing.as_str(), false, false, config, "no such key file"),
        (junk.as_str(), false, false, config, "--bearer"),
    ];
    for (word, granted, no_e2e, code, words) in table {
        let refused = ask(Some(*word), *granted, *no_e2e).expect_err(word);
        assert_eq!(refused.code, *code, "{word}: {}", refused.message);
        assert!(refused.message.contains(words), "{word}: {}", refused.message);
        assert!(!refused.message.contains('\n'), "one line: {}", refused.message);
    }
    assert!(ask(None, true, true).is_ok(), "no --bearer, nothing to refuse");
    assert!(take().is_none(), "no refused signer is kept");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A key file is read, never made, and signs as its key.
#[test]
fn a_key_file_is_a_signer() {
    let dir = scratch("file");
    let path = dir.join("signer.key");
    let made = file::load(&file::Place::File(path.clone()), &mut OsEntropy).unwrap();
    let signer = read(&path.to_string_lossy()).unwrap_or_else(|r| panic!("{}", r.message));
    assert_eq!(signer.key(), made.identity.public());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The agent's first Ed25519 key, or the one that a fingerprint names.
#[test]
fn the_agent_s_key_is_its_first_or_the_one_named() {
    let (a, b) = (identity(1).public(), identity(2).public());
    let keys = [a.0, b.0];
    assert_eq!(choose(&keys, None), Ok(a));
    let named = KeyName::parse(&b.fingerprint()).unwrap();
    assert_eq!(choose(&keys, Some(&named)), Ok(b));
    let other = KeyName::parse(&identity(3).public().fingerprint()).unwrap();
    assert!(choose(&keys, Some(&other)).unwrap_err().contains("holds no Ed25519 key SHA256:"));
    assert!(choose(&[], None).unwrap_err().contains("ssh-add one"));
}

/// A door of the node `node` whose other issuer is `issuer`, for the
/// target with no route and the route `web` alone.
fn door(node: PublicKey, issuer: PublicKey) -> Door {
    let issuers: Arc<grant::Issuers> = Arc::new(move |key: &PublicKey, ask: &Ask| -> Result<(), String> {
        match (key == &issuer, ask) {
            (true, Ask::Target) => Ok(()),
            (true, Ask::Route(route)) if route == "web" => Ok(()),
            _ => Err("not an issuer for that".into()),
        }
    });
    Door { node, issuers, spent: Spent::nowhere("no record in this test"), revoked: None }
}

/// Who may sign a bearer: the node's key, an issuer for what it may reach,
/// and at an exit's target the exit's door alone.
#[test]
fn a_signer_reaches_what_it_may_reach_itself() {
    let (node, issuer, stranger) = (identity(1).public(), identity(2).public(), identity(3).public());
    let gate = door(node, issuer);
    let none: Arc<grant::Issuers> =
        Arc::new(|_: &PublicKey, _: &Ask| -> Result<(), String> { Err("no exit issuer".into()) });
    let exit = Door { issuers: none, ..gate.clone() };
    let route = |name: &str| Ask::Route(name.into());
    let out = Ask::Exit { host: "example.com".into(), port: 443 };
    let table: &[(&PublicKey, Ask, Option<&Door>, bool)] = &[
        (&node, Ask::Target, None, true),
        (&node, route("db"), None, true),
        (&issuer, Ask::Target, None, true),
        (&issuer, route("web"), None, true),
        (&issuer, route("db"), None, false),
        (&stranger, Ask::Target, None, false),
        (&node, out.clone(), None, false),
        (&node, out.clone(), Some(&exit), true),
        (&issuer, out, Some(&exit), false),
        (&node, route(exit_caller::GRANT_ROUTE), Some(&exit), false),
    ];
    for (signer, ask, exit, may) in table {
        assert_eq!(signs(&gate, *exit, signer, ask), *may, "{signer} for {ask:?}");
    }
}

/// The node's check: a bearer of its channel once, and each copy, other
/// channel, signer and missing binding refused by name.
#[test]
fn the_node_takes_a_bearer_once_and_names_each_refusal() {
    let node = identity(1);
    let operator = identity(4).public();
    let gate = door(node.public(), identity(2).public());
    let bearers = Bearers::default();
    let here = Binding::from_bytes([7; 32]);
    let blob = bearer::mint(&node, operator, &here, NOW, [9; 32]);
    let check = |blob: &[u8], binding: Option<&Binding>| {
        redeem_in(&bearers, binding, &gate, None, &operator, &Ask::Target, blob, NOW + 1)
    };
    let line = check(&blob, Some(&here)).unwrap();
    assert!(line.contains(&node.public().to_string()), "the line names the signer: {line}");
    assert!(check(&blob, Some(&here)).unwrap_err().contains("(replayed)"));
    let there = Binding::from_bytes([8; 32]);
    let copied = bearer::mint(&node, operator, &here, NOW, [10; 32]);
    assert!(check(&copied, Some(&there)).unwrap_err().contains("(binding)"));
    let stranger = bearer::mint(&identity(3), operator, &here, NOW, [11; 32]);
    assert!(check(&stranger, Some(&here)).unwrap_err().contains("(signer)"));
    assert!(check(&copied, None).unwrap_err().contains("(unbound)"));
}

/// The door for grants sends a bearer to the bearer's check, and each
/// other blob to the grant's: outside a node's check no binding exists, so
/// the bearer is refused as unbound, and the junk as no grant.
#[test]
fn the_door_tells_a_bearer_from_a_certificate() {
    let node = identity(1);
    let redeem = crate::grants::door("bearer-door-test", node.public(), None).expect("a door");
    let operator = identity(4).public();
    let blob = bearer::mint(&node, operator, &Binding::from_bytes([7; 32]), now(), [12; 32]);
    assert!(is_bearer(&blob));
    let refused = redeem(&operator, &Ask::Target, &blob).unwrap_err();
    assert!(refused.contains("(unbound)"), "{refused}");
    let refused = redeem(&operator, &Ask::Target, &b"ssh-ed25519-cert-v01@openssh.com junk"[..]).unwrap_err();
    assert!(refused.contains("not a grant"), "{refused}");
}

/// A key file's bearer is made for the channel's binding, and a grant
/// given beside it is the proof unchanged.
#[tokio::test]
async fn the_proof_is_the_grant_or_a_bearer_of_the_channel() {
    let signer = Signer::File(Arc::new(identity(1)));
    let holder = identity(4).public();
    let here = Binding::from_bytes([7; 32]);
    let blob = make(&signer, holder, &here, NOW).await.unwrap();
    assert_eq!(blob.len(), bearer::LEN);
    let gate = door(identity(1).public(), identity(2).public());
    let checked = redeem_in(&Bearers::default(), Some(&here), &gate, None, &holder, &Ask::Target, &blob, NOW);
    assert!(checked.is_ok(), "{checked:?}");
    let quiet = shared(|line: String| panic!("nothing to say: {line}"));
    let grant = proof(Some(b"a grant".to_vec()), holder, quiet)(identity(1).public(), here).await;
    assert_eq!(grant.as_deref(), Some(&b"a grant"[..]));
}

/// The node's refusal of the proof, in pod-e2e's words of a grant, names the
/// bearer when this run sent one, and stays a grant's words when it did not
/// (T-942).
#[test]
fn a_refused_bearer_is_named_a_bearer_at_the_operator() {
    let why = podssh_relay::e2e::ends::GRANT_REFUSED;
    let bearer = refused_line_of(true, why);
    assert!(bearer.starts_with("the node refused this run's bearer (--bearer)"), "{bearer}");
    assert!(!bearer.contains("grant"), "{bearer}");
    assert_eq!(refused_line_of(false, why), format!("the node refused: {why}"));
}
