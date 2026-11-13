//! The word of srv.us (T-566) of the road of a tunnel of HTTP made by
//! `ssh -R`, through T-565's stand-in in its shape
//! (`ssh_tunnel_http_stand_in`): as srv.us, the node logs in with its own
//! key as `nomatch`, opens its session before the forward of port 1, and the
//! stand-in names the tunnel by srv.us's steps; a client that names the
//! node's whole key derives the same name and reaches it with no URL, and a
//! fingerprint alone derives none. The switch turns it off. Planted: a
//! wrong derivation of srv.us's name
//! (`scripts/plants/t566-wrong-derivation.patch`), and the session with no
//! URL fails.

use std::sync::atomic::Ordering;

use podssh_relay::identity::file::{self, Place};
use podssh_relay::identity::PublicKey;
use podssh_relay::session::OsEntropy;

use super::ssh_harness::GREETING;
use super::ssh_tunnel_http_stand_in::{srv_us_label, ZONE};
use super::{command, name_of, run, Lab};

/// The whole key of the node's key file `key`, once it ran.
fn whole_key(lab: &Lab, key: &str) -> PublicKey {
    let loaded = file::load(&Place::File(lab.node_home.join(key)), &mut OsEntropy).expect("the node's key");
    loaded.identity.public()
}

#[test]
fn srv_us_the_name_of_the_node_s_key_carries_the_session_with_no_url() {
    let lab = Lab::new("srv-us");
    lab.stand_in.srv_us.store(true, Ordering::SeqCst);
    lab.let_in();
    lab.pair_down();
    let env = [("PODSSH_SRV_US", ZONE), ("PODSSH_LOCALHOST_RUN", "no")];
    let (_node, lines, _) = lab.node("node.key", &["--srv-us"], &env);
    assert!(lines.iter().any(|l| l.contains("as nomatch, by the node's own key")), "{lines:#?}");
    assert!(!lines.iter().any(|l| l.contains("which a client derives")), "the name is the key's: {lines:#?}");
    let name = name_of(lines.last().unwrap());
    let public = whole_key(&lab, "node.key");
    assert_eq!(name, format!("{}.{ZONE}", srv_us_label(&public.0, 1)), "srv.us's steps, the stand-in's own");
    assert_eq!(name, podssh_relay::ssh_http::srv_us::name(&public, ZONE), "podssh's derivation");
    assert_eq!(lab.stand_in.users(), ["nomatch"], "no GitHub or GitLab lookup, no local user");
    assert_eq!(lab.stand_in.keys(), [public.fingerprint()], "the node's own key");
    assert_eq!(lab.stand_in.forwards(), [("localhost".to_string(), 1)], "srv.us's -R 1:...");

    // The client names the whole key and no URL: it derives the name.
    let (hex, client_env) = (public.hex(), [("PODSSH_SRV_US", ZONE)]);
    let mut ssh = lab.ssh(&["-v", "--node-key", &hex, "node://tester@lab", "greet"]);
    let (rc, out, err) = run(ssh.envs(client_env));
    assert_eq!((rc, out.as_str()), (0, GREETING), "{err}");
    assert!(err.contains("the srv.us road answered first"), "{err}");
    assert!(err.contains("nobody vouches for") && err.contains("PODSSH_SRV_US=no"), "the line of Q78: {err}");

    // A fingerprint alone hashes nothing that srv.us hashed: no such road.
    let print = public.fingerprint();
    let mut ssh = lab.ssh(&["-v", "--node-key", &print, "node://tester@lab", "greet"]);
    let (rc, out, err) = run(ssh.envs(client_env));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(!err.contains("the srv.us road answered"), "{err}");
    drop(lab.runtime);
}

#[test]
fn srv_us_is_served_unasked_after_the_words_before_it_and_its_switch_turns_it_off() {
    let lab = Lab::new("srv-us-unasked");
    lab.stand_in.srv_us.store(true, Ordering::SeqCst);
    let env = [("PODSSH_SRV_US", ZONE), ("PODSSH_LOCALHOST_RUN", "no"), ("PODSSH_DERP", "no")];
    let (_node, lines, _) = lab.node("node.key", &[], &env);
    let unasked = lines.iter().find(|l| l.contains("unasked")).unwrap_or_else(|| panic!("{lines:#?}"));
    assert!(unasked.contains("serves the srv.us road unasked, the last"), "{unasked}");
    assert!(lines.iter().any(|l| l.contains("PODSSH_SRV_US=no") && l.contains("nobody vouches for")), "{lines:#?}");
    let words = ["node", "lab", &lab.target, "--srv-us", "--allow"];
    let mut cmd = command(&lab.node_home, lab.proxy, &lab.ca, &words);
    let (rc, out, err) = run(cmd.arg(&lab.allow).env("PODSSH_SRV_US", "no"));
    assert_eq!(rc, 64, "stdout {out:?}, stderr {err}");
    assert!(err.contains("PODSSH_SRV_US=no turns the srv.us road off"), "{err}");
    let words = ["node", "lab", &lab.target, "--srv-us", "--sandhole"];
    let (rc, _, err) = run(&mut command(&lab.node_home, lab.proxy, &lab.ca, &words));
    assert_eq!(rc, 64, "two roads: {err}");
    drop(lab.runtime);
}
