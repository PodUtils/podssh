//! The relay role as a net's meeting point (T-720, `--relay-roads`): its
//! words, the roads that would admit nobody, and, with the iroh road built,
//! two iroh endpoints of podssh (`podssh node --iroh` and `podssh ssh
//! iroh:TICKET`) that meet through the role alone and carry 1 MiB each way.
//! The protocol against clients of n0's own code is podssh-relay's
//! `tests/relay_meet.rs`.

use crate::throughput_harness::Session;
use crate::{ran, said};

/// `relay serve` on the loopback with `extra`; the certificate's files need
/// not exist, as each refusal here comes before they are read.
fn serve(extra: &[&str]) -> Vec<String> {
    let mut args: Vec<String> =
        ["relay", "serve", "--listen", "127.0.0.1:0", "--cert", "c", "--key", "k"].map(String::from).to_vec();
    args.extend(extra.iter().map(|a| a.to_string()));
    args
}

#[test]
fn relay_roads_of_an_unknown_word_or_derp_and_iroh_that_admit_nobody_stop_the_start() {
    let s = Session::start("serve-meet-usage");
    let cases: [(&[&str], &str); 3] = [
        (&["--relay-roads", "tailscale"], "iroh, derp, or iroh,derp"),
        // DERP with no file of keys, where the role does not mint for anyone.
        (&["--relay-roads", "derp", "--mint", "nobody"], "--derp-keys FILE"),
        (&["relay", "info", "--relay-roads", "iroh"][..], "go with `podssh relay serve` only"),
    ];
    for (extra, says) in cases {
        let args = if extra[0] == "relay" { extra.iter().map(|a| a.to_string()).collect() } else { serve(extra) };
        let out = ran(s.command(&args));
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", said(&out));
        assert!(said(&out).contains(says), "{args:?}: {}", said(&out));
    }
}

#[cfg(feature = "iroh")]
#[test]
fn relay_roads_iroh_with_a_mint_for_nobody_admits_nobody_and_stops_the_start() {
    let s = Session::start("serve-meet-nobody");
    let out = ran(s.command(&serve(&["--relay-roads", "iroh", "--mint", "nobody"])));
    assert_eq!(out.status.code(), Some(64), "{}", said(&out));
    assert!(said(&out).contains("--mint nobody admits none"), "{}", said(&out));
}

#[cfg(not(feature = "iroh"))]
#[test]
fn relay_roads_iroh_in_a_build_with_no_iroh_road_is_refused_with_70() {
    let s = Session::start("serve-meet-unbuilt");
    let out = ran(s.command(&serve(&["--relay-roads", "iroh", "--mint", "anyone"])));
    assert_eq!(out.status.code(), Some(70), "{}", said(&out));
    assert!(said(&out).contains("--features iroh"), "{}", said(&out));
}

#[cfg(feature = "iroh")]
#[test]
fn iroh_relay_of_the_role_carries_a_session_of_two_podssh_endpoints_each_way() {
    use crate::throughput_harness::{run, Cell};
    let s = Session::start("serve-meet-iroh");
    let cell = match Cell::iroh_through_role(&s) {
        Ok(cell) => cell,
        Err((_, why)) if why.contains("no openssl") || why.contains("no Python") => {
            return eprintln!("did not run: {why}");
        }
        Err((name, why)) => panic!("{name}: {why}"),
    };
    // 1 MiB each way; the cell's runs must say that the relay carried each byte.
    for up in [true, false] {
        run(&s, &cell, up, 1 << 20).unwrap_or_else(|why| panic!("up {up}: {why}"));
    }
    let events = std::fs::read_to_string(s.home.join("fake-relay-normal-events.log")).unwrap_or_default();
    // The line's words, before its time (T-1016).
    let words = podssh_relay::serve::said::words;
    let up = events.lines().filter(|l| l.starts_with("iroh: the endpoint ") && words(l).ends_with(" is up")).count();
    assert!(up >= 2, "both endpoints came up at the role: {events}");
    let log = std::fs::read_to_string(s.home.join("fake-relay-normal-role.log")).unwrap_or_default();
    assert!(log.contains("iroh's relay protocol at /relay for the endpoints of --mint anyone"), "{log}");
}
