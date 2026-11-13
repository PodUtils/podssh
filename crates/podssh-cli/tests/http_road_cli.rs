//! The HTTP road (T-319) of the CLI, through a proxy that ends TLS for the
//! relay's name and refuses the WebSocket upgrade, as a cloud container's
//! proxy does (T-311): `podssh relay serve` on the loopback with a CA of the
//! run, and in front of it, as `https_proxy`, a proxy whose CA podssh is
//! given with `--ca-file` (`http_road_cli_support`). podssh's WebSocket road
//! is refused there, so it falls to the HTTP road: `podssh proxy` to an echo
//! and `podssh ssh` to the test's SSH server (`ssh_harness`, whose `echo`
//! sends back its input) each move 20 MiB each way with equal digests, in
//! the split form and in the serial form (`PODSSH_HTTP_ROAD`). A close of the
//! road other than `1000`, the role's byte cap, is said by `ssh` as by
//! `proxy`: its code and its reason.
//!
//!     cargo test -p podssh-cli --test http_road_cli

mod cloud_support;
mod http_road_cli_support;
mod ssh_harness;
mod throughput_harness;

use http_road_cli_support::{bytes, echo_target, run, source_target, Bench, Ran, MIB};
use sha2::{Digest, Sha256};

/// The bytes of each session, each way.
const SIZE: usize = 20 * MIB;

/// What came back is what went: its length, then its digest.
fn same_bytes(ran: &Ran, sent: &[u8]) {
    let (came, went) = (ran.out.len(), sent.len());
    assert_eq!(came, went, "each byte came back once: {came} of {went}; {}", ran.err);
    assert!(Sha256::digest(&ran.out) == Sha256::digest(sent), "the digests differ; {}", ran.err);
}

/// `podssh proxy` through the road in `form` to an echo: 20 MiB each way.
fn proxy_carries_20_mib_each_way(form: &str, seed: u64) {
    let bench = Bench::start(&format!("http-road-proxy-{form}"), &[]);
    let mut args = vec!["proxy".to_string()];
    args.extend(bench.relay_flags());
    args.extend(["127.0.0.1".to_string(), echo_target().to_string()]);
    let sent = bytes(SIZE, seed);
    let ran = run(bench.podssh(&args, Some(form)), sent.clone());
    assert_eq!(ran.code, Some(0), "{}", ran.err);
    assert!(ran.err.contains("podssh tries its HTTP road there"), "the road was announced: {}", ran.err);
    same_bytes(&ran, &sent);
    bench.carried_in(form);
}

/// `podssh ssh` through the road in `form` to the test's SSH server, whose
/// `echo` sends back its input: 20 MiB each way.
fn ssh_carries_20_mib_each_way(form: &str, seed: u64) {
    let bench = Bench::start(&format!("http-road-ssh-{form}"), &[]);
    let mut args = vec!["ssh".to_string(), "-v".to_string()];
    args.extend(bench.s.common());
    args.extend(bench.relay_flags());
    args.extend(["-p".to_string(), bench.s.port.to_string(), "tester@127.0.0.1".into(), "echo".into()]);
    let sent = bytes(SIZE, seed);
    let ran = run(bench.podssh(&args, Some(form)), sent.clone());
    assert_eq!(ran.code, Some(0), "{}", ran.err);
    let carried = format!("carries the session, in its {form} form");
    assert!(ran.err.contains(&carried), "the road of {form} carried it: {}", ran.err);
    same_bytes(&ran, &sent);
    bench.carried_in(form);
}

#[test]
fn podssh_proxy_carries_20_mib_each_way_over_the_split_form() {
    proxy_carries_20_mib_each_way("split", 31);
}

#[test]
fn podssh_proxy_carries_20_mib_each_way_over_the_serial_form() {
    proxy_carries_20_mib_each_way("serial", 32);
}

#[test]
fn podssh_ssh_carries_20_mib_each_way_over_the_split_form() {
    ssh_carries_20_mib_each_way("split", 33);
}

#[test]
#[ignore = "pod-relay's serial form stalls SSH's flow: COORD-047 (#222); it runs again at the take of its fix"]
fn podssh_ssh_carries_20_mib_each_way_over_the_serial_form() {
    ssh_carries_20_mib_each_way("serial", 34);
}

/// The line of a run that names the role's close, with the target's
/// authority taken out and the prefix of podssh's own lines off, so that
/// the lines of two runs to two targets compare.
fn close_line(ran: &Ran, target: &str) -> String {
    let line = ran.err.lines().find(|line| line.contains("1009 session byte cap"));
    let line = line.unwrap_or_else(|| panic!("no line names the close 1009: {}", ran.err));
    line.trim_start_matches("podssh: ").replace(target, "TARGET")
}

/// A role whose cap is 1 MiB ends a session that carries more with `1009
/// session byte cap`: `proxy` names it, and `ssh`, which saw only the end of
/// its stream, now says the same line.
#[test]
fn a_close_of_the_road_other_than_1000_is_said_by_ssh_as_by_proxy() {
    let bench = Bench::start("http-road-cap", &["--max-session-mib", "1"]);
    let source = source_target(4 * MIB);
    let mut args = vec!["proxy".to_string()];
    args.extend(bench.relay_flags());
    args.extend(["127.0.0.1".to_string(), source.to_string()]);
    let proxied = run(bench.podssh(&args, Some("split")), Vec::new());
    assert_ne!(proxied.code, Some(0), "the cap ended the session: {}", proxied.err);
    assert!(proxied.out.len() <= MIB, "no byte past the cap: {}", proxied.out.len());
    let said = close_line(&proxied, &format!("127.0.0.1:{source}"));

    let mut args = vec!["ssh".to_string()];
    args.extend(bench.s.common());
    args.extend(bench.relay_flags());
    let far = format!("source {}", 4 * MIB);
    args.extend(["-p".to_string(), bench.s.port.to_string(), "tester@127.0.0.1".into(), far]);
    let ssh = run(bench.podssh(&args, Some("split")), Vec::new());
    assert_eq!(ssh.code, Some(255), "{}", ssh.err);
    assert_eq!(close_line(&ssh, &format!("127.0.0.1:{}", bench.s.port)), said, "{}", ssh.err);
}
