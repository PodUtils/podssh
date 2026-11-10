//! The public Wisp servers in the fallback (T-535): `after_relay_in` with a
//! stand-in list, in process, since `pod-services`' list is empty and the
//! binary cannot exercise a non-empty one. The stand-ins sit behind the
//! proxy of `cloud_support` with the test's own CA, as in `forwarder_cli`.

mod cloud_support;
mod forwarder_support;
mod ssh_harness;

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use cloud_support::{scratch, Proxy};
use forwarder_support::{wisp, Stands, FRAME_HOSTS, QUERY_HOSTS, WISP_PUBLIC_HOSTS};
use podssh_cli::exitmap::sysexits::EX_UNAVAILABLE;
use podssh_cli::forwarder::fallback::after_relay_in;
use podssh_cli::forwarder::public::{forwarders_of, Public};
use podssh_cli::ssh::transport::NotReached;
use podssh_ssh::{Log, LogLevel};
use podssh_ws::Trust;
use tokio::io::AsyncReadExt;

fn stand_in(word: &'static str, host: &str) -> Public {
    let template: &'static str = Box::leak(format!("wisp+wss://{host}/").into_boxed_str());
    Public { word, template, note: "a stand-in" }
}

/// Every name of the built-in forwarders closes, so only a later one carries.
fn close_builtins(stands: &Stands) {
    let mut closing = stands.closing.lock().unwrap();
    for h in QUERY_HOSTS.iter().chain(FRAME_HOSTS) {
        closing.insert(h.to_string());
    }
    closing.insert(wisp::HOST.to_string());
}

/// The SSH version line that the reached stream opens with.
async fn version_line(reached: podssh_cli::ssh::transport::Reached) -> String {
    let mut stream = reached.stream;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while !line.ends_with(b"\n") {
        let n = tokio::time::timeout(Duration::from_secs(20), stream.read(&mut byte)).await.unwrap().unwrap();
        assert!(n == 1, "the stream ended before a version line: {:?}", String::from_utf8_lossy(&line));
        line.push(byte[0]);
    }
    String::from_utf8_lossy(&line).into_owned()
}

fn failed() -> NotReached {
    NotReached { lines: vec!["r0.example: refused".into()], code: EX_UNAVAILABLE }
}

/// One test, not two: the proxy is the process's environment, which two
/// tests would set at once.
#[test]
fn the_public_wisp_servers_come_after_the_built_ins_and_only_when_listed() {
    let dir = scratch("forwarder-public");
    let key = dir.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let sshd = runtime.block_on(ssh_harness::start(&key));
    let stands = Stands::new(sshd);
    let proxy = runtime.block_on(Proxy::start(&dir, stands.handler()));
    // SAFETY: set before any thread of this test reads it, and no other test
    // of this binary runs: the one test owns the process's environment.
    unsafe {
        for name in ["HTTPS_PROXY", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "PODSSH_OFFLINE"] {
            std::env::remove_var(name);
        }
        std::env::set_var("https_proxy", proxy.url());
        // No ws:// probe, which would leave the loopback proxy's stand-ins.
        std::env::set_var("PODSSH_CLEARTEXT", "no");
        std::env::set_var("PODSSH_FORWARDER_FALLBACK", "yes");
        std::env::set_var("PODSSH_SETTINGS", "none");
    }
    let trust = Trust::File(proxy.ca_file.clone());
    let relays = podssh_relay::relay::select_relays(None, None, &[]).unwrap();
    let log = Arc::new(Log::new(LogLevel::Quiet));
    let call = |public: Vec<podssh_cli::forwarder::Forwarder>| {
        let (trust, relays, log) = (&trust, &relays, &log);
        async move {
            // A bound beside the fallback's own: a hang fails the test.
            let to = ("192.0.2.1", 22);
            let run = after_relay_in(failed(), false, relays, None, trust, to, log, &public);
            tokio::time::timeout(Duration::from_secs(120), run).await.expect("the fallback ended")
        }
    };

    // 1. Each built-in closes: the public stand-in carries, after them all.
    close_builtins(&stands);
    let list = [stand_in("one", WISP_PUBLIC_HOSTS[0]), stand_in("two", WISP_PUBLIC_HOSTS[1])];
    let reached = runtime.block_on(call(forwarders_of(&list))).unwrap_or_else(|e| panic!("not reached: {e:?}"));
    let line = runtime.block_on(version_line(reached));
    assert!(line.starts_with("SSH-2.0-"), "{line:?}");
    // mudlet, ssheasy, mudix, wisp (the demo server), then the public list.
    let want = [QUERY_HOSTS[1], FRAME_HOSTS[1], QUERY_HOSTS[2], wisp::HOST, WISP_PUBLIC_HOSTS[0]];
    assert_eq!(stands.hosts(), want, "the built-ins in their order, then the public one; the second never");

    // 2. An empty list: nothing carries, and no public name is ever asked.
    stands.seen.lock().unwrap().clear();
    let got = runtime.block_on(call(Vec::new()));
    assert!(got.is_err(), "no forwarder is left to carry");
    let hosts = stands.hosts();
    assert!(hosts.iter().all(|h| !WISP_PUBLIC_HOSTS.contains(&h.as_str())), "{hosts:?}");
    assert_eq!(hosts, &want[..4], "the built-ins were tried");
}
