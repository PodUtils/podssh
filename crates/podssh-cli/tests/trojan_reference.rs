//! `--trojan` against the reference servers of `scripts/interop-trojan.sh`
//! (T-760): Xray-core's own trojan inbound in TLS and in a WebSocket over
//! TLS, trojan-gfw's server in TLS, trojan-go's in a WebSocket, an OpenSSH
//! target, and a plain squid as the host's proxy. The script builds the
//! containers, runs each session through `podssh`, and refuses a wrong
//! password, a wrong path and a secret in the output.
//!
//! A run needs Docker or podman, their images and the releases through the
//! network, so it is not part of the ordinary gate. On request:
//!
//! ```sh
//! PODSSH_REFERENCE=1 cargo test -p podssh-cli --test trojan_reference -- --nocapture
//! ```
//!
//! `PODSSH_INTEROP_EVIDENCE` keeps the run's raw client, server and container
//! logs; `PODSSH_INTEROP_CONTAINER_PROXY` gives each container the host's
//! proxy. Both are inherited. A run that was not requested prints its skip
//! and passes; a requested run that lacks its tools or fails a check fails
//! this test with the script's exit code.

use std::process::Command;

/// The reference run, when `PODSSH_REFERENCE` asks for it.
#[test]
fn the_trojan_road_carries_a_session_to_a_reference_server() {
    if std::env::var_os("PODSSH_REFERENCE").is_none() {
        eprintln!("skipped: reference runs were not requested; set PODSSH_REFERENCE=1");
        return;
    }
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/interop-trojan.sh");
    assert!(script.is_file(), "the reference script is missing: {}", script.display());
    let status = Command::new("sh")
        .arg(&script)
        .arg(env!("CARGO_BIN_EXE_podssh"))
        .status()
        .unwrap_or_else(|e| panic!("could not run {}: {e}", script.display()));
    assert!(status.success(), "the reference run failed: {} exited {:?}", script.display(), status.code());
}
