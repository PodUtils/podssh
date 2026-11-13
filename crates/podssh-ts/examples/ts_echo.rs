//! Node A of the live test with two nodes (T-106): an echo on the tailnet
//! stack of a node of podssh's adapter, which `podssh ts -W A:PORT` (node B)
//! reaches. In place of the fork's `tcp_echo` example, which takes the auth
//! key on its command line: here the key comes from a file, by its path
//! alone (`AGENTS.md`, section 4), and no socket of the host is bound.
//!
//! ```sh
//! # The node key of a state file, made when missing, for a DERP server's
//! # allowlist (podssh relay serve --derp-keys FILE):
//! cargo run -p podssh-ts --example ts_echo -- --state A.json --node-key
//! # The echo, in relay mode pinned to HOST:PORT, for SECONDS at most:
//! cargo run -p podssh-ts --example ts_echo -- --state A.json --auth-key-file KEY \
//!     [--control-url https://HOST[:PORT]] [--relay HOST[:PORT]] [--port 4242] [--seconds 600]
//! ```
//!
//! stdout: `node-key nodekey:HEX`, then `listening IP:PORT` once the echo
//! waits, then `echoed BYTES sha256 HEX` for each connection that ended.
//! The proxy is the environment's, as for each podssh command. Exit 0 at
//! the end of `--seconds`, 64 for a usage error, 1 when the node failed.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use podssh_ts::config::{choose_proxy, TsConfig, TsMode, TsProxy};
use podssh_ts::node::TsNode;
use podssh_ts::secret::AuthKey;

/// The flags, read by hand: the crate has no parser of its own.
#[derive(Default)]
struct Args {
    state: Option<PathBuf>,
    auth_key_file: Option<PathBuf>,
    control_url: Option<String>,
    relay: Option<(String, u16)>,
    port: u16,
    seconds: u64,
    node_key: bool,
}

fn usage(why: &str) -> ExitCode {
    eprintln!("ts_echo: {why}");
    eprintln!(
        "usage: ts_echo --state FILE (--node-key | --auth-key-file FILE [--control-url URL] \
         [--relay HOST[:PORT]] [--port N] [--seconds N])"
    );
    ExitCode::from(64)
}

fn parse() -> Result<Args, String> {
    let mut args = Args { port: 4242, seconds: 600, ..Default::default() };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--state" => args.state = Some(value()?.into()),
            "--auth-key-file" => args.auth_key_file = Some(value()?.into()),
            "--control-url" => args.control_url = Some(value()?),
            "--relay" => {
                let text = value()?;
                let (host, port) = match text.rsplit_once(':') {
                    Some((host, port)) => (host.to_string(), port.parse().map_err(|_| format!("--relay {text}"))?),
                    None => (text, 443),
                };
                args.relay = Some((host, port));
            }
            "--port" => args.port = value()?.parse().map_err(|_| "--port takes a number".to_string())?,
            "--seconds" => args.seconds = value()?.parse().map_err(|_| "--seconds takes a number".to_string())?,
            "--node-key" => args.node_key = true,
            other => return Err(format!("{other} is not a flag of ts_echo")),
        }
    }
    Ok(args)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let args = match parse() {
        Ok(args) => args,
        Err(why) => return usage(&why),
    };
    let Some(state) = args.state.clone() else { return usage("--state FILE is needed") };
    match podssh_ts::keys::node_key(&state).await {
        Ok(key) => println!("node-key {key}"),
        Err(e) => {
            eprintln!("ts_echo: the state file {}: {e:?}", state.display());
            return ExitCode::from(1);
        }
    }
    if args.node_key {
        return ExitCode::SUCCESS;
    }
    let Some(key_file) = args.auth_key_file.clone() else { return usage("--auth-key-file FILE is needed") };
    match serve(&args, state, &key_file).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("ts_echo: {why}");
            ExitCode::from(1)
        }
    }
}

/// The node up, the echo on its port, until `--seconds` pass.
async fn serve(args: &Args, state: PathBuf, key_file: &std::path::Path) -> Result<(), String> {
    // Read into memory that is cleared; the trailing line end is no part of a key.
    let mut raw = zeroize::Zeroizing::new(std::fs::read(key_file).map_err(|e| format!("{}: {e}", key_file.display()))?);
    while raw.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        raw.pop();
    }
    let mut key = AuthKey::new(raw).map_err(|why| format!("{}: {why}", key_file.display()))?;
    let proxy = choose_proxy(None, |name| std::env::var(name).ok()).map_err(|e| e.to_string())?;
    let mode = match &args.relay {
        Some((host, port)) => TsMode::Relay { host: host.clone(), port: *port },
        None => TsMode::Tcp,
    };
    let cfg = TsConfig {
        state_file: state,
        control_url: args.control_url.clone(),
        hostname: Some("podssh-ts-echo".to_string()),
        ephemeral: false,
        mode,
        proxy_url: proxy.as_ref().map(TsProxy::url),
        no_proxy: proxy.and_then(|p| p.no_proxy),
        retry_refused: true,
        link_events: None,
    };
    let node = TsNode::start(&cfg, &key).await.map_err(|e| format!("the node did not start: {e:?}"))?;
    key.expire();
    let bound = Duration::from_secs(args.seconds);
    let served = async {
        node.derp_ready_within(bound).await.map_err(|e| format!("no DERP link: {e:?}"))?;
        let mut echo = podssh_ts::echo::start(&node, args.port, bound).await.map_err(|e| format!("{e:?}"))?;
        println!("listening {}", echo.addr);
        while let Some(ended) = echo.ended.recv().await {
            match ended {
                Ok(got) => println!("echoed {} sha256 {}", got.bytes, got.sha256),
                Err(why) => eprintln!("ts_echo: a connection failed: {why}"),
            }
        }
        Ok::<(), String>(())
    };
    let result = match tokio::time::timeout(bound, served).await {
        Ok(result) => result,
        // The end of --seconds is the planned end.
        Err(_) => Ok(()),
    };
    let _ = node.shutdown(Some(Duration::from_secs(2))).await;
    result
}
