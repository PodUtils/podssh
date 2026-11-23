//! Dispatch: the parse result becomes bytes on two streams and an exit code.
//!
//! **stdout carries the answer and nothing else.** `docs/architecture.md`, "Design rules":
//! *"stdout is data. Diagnostics go to stderr, so podssh can be in a pipe or be the
//! `ProxyCommand` of OpenSSH."* This module is where that is
//! enforced, and the target of plant 6 (`tests/binary_streams.rs`): one `println!` on the
//! wrong path and `podssh example.org 2>/dev/null | wc -c` stops reading 0.
//!
//! **The terminal state is a parameter, not a probe.** [`run`] — the entry
//! point every test calls — gets [`Tty::none`], so no test can enter the
//! pager and block on a terminal; [`main_with_args`] asks the operating system
//! once, where the real file descriptors are, and passes the answer down.

use std::io::Write;

use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
use crate::help;
use crate::pager::Tty;
use crate::retired::Retired;
use crate::tree::Parsed;

/// The two streams, as a pair of sinks, so a test can assert on both without
/// spawning a process. This is what makes plant 6 a unit test as well as a
/// shell assertion — and the shell assertion is still the one that counts,
/// because it runs the real binary.
pub struct Streams<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

/// Run a parsed command line **with no terminal**. Returns the process exit
/// code.
///
/// This is the entry point tests use, and it cannot page — nothing in a test
/// may block on a terminal, and a test that could page
/// would block on a key nobody presses.
pub fn run(p: &Parsed, s: &mut Streams<'_>) -> i32 {
    run_with(p, s, Tty::none())
}

/// [`run_with`], unless `vars` sets a name of `retired`, which a release
/// stopped reading: that stops the run with 78 before anything is tried,
/// and what only prints still answers (T-634). The table and the variables
/// are parameters, so that a test needs a row of its own and no environment.
pub fn run_unless_retired(
    p: &Parsed,
    s: &mut Streams<'_>,
    tty: Tty,
    retired: &[Retired],
    vars: &[(String, String)],
) -> i32 {
    match crate::retired::check(p, retired, vars, s.err) {
        Some(code) => code,
        None => run_with(p, s, tty),
    }
}

/// Run a parsed command line, with the terminal state the caller probed.
pub fn run_with(p: &Parsed, s: &mut Streams<'_>, tty: Tty) -> i32 {
    // T-763: the shape of the HTTP/2 road is chosen once, before any road is
    // built, and a word that is not a shape refuses the run rather than
    // silently sending the default.
    // The cover credential is checked after the shape, because the two
    // cannot share a road and the shape is what the check reads.
    if let Some(code) = crate::h2_choice::apply(p, s.err) {
        return code;
    }
    if let Some(code) = crate::cover_choice::apply(p, s.err) {
        return code;
    }
    match p {
        Parsed::Help(section) => {
            let text = if section.is_empty() {
                help::top_level_help()
            } else {
                match crate::flags::verb_for(section) {
                    Some(v) => help::verb_help(v),
                    None => help::top_level_help(),
                }
            };
            let _ = s.out.write_all(text.as_bytes());
            0
        }
        Parsed::Version => {
            let _ = writeln!(s.out, "{}", crate::version::line());
            // A node that would hand its sessions to this binary asks (T-668).
            if std::env::var_os(crate::node_upgrade::VARIABLE).is_some_and(|v| v == crate::node_upgrade::PROBE) {
                let (word, version) = (crate::node_upgrade::PROBE_WORD, crate::node_upgrade::HANDOVER_VERSION);
                let _ = writeln!(s.out, "{word}{version}");
            }
            0
        }
        // A usage error is a refusal. Nothing goes to stdout, because the
        // only thing that should ever be there is an answer.
        Parsed::Usage(m) => {
            let _ = writeln!(s.err, "{m}");
            EXIT_USAGE
        }
        Parsed::NoArguments(m) => {
            let _ = writeln!(s.err, "{m}");
            EXIT_USAGE
        }
        Parsed::UnknownVerb(m) => {
            let _ = writeln!(s.err, "{m}");
            EXIT_USAGE
        }
        // Refusals are read first, so a `Refused` row added to `MAN_FLAGS`
        // later refuses rather than being dropped.
        Parsed::Man { section, no_pager, roff, json, llms, refused } => {
            if refusals("man", refused, s.err) {
                return EXIT_USAGE;
            }
            if let Some(which) = llms {
                return crate::man::llms::run(which, section.is_some() || *roff || *json, s.out, s.err);
            }
            let stdin = std::io::stdin();
            let mut keys = stdin.lock();
            let request =
                crate::man::Request { section: section.as_deref(), no_pager: *no_pager, roff: *roff, json: *json };
            crate::man::run(&request, tty, &mut keys, s.out, s.err)
        }
        Parsed::Proxy {
            target,
            port,
            relay_host,
            relay_failover,
            relay_addr,
            ca_file,
            forwarder,
            shadowsocks,
            via,
            vless,
            early_data,
            h2_shape,
            cover_credential: _,
            trojan,
            hysteria,
            tuic,
            wstunnel,
            chisel,
            turn,
            exit,
            idle_warn,
            node,
            connect_timeout,
            timeout,
            refused,
        } => {
            if refusals("proxy", refused, s.err) {
                return EXIT_USAGE;
            }
            crate::proxy::run_proxy(
                &crate::proxy::ProxyArgs {
                    target: target.clone(),
                    port: port.clone(),
                    relay_host: relay_host.clone(),
                    relay_failover: relay_failover.clone(),
                    relay_addr: relay_addr.clone(),
                    ca_file: ca_file.clone(),
                    forwarder: forwarder.clone(),
                    shadowsocks: shadowsocks.clone(),
                    via: via.clone(),
                    vless: vless.clone(),
                    early_data: early_data.clone(),
                    h2_shape: h2_shape.clone(),
                    trojan: trojan.clone(),
                    hysteria: hysteria.clone(),
                    tuic: tuic.clone(),
                    wstunnel: wstunnel.clone(),
                    chisel: chisel.clone(),
                    turn: turn.clone(),
                    exit: exit.clone(),
                    idle_warn: idle_warn.clone(),
                    node: node.clone(),
                    connect_timeout: connect_timeout.clone(),
                    timeout: timeout.clone(),
                },
                s.err,
            )
        }
        Parsed::Node(args) if refusals("node", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Node(args) => crate::node_install::dispatch(args, s.out, s.err),
        Parsed::Operator(args) if refusals("operator", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Operator(args) => crate::operator::run_operator(args, s.err),
        Parsed::Pipe(args) if refusals("pipe", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Pipe(args) => crate::pipe::run_pipe(args, s.err),
        Parsed::Relay(args) if refusals("relay", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Relay(args) => crate::relay_cmd::run_relay(args, s.out, s.err),
        Parsed::Ping(args) if refusals("ping", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Ping(args) => crate::ping::node::run(args, s.out, s.err),
        Parsed::Health(args) if refusals("health", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Health(args) => crate::health::run(args, s.out, s.err),
        Parsed::Play(args) if refusals("play", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Play(args) => crate::play::run(args, s.out, s.err),
        Parsed::Update(args) if refusals("update", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Update(args) => crate::update::run(args, s.out, s.err),
        Parsed::Edit(args) if refusals("edit", &args.refused, s.err) => EXIT_USAGE,
        // The editor is on the process's own terminal.
        Parsed::Edit(args) => crate::edit::run_edit(args, tty, s.err),
        Parsed::Each(args) if refusals("each", &args.refused, s.err) => EXIT_USAGE,
        // The lines typed on the process's own stdin go to the hosts (T-185).
        Parsed::Each(args) if args.interactive || args.confirm || args.stop_key.is_some() => {
            crate::each::broadcast::run(args, s.err)
        }
        // The hosts' output goes to the process's own streams, line by line;
        // with --json, the record to stdout (T-484).
        Parsed::Each(args) => crate::each::run_each(args, s.out, s.err),
        Parsed::Containers(args) if refusals("containers", &args.refused, s.err) => EXIT_USAGE,
        // The list goes to stdout; --exec's session to the process's streams.
        Parsed::Containers(args) => crate::containers::run_containers(args, s.out, s.err),
        Parsed::Job(args) if refusals("job", &args.refused, s.err) => EXIT_USAGE,
        // An ID, a list or a job's output on stdout; podssh's words on stderr.
        Parsed::Job(args) => crate::job::run_job(args, s.out, s.err),
        Parsed::Run(args) if refusals("run", &args.refused, s.err) => EXIT_USAGE,
        // The command's output is on the process's own streams; a dry run's
        // plan on stdout (T-475).
        Parsed::Run(args) => crate::run_cmd::run_run(args, s.out, s.err),
        Parsed::Config(args) if refusals("config", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Config(args) => crate::config_import::run(args, s.out, s.err),
        Parsed::Mcp(args) if refusals("mcp", &args.refused, s.err) => EXIT_USAGE,
        // The protocol is on the process's own stdin and stdout.
        Parsed::Mcp(args) => crate::mcp::run(args, s.err),
        Parsed::Serve(args) if refusals("serve", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Serve(args) if args.print_unit => crate::node_install::print::serve(args, s.out, s.err),
        // SSH is on the process's own stdin and stdout; its lines on stderr.
        Parsed::Serve(args) => crate::serve::run(args, s.err),
        Parsed::Session(args) if refusals("session", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Session(args) => crate::session::run(args, s.out, s.err),
        Parsed::Detached(args) if refusals("detached", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Detached(args) => crate::detach::control::run(args, s.out, s.err),
        Parsed::Net(args) if refusals("net", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Net(args) => crate::net::run(args, s.out, s.err),
        Parsed::Exit(args) if refusals("exit", &args.refused, s.err) => EXIT_USAGE,
        // Its lines go to stderr; it has no answer for stdout.
        Parsed::Exit(args) => crate::exit::run_exit(args, s.err),
        Parsed::Share(args) if refusals("share", &args.refused, s.err) => EXIT_USAGE,
        // A list on stdout; each change said on stderr.
        Parsed::Share(args) => crate::share::run(args, s.out, s.err),
        Parsed::Funnel(args) if refusals("funnel", &args.refused, s.err) => EXIT_USAGE,
        // The URL on stdout; each line on stderr.
        Parsed::Funnel(args) => crate::funnel::run(args, s.out, s.err),
        Parsed::Agent(args) if refusals("agent", &args.refused, s.err) => EXIT_USAGE,
        Parsed::Agent(args) => crate::agent::run(args, s.out, s.err),
        Parsed::Status { refused, .. } if refusals("status", refused, s.err) => EXIT_USAGE,
        Parsed::Status { relay_host, relay_addr, destination, net, keys, .. } => {
            let args = crate::status::StatusArgs {
                relay_host: relay_host.clone(),
                relay_addr: relay_addr.clone(),
                destination: destination.clone(),
                // `--net`: each member of the net held, and its road (T-435).
                net: *net,
                keys: *keys,
            };
            crate::status::run_status(&args, tty, s.out, s.err)
        }
        Parsed::Doctor {
            relay_host,
            relay_failover,
            relay_addr,
            ca_file,
            json,
            full,
            hop,
            policy,
            forwarder,
            shadowsocks,
            via,
            vless,
            early_data,
            h2_shape,
            trojan,
            hysteria,
            tuic,
            turn,
            devtunnel,
            cover,
            quick,
            tier,
            jobs,
            stream,
            stream_idle,
            exit,
            refused,
        } => {
            if refusals("doctor", refused, s.err) {
                return EXIT_USAGE;
            }
            crate::doctor::run_doctor(
                &crate::doctor::DoctorArgs {
                    relay_host: relay_host.clone(),
                    relay_failover: relay_failover.clone(),
                    relay_addr: relay_addr.clone(),
                    ca_file: ca_file.clone(),
                    json: *json,
                    full: *full,
                    hop: hop.clone(),
                    policy: policy.clone(),
                    forwarder: forwarder.clone(),
                    shadowsocks: shadowsocks.clone(),
                    via: via.clone(),
                    vless: vless.clone(),
                    early_data: early_data.clone(),
                    h2_shape: h2_shape.clone(),
                    trojan: *trojan,
                    hysteria: hysteria.clone(),
                    tuic: tuic.clone(),
                    turn: turn.clone(),
                    devtunnel: devtunnel.clone(),
                    cover: cover.clone(),
                    quick: *quick,
                    tier: *tier,
                    jobs: jobs.clone(),
                    stream: stream.clone(),
                    stream_idle: stream_idle.clone(),
                    exit: exit.clone(),
                },
                s.out,
                s.err,
            )
        }
        // A build without the `ts` feature still parses `ts` (so help and the
        // man page stay complete) but refuses it, naming the feature.
        #[cfg(not(feature = "ts"))]
        Parsed::Ts { refused, .. } => {
            if refusals("ts", refused, s.err) {
                return EXIT_USAGE;
            }
            let _ = writeln!(
                s.err,
                "podssh: 'ts' is not available in this build.\n  \
                 It was compiled without Tailscale support; rebuild with \
                 `cargo build -p podssh-cli --features ts`."
            );
            EXIT_NOT_IMPLEMENTED
        }
        // `ts` is dispatched, not refused: `ts.rs` owns the verb the way
        // `src/man/` owns `man`. The VERB_OWNER row is gone — and
        // `tests/ts_behave.rs` proves no `ts` shape exits 0 having done
        // nothing, which is what the row used to guarantee.
        #[cfg(feature = "ts")]
        Parsed::Ts {
            destination,
            args,
            w_target,
            mode,
            proxy,
            auth_key_file,
            state,
            ephemeral,
            relay,
            control_url,
            wait_allowlist,
            refused,
            timeout,
            jsonl,
        } => {
            if refusals("ts", refused, s.err) {
                return EXIT_USAGE;
            }
            crate::ts::run_ts(
                &crate::ts::TsArgs {
                    destination: destination.clone(),
                    args: args.clone(),
                    w_target: w_target.clone(),
                    mode: mode.clone(),
                    proxy: proxy.clone(),
                    auth_key_file: auth_key_file.clone(),
                    state: state.clone(),
                    ephemeral: *ephemeral,
                    relay: relay.clone(),
                    control_url: control_url.clone(),
                    wait_allowlist: wait_allowlist.clone(),
                    timeout: timeout.clone(),
                    jsonl: *jsonl,
                },
                s.out,
                s.err,
                tty,
            )
        }
        Parsed::Command { verb, refused, tag, timeout, jsonl, ssh, keygen, cp, sftp, chat } => {
            command::run(verb, refused, tag, timeout, *jsonl, ssh, keygen, cp, sftp, chat, tty, s)
        }
    }
}
/// Print every refused flag, and say whether there was one. One function so
/// `man` and every other verb refuse in the same words.
///
/// The third line is the row's own reason, because the causes differ: `-L`
/// and `-D` need a local listener, and `-A` is not supported.
fn refusals(verb: &str, refused: &[(String, &'static str, &'static str)], err: &mut dyn Write) -> bool {
    if refused.is_empty() {
        return false;
    }
    for (given, instead, reason) in refused {
        let _ = writeln!(err, "{}", crate::refuse::refused(verb, given, instead, reason));
    }
    true
}

/// The one function `main` calls. It is here rather than in `main.rs` so a
/// test can call the whole path — parse, dispatch, both streams, exit code —
/// with no process and no pipe.
pub fn main_with_args<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let argv: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
    // A detached child's first word, which podssh alone writes (T-380).
    let argv = crate::detach::take_child_flag(argv);
    // A supervisor of --restart runs no command of its own (T-390).
    if crate::detach::is_supervisor() {
        return crate::detach::supervise::run(&argv);
    }
    // A detached run holds the lock of its name before anything (T-392).
    if let Some(code) = crate::detach::lock::enter_child(&argv) {
        return code;
    }
    // The binary that an update on Windows moved aside, which runs no more
    // (T-375); elsewhere nothing.
    crate::update::remove_aside();
    // A program that the user names gets the report of a failure (T-195).
    let hook = crate::error_program::Hook::from_env(argv.first().map(|a| a.as_os_str()));
    let parsed = crate::tree::parse(argv);
    // A PODSSH_ name that a release stopped reading stops the run (T-634).
    let vars = crate::retired::environment();
    let run = |s: &mut Streams<'_>| run_unless_retired(&parsed, s, Tty::probed(), crate::retired::RETIRED, &vars);
    // Unlocked handles: each write takes the lock briefly. Holding the lock
    // for the whole run would deadlock any verb that writes through
    // tokio's stdout, which locks from a helper thread.
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let rc = if hook.is_some() {
        let mut tee = crate::error_program::Tee::new(&mut err);
        let rc = run(&mut Streams { out: &mut out, err: &mut tee });
        tee.finish();
        rc
    } else {
        run(&mut Streams { out: &mut out, err: &mut err })
    };
    let _ = out.flush();
    let _ = err.flush();
    if let Some(hook) = hook {
        hook.after(rc, &mut err);
    }
    rc
}
// The `Parsed::Command` arm: the `--timeout` gate and each verb's handler.
mod command;
#[cfg(test)]
mod tests;
