//! `podssh serve --listen ADDR` (T-124): podssh's SSH server on listeners
//! that the user asks for, on a host that allows the bind (the operator's
//! ruling on Q1, rule 2 of `AGENTS.md`, its first exception). `PORT` is
//! 127.0.0.1, another address only as the user writes it, and `unix:PATH` a
//! socket of mode 0600 for this user alone, as `pipe`'s `unix-listen:` makes
//! it. `PODSSH_LISTEN=no` refuses each before anything binds.
//!
//! The bind is the probe: no second socket is made to test the first, and
//! a refused one names the address, the system's words and the ways that
//! need no listener (77 where the host refuses it, as `pipe` exits; else
//! 69). Each binds before the drop of the capabilities, as the relay role
//! does: a port under 1024 needs the one capability that the drop takes.
//!
//! Each connection accepted takes a place under the caps of
//! `podssh_ssh::server::listen` before a byte of it is read, then goes to
//! the server of `--stdio`, with the client's address for `from=` where a
//! TCP socket gives one, and a deadline from its accept for its login
//! (T-631): each one reaped is a line of serve's log. SIGTERM and SIGINT close the listeners and stop
//! each connection as `--stdio` stops its one; SIGHUP reads the keys again
//! for each connection.

use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use podssh_ssh::russh::keys::PrivateKey;
use podssh_ssh::server::listen::{self, Entry, Gate, Limits, Why};
use podssh_ssh::server::{self, Control, Keys, Settings};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::exit_codes::EXIT_NOT_IMPLEMENTED;
use crate::exitmap::sysexits::{EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use crate::pipe::address::{socket_name, tcp_port, Address};
use crate::pipe::listen::{self as pipe_listen, Listener};
use crate::relay_settings::Refusal;
use crate::serve_keys::{self, Asked, Signals, Sources};

/// Accepts that fail in a row before a listener is taken for dead, as
/// `pipe`'s.
const FAILED_ACCEPTS: u32 = 10;
/// The wait after a failed accept: a host out of descriptors frees one.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);
/// How long a stop waits for the connections: each winds down within its
/// own grace, and kills its children past it.
const STOP_LIMIT: Duration = Duration::from_secs(15);
/// The ways that need no listener, for the line of a refused bind.
const INSTEAD: &str = "--stdio and podssh serve NAME need no listener";

/// The caps as typed: `--max-connections`, `--pending-max` and
/// `--login-timeout` (T-631).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Caps<'a> {
    pub max_connections: Option<&'a str>,
    pub pending_max: Option<&'a str>,
    pub login_timeout: Option<&'a str>,
}

/// What `--listen` asks: each address, and the caps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub listen: Vec<Address>,
    pub limits: Limits,
}

impl Plan {
    /// None with no `--listen`; else each address checked in order, and
    /// the caps. `PODSSH_LISTEN=no` is a refusal (78) before any bind.
    pub(crate) fn of(values: &[String], caps: &Caps<'_>) -> Result<Option<Plan>, Refusal> {
        if values.is_empty() {
            return Ok(None);
        }
        pipe_listen::allowed()?;
        let mut listen = Vec::new();
        for value in values {
            let address = address(value)?;
            // Port 0 twice is two ports that the system chooses.
            let any_port = matches!(address, Address::TcpListen { port: 0, .. });
            if !any_port && listen.contains(&address) {
                return Err(Refusal::usage(format!("--listen {value}: that address is given twice")));
            }
            listen.push(address);
        }
        let connections = caps.max_connections.map(|v| cap("--max-connections", v)).transpose()?;
        let pending = caps.pending_max.map(|v| cap("--pending-max", v)).transpose()?;
        let login = caps.login_timeout.map(seconds).transpose()?;
        let limits = Limits {
            connections: connections.unwrap_or(listen::CONNECTIONS),
            pending: pending.unwrap_or(listen::PENDING),
            login: login.unwrap_or(listen::LOGIN),
        };
        Ok(Some(Plan { listen, limits }))
    }
}

/// One `--listen` value: `unix:PATH`, else `[ADDR:]PORT` as `pipe`'s
/// `tcp-listen:` reads it (an address of this host, no name resolved).
pub(crate) fn address(value: &str) -> Result<Address, Refusal> {
    let worded = |r: Refusal| Refusal::usage(format!("--listen {}", r.message));
    if let Some(path) = value.strip_prefix("unix:") {
        return socket_name("unix", path).map(Address::UnixListen).map_err(worded);
    }
    tcp_port("tcp", value).map_err(|r| {
        let message = r.message.strip_prefix("tcp:").unwrap_or(&r.message).to_string();
        worded(Refusal::usage(message))
    })
}

/// A cap's value: a whole number from 1 to [`listen::CAP_MAX`].
pub(crate) fn cap(flag: &str, value: &str) -> Result<usize, Refusal> {
    match value.trim().parse::<usize>() {
        Ok(n) if (1..=listen::CAP_MAX).contains(&n) => Ok(n),
        _ => Err(Refusal::usage(format!("{flag} {value:?}: a whole number from 1 to {}", listen::CAP_MAX))),
    }
}

/// `--login-timeout SECS`: whole seconds from 1 to [`listen::LOGIN_MAX`]; 0,
/// which OpenSSH reads as no limit, is refused, as a listener needs one.
pub(crate) fn seconds(value: &str) -> Result<Duration, Refusal> {
    let most = listen::LOGIN_MAX.as_secs();
    match value.trim().parse::<u64>() {
        Ok(n) if (1..=most).contains(&n) => Ok(Duration::from_secs(n)),
        _ => Err(Refusal::usage(format!("--login-timeout {value:?}: whole seconds from 1 to {most}"))),
    }
}

/// A stream of one connection, of either kind of listener.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type Stream = Box<dyn Io>;

/// One connection accepted: its stream, the client's address where a TCP
/// socket gives one, and how serve's lines name it.
struct Accepted {
    stream: Stream,
    peer: Option<IpAddr>,
    from: String,
}

/// One listener, bound and listening, and how its lines name it.
enum Listening {
    Tcp(tokio::net::TcpListener, String),
    Unix(Listener, String),
}

/// The listeners of a plan, bound in the runtime that serves them.
pub(crate) struct Bound {
    // Before the runtime: a start that ends early drops the listeners while
    // their runtime still runs.
    listening: Vec<Listening>,
    runtime: tokio::runtime::Runtime,
    limits: Limits,
}

impl Bound {
    /// Bind each address of `plan` in order, each said; the first that
    /// fails ends the start with its code and line, and the ones bound
    /// before it close. The runtime has one thread, this one, so the drop
    /// of the capabilities after it finds no other.
    pub(crate) fn all(plan: &Plan) -> Result<Bound, (i32, String)> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| (EXIT_NOT_IMPLEMENTED, format!("no runtime: {e}")))?;
        let listening = runtime.block_on(async {
            let mut listening = Vec::new();
            for address in &plan.listen {
                listening.push(bind(address).await?);
            }
            Ok::<_, (i32, String)>(listening)
        })?;
        Ok(Bound { listening, runtime, limits: plan.limits })
    }
}

async fn bind(address: &Address) -> Result<Listening, (i32, String)> {
    match address {
        Address::TcpListen { host, port } => {
            let shown = podssh_ws::dial::authority(host, *port);
            let listener = tokio::net::TcpListener::bind((host.as_str(), *port))
                .await
                .map_err(|e| (pipe_listen::code(&e), cannot(&shown, &e.to_string(), pipe_listen::code(&e))))?;
            let at = listener.local_addr().map(|a| a.to_string()).unwrap_or(shown);
            let loopback = host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
            let who = if loopback { "each user of this host can connect" } else { "other hosts can connect" };
            podssh_ssh::err_line!("podssh serve: listening on {at}: {who}; the authorized keys guard each login");
            Ok(Listening::Tcp(listener, at))
        }
        Address::UnixListen(path) => {
            let mut say = |line: &str| podssh_ssh::err_line!("podssh serve: {}", line.replace("unix-listen:", "unix:"));
            match Listener::bind(address, &mut say).await {
                Ok(listener) => Ok(Listening::Unix(listener, format!("unix:{path}"))),
                Err((code, line)) => {
                    // pipe's words name its own ways with no listener.
                    let line = line.split("; this host refuses the listener").next().unwrap_or(&line);
                    let why = line.strip_prefix(&format!("unix-listen:{path}: ")).unwrap_or(line);
                    Err((code, cannot(&format!("unix:{path}"), why, code)))
                }
            }
        }
        _ => Err((EX_USAGE, "--listen takes PORT, ADDR:PORT or unix:PATH".into())),
    }
}

/// The line of a bind that failed: the address, the system's words, and
/// the ways with no listener where the host refused it.
fn cannot(shown: &str, why: &str, code: i32) -> String {
    let refuses = if code == EX_NOPERM { "; this host refuses the listener" } else { "" };
    format!("cannot listen on {shown}: {why}{refuses}; {INSTEAD}")
}

/// Serve each connection of `bound` until a signal stops serve: 0, or 69
/// when each listener failed.
pub(crate) fn run(
    bound: Bound,
    key: PrivateKey,
    keys: Keys,
    settings: Settings,
    sources: &Sources,
    err: &mut dyn Write,
) -> i32 {
    let Bound { runtime, listening, limits } = bound;
    let served = Served { key, keys, settings: Arc::new(settings), control: Control::new(), gate: Gate::new(limits) };
    let code = runtime.block_on(serve(listening, served, sources, err));
    // Each -R's pair is stopped at the relay while the runtime runs (T-123).
    runtime.block_on(crate::serve_forward::end_all());
    code
}

/// What each connection is served with.
struct Served {
    key: PrivateKey,
    keys: Keys,
    settings: Arc<Settings>,
    control: Control,
    gate: Gate,
}

async fn serve(listening: Vec<Listening>, served: Served, sources: &Sources, err: &mut dyn Write) -> i32 {
    // Caught before the first accept, so that no stop finds the default.
    let mut signals = Signals::new();
    let (tx, mut rx) = mpsc::channel::<Accepted>(1);
    let mut accepting = JoinSet::new();
    for one in listening {
        accepting.spawn(accept_each(one, tx.clone()));
    }
    drop(tx);
    let mut running = JoinSet::new();
    let mut quiet = Quiet::default();
    let ends = served.settings.revoke_ends_sessions;
    let code = loop {
        tokio::select! {
            accepted = rx.recv() => match accepted {
                Some(accepted) => admit(accepted, &served, &mut running, &mut quiet),
                None => {
                    let _ = writeln!(err, "podssh serve: no listener is left (each one's failure is said above)");
                    break EX_UNAVAILABLE;
                }
            },
            Some(_) = running.join_next(), if !running.is_empty() => {}
            asked = signals.next() => match asked {
                Asked::Stop => break 0,
                Asked::Reload => serve_keys::reload(sources, &served.keys, &served.control, ends, err),
            },
        }
    };
    // The listeners close first, and a socket's file goes with its own.
    accepting.abort_all();
    while accepting.join_next().await.is_some() {}
    served.control.stop();
    wait_out(&mut running, &mut signals, &served.control).await;
    code
}

/// Each connection of one listener, sent on until serve stops or the
/// listener fails [`FAILED_ACCEPTS`] times in a row.
async fn accept_each(mut listening: Listening, tx: mpsc::Sender<Accepted>) {
    let mut failed = 0u32;
    loop {
        let (next, at) = match &mut listening {
            Listening::Tcp(listener, at) => {
                let next = listener.accept().await.map(|(stream, peer)| {
                    let _ = stream.set_nodelay(true);
                    podssh_ssh::err_line!("podssh serve: a client connected from {peer}");
                    Accepted { stream: Box::new(stream), peer: Some(peer.ip().to_canonical()), from: peer.to_string() }
                });
                (next, at.as_str())
            }
            Listening::Unix(listener, at) => {
                let shown = at.clone();
                let mut say = |line: &str| podssh_ssh::err_line!("podssh serve: {shown}: {line}");
                let next = listener.accept(&mut say).await.map(|end| Accepted {
                    stream: Box::new(tokio::io::join(end.read, end.write)),
                    peer: None,
                    from: shown.clone(),
                });
                (next, at.as_str())
            }
        };
        match next {
            Ok(accepted) => {
                failed = 0;
                if tx.send(accepted).await.is_err() {
                    return;
                }
            }
            Err(e) => {
                failed += 1;
                podssh_ssh::err_line!("podssh serve: {at}: an accept failed: {e}");
                if failed >= FAILED_ACCEPTS {
                    let gone = format!("{FAILED_ACCEPTS} accepts failed in a row: it listens no more");
                    podssh_ssh::err_line!("podssh serve: {at}: {gone}");
                    return;
                }
                tokio::time::sleep(ACCEPT_PAUSE).await;
            }
        }
    }
}

/// The lines of connections closed with no word, one a second at most, so
/// that a flood does not fill serve's log.
#[derive(Default)]
struct Quiet {
    until: Option<tokio::time::Instant>,
    closed: u64,
}

impl Quiet {
    fn closed(&mut self, from: &str, why: Why) {
        self.closed += 1;
        let now = tokio::time::Instant::now();
        if self.until.is_some_and(|until| now < until) {
            return;
        }
        self.until = Some(now + Duration::from_secs(1));
        let n = std::mem::take(&mut self.closed);
        podssh_ssh::err_line!(
            "podssh serve: {from}: closed with no word, as {} refusals are under way ({n} since the last line): {}",
            listen::REFUSING,
            why.words()
        );
    }
}

/// Place one connection under the caps: served, refused with a disconnect,
/// or closed at once.
fn admit(accepted: Accepted, served: &Served, running: &mut JoinSet<()>, quiet: &mut Quiet) {
    let Accepted { stream, peer, from } = accepted;
    match served.gate.enter() {
        Entry::Admitted(place) => {
            let mut own = (*served.settings).clone();
            own.peer = peer;
            let (key, keys, control) = (served.key.clone(), served.keys.clone(), served.control.clone());
            running.spawn(async move {
                // The places go back as the connection ends; past its
                // deadline the line says so (T-631).
                let ended = server::serve_admitted(stream, key, keys, Arc::new(own), control, place).await;
                if let Err(why) = ended {
                    podssh_ssh::err_line!("podssh serve: {from}: {why}");
                }
            });
        }
        Entry::Full(full) => {
            podssh_ssh::err_line!("podssh serve: {from}: refused: {}", full.why.words());
            running.spawn(listen::refuse(stream, full));
        }
        Entry::Dropped(why) => {
            drop(stream);
            quiet.closed(&from, why);
        }
    }
}

/// Wait for the connections after a stop, each winding down; a second
/// signal kills each child at once, and [`STOP_LIMIT`] ends the wait.
async fn wait_out(running: &mut JoinSet<()>, signals: &mut Signals, control: &Control) {
    let deadline = tokio::time::Instant::now() + STOP_LIMIT;
    loop {
        tokio::select! {
            next = running.join_next() => if next.is_none() { return },
            asked = signals.next() => if matches!(asked, Asked::Stop) { control.stop() },
            () = tokio::time::sleep_until(deadline) => {
                running.abort_all();
                while running.join_next().await.is_some() {}
                return;
            }
        }
    }
}

#[cfg(test)]
#[path = "serve_listen_tests.rs"]
mod tests;
