//! `podssh node NAME TARGET... --install` and `--uninstall` (T-121), and
//! `podssh ssh --install NAME -N -R ... --persist` (T-393, `ssh`): the run
//! as a service that this user may make with no privilege, found by a probe
//! at run time: a user unit of systemd when `systemctl --user` answers, else
//! a LaunchAgent when `launchctl` has this user's login session, else two
//! lines of the crontab (one at boot, one each 5 minutes) when `crontab -l`
//! answers; on Windows a task at logon (`schtasks`), never a Windows service,
//! which needs an administrator. With none of them, the command to run at
//! login is printed, and the exit is 69. Each way starts the run again
//! whenever it ends, with no limit of starts: a tunnel that stays down locks
//! its server out. The service runs this binary by its absolute path, with
//! the run's own arguments and `--env-file`: the variables that the run
//! reads (the proxy, the relay, the places of podssh's files) go into a
//! private file beside the pair, so that no token is on a command line or in
//! a unit file, and the pair's tokens stay in the pair's own file. A run with
//! `--env-file` holds a lock beside that file (`lock`), so that a second
//! start of the same service ends at once. `--uninstall` removes what
//! `--install` wrote, and nothing else.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::{EX_CANTCREAT, EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE};
use crate::node::NodeArgs;
use crate::relay_settings::Refusal;

mod env;
pub(crate) mod lock;
pub(crate) mod pipe;
pub(crate) mod print;
pub(crate) mod ssh;
pub(crate) mod system;
#[cfg(unix)]
mod system_install;
mod system_text;
mod text;
mod ways;

#[cfg(all(test, unix))]
mod pod_unit_tests;
#[cfg(test)]
mod system_tests;
#[cfg(test)]
mod tests;

/// The bound on each program that a probe or an install runs.
const PROGRAM_LIMIT: Duration = Duration::from_secs(10);

/// Which command a service runs: a node, or a tunnel of `podssh ssh`. The
/// names of its files and units come from it, so that a node and a tunnel
/// of the same NAME are two services.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Node,
    Ssh,
    /// `podssh serve NAME`, whose unit is printed alone (`--print-unit`).
    Serve,
    /// `podssh pipe --install NAME A B` (T-726).
    Pipe,
}

impl Kind {
    pub fn verb(self) -> &'static str {
        match self {
            Kind::Node => "node",
            Kind::Ssh => "ssh",
            Kind::Serve => "serve",
            Kind::Pipe => "pipe",
        }
    }

    /// How a person makes it again, after `podssh `.
    pub fn install_words(self, name: &str) -> String {
        match self {
            Kind::Node => format!("node {name} --install"),
            Kind::Ssh => format!("ssh --install {name}"),
            Kind::Serve => format!("serve {name} --print-unit"),
            Kind::Pipe => format!("pipe --install {name}"),
        }
    }

    /// How a person removes it, after `podssh `.
    pub fn uninstall_words(self, name: &str) -> String {
        match self {
            Kind::Node => format!("node {name} --uninstall"),
            Kind::Ssh => format!("ssh --uninstall {name}"),
            Kind::Serve => format!("serve {name} --print-unit"),
            Kind::Pipe => format!("pipe --uninstall {name}"),
        }
    }

    /// `VERB-NAME`: the stem of the service's files, units and tasks.
    pub fn stem(self, name: &str) -> String {
        format!("{}-{name}", self.verb())
    }
}

/// What a service runs: this binary by its absolute path, and its words.
pub(crate) struct Spec {
    pub kind: Kind,
    pub name: String,
    pub exe: PathBuf,
    pub args: Vec<String>,
    /// The directory that the run starts in, for the relative paths among
    /// the words that it keeps as typed (`podssh ssh`); none for a node,
    /// whose files are absolute already.
    pub dir: Option<PathBuf>,
    /// The file of `--env-file`, beside which a LaunchAgent's log or a
    /// Windows task's temporary XML goes.
    pub env_file: PathBuf,
}

/// Whose service it is: this user's, or a system unit that runs as the
/// account of `--run-as` (T-709).
pub(crate) enum Target {
    User,
    System(system::Account),
}

/// Map a `pod-unit` / `pod-core` failure to podssh's documented exit codes.
pub(super) fn refusal_of(failure: pod_core::Failure) -> Refusal {
    let code = match failure.class {
        pod_core::Class::Usage => EXIT_USAGE,
        pod_core::Class::Config | pod_core::Class::Unsupported => EX_CONFIG,
        pod_core::Class::Refused => EX_NOPERM,
        pod_core::Class::CantCreate => EX_CANTCREAT,
        _ => EX_UNAVAILABLE,
    };
    Refusal { message: failure.chain(), code }
}

pub(crate) use ways::{install, uninstall};

/// `podssh node`: the variables of `--env-file` and the lock of its service
/// first, then the node, or its install or uninstall.
pub fn dispatch(args: &NodeArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    // The hosts of Cloudflare Access on the pair's road (T-718).
    if let Err(refusal) = crate::access::take_flags(&args.access_hosts) {
        return refusal.report("node", err);
    }
    // Grants used once (T-226): one minted with the node's key, which serves
    // nothing, and the serials that a node refuses, on each road.
    if let Some(code) = crate::grants::node(args, out, err) {
        return code;
    }
    // A node of a carrier is no service: its stream is its parent's (T-595).
    if let Err(refusal) = crate::node_carrier::check(args) {
        return refusal.report("node", err);
    }
    // A person at the node's terminal (T-638): before --detach leaves it, and
    // before a service that has none.
    if let Err(refusal) = crate::node_ask::check(args) {
        return refusal.report("node", err);
    }
    let (installing, removing, printing) = (args.install, args.uninstall, args.print_unit);
    if let Err(refusal) = system::flags(installing, removing, printing, args.system, args.run_as.as_deref()) {
        return refusal.report("node", err);
    }
    if let Some(file) = &args.env_file {
        if installing || removing || printing {
            let why = "--env-file is the file that --install writes for the service: give it to the node alone";
            return Refusal::usage(why).report("node", err);
        }
        if let Err(refusal) = env::apply(Path::new(file)) {
            return refusal.report("node", err);
        }
        // The parent of --detach holds nothing: its child takes the lock. A
        // node's next binary on Windows neither: the binary before it, which
        // waits for it, holds it (T-678).
        if (!args.detach || crate::detach::is_child()) && !crate::node_upgrade::handed_by_parent() {
            if let Some(code) = lock::enter("node", Some(file), err) {
                return code;
            }
        }
    }
    if args.detach && (installing || removing || printing || args.temporary.is_some()) {
        let why = "--detach sends this run into the background: it goes with no --install, --uninstall, --print-unit \
                   or --temporary";
        return Refusal::usage(why).report("node", err);
    }
    if printing {
        return print::node(args, out, err);
    }
    match (installing, removing) {
        (true, true) => Refusal::usage("--install and --uninstall: give one").report("node", err),
        (true, false) if args.system => system::install_node(args, err),
        (true, false) => match prepare(args, &Target::User, false) {
            Ok((spec, notes)) => install(&spec, &notes, out, err),
            Err(refusal) => refusal.report("node", err),
        },
        (false, true) => match label(args, "--uninstall") {
            Ok(name) if args.system => system::uninstall(Kind::Node, &name, &system::Probes::host(), err),
            Ok(name) => uninstall(Kind::Node, &name, err),
            Err(refusal) => refusal.report("node", err),
        },
        (false, false) => crate::node::run_node(args, err),
    }
}

/// The label of `--install` or `--uninstall`, checked.
fn label(args: &NodeArgs, flag: &str) -> Result<String, Refusal> {
    let name = args.name.clone().ok_or_else(|| Refusal::usage(format!("{flag} needs NAME, the label of a pair")))?;
    crate::pairs::check_label(&name)?;
    Ok(name)
}

/// This binary by its absolute path, as a service starts in another
/// directory.
pub(crate) fn this_binary() -> Result<PathBuf, Refusal> {
    std::env::current_exe()
        .and_then(std::path::absolute)
        .map_err(|e| Refusal::config(format!("the path of this podssh is not known: {}", podssh_ws::text::said(&e))))
}

/// The private file of the variables of `kind`'s service NAME, written now,
/// and the notes on what it carries.
pub(crate) fn env_file(kind: Kind, name: &str, notes: &mut Vec<String>) -> Result<PathBuf, Refusal> {
    let (body, left) = env::body();
    note_left(left, notes);
    let file = podssh_relay::cache::store_file(&env::file_name(kind, name), body.as_bytes())
        .map_err(|e| Refusal::config(format!("the file of the service's variables: {}", podssh_ws::text::said(&e))))?;
    notes.push(format!(
        "its variables are in {}, a private file (a proxy's password too, when its URL has one)",
        file.display()
    ));
    Ok(file)
}

/// The note of each variable that is set and left out of the file.
pub(super) fn note_left(left: Vec<String>, notes: &mut Vec<String>) {
    for variable in left {
        // A retired name says what replaced it (T-634); else it is a token.
        let why = match crate::retired::named(crate::retired::RETIRED, &variable) {
            Some(row) => row.refusal(),
            None => "a service keeps no token of the environment".to_string(),
        };
        notes.push(format!("{variable} is set and is not carried: {why}"));
    }
}

/// The service's command and the notes on what it carries. The file of a
/// user's service is written here, unless the unit is only printed; a
/// system unit's is written by `system`, once its unit is known to be
/// sound.
fn prepare(args: &NodeArgs, target: &Target, print: bool) -> Result<(Spec, Vec<String>), Refusal> {
    let flag = if print { "--print-unit" } else { "--install" };
    let name = label(args, flag)?;
    let refused = [
        (args.temporary.is_some(), "--temporary", "the node of podssh ssh --upgrade ends with its last session"),
        (
            args.ephemeral_key,
            "--ephemeral-key",
            "each start of the service would bring a new key, which an operator that pinned the node's key refuses",
        ),
        (args.iroh_ephemeral, "--iroh-ephemeral", "each start of the service would bring a new key and a new ticket"),
    ];
    if let Some((_, named, why)) = refused.iter().find(|(given, ..)| *given) {
        return Err(Refusal::usage(format!("{flag} with {named}: {why}")));
    }
    // A relative socket of a Unix route would be read from the service's
    // own directory (T-714).
    crate::node_unix::service_sockets(&crate::node::words_of(args))?;
    let mut notes = Vec::new();
    if let Target::System(account) = target {
        // root does not read the user's pair: the service does, as the user.
        let (cache, user) = (account.cache_dir(), &account.user);
        notes.push(format!("it reads the pair {name} and its keys from {}, the cache of {user}", cache.display()));
    }
    // A pair that is missing or has expired makes a service that fails at
    // each start: it is read now, for this user's own service, also for a
    // unit that is only printed (T-1024).
    // The iroh road, the DERP road, OpenTunnel's, Pinggy's, Serveo's and
    // ssh-j's, localhost.run's, localtunnel's and bore's serve with no pair
    // (T-379, T-531, T-548, T-549, T-570, T-565, T-568, T-569).
    let tunnel = args.tunnel_asked();
    let paired = !(args.iroh || args.derp || tunnel);
    // The TARGETs first, as the node's own run checks them (64), then the
    // pair (78).
    if paired {
        check_targets(args)?;
    }
    let own = matches!(target, Target::User);
    let pair = match (&args.pair_file, !paired || !own) {
        (_, true) => None,
        (Some(file), false) => Some(crate::pairs::from_file(file)?),
        (None, false) => Some(crate::pairs::stored(&name)?),
    };
    if let Some(pair) = pair {
        notes.push(format!(
            "the pair expires at {}: then the node exits with 77, and the service starts it again, in vain until \
             a new pair (podssh relay pair {name}), which its next start takes",
            crate::pairs::utc(pair.expires_ms)
        ));
    }
    let exe = this_binary()?;
    let env_file = match target {
        Target::System(_) => system_text::env_path(Kind::Node, &name),
        Target::User if print => env::planned(Kind::Node, &name)?,
        Target::User => env_file(Kind::Node, &name, &mut notes)?,
    };
    let words = text::service_args(args, &name, &env_file)?;
    Ok((Spec { kind: Kind::Node, name, exe, args: words, dir: None, env_file }, notes))
}

/// The TARGETs of a node of the pair's road, as its run checks them (64): a
/// unit of words that the node refuses fails at each start (T-1024). An
/// exit, the relay role and a quick tunnel can serve with no TARGET, and a
/// `udp:` TARGET is `node_udp`'s.
fn check_targets(args: &NodeArgs) -> Result<(), Refusal> {
    if args.exit || args.relay || args.quick_tunnel || crate::node_udp::target_of(&args.targets)?.is_some() {
        return Ok(());
    }
    crate::node::targets_of(&crate::node::words_of(args), args.no_e2e).map(|_| ())
}
