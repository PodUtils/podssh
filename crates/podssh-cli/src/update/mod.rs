//! `podssh update` (T-375): the release for this binary's own target,
//! fetched through the proxy, its `SHA256SUMS` checked against the
//! signature that the release workflow made, and its binary against that
//! file, then run once here and in place of the running one, the one before
//! it kept beside it, which `--rollback` puts back (T-396). The steps are
//! `pod-release`'s (T-880); what stays here is the flags, the lines that
//! tell each step, the exit codes, the trust and the way out. It runs only
//! when asked: no other command looks for a release.

pub mod way;

use std::io::Write;
use std::path::{Path, PathBuf};

use pod_release::fetch::Fetcher;
use pod_release::replace::{self, Stopped};
use pod_release::trial::{self, Expect};
use pod_release::update::{self as steps, Source};
use pod_release::{keep, version, Error, Version};
use podssh_ws::{ProxyChoice, Trust};

use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::{EX_CANTCREAT, EX_CONFIG, EX_DATAERR, EX_UNAVAILABLE};
pub use way::{has_rollback, moved_back, way_back, ROLLBACK_SINCE};

/// The name that a binary of this program says first to `--version`, and
/// that the file of its release begins with.
pub const PROGRAM: &str = "podssh";
/// The release workflow whose token signs a release (its file in
/// `.github/workflows/`).
const WORKFLOW: &str = "release.yml";

/// Every value `podssh update` accepts, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateArgs {
    pub check: bool,
    pub version: Option<String>,
    pub ca_file: Option<String>,
    /// `--rollback`: the binary that the last update kept, back (T-396).
    pub rollback: bool,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl UpdateArgs {
    pub fn from_matches(matches: &clap::ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> UpdateArgs {
        let get = |id: &str| matches.get_one::<String>(id).cloned();
        let (check, rollback) = (matches.get_flag("check"), matches.get_flag("rollback"));
        UpdateArgs { check, version: get("version"), ca_file: get("ca-file"), rollback, refused }
    }
}

/// How a new binary is tried instead of the crate's (`--version` of the
/// file, once): only a test on a system with no small program of its own
/// to run gives one.
pub type Check = fn(&Path, &Version) -> Result<String, String>;

/// Where the releases are, and what this binary is.
#[derive(Debug, Clone)]
pub struct Options {
    /// The repository, its hosts, its workflow and the roots of Sigstore.
    pub source: Source,
    pub fetcher: Fetcher,
    /// The file that the update replaces.
    pub exe: PathBuf,
    /// The release's name of this build's target.
    pub target: String,
    /// This build's version.
    pub current: Version,
    /// `None`: the crate's trial, `--version` once (T-396).
    pub trial: Option<Check>,
}

/// The exit code of a failure of an update.
pub fn code(error: &Error) -> i32 {
    match error {
        Error::Unavailable(_) | Error::NotFound(_) => EX_UNAVAILABLE,
        Error::Refused(_) => EX_DATAERR,
        Error::CantWrite(_) => EX_CANTCREAT,
        Error::Config(_) => EX_CONFIG,
    }
}

/// What a trial run of this program's binary expects: `podssh`, any
/// version (an update gives the release's own), within the crate's bound.
pub fn expect() -> Expect<'static> {
    Expect { program: PROGRAM, version: None, limit: trial::LIMIT }
}

/// The binary that an update on Windows moved aside, removed once it runs no
/// more (T-375); elsewhere nothing.
pub fn remove_aside() {
    if cfg!(windows) {
        if let Ok(exe) = pod_release::replace::running() {
            pod_release::replace::remove_aside(&exe);
        }
    }
}

/// The binary that the last update kept beside `exe`, when it runs here:
/// what the supervisor of a detached run (T-390) starts after the new
/// binary failed to start again and again.
pub fn fallback(exe: &Path) -> Option<PathBuf> {
    keep::fallback(exe, &expect())
}

/// The release's name of this build's target: the triple of its binary.
/// On Linux the release's binary is static (musl), so it is the one for a
/// build of either libc; a 32-bit ARM build takes the armv7 one, the only
/// one of the release.
pub fn target() -> Option<&'static str> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    Some(match (os, arch) {
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") => "aarch64-unknown-linux-musl",
        ("linux", "arm") if cfg!(target_abi = "eabihf") => "armv7-unknown-linux-musleabihf",
        ("linux", "riscv64") => "riscv64gc-unknown-linux-musl",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("windows", "aarch64") => "aarch64-pc-windows-msvc",
        _ => return None,
    })
}

/// The file of a target's binary in a release.
pub fn asset(target: &str) -> String {
    version::asset(PROGRAM, target)
}

fn mib(bytes: usize) -> String {
    format!("{:.1} MiB", bytes as f64 / (1 << 20) as f64)
}

impl Options {
    /// This binary, the releases of its repository on GitHub, and Sigstore's
    /// roots; `trust` for TLS to GitHub.
    pub fn of_this_build(trust: Trust) -> Result<Options, Error> {
        let repository = env!("CARGO_PKG_REPOSITORY");
        let repo = repository
            .strip_prefix("https://github.com/")
            .filter(|r| r.split('/').count() == 2)
            .ok_or_else(|| Error::Config(format!("this build's repository, {repository}, is not one of GitHub")))?;
        let target = target().ok_or_else(|| {
            Error::Config(format!(
                "no release has a binary for {} {}: build podssh from its source",
                std::env::consts::OS,
                std::env::consts::ARCH
            ))
        })?;
        let current = Version::parse(env!("CARGO_PKG_VERSION"))
            .ok_or_else(|| Error::Config("this build's version is not one of semver".into()))?;
        // `--ca-file` once, in the client's own TLS: the crate sends no
        // trust with each request.
        let client = podssh_ws::client::getter_trusting(&ProxyChoice::FromEnvironment, &trust);
        Ok(Options {
            source: Source::github(repo, WORKFLOW),
            fetcher: Fetcher::new(client),
            exe: replace::running().map_err(Error::Config)?,
            target: target.to_string(),
            current,
            trial: None,
        })
    }

    /// `bytes` in place of the running binary, once it ran here.
    fn install(&self, bytes: &[u8], version: &Version) -> Result<replace::Replaced, Error> {
        let Some(check) = self.trial else {
            return steps::install(&self.exe, bytes, PROGRAM, version, trial::LIMIT);
        };
        let exe = replace::shown(&self.exe);
        let tried = |file: &Path| check(file, version);
        replace::replace(&self.exe, bytes, &tried).map_err(|stopped| match stopped {
            Stopped::Trial(why) => {
                Error::Refused(format!("{PROGRAM} {version} did not run here: {why}; nothing was replaced"))
            }
            Stopped::Disk(why) => Error::CantWrite(format!("{why}; {exe} is as it was")),
        })
    }
}

/// The update: the release that `asked` names, else the newest one; its
/// `SHA256SUMS` and its signature, checked; with `check`, no more; else the
/// binary of this target, checked, in place of `opts.exe`.
pub async fn update(opts: &Options, check: bool, asked: Option<&Version>, out: &mut dyn Write) -> Result<(), Error> {
    let _ = writeln!(out, "podssh {}, {}: {}", opts.current, opts.target, replace::shown(&opts.exe));
    let version = match asked {
        Some(version) => version.clone(),
        None => {
            let Some((newest, from)) = steps::newest(&opts.fetcher, &opts.source, &opts.current).await? else {
                let which = if opts.current.is_prerelease() { "release" } else { "release (not a prerelease)" };
                let _ = writeln!(
                    out,
                    "the list of releases holds no {which} newer than this build, {}: nothing to do (--version TAG \
                     installs one)",
                    opts.current
                );
                return Ok(());
            };
            let which = if opts.current.is_prerelease() {
                "the newest release, a prerelease too"
            } else {
                "the newest release"
            };
            let _ = writeln!(out, "{which}: {} (from {from})", newest.tag());
            // pod-release's plan with no tag pinned: the same version, an
            // older release or an update; `Same` and `Available` need a pin
            // or a check, so they mean an update here.
            match pod_release::update::plan(&newest, &opts.current, false, false, false) {
                pod_release::update::Plan::UpToDate => {
                    let _ = writeln!(out, "podssh {} is the newest release: nothing to do", opts.current);
                    return Ok(());
                }
                pod_release::update::Plan::Newer => {
                    let _ = writeln!(
                        out,
                        "this build, {}, is newer than {}: nothing to do (--version TAG installs a release)",
                        opts.current,
                        newest.tag()
                    );
                    return Ok(());
                }
                pod_release::update::Plan::Same
                | pod_release::update::Plan::Available
                | pod_release::update::Plan::Install => newest,
            }
        }
    };
    if asked.is_some() && version < opts.current {
        let _ = writeln!(out, "{} is older than this build, as --version asked", version.tag());
    }
    let tag = version.tag();
    let signed = steps::signed(&opts.fetcher, &opts.source, &version).await.map_err(|e| moved(e, &version, opts))?;
    let logged = signed.verified.logged;
    let at = crate::doctor::clock::format_utc(logged.time);
    let _ = writeln!(
        out,
        "SHA256SUMS of {tag}: signed by {}, logged by Rekor at {at} (entry {})",
        signed.identity.uri, logged.index
    );
    let name = asset(&opts.target);
    // Before a check says that it would replace: the file must be named.
    signed.verified.sums.get(&name).map_err(|why| Error::NotFound(format!("{tag} has no {name}: {why}")))?;
    if cfg!(feature = "ts") {
        let _ = writeln!(out, "this build has the feature ts, which the release's binary has not");
    }
    if check {
        let _ = writeln!(out, "podssh update would replace {} with {name} of {tag}", replace::shown(&opts.exe));
        return Ok(());
    }
    let binary = steps::binary(&opts.fetcher, &opts.source, &signed, &name).await?;
    let _ = writeln!(out, "{name}: {}, its SHA-256 is the one of SHA256SUMS", mib(binary.len()));
    let exe = replace::shown(&opts.exe);
    let replaced = opts.install(&binary, &version)?;
    let _ = writeln!(out, "{name}: it ran here, and said {}", replaced.said);
    let _ = writeln!(out, "{exe}: replaced; it is podssh {version} now");
    // The way back that the binary now in place can run (T-507).
    let _ = match &replaced.prev {
        Ok(prev) => writeln!(out, "{}", way_back(prev, &opts.exe, &version)),
        Err(why) => writeln!(out, "the binary before it is not kept ({why}): there is none to put back"),
    };
    Ok(())
}

/// The last release made before the repository moved (2026-11-05): each
/// release through it names the workflow of the repository's old name, which
/// this build does not take (T-683's ruling, no second signer).
const LAST_BEFORE_THE_MOVE: &str = "1.1.0-beta.3";

/// A refused signature of a release made before the move, said as it is
/// (T-967): the release is genuine, signed by the repository's old name,
/// and the hint of Sigstore's roots, which pod-release adds, is no cause.
fn moved(failure: Error, version: &Version, opts: &Options) -> Error {
    let Error::Refused(why) = &failure else { return failure };
    let tag = version.tag();
    let ours = opts.source.identity(&tag).uri;
    let before = Version::parse(LAST_BEFORE_THE_MOVE).is_some_and(|last| *version <= last);
    if !before || !why.contains(&ours) {
        return failure;
    }
    let cause = why.split_once("; nothing was replaced").map_or(why.as_str(), |(cause, _)| cause);
    let repo = &opts.source.repo;
    Error::Refused(format!(
        "{cause}; nothing was replaced. {tag} was signed under the repository's old name, before it moved to {repo}, \
         and this build takes only {repo}'s signature: download {tag} by hand from {}/{repo}/releases/tag/{tag}",
        opts.source.web
    ))
}

/// The trust of TLS to GitHub: `--ca-file`, else `SSL_CERT_FILE`, else the
/// settings file's `CaFile`, else the default, as doctor's.
fn trust(args: &UpdateArgs) -> Trust {
    let cert_env = std::env::var("SSL_CERT_FILE").ok().filter(|v| !v.trim().is_empty());
    match (&args.ca_file, cert_env, &crate::settings::here().ca_file) {
        (Some(file), ..) => Trust::File(file.into()),
        (None, Some(file), _) => Trust::File(file.into()),
        (None, None, Some(value)) => Trust::File(value.text.clone().into()),
        (None, None, None) => Trust::Default,
    }
}

pub fn run(args: &UpdateArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if args.rollback {
        return rollback(args, out, err);
    }
    // Each other form reads the releases' feed (T-810); --rollback is local.
    if podssh_relay::open::offline() {
        let _ = writeln!(
            err,
            "podssh update: {} is set, so podssh does not connect anywhere",
            podssh_relay::open::OFFLINE_ENV
        );
        return EX_UNAVAILABLE;
    }
    let asked = match args.version.as_deref() {
        None => None,
        Some(text) => match Version::parse(text.strip_prefix('v').unwrap_or(text)) {
            Some(version) => Some(version),
            None => {
                let _ = writeln!(err, "podssh update: --version {text}: the version of a release, as v1.0.0-beta.3");
                return EXIT_USAGE;
            }
        },
    };
    let fail = |failure: Error, err: &mut dyn Write| {
        let _ = writeln!(err, "podssh update: {}", failure.why());
        code(&failure)
    };
    let opts = match Options::of_this_build(trust(args)) {
        Ok(opts) => opts,
        Err(failure) => return fail(failure, err),
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => return fail(Error::Config(format!("a runtime: {e}")), err),
    };
    let before = stamp(&opts.exe);
    match runtime.block_on(update(&opts, args.check, asked.as_ref(), out)) {
        Ok(()) => {
            // Each node of --detach that takes the signal of an upgrade
            // takes the binary now in place, its sessions with it (T-668).
            if !args.check && stamp(&opts.exe) != before {
                crate::node_upgrade::mark::ask_each(out);
            }
            0
        }
        Err(failure) => fail(failure, err),
    }
}

/// What tells a file that an update replaced from the one before it: its
/// length and the time of its last write.
fn stamp(path: &Path) -> Option<(u64, Option<std::time::SystemTime>)> {
    std::fs::metadata(path).ok().map(|meta| (meta.len(), meta.modified().ok()))
}

/// `podssh update --rollback` (T-396): no network, only the file that the
/// last update kept beside this binary.
fn rollback(args: &UpdateArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if args.check || args.version.is_some() {
        let why = "--rollback puts back the binary that the last update kept: it goes with no --check or --version";
        let _ = writeln!(err, "podssh update: {why}");
        return EXIT_USAGE;
    }
    let done = replace::running().map_err(Error::Config).and_then(|exe| {
        let done = keep::rollback(&exe, &expect())?;
        Ok((exe, done))
    });
    match done {
        Ok((exe, done)) => {
            for line in way::rolled_back(&exe, &done) {
                let _ = writeln!(out, "{line}");
            }
            0
        }
        Err(failure) => {
            let _ = writeln!(err, "podssh update: {}", failure.why());
            code(&failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_target_of_the_release_has_its_file() {
        assert_eq!(asset("x86_64-unknown-linux-musl"), "podssh-x86_64-unknown-linux-musl");
        assert_eq!(asset("aarch64-pc-windows-msvc"), "podssh-aarch64-pc-windows-msvc.exe");
        // The build of the tests has a target of the release.
        assert!(target().is_some(), "{} {}", std::env::consts::OS, std::env::consts::ARCH);
    }

    /// beta.2's own SHA256SUMS names each target of the release: the
    /// identity of this program's files, which the crate's tests do not
    /// have.
    #[test]
    fn the_published_sums_name_each_target() {
        let sums = include_bytes!("../../tests/fixtures/update/SHA256SUMS-v1.0.0-beta.2");
        let sums = pod_release::Sums::parse(sums).unwrap();
        for target in [
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
            "armv7-unknown-linux-musleabihf",
            "riscv64gc-unknown-linux-musl",
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "x86_64-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
        ] {
            assert!(sums.get(&asset(target)).is_ok(), "{target}");
        }
    }

    /// Each failure of the crate has the exit code that the manual gives.
    #[test]
    fn each_failure_has_its_documented_exit_code() {
        for (error, want) in [
            (Error::Unavailable(String::new()), EX_UNAVAILABLE),
            (Error::NotFound(String::new()), EX_UNAVAILABLE),
            (Error::Refused(String::new()), EX_DATAERR),
            (Error::CantWrite(String::new()), EX_CANTCREAT),
            (Error::Config(String::new()), EX_CONFIG),
        ] {
            assert_eq!(code(&error), want, "{error:?}");
        }
    }
}
