//! `podssh ssh --list-hosts` (T-832): one record for each literal `Host`
//! alias of ssh_config, with what a connection to it resolves. Each record
//! comes from [`super::resolve::resolve_or_refuse`] with the alias as the
//! destination, the path of `podssh ssh ALIAS` itself, so that the list and
//! a run cannot differ. The aliases are the picker's (T-188): no pattern, no
//! negated name, and each `Include` read as the picker reads it. The picker
//! shows the same records beside its names.
//!
//! A fault that each alias meets stops the list (78): a file of the list, a
//! line that holds for any host, the environment. A fault that only some
//! aliases meet, in their own blocks, is their record's `error` (T-867).

use std::io::Write;

use serde_json::{json, Value};

use super::args::SshArgs;
use super::resolve::Env;
use crate::exitmap::sysexits::EX_CONFIG;
use crate::relay_settings::Refusal;

/// The run's exit when stdout cannot take the list: podssh's own failure.
const EXIT_WRITE: i32 = podssh_ssh::EXIT_FAILURE;

/// One alias, and what a connection to it resolves, or why it resolves
/// nothing (a usage fault of its block, as `podssh ssh ALIAS` would say).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub alias: String,
    pub resolved: Result<Fields, String>,
}

/// The fields of a record: no secret and no passphrase, only names, a port
/// and paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fields {
    /// The host after `HostName`, lowercased, as `-G` prints `hostname`.
    pub host: String,
    pub port: u16,
    pub user: String,
    /// The files that the login would try, in order, expanded: those given,
    /// else OpenSSH's defaults under the home.
    pub identity_files: Vec<String>,
    /// `ProxyJump` or `-J` as given; `None` for none.
    pub proxy_jump: Option<String>,
}

/// The host of no alias, which [`records`] resolves first: a fault that it
/// meets is met by each alias too, as it comes from no alias's own block.
/// `.invalid` is reserved (RFC 2606), so no real host is named.
const NO_ALIAS: &str = "podssh-list-hosts.invalid";

/// The record of `alias`, resolved with the rest of `args` as `podssh ssh
/// ALIAS` resolves it. Each refusal is the record's `error`, 64 and 78
/// alike: [`records`] has already stopped on the faults of each alias.
pub fn record(args: &SshArgs, env: &Env, alias: &str) -> Record {
    let one = SshArgs { destination: Some(alias.to_string()), list_hosts: false, ..args.clone() };
    match super::resolve::resolve_or_refuse(&one, env) {
        Ok(resolved) => {
            let options = &resolved.options;
            let fields = Fields {
                host: resolved.shown.hostname.clone(),
                port: options.destination.port,
                user: options.user.clone(),
                identity_files: options.identity_files.iter().map(|p| p.display().to_string()).collect(),
                proxy_jump: resolved.shown.proxy_jump.clone(),
            };
            Record { alias: alias.to_string(), resolved: Ok(fields) }
        }
        Err(refusal) => Record { alias: alias.to_string(), resolved: Err(refusal.message) },
    }
}

/// The record of each alias of the files of `args` and `env`, in the order
/// of the files. A refusal of 78 is a fault that each alias meets: a file
/// that the list reads cannot be read or others may change it, a line
/// that holds for any host is bad (both found while the names are read),
/// or the environment is bad (found by a host of no alias).
pub fn records(args: &SshArgs, env: &Env) -> Result<Vec<Record>, Refusal> {
    let names = super::picker::names(args, env).map_err(Refusal::config)?;
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let none = SshArgs { destination: Some(NO_ALIAS.to_string()), list_hosts: false, ..args.clone() };
    if let Err(refusal) = super::resolve::resolve_or_refuse(&none, env) {
        // A usage fault of the host of no alias is no fault of an alias.
        if refusal.code == EX_CONFIG {
            return Err(refusal);
        }
    }
    Ok(names.iter().map(|alias| record(args, env, alias)).collect())
}

/// The JSON of `records`: an array, each object with the same keys, `null`
/// where a value is not known, so that a script reads one shape.
pub fn json(records: &[Record]) -> Value {
    let one = |r: &Record| match &r.resolved {
        Ok(f) => json!({
            "alias": r.alias,
            "host": f.host,
            "port": f.port,
            "user": f.user,
            "identity_files": f.identity_files,
            "proxy_jump": f.proxy_jump,
            "error": null,
        }),
        Err(why) => json!({
            "alias": r.alias,
            "host": null,
            "port": null,
            "user": null,
            "identity_files": null,
            "proxy_jump": null,
            "error": why,
        }),
    };
    Value::Array(records.iter().map(one).collect())
}

/// What the picker shows beside a name: `user@host`, `:PORT` when it is
/// not 22, and the jump.
pub fn detail(f: &Fields) -> String {
    // An IPv6 address takes brackets before a port, as a destination does.
    let host = if f.port != 22 && f.host.contains(':') { format!("[{}]", f.host) } else { f.host.clone() };
    let mut text = format!("{}@{host}", f.user);
    if f.port != 22 {
        text.push_str(&format!(":{}", f.port));
    }
    if let Some(jump) = &f.proxy_jump {
        text.push_str(&format!(" via {jump}"));
    }
    text
}

/// Run `--list-hosts`: the array on `out`, exit 0; 64 with a destination
/// or a command, which the list never uses; 78 for a fault that each alias
/// meets ([`records`]); 255 when `out` takes nothing.
pub fn run(args: &SshArgs, env: &Env, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    if args.destination.is_some() || !args.command.is_empty() {
        let why = "--list-hosts lists the Host aliases of ssh_config, and takes no destination and no command";
        return Refusal::usage(why).report("ssh", err);
    }
    let records = match records(args, env) {
        Ok(records) => records,
        Err(refusal) => return refusal.report("ssh", err),
    };
    let text = match serde_json::to_string_pretty(&json(&records)) {
        Ok(text) => text,
        Err(e) => {
            return Refusal { message: format!("--list-hosts: {}", podssh_ws::text::said(&e)), code: EXIT_WRITE }
                .report("ssh", err)
        }
    };
    if let Err(e) = writeln!(out, "{text}").and_then(|()| out.flush()) {
        return Refusal { message: format!("--list-hosts: stdout: {}", podssh_ws::text::said(&e)), code: EXIT_WRITE }
            .report("ssh", err);
    }
    0
}

#[cfg(test)]
#[path = "list_hosts_tests.rs"]
mod tests;
