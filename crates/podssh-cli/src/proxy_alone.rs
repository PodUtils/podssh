//! What `podssh proxy` takes beside `--exit` and `--client-key` (T-431,
//! T-614): apart from `proxy`, for the length of that file.

use std::path::Path;

use crate::proxy::ProxyArgs;
use crate::relay_settings::Refusal;

/// `--exit` takes the relay's place: no relay host, no server of another
/// road, and no cf://HOST, iap:// or eice://, which have roads of their own.
/// Over a carrier (T-614), no flag of the pair's relay either, and no stdio,
/// which carries the pipe's bytes.
pub(crate) fn exit_alone(args: &ProxyArgs) -> Result<(), crate::relay_settings::Refusal> {
    let other = args.relay_host.is_some()
        || args.relay_failover.is_some()
        || args.forwarder.is_some()
        || args.shadowsocks.is_some()
        || args.vless.is_some()
        || args.trojan.is_some()
        || args.hysteria.is_some()
        || args.tuic.is_some()
        || args.via != crate::via::Flags::default()
        || args.wstunnel != crate::wstunnel::Flags::default()
        || args.chisel != crate::chisel::Flags::default()
        || args.turn != crate::turn::Flags::default();
    if other {
        let why = "--exit takes the relay's place: it goes with no relay host and no server of another road";
        return Err(crate::relay_settings::Refusal::usage(why));
    }
    let exit = format!("--exit {}", args.exit.name.as_deref().unwrap_or_default());
    no_relay_env(&exit, args.node.carrier.is_some(), &|name| std::env::var(name).ok())?;
    let Some(text) = args.node.carrier.as_deref() else { return Ok(()) };
    crate::exit::no_relay(&[(args.relay_addr.is_some(), "--relay-addr"), (args.ca_file.is_some(), "--ca-file")])?;
    crate::carrier::for_a_client(text, "stdin and stdout carry the pipe's bytes here").map(|_| ())
}

/// `PODSSH_RELAY` beside a node or an exit of `proxy` (`target`, as the
/// line names it), refused as `ssh` refuses it (T-697, T-1013): the pair
/// names the relay, and a variable that picks one would be dropped with no
/// word. With a carrier there is no relay at all, so it is not read.
pub(crate) fn no_relay_env(target: &str, carrier: bool, var: &dyn Fn(&str) -> Option<String>) -> Result<(), Refusal> {
    if carrier {
        return Ok(());
    }
    crate::node_relay::check(false, false, var(podssh_relay::relay::RELAY_ENV).as_deref(), target)
}

/// What `proxy` checks before any road, beside the roads' own flags: the
/// key of [`key_alone`], then the CA file of [`ca_readable`]. A carrier
/// takes no TLS of podssh's: [`exit_alone`] refuses its `--ca-file`.
pub(crate) fn checked(args: &ProxyArgs) -> Result<(), Refusal> {
    key_alone(args)?;
    match args.node.carrier {
        Some(_) => Ok(()),
        None => ca_readable(args.ca_file.as_deref(), &|name| std::env::var(name).ok()),
    }
}

/// The CA file that the run trusts (`--ca-file`, else `SSL_CERT_FILE`, else
/// the settings file's `CaFile`), opened before any road (T-1011): one line
/// names it once, where the TLS library's named it twice, after the dial.
/// A flag's file is a fault of the command line (64), the others' of the
/// setting (78).
pub(crate) fn ca_readable(flag: Option<&str>, var: &dyn Fn(&str) -> Option<String>) -> Result<(), Refusal> {
    let env = var("SSL_CERT_FILE").filter(|v| !v.trim().is_empty());
    let (named, usage) = match (flag, &env) {
        (Some(_), _) => ("--ca-file", true),
        (None, Some(_)) => ("SSL_CERT_FILE", false),
        (None, None) => ("the settings file's CaFile", false),
    };
    let Some(path) = crate::settings::ca_file_from(flag, env, crate::settings::here()) else { return Ok(()) };
    let fault = |why: String| {
        let message = format!("{named} {path}: {why}");
        if usage {
            Refusal::usage(message)
        } else {
            Refusal::config(message)
        }
    };
    let file = std::fs::File::open(&path).map_err(|e| fault(podssh_ws::text::file_said(Path::new(&path), &e)))?;
    match file.metadata() {
        Ok(meta) if meta.is_dir() => Err(fault("a directory, where a CA file is one file of PEM".to_string())),
        _ => Ok(()),
    }
}

/// `--client-key` is the channel's of the exit, or of a node, which takes
/// it before this.
pub(crate) fn key_alone(args: &ProxyArgs) -> Result<(), crate::relay_settings::Refusal> {
    match (&args.exit.name, &args.exit.client_key) {
        (None, Some(_)) => {
            let why = "--client-key is this client's key for --exit NAME or node://NAME: give one of them";
            Err(crate::relay_settings::Refusal::usage(why))
        }
        _ => Ok(()),
    }
}

/// The exit of `--exit NAME`, with the trust of `--ca-file` for its pair's
/// relay, or the stream of `--carrier` in place of its pair (T-614).
pub(crate) fn exit_to(name: &str, args: &ProxyArgs) -> crate::exit::open::To {
    let (name, client_key, ca_file) = (name.to_string(), args.exit.client_key.clone(), args.ca_file.clone());
    let carrier = args.node.carrier.clone();
    crate::exit::open::To { name, client_key, ca_file, carrier, ..Default::default() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CA file that cannot be opened is one line that names it once, and
    /// whose flag or variable gave it, with the code of where the fault is
    /// (T-1011); a file that opens passes.
    #[test]
    fn a_ca_file_that_cannot_be_read_is_named_once() {
        let dir = std::env::temp_dir().join(format!("podssh-ca-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let pem = dir.join("ca.pem").display().to_string();
        std::fs::write(&pem, "not read here").unwrap();
        let gone = dir.join("gone").join("ca.pem").display().to_string();
        let folder = dir.display().to_string();
        let none = |_: &str| -> Option<String> { None };
        let env = |name: &str| (name == "SSL_CERT_FILE").then(|| "/nonexistent".to_string());
        // (--ca-file, the environment, the path named, the code, the words)
        type Row<'a> = (Option<&'a str>, &'a dyn Fn(&str) -> Option<String>, &'a str, i32, &'a str);
        let rows: [Row; 4] = [
            (Some("/nonexistent"), &none, "/nonexistent", 64, "--ca-file /nonexistent: no such file"),
            (Some(&gone), &none, &gone, 64, "--ca-file "),
            (Some(&folder), &none, &folder, 64, "--ca-file "),
            (None, &env, "/nonexistent", 78, "SSL_CERT_FILE /nonexistent: no such file"),
        ];
        for (flag, var, path, code, says) in rows {
            let refusal = ca_readable(flag, var).unwrap_err();
            assert_eq!(refusal.code, code, "{refusal}");
            assert!(refusal.message.starts_with(says), "{refusal}");
            assert_eq!(refusal.message.matches(path).count(), 1, "the path once: {refusal}");
        }
        assert!(ca_readable(Some(&pem), &none).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A node and an exit refuse `PODSSH_RELAY` in ssh's words (78), a
    /// carrier and an empty or unset variable pass (T-1013).
    #[test]
    fn a_node_or_an_exit_refuses_the_relay_s_variable() {
        let set = |value: &'static str| move |name: &str| (name == "PODSSH_RELAY").then(|| value.to_string());
        for target in ["node://lab", "--exit lab"] {
            let refusal = no_relay_env(target, false, &set("relay.example")).unwrap_err();
            assert_eq!(refusal.code, 78, "{refusal}");
            assert_eq!(refusal.message, crate::node_relay::words("PODSSH_RELAY", target));
            assert!(no_relay_env(target, true, &set("relay.example")).is_ok(), "a carrier has no relay");
            assert!(no_relay_env(target, false, &set("")).is_ok(), "an empty variable names none here");
            assert!(no_relay_env(target, false, &|_: &str| -> Option<String> { None }).is_ok());
        }
    }
}
