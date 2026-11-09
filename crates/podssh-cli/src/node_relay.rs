//! The relay's settings beside a node (T-697): the pair names its relay, so
//! `podssh proxy node://NAME`, `podssh ssh node://NAME` and `--exit NAME`
//! refuse a flag or a variable that picks one, in the same words, from one
//! list. A settings file's `RelayHost` is a default that this run did not
//! type, so a node ignores it with a note at -v.

use crate::relay_settings::Refusal;

/// Why a flag of the relay goes with no node.
pub const WHY: &str = "the pair names its relay";

/// The first of `--relay-host` and `--relay-failover` that was given.
pub fn flag(host: bool, failover: bool) -> Option<&'static str> {
    [(host, "--relay-host"), (failover, "--relay-failover")].into_iter().find_map(|(given, name)| given.then_some(name))
}

/// The words of a refusal of `what` (a flag or a variable) beside `target`.
pub fn words(what: &str, target: &str) -> String {
    format!("{what} does not apply to {target}: {WHY}")
}

/// The refusal for a node or an exit `target`: a flag is a fault of the
/// command line (64), `PODSSH_RELAY` of the environment (78). An empty
/// variable is no variable, as for the relay road.
pub fn check(host: bool, failover: bool, env_relay: Option<&str>, target: &str) -> Result<(), Refusal> {
    if let Some(name) = flag(host, failover) {
        return Err(Refusal::usage(words(name, target)));
    }
    if env_relay.is_some_and(|v| !v.trim().is_empty()) {
        return Err(Refusal::config(words("PODSSH_RELAY", target)));
    }
    Ok(())
}

/// The note at -v for a `RelayHost` of the settings file that a node
/// ignores.
pub fn ignored(file: &crate::settings::Defaults) -> Option<String> {
    let value = file.relay_host.as_ref()?;
    Some(format!("{}: RelayHost {} is ignored for a node: {WHY}", value.at, value.text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{Defaults, Value};

    #[test]
    fn a_flag_is_64_the_variable_78_and_each_names_itself() {
        let flag = check(true, false, None, "node://lab").unwrap_err();
        assert_eq!(flag.code, 64);
        assert_eq!(flag.message, "--relay-host does not apply to node://lab: the pair names its relay");
        let failover = check(false, true, None, "node://lab").unwrap_err();
        assert!(failover.code == 64 && failover.message.starts_with("--relay-failover does not apply"));
        let env = check(false, false, Some("relay.example"), "node://lab").unwrap_err();
        assert!(env.code == 78 && env.message.starts_with("PODSSH_RELAY does not apply to node://lab"), "{env}");
        // The flag, typed for this run, wins over the variable.
        assert_eq!(check(true, false, Some("x"), "node://lab").unwrap_err().code, 64);
    }

    use crate::ssh::args::SshArgs;
    use crate::ssh::resolve::{resolve_or_refuse, Env, Resolved};

    fn ssh(destination: &str, edit: impl FnOnce(&mut SshArgs, &mut Env)) -> Result<Resolved, Refusal> {
        let mut args = SshArgs { destination: Some(destination.into()), ..Default::default() };
        let mut env = Env { user: Some("me".into()), ..Default::default() };
        edit(&mut args, &mut env);
        resolve_or_refuse(&args, &env)
    }

    /// `podssh ssh node://NAME` refuses what `proxy` refuses, in its words.
    #[test]
    fn ssh_node_refuses_the_relay_s_flags_and_variable_as_proxy_does() {
        let r = ssh("node://lab", |a, _| a.relay_host = Some("relay.example".into())).unwrap_err();
        assert_eq!(r.code, 64);
        assert_eq!(r.message, "--relay-host does not apply to node://lab: the pair names its relay");
        let r = ssh("node://lab", |a, _| a.relay_failover = Some("parallel".into())).unwrap_err();
        assert!(r.code == 64 && r.message.starts_with("--relay-failover does not apply to node://lab"), "{r}");
        let r = ssh("node://lab", |_, e| e.relay = Some("relay.example".into())).unwrap_err();
        assert!(r.code == 78 && r.message.starts_with("PODSSH_RELAY does not apply to node://lab"), "{r}");
    }

    #[test]
    fn ssh_node_still_takes_ca_file_and_a_settings_file_s_relay_host_is_a_note() {
        let r = ssh("node://lab", |a, _| a.ca_file = Some("ca.pem".into())).unwrap();
        assert!(matches!(r.transport, crate::ssh::resolve::Transport::Node { .. }));
        let relay_host = Some(Value { text: "relay.example".into(), at: "settings:3".into() });
        let r = ssh("node://lab", |_, e| e.settings = Defaults { relay_host, ..Defaults::default() }).unwrap();
        let notes = r.notes.iter().filter(|n| n.contains("RelayHost")).count();
        assert_eq!(notes, 1, "one -v line: {:?}", r.notes);
    }

    /// A host that is no node keeps its relay list and its failover.
    #[test]
    fn a_plain_host_still_takes_its_relay_list() {
        let r = ssh("host.example", |a, _| {
            a.relay_host = Some("a.example,b.example".into());
            a.relay_failover = Some("parallel".into());
        })
        .unwrap();
        match r.transport {
            crate::ssh::resolve::Transport::Relay { relays, .. } => assert_eq!(relays.hosts.len(), 2),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn nothing_given_or_an_empty_variable_is_no_refusal() {
        assert!(check(false, false, None, "node://lab").is_ok());
        assert!(check(false, false, Some("  "), "node://lab").is_ok());
    }

    #[test]
    fn the_settings_file_is_a_note_and_never_a_refusal() {
        assert_eq!(ignored(&Defaults::default()), None);
        let relay_host = Some(Value { text: "relay.example".into(), at: "settings:3".into() });
        let note = ignored(&Defaults { relay_host, ..Defaults::default() }).unwrap();
        assert_eq!(note, "settings:3: RelayHost relay.example is ignored for a node: the pair names its relay");
    }
}
