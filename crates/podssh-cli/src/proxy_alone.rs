//! What `podssh proxy` takes beside `--exit` and `--client-key` (T-431,
//! T-614): apart from `proxy`, for the length of that file.

use crate::proxy::ProxyArgs;

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
    let Some(text) = args.node.carrier.as_deref() else { return Ok(()) };
    crate::exit::no_relay(&[(args.relay_addr.is_some(), "--relay-addr"), (args.ca_file.is_some(), "--ca-file")])?;
    crate::carrier::for_a_client(text, "stdin and stdout carry the pipe's bytes here").map(|_| ())
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
