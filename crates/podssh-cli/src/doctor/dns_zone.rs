//! `--dns-zone ZONE` and `--dns-server ADDR` (T-875): whether a resolver
//! passes a TXT query for a name under the user's own zone, as the DNS road
//! (`--carrier dns:FILE`, T-877) needs. Two queries, each for a random name
//! (so no cache answers it): one with an OPT record of EDNS0 of 1232 bytes,
//! one with none; each waits 3 s. Each line says the RCODE, the time, the
//! size, the TC bit, what became of the OPT record and whether the answer
//! holds records of another type, as a portal that answers each name itself
//! gives. The owner's ruling Q107 holds the bound: nothing is sent without
//! `--dns-zone`, and nothing where the probe found UDP refused.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use pod_dns::txt;
use podssh_relay::session::{Entropy, OsEntropy};
use podssh_ws::Verdict;
use tokio::net::UdpSocket;

use super::Report;
use crate::dns_road::{self, Resolver};
use crate::relay_settings::Refusal;

/// How long each query waits for its answer.
pub(crate) const WAIT: Duration = Duration::from_secs(3);
/// The EDNS0 size of the first query: the carrier's own (DNS Flag Day 2020).
pub(crate) const EDNS: u16 = txt::EDNS_SIZE;
/// The lines of the section.
pub(crate) const RESOLVER_LINE: &str = "dns resolver";
pub(crate) const EDNS_LINE: &str = "dns edns0";
pub(crate) const PLAIN_LINE: &str = "dns no edns0";
/// The first word of each probe's name, so that a resolver's log tells it.
const PREFIX: &str = "podssh-";
/// The largest datagram that a reply can be.
const MOST_DATAGRAM: usize = 65_535;

/// The flags as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags {
    /// `--dns-zone ZONE`.
    pub zone: Option<String>,
    /// `--dns-server ADDR`.
    pub server: Option<String>,
}

/// What the section asks: the zone, in lower case with no final dot, and
/// its resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) zone: String,
    pub(crate) resolver: Resolver,
}

/// The name of one probe under `zone`: the prefix and 16 hex digits.
fn probe_name(zone: &str, random: &[u8]) -> String {
    let hex: String = random.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{PREFIX}{hex}.{zone}")
}

/// The plan of the flags, checked before any probe: a zone that a query
/// can name with room for the probe's label (64), an address of a resolver
/// (64), and `--dns-server` only with `--dns-zone` (64).
pub(super) fn asked(flags: &Flags) -> Result<Option<Plan>, Refusal> {
    let Some(typed) = flags.zone.as_deref() else {
        if flags.server.is_some() {
            return Err(Refusal::usage("--dns-server names the resolver of --dns-zone ZONE; it goes with --dns-zone"));
        }
        return Ok(None);
    };
    let zone = typed.trim().trim_end_matches('.').to_ascii_lowercase();
    let shown = podssh_ws::text::one_line(&typed.chars().take(64).collect::<String>());
    if zone.is_empty() || txt::query(0, &probe_name(&zone, &[0; 8]), txt::TXT, Some(EDNS)).is_err() {
        return Err(Refusal::usage(format!(
            "--dns-zone {shown}: give a zone of your own, as t.example.com: letters, digits, - and _ in labels of 63 \
             or fewer, short enough for a label of 23 under it"
        )));
    }
    let resolver = match flags.server.as_deref() {
        Some(text) => {
            let addr = dns_road::address(text).map_err(|why| Refusal::usage(format!("--dns-server {why}")))?;
            Resolver::Named(addr)
        }
        None => Resolver::System,
    };
    Ok(Some(Plan { zone, resolver }))
}

/// The line of a run with `PODSSH_OFFLINE`: nothing was sent.
pub(super) fn offline(report: &mut Report<'_>) {
    report.unknown(RESOLVER_LINE, "not attempted: PODSSH_OFFLINE is set");
}

/// The section: the resolver and the probe of UDP, then the two queries.
pub(super) async fn check(report: &mut Report<'_>, plan: &Plan) {
    let (server, shown) = match plan.resolver.resolve("--dns-server") {
        Ok(found) => found,
        Err(why) => return report.unknown(RESOLVER_LINE, format!("{why}; nothing was sent")),
    };
    if let Err(why) = dns_road::udp_out(server) {
        return report.fail(RESOLVER_LINE, format!("{shown}: {why}; the DNS road needs UDP to a resolver"));
    }
    report.ok(RESOLVER_LINE, format!("{shown}: UDP toward it opens here, straight, as no HTTP proxy carries UDP"));
    for (line, edns) in [(EDNS_LINE, Some(EDNS)), (PLAIN_LINE, None)] {
        let got = ask(server, &plan.zone, edns, WAIT).await;
        report.line(line, judge(&got, edns, server));
    }
}

/// What one query found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Got {
    /// The answer to this query.
    Answered(Facts),
    /// No answer to this query within `waited`: `ignored` datagrams that
    /// answer another query, and the last answer with this query's ID that
    /// did not read, with why.
    Silent { waited: Duration, ignored: usize, unreadable: Option<String> },
    /// The query did not go out, or the system said that nothing serves
    /// the port.
    Failed(String),
}

/// The facts of an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Facts {
    pub(crate) ms: u128,
    pub(crate) size: usize,
    /// The RCODE, with the bits of the OPT record above the header's.
    pub(crate) rcode: u16,
    pub(crate) truncated: bool,
    /// The OPT record's size, or none.
    pub(crate) edns: Option<u16>,
    pub(crate) txt: usize,
    /// The records of the answer section of another type than TXT and
    /// CNAME: an address, where a portal answers each name itself.
    pub(crate) others: usize,
}

/// One TXT query for a random name under `zone` to `server`, with an OPT
/// record of `edns` or none, from a socket connected to it alone; the first
/// datagram that answers it, within `wait`.
pub(crate) async fn ask(server: SocketAddr, zone: &str, edns: Option<u16>, wait: Duration) -> Got {
    let mut random = [0u8; 10];
    if let Err(e) = OsEntropy.fill(&mut random) {
        return Got::Failed(format!("no random name for the query: {e}"));
    }
    let id = u16::from_be_bytes([random[0], random[1]]);
    let name = probe_name(zone, &random[2..]);
    let query = match txt::query(id, &name, txt::TXT, edns) {
        Ok(query) => query,
        Err(why) => return Got::Failed(why),
    };
    let any: SocketAddr = match server {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = match UdpSocket::bind(any).await {
        Ok(socket) => socket,
        Err(e) => return Got::Failed(format!("no UDP socket ({e}), so nothing was sent")),
    };
    if let Err(e) = socket.connect(server).await {
        return Got::Failed(format!("no UDP toward {server} ({e}), so nothing was sent"));
    }
    let started = Instant::now();
    if let Err(e) = socket.send(&query).await {
        return Got::Failed(format!("the query did not go out: {e}"));
    }
    let deadline = tokio::time::Instant::now() + wait;
    let mut datagram = vec![0u8; MOST_DATAGRAM];
    let (mut ignored, mut unreadable) = (0, None);
    loop {
        let n = match tokio::time::timeout_at(deadline, socket.recv(&mut datagram)).await {
            Err(_) => return Got::Silent { waited: wait, ignored, unreadable },
            Ok(Ok(n)) => n,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                return Got::Failed(format!("the system says that nothing serves UDP port {} there", server.port()));
            }
            Ok(Err(e)) => return Got::Failed(format!("the read of the answer failed: {e}")),
        };
        let reply = &datagram[..n];
        match txt::read(reply, id, &name, txt::TXT) {
            Ok(answer) => return Got::Answered(facts(reply, &answer, started.elapsed())),
            // This query's ID, but bytes that do not read as its answer: kept
            // for the line, as a spoof may come first and the answer after.
            Err(why) if reply.len() >= 2 && reply[..2] == id.to_be_bytes() => {
                unreadable = Some(podssh_ws::text::one_line(&why));
            }
            // The answer of another query, or no DNS message: not this one's.
            Err(_) => ignored += 1,
        }
    }
}

/// The facts of `reply`, read as `answer`, after `took`.
fn facts(reply: &[u8], answer: &txt::Answer, took: Duration) -> Facts {
    let count = usize::from(u16::from_be_bytes([reply[6], reply[7]]));
    // A cut answer ends before its count; each record that was not read is
    // of another type only in a whole one.
    let others = if answer.truncated { 0 } else { count.saturating_sub(answer.records.len()) };
    Facts {
        ms: took.as_millis(),
        size: reply.len(),
        rcode: answer.rcode,
        truncated: answer.truncated,
        edns: answer.edns,
        txt: answer.txt().len(),
        others,
    }
}

/// The name of an RCODE (RFC 1035, RFC 6891).
fn rcode_name(rcode: u16) -> String {
    match rcode {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        16 => "BADVERS".into(),
        other => format!("RCODE {other}"),
    }
}

/// The verdict of one query sent with an OPT record of `edns`, or none, to
/// `server`: ok where the resolver answered for the zone, FAIL where the road
/// cannot pass, each with what was found.
pub(crate) fn judge(got: &Got, edns: Option<u16>, server: SocketAddr) -> Verdict {
    let asked = match edns {
        Some(size) => format!("a TXT query with an OPT record of {size}"),
        None => "a TXT query with no OPT record".to_string(),
    };
    let fail = |detail: String| Verdict::Failed { detail };
    let facts = match got {
        Got::Failed(why) => return fail(format!("{asked}: {why}")),
        Got::Silent { unreadable: Some(why), .. } => return fail(format!("{asked}: its answer does not read: {why}")),
        Got::Silent { waited, ignored, unreadable: None } => {
            let others = match ignored {
                0 => String::new(),
                1 => " (1 datagram that answers another query was not taken)".to_string(),
                n => format!(" ({n} datagrams that answer other queries were not taken)"),
            };
            return fail(format!(
                "{asked}: no answer from {server} in {} s{others}: the path or the resolver drops it, or the \
                 zone's server answers nothing for this name",
                waited.as_secs()
            ));
        }
        Got::Answered(facts) => facts,
    };
    let opt = match (edns, facts.edns) {
        (Some(_), Some(size)) => format!("the OPT record kept ({size})"),
        (Some(_), None) => "the OPT record stripped, so answers keep to 512 bytes".to_string(),
        (None, None) => "no OPT record, as asked".to_string(),
        (None, Some(size)) => format!("an OPT record of {size} that the query had not"),
    };
    let tc = if facts.truncated { "TC set" } else { "TC clear" };
    let detail = format!(
        "{asked}: {} in {} ms, {} bytes, {tc}, {opt}, {} TXT records",
        rcode_name(facts.rcode),
        facts.ms,
        facts.size,
        facts.txt
    );
    if facts.others > 0 {
        return fail(format!(
            "{detail}; and {} records of another type, as a portal that answers each name itself gives: the road \
             cannot pass here",
            facts.others
        ));
    }
    match facts.rcode {
        0 | 3 => Verdict::Ok { detail: format!("{detail}: the resolver answered it for the zone") },
        2 => fail(format!("{detail}: the resolver got no answer from the zone's server; check its delegation")),
        5 => fail(format!("{detail}: the resolver refuses to ask for this zone")),
        _ => fail(detail),
    }
}

#[cfg(test)]
#[path = "dns_zone_tests.rs"]
mod tests;
