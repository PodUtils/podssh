//! What a node's record of pkarr names (T-350, T-445): its iroh home relay,
//! in iroh's own `_iroh` TXT, and its other roads, in podssh's `_podssh` TXT
//! of the same signed packet: its DERP home, as the node's DERP ticket, its
//! quick tunnel's name, its Pinggy address, the tunnel's name and the pin
//! of the node's TLS key (T-548), and the name of its tunnel of HTTP made by
//! `ssh -R`, localhost.run's (T-565). iroh reads `_iroh` alone (iroh-dns 1.4.1's
//! `EndpointInfo::from_pkarr_signed_packet` asks for `txt_records("_iroh")`),
//! so its tools and n0's DNS pass podssh's names by; a key that iroh does not
//! know under `_iroh` would make iroh refuse the whole record, which is why
//! podssh's roads have a name of their own.
//!
//! A client takes of a record only what it takes of a command line: a relay
//! `https://HOST[:PORT]`, a DERP ticket that names the record's own key, one
//! label under `trycloudflare.com`, a Pinggy address as `--pinggy-name`
//! takes it, and a DNS name as `--tunnel-url` takes it. Each other value is set aside, and the record keeps its other
//! roads. The record is signed by the node's key, which the client already
//! holds, and each road checks that key again (the QUIC handshake, the
//! end-to-end channel), so a road that a record names reaches the node or
//! nothing. The Pinggy address's pin is trusted for that signature: only the
//! holder of the node's key can say which TLS key ends the tunnel, so a
//! stranger who takes a free tunnel's old name shows another key and is
//! refused at TLS, before the end-to-end channel refuses it too.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::endpoint_info::EndpointInfo;
use iroh::{PublicKey, RelayUrl, SecretKey};
use iroh_dns::pkarr::{SignedPacket, Timestamp};
use iroh_dns::IROH_TXT_NAME;
use podssh_relay::derp::Ticket;
use podssh_relay::pinggy::Address;
use simple_dns::rdata::{RData, TXT};
use simple_dns::{Name, Packet, ResourceRecord, CLASS};

/// podssh's name in a node's zone, beside iroh's `_iroh`: the underscore
/// keeps it out of the names of hosts, as `_iroh` is.
pub const PODSSH_TXT_NAME: &str = "_podssh";

/// The key of the DERP home: the node's DERP ticket, as the node prints it.
pub const DERP_KEY: &str = "derp";

/// The key of the quick tunnel: its name, `NAME.trycloudflare.com`.
pub const QUICK_KEY: &str = "quick";

/// The zone of each quick tunnel's name, as Cloudflare's API gives one: the
/// fact `tunnel-zone` of `trycloudflare` (`pod-services`).
pub fn quick_zone() -> &'static str {
    let service = pod_services::get("trycloudflare").expect("pod-services holds the service trycloudflare");
    service.text("tunnel-zone").expect("trycloudflare of pod-services holds the fact tunnel-zone")
}

/// The key of the Pinggy road: the node's address there, `NAME#PIN`, as
/// the node's line says it and `--pinggy-name` takes it (T-548).
pub const PINGGY_KEY: &str = "pinggy";

/// The key of the tunnel of HTTP made by `ssh -R` (T-565): its name, a DNS
/// name whose WebSocket at `/` is the node's, new after a few hours.
pub const TUNNEL_KEY: &str = "tunnel";

/// The longest name of a tunnel of `ssh -R` that a record holds: a free
/// name of localhost.run's is some 21 characters (`a1b2c3d4e5f6.lhr.life`),
/// so this leaves room, and keeps the record within [`MAX_DNS_PACKET`].
pub const MAX_TUNNEL: usize = 100;

/// The longest Pinggy address that a record holds: a free tunnel's name is
/// some 40 characters and the pin 50, so this leaves room, and a record with
/// each road at its longest stays within [`MAX_DNS_PACKET`].
pub const MAX_PINGGY: usize = 200;

/// pkarr's cap on the DNS packet of a record (iroh-dns's
/// `MAX_DNS_PACKET_SIZE`), checked here to say so in words.
const MAX_DNS_PACKET: usize = 1000;

/// The longest label of a DNS name.
const MAX_LABEL: usize = 63;

/// What a node puts in its record: each road that it has now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roads {
    /// The iroh home relay.
    pub relay: Option<RelayUrl>,
    /// The DERP home, as the node's ticket there.
    pub derp: Option<Ticket>,
    /// The quick tunnel's name.
    pub quick: Option<String>,
    /// The Pinggy address of the node's tunnel now: a free tunnel's name
    /// changes each hour, and the node puts each new one (T-548).
    pub pinggy: Option<Address>,
    /// The name of the node's tunnel of HTTP made by `ssh -R` now (T-565).
    pub tunnel: Option<String>,
}

impl Roads {
    /// Whether the record would name no road, and so is not put.
    pub fn is_empty(&self) -> bool {
        let others = self.quick.is_none() && self.pinggy.is_none() && self.tunnel.is_none();
        self.relay.is_none() && self.derp.is_none() && others
    }

    /// The roads in words, for the node's line: "the home relay URL, the
    /// DERP home HOST, the quick tunnel NAME and the Pinggy tunnel NAME".
    pub fn said(&self) -> String {
        let mut each = Vec::new();
        if let Some(relay) = &self.relay {
            each.push(format!("the home relay {relay}"));
        }
        if let Some(ticket) = &self.derp {
            each.push(format!("the DERP home {}", ticket.server));
        }
        if let Some(name) = &self.quick {
            each.push(format!("the quick tunnel {name}"));
        }
        if let Some(address) = &self.pinggy {
            each.push(format!("the Pinggy tunnel {}", address.name));
        }
        if let Some(name) = &self.tunnel {
            each.push(format!("the tunnel {name}"));
        }
        match each.split_last() {
            None => "no road".to_string(),
            Some((last, [])) => last.clone(),
            Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        }
    }
}

/// A node's record, read and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The relays that it names, `https://` alone, in its order.
    pub relays: Vec<RelayUrl>,
    /// The node's DERP home, as its ticket; one that names another key is
    /// never here.
    pub derp: Option<Ticket>,
    /// The node's quick tunnel, `NAME.trycloudflare.com` in lower case.
    pub quick: Option<String>,
    /// The node's Pinggy address, its tunnel's name and its TLS key's pin.
    pub pinggy: Option<Address>,
    /// The name of the node's tunnel of HTTP made by `ssh -R` (T-565).
    pub tunnel: Option<String>,
    /// When the node signed it, in microseconds since the epoch (pkarr's
    /// sequence number).
    pub signed_at: u64,
    /// What was set aside, and why, for `-v`: no value is said back.
    pub set_aside: Vec<String>,
}

impl Record {
    /// The names of `packet`, whose signature the caller checked: iroh's
    /// part by iroh's own reading, podssh's by iroh-dns's reading of TXT.
    pub fn of(packet: &SignedPacket) -> Result<Record, String> {
        let mut set_aside = Vec::new();
        // A relay that podssh would not dial is no relay of the record.
        let relays = match EndpointInfo::from_pkarr_signed_packet(packet) {
            Ok(info) => info.relay_urls().filter_map(|url| crate::relays::parse_url(url.as_str()).ok()).collect(),
            Err(e) => {
                set_aside.push(format!("its {IROH_TXT_NAME} names are not iroh's record of a node: {e}"));
                Vec::new()
            }
        };
        let node = packet.public_key();
        let (mut derp, mut quick, mut pinggy, mut tunnel) = (None, None, None, None);
        for value in packet.txt_records(PODSSH_TXT_NAME) {
            let Some((key, value)) = value.split_once('=') else {
                set_aside.push(format!("a {PODSSH_TXT_NAME} value that is not KEY=VALUE"));
                continue;
            };
            match key {
                DERP_KEY if derp.is_none() => match derp_home(value, &node) {
                    Ok(ticket) => derp = Some(ticket),
                    Err(why) => set_aside.push(why),
                },
                QUICK_KEY if quick.is_none() => match quick_name(value) {
                    Ok(name) => quick = Some(name),
                    Err(why) => set_aside.push(why),
                },
                PINGGY_KEY if pinggy.is_none() => match pinggy_address(value) {
                    Ok(address) => pinggy = Some(address),
                    Err(why) => set_aside.push(why),
                },
                TUNNEL_KEY if tunnel.is_none() => match tunnel_name(value) {
                    Ok(name) => tunnel = Some(name),
                    Err(why) => set_aside.push(why),
                },
                DERP_KEY | QUICK_KEY | PINGGY_KEY | TUNNEL_KEY => {
                    set_aside.push(format!("a second {key}= of {PODSSH_TXT_NAME}"))
                }
                // A road of a later podssh: passed by, as iroh passes ours.
                _ => {}
            }
        }
        let tunnels = quick.is_none() && pinggy.is_none() && tunnel.is_none();
        if relays.is_empty() && derp.is_none() && tunnels {
            let why = if set_aside.is_empty() { String::new() } else { format!(" ({})", set_aside.join("; ")) };
            return Err(format!(
                "the record names no road: no https:// relay, no DERP home, no quick tunnel, no Pinggy tunnel and \
                 no tunnel of ssh -R{why}"
            ));
        }
        let signed_at = packet.timestamp().as_micros();
        Ok(Record { relays, derp, quick, pinggy, tunnel, signed_at, set_aside })
    }

    /// How long ago the node signed it; none for a time after this host's.
    pub fn age(&self) -> Duration {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros()).unwrap_or_default();
        Duration::from_micros(u64::try_from(now).unwrap_or(u64::MAX).saturating_sub(self.signed_at))
    }
}

/// A DERP ticket of the record of `node`: one of another node would send
/// the client to a stranger, whose channel would fail.
fn derp_home(value: &str, node: &PublicKey) -> Result<Ticket, String> {
    let ticket = Ticket::parse(value).map_err(|why| format!("its DERP home is not a ticket: {why}"))?;
    if ticket.node.0 != *node.as_bytes() {
        return Err("its DERP home is the ticket of another node's key, and is set aside".into());
    }
    Ok(ticket)
}

/// A quick tunnel's name: one label of letters, digits and '-', under
/// [`quick_zone`], as Cloudflare's API gives one; so a record never sends a
/// client to a host outside Cloudflare's edge. Not echoed: a stranger's
/// record may hold anything.
pub fn quick_name(value: &str) -> Result<String, String> {
    let name = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let label = name.strip_suffix(quick_zone()).and_then(|rest| rest.strip_suffix('.'));
    let good = label.is_some_and(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    match good {
        true => Ok(name),
        false => Err(format!("its quick tunnel is not one name under {}, and is set aside", quick_zone())),
    }
}

/// A Pinggy address of a record: `NAME#PIN` as `--pinggy-name` takes it,
/// of [`MAX_PINGGY`] bytes at most. Any DNS name, not Pinggy's zone alone:
/// the zone of its free names moved once already (`run.pinggy-free.link`,
/// where its documents say `a.pinggy.link`), and `PODSSH_PINGGY` may name
/// another server; the pin, which the node's signature vouches for, is the
/// check. Not echoed: a stranger's record may hold anything.
pub fn pinggy_address(value: &str) -> Result<Address, String> {
    let bad = || format!("its Pinggy tunnel is not NAME#PIN of {MAX_PINGGY} bytes at most, and is set aside");
    if value.trim().len() > MAX_PINGGY {
        return Err(bad());
    }
    Address::parse(value).map_err(|_| bad())
}

/// The name of a tunnel of HTTP made by `ssh -R`: a DNS name of two labels
/// or more and of [`MAX_TUNNEL`] bytes at most, in lower case, as the node's
/// line says it. Any zone: the free
/// zone of a service may move, and `PODSSH_LOCALHOST_RUN` may name another
/// server; the end-to-end channel checks the node's key on the road, so a
/// stranger at an old name is refused. Not echoed: a stranger's record may
/// hold anything.
pub fn tunnel_name(value: &str) -> Result<String, String> {
    let name = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.len() <= MAX_TUNNEL && podssh_relay::pinggy::urls::is_name(&name) {
        return Ok(name);
    }
    Err(format!("its tunnel of ssh -R is not one DNS name of {MAX_TUNNEL} bytes at most, and is set aside"))
}

/// The signed packet of `roads`, under `secret`'s key: iroh's `_iroh`
/// values for the relay, as iroh-dns writes them, and podssh's `_podssh`
/// values for the rest, each name in the node's zone, as iroh-dns builds a
/// packet; a value longer than a DNS string goes in pieces, which a reader
/// of TXT joins again.
pub fn packet(secret: &SecretKey, roads: &Roads, ttl: u32) -> Result<SignedPacket, String> {
    let key = secret.public();
    let zone = key.to_z32();
    let mut values: Vec<(String, String)> = Vec::new();
    if let Some(relay) = &roads.relay {
        // iroh's own words for its part, so that iroh reads them as its own.
        let iroh = EndpointInfo::new(key)
            .with_relay_url(relay.clone())
            .to_pkarr_signed_packet(secret, ttl)
            .map_err(|e| format!("the record could not be made: {e}"))?;
        let name = format!("{IROH_TXT_NAME}.{zone}");
        values.extend(iroh.txt_records(IROH_TXT_NAME).into_iter().map(|value| (name.clone(), value)));
    }
    let ours = format!("{PODSSH_TXT_NAME}.{zone}");
    if let Some(ticket) = &roads.derp {
        values.push((ours.clone(), format!("{DERP_KEY}={ticket}")));
    }
    if let Some(name) = &roads.quick {
        values.push((ours.clone(), format!("{QUICK_KEY}={name}")));
    }
    if let Some(address) = &roads.pinggy {
        // A node never puts what a client would set aside.
        let text = address.to_string();
        if text.len() > MAX_PINGGY {
            return Err(format!("the record's Pinggy tunnel is {} bytes, more than {MAX_PINGGY}", text.len()));
        }
        values.push((ours.clone(), format!("{PINGGY_KEY}={text}")));
    }
    if let Some(name) = &roads.tunnel {
        // A node never puts what a client would set aside.
        let name = tunnel_name(name)?;
        values.push((ours.clone(), format!("{TUNNEL_KEY}={name}")));
    }
    let mut dns = Packet::new_reply(0);
    for (name, value) in &values {
        let txt = TXT::try_from(value.as_str()).map_err(|e| format!("the record could not be made: {e}"))?;
        dns.answers.push(ResourceRecord::new(Name::new_unchecked(name), CLASS::IN, ttl, RData::TXT(txt)));
    }
    let encoded = dns.build_bytes_vec_compressed().map_err(|e| format!("the record could not be made: {e}"))?;
    if encoded.len() > MAX_DNS_PACKET {
        return Err(format!("the record would be {} bytes, more than pkarr's {MAX_DNS_PACKET}", encoded.len()));
    }
    sign(secret, &encoded)
}

/// `encoded`, signed as pkarr signs a packet: BEP 44's form of the sequence
/// number, a time in microseconds, and the value. iroh-dns checks it again
/// as it reads the bytes, so a fault here is never put.
fn sign(secret: &SecretKey, encoded: &[u8]) -> Result<SignedPacket, String> {
    let time = Timestamp::now();
    let mut signed = format!("3:seqi{}e1:v{}:", time.as_micros(), encoded.len()).into_bytes();
    signed.extend_from_slice(encoded);
    let signature = secret.sign(&signed);
    let mut bytes = Vec::with_capacity(32 + 64 + 8 + encoded.len());
    bytes.extend_from_slice(secret.public().as_bytes());
    bytes.extend_from_slice(&signature.to_bytes());
    bytes.extend_from_slice(&time.to_be_bytes());
    bytes.extend_from_slice(encoded);
    SignedPacket::from_bytes(&bytes).map_err(|e| format!("the record does not read back as signed: {e}"))
}

#[cfg(test)]
#[path = "pkarr_record_tests.rs"]
mod tests;
