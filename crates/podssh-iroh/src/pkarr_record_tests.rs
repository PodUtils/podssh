//! A record with each road (T-445), with no network: what podssh puts is
//! read back whole by podssh, and iroh-dns reads its iroh part alone, in
//! iroh's own words; each road that a record names is checked, and one that
//! fails its check is set aside while the others stay.

use iroh::endpoint_info::EndpointInfo;
use iroh::{RelayUrl, SecretKey};
use podssh_relay::derp::{Key, Server, Ticket};
use podssh_relay::identity::PublicKey as IdentityKey;
use simple_dns::rdata::{RData, TXT};
use simple_dns::{Name, Packet, ResourceRecord, CLASS};

use super::*;
use crate::pkarr::TTL;

const QUICK: &str = "four-words-of-a.trycloudflare.com";

/// A free tunnel's name, as Pinggy gave one to the live run (T-548).
const PINGGY_NAME: &str = "rnwxy-12-34-56-78.run.pinggy-free.link";

/// A Pinggy address of `name`: the name and the pin of a TLS key.
fn pinggy(name: &str) -> Address {
    let pin = podssh_relay::pinggy::Pin::of_spki(b"the node's TLS key");
    Address::parse(&format!("{name}#{pin}")).expect("an address")
}

fn relay() -> RelayUrl {
    "https://usw1-1.relay.n0.iroh.link.".parse().expect("a relay URL")
}

/// The DERP ticket of `secret`'s node at `host`.
fn ticket(secret: &SecretKey, host: &str) -> Ticket {
    let node = IdentityKey(*secret.public().as_bytes());
    Ticket { node, derp: Key([8; 32]), server: Server::new(host, 443).expect("a server") }
}

fn each_road(secret: &SecretKey) -> Roads {
    Roads {
        relay: Some(relay()),
        derp: Some(ticket(secret, "tc301a.ipn.dev")),
        quick: Some(QUICK.into()),
        pinggy: Some(pinggy(PINGGY_NAME)),
        tunnel: None,
        onion: None,
    }
}

/// The record that `packet` is, as a client reads it from a server.
fn read_back(secret: &SecretKey, packet: &SignedPacket) -> Result<Record, String> {
    crate::pkarr::read(&secret.public(), &packet.to_relay_payload())
}

/// A packet of `secret`'s node whose `_podssh` values are `values`, as a
/// node of another podssh, or a planted one, would sign it.
fn planted(secret: &SecretKey, values: &[&str]) -> SignedPacket {
    let name = format!("{PODSSH_TXT_NAME}.{}", secret.public().to_z32());
    let mut dns = Packet::new_reply(0);
    for value in values {
        let txt = TXT::try_from(*value).expect("a TXT value");
        dns.answers.push(ResourceRecord::new(Name::new_unchecked(&name), CLASS::IN, TTL, RData::TXT(txt)));
    }
    sign(secret, &dns.build_bytes_vec_compressed().expect("a DNS packet")).expect("a signed packet")
}

#[test]
fn a_record_with_each_road_reads_back_whole_and_iroh_reads_its_relay_alone() {
    let node = SecretKey::from_bytes(&[0x41; 32]);
    let roads = each_road(&node);
    let packet = packet(&node, &roads, TTL).expect("the record");
    let record = read_back(&node, &packet).expect("the node's own record");
    assert_eq!(record.relays, vec![relay()]);
    assert_eq!(record.derp, roads.derp);
    assert_eq!(record.quick.as_deref(), Some(QUICK));
    assert_eq!(record.pinggy, roads.pinggy, "the Pinggy address, its pin with it");
    assert!(record.set_aside.is_empty(), "{:?}", record.set_aside);
    // iroh's own reading: the relay, and nothing of podssh's names.
    let info = EndpointInfo::from_pkarr_signed_packet(&packet).expect("iroh reads the record as its own");
    assert_eq!(info.relay_urls().cloned().collect::<Vec<_>>(), vec![relay()]);
    // In iroh's own words: what iroh-dns writes for the relay alone.
    let theirs = EndpointInfo::new(node.public()).with_relay_url(relay()).to_pkarr_signed_packet(&node, TTL).unwrap();
    assert_eq!(packet.txt_records(IROH_TXT_NAME), theirs.txt_records(IROH_TXT_NAME));
    assert_eq!(packet.txt_records(PODSSH_TXT_NAME).len(), 3, "the DERP home, the quick tunnel and Pinggy's");
}

#[test]
fn a_record_of_the_derp_road_alone_reads_with_no_relay() {
    let node = SecretKey::from_bytes(&[0x42; 32]);
    let roads = Roads { derp: Some(ticket(&node, "tc302a.ipn.dev")), ..Roads::default() };
    let record = read_back(&node, &packet(&node, &roads, TTL).unwrap()).expect("a record of one road");
    assert_eq!((record.relays.len(), record.derp, record.quick, record.pinggy), (0, roads.derp.clone(), None, None));
    // iroh reads it as a node with no relay, and refuses nothing of it.
    let info = EndpointInfo::from_pkarr_signed_packet(&packet(&node, &roads, TTL).unwrap()).unwrap();
    assert_eq!(info.relay_urls().count(), 0);
    assert!(Roads::default().is_empty() && !roads.is_empty());
}

#[test]
fn a_long_derp_home_goes_in_pieces_and_comes_back_whole() {
    let node = SecretKey::from_bytes(&[0x43; 32]);
    // A name of 253 characters, the longest: its ticket is past a DNS
    // string's 255 bytes, so it goes in pieces.
    let host = format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61));
    assert_eq!(host.len(), 253);
    let roads = Roads { derp: Some(ticket(&node, &host)), ..each_road(&node) };
    assert!(roads.derp.as_ref().unwrap().to_string().len() > 255);
    let record = read_back(&node, &packet(&node, &roads, TTL).expect("within pkarr's bytes")).unwrap();
    assert_eq!(record.derp, roads.derp);
    assert_eq!(record.quick.as_deref(), Some(QUICK));
}

#[test]
fn a_road_that_fails_its_check_is_set_aside_and_the_others_stay() {
    let node = SecretKey::from_bytes(&[0x44; 32]);
    let other = SecretKey::from_bytes(&[0x45; 32]);
    let mine = format!("derp={}", ticket(&node, "tc303a.ipn.dev"));
    let theirs = format!("derp={}", ticket(&other, "tc303a.ipn.dev"));
    let quick = format!("quick={QUICK}");
    let (mine, theirs, quick) = (mine.as_str(), theirs.as_str(), quick.as_str());
    // Another node's DERP ticket: set aside; the quick tunnel stays.
    let record = read_back(&node, &planted(&node, &[theirs, quick])).unwrap();
    assert_eq!((record.derp, record.quick.as_deref()), (None, Some(QUICK)));
    assert!(record.set_aside.iter().any(|why| why.contains("another node's key")), "{:?}", record.set_aside);
    // A quick tunnel outside Cloudflare's zone, of two labels, or with a
    // bad first character: set aside, never said back; the DERP home stays.
    for bad in ["quick=evil.example.com", "quick=a.b.trycloudflare.com", "quick=-x.trycloudflare.com"] {
        let record = read_back(&node, &planted(&node, &[bad, mine])).unwrap();
        assert_eq!(record.quick, None, "{bad}");
        assert!(record.derp.is_some(), "{bad}");
        assert!(!format!("{:?}", record.set_aside).contains("evil"), "{:?}", record.set_aside);
    }
    // A road of a later podssh passes by in silence; a value with no key,
    // and a second DERP home, are set aside.
    let record = read_back(&node, &planted(&node, &["transit=wss://x.example", "novalue", mine, theirs])).unwrap();
    assert!(record.derp.is_some());
    assert_eq!(record.set_aside.len(), 2, "{:?}", record.set_aside);
    // Nothing that passes its check: no road, and the reasons.
    let why = read_back(&node, &planted(&node, &[theirs])).unwrap_err();
    assert!(why.contains("names no road") && why.contains("another node's key"), "{why}");
    // A ticket that is no ticket.
    let record = read_back(&node, &planted(&node, &["derp=derp:notaticket", quick])).unwrap();
    assert!(record.set_aside.iter().any(|why| why.contains("not a ticket")), "{:?}", record.set_aside);
}

#[test]
fn a_quick_tunnel_s_name_is_one_label_under_cloudflare_s_zone() {
    assert_eq!(quick_name("Four-Words-Of-A.TryCloudflare.com.").as_deref(), Ok(QUICK));
    let long = format!("{}.trycloudflare.com", "a".repeat(64));
    for bad in [
        "trycloudflare.com",
        ".trycloudflare.com",
        "x-.trycloudflare.com",
        "a_b.trycloudflare.com",
        "x.trycloudflare.com.evil.example",
        "xtrycloudflare.com",
        long.as_str(),
    ] {
        assert!(quick_name(bad).is_err(), "{bad}");
    }
}

#[test]
fn the_node_says_its_roads_in_words() {
    let node = SecretKey::from_bytes(&[0x46; 32]);
    let said = each_road(&node).said();
    assert!(said.starts_with(&format!("the home relay {}", relay())), "{said}");
    let end = format!(", the DERP home tc301a.ipn.dev, the quick tunnel {QUICK} and the Pinggy tunnel {PINGGY_NAME}");
    assert!(said.ends_with(&end), "{said}");
    let alone = Roads { quick: Some(QUICK.into()), ..Roads::default() };
    assert_eq!(alone.said(), format!("the quick tunnel {QUICK}"));
}

#[test]
fn a_record_of_the_pinggy_road_alone_names_the_tunnel_and_its_pin() {
    let node = SecretKey::from_bytes(&[0x47; 32]);
    let roads = Roads { pinggy: Some(pinggy(PINGGY_NAME)), ..Roads::default() };
    assert!(!roads.is_empty(), "a record of Pinggy alone is put");
    let record = read_back(&node, &packet(&node, &roads, TTL).unwrap()).expect("a record of one road");
    assert_eq!(record.pinggy, roads.pinggy);
    assert_eq!((record.relays.len(), record.derp, record.quick), (0, None, None));
    // As the node's line says it and --pinggy-name takes it.
    let text = record.pinggy.unwrap().to_string();
    assert!(text.starts_with(&format!("{PINGGY_NAME}#SHA256:")), "{text}");
}

#[test]
fn a_bad_pinggy_address_is_set_aside_unsaid_and_the_others_stay() {
    let node = SecretKey::from_bytes(&[0x48; 32]);
    let mine = format!("derp={}", ticket(&node, "tc304a.ipn.dev"));
    let pin = pinggy(PINGGY_NAME).pin.to_string();
    // A name of more than MAX_PINGGY bytes with its pin, each label good.
    let long = format!("{}.{}.{}.evil.example", "a".repeat(63), "b".repeat(63), "c".repeat(30));
    let bad = [
        "pinggy=evil.example".to_string(),
        format!("pinggy=evil_name.example#{pin}"),
        "pinggy=evil.example#SHA256:short".to_string(),
        format!("pinggy={long}#{pin}"),
    ];
    for bad in &bad {
        let record = read_back(&node, &planted(&node, &[bad.as_str(), mine.as_str()])).unwrap();
        assert_eq!(record.pinggy, None, "{bad}");
        assert!(record.derp.is_some(), "{bad}");
        assert!(record.set_aside.iter().any(|why| why.contains("Pinggy")), "{:?}", record.set_aside);
        assert!(!format!("{:?}", record.set_aside).contains("evil"), "{:?}", record.set_aside);
    }
    // A second address is set aside; the first stays.
    let first = format!("pinggy={}", pinggy(PINGGY_NAME));
    let second = format!("pinggy={}", pinggy("other.run.pinggy-free.link"));
    let record = read_back(&node, &planted(&node, &[first.as_str(), second.as_str()])).unwrap();
    assert_eq!(record.pinggy, Some(pinggy(PINGGY_NAME)));
    assert!(record.set_aside.iter().any(|why| why.contains("a second pinggy=")), "{:?}", record.set_aside);
    assert!(pinggy_address(&format!("{long}#{pin}")).is_err() && Address::parse(&format!("{long}#{pin}")).is_ok());
}

#[test]
fn a_record_with_each_road_at_its_longest_fits_pkarr_s_bytes() {
    let node = SecretKey::from_bytes(&[0x49; 32]);
    let derp = format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61));
    let quick = format!("{}.{}", "q".repeat(63), quick_zone());
    // A name whose address is MAX_PINGGY bytes exactly.
    let pin_len = pinggy(PINGGY_NAME).pin.to_string().len();
    let rest = MAX_PINGGY - pin_len - 1 - 2 * 64;
    let name = format!("{}.{}.{}", "e".repeat(63), "f".repeat(63), "g".repeat(rest));
    assert_eq!(pinggy(&name).to_string().len(), MAX_PINGGY);
    let roads = Roads {
        relay: Some(relay()),
        derp: Some(ticket(&node, &derp)),
        quick: Some(quick.clone()),
        pinggy: Some(pinggy(&name)),
        tunnel: None,
        onion: None,
    };
    let packet = packet(&node, &roads, TTL).expect("each road at its longest fits");
    // With the onion service too it would not fit, so it goes without it.
    let onion = Roads { onion: Some(ONION.into()), ..roads.clone() };
    let without = read_back(&node, &super::packet(&node, &onion, TTL).expect("put without the onion")).unwrap();
    assert_eq!((without.onion, without.pinggy.is_some()), (None, true));
    let record = read_back(&node, &packet).unwrap();
    assert_eq!((record.quick, record.pinggy), (Some(quick), roads.pinggy.clone()));
    assert!(packet.encoded_packet().len() <= MAX_DNS_PACKET, "{}", packet.encoded_packet().len());
    // One byte more is never put: a client would set it aside.
    let longer = format!("{}.{}.{}", "e".repeat(63), "f".repeat(63), "g".repeat(rest + 1));
    let over = Roads { pinggy: Some(pinggy(&longer)), ..Roads::default() };
    let why = super::packet(&node, &over, TTL).unwrap_err();
    assert!(why.contains("Pinggy") && why.contains(&MAX_PINGGY.to_string()), "{why}");
}

/// The tunnel of HTTP made by `ssh -R` (T-565): its name comes back as the
/// node put it, in lower case; a value that is no DNS name, or too long, is
/// set aside unsaid, a second one too, and a node never puts one.
#[test]
fn a_record_of_a_tunnel_of_ssh_r_names_it_and_sets_a_bad_name_aside() {
    let node = SecretKey::from_bytes(&[0x47; 32]);
    let roads = Roads { tunnel: Some("a1b2c3d4e5f6.lhr.life".into()), ..Roads::default() };
    assert!(!roads.is_empty() && roads.said().contains("the tunnel a1b2c3d4e5f6.lhr.life"), "{}", roads.said());
    let record = read_back(&node, &packet(&node, &roads, TTL).unwrap()).expect("a record of one road");
    assert_eq!((record.tunnel.as_deref(), record.quick, record.pinggy), (Some("a1b2c3d4e5f6.lhr.life"), None, None));
    let quick = format!("quick={QUICK}");
    let long = format!("tunnel={}.lhr.life", "a".repeat(MAX_TUNNEL));
    for bad in ["tunnel=192.0.2.1", "tunnel=SECRET/path", long.as_str()] {
        let record = read_back(&node, &planted(&node, &[bad, quick.as_str()])).unwrap();
        assert_eq!((record.tunnel, record.quick.as_deref()), (None, Some(QUICK)), "{bad}");
        assert!(record.set_aside.iter().all(|why| !why.contains("SECRET")), "{:?}", record.set_aside);
    }
    let two = read_back(&node, &planted(&node, &["tunnel=One.lhr.life.", "tunnel=two.lhr.life"])).unwrap();
    assert_eq!(two.tunnel.as_deref(), Some("one.lhr.life"));
    assert!(two.set_aside.iter().any(|why| why.contains("a second tunnel=")), "{:?}", two.set_aside);
    let bad = Roads { tunnel: Some("not a name".into()), ..Roads::default() };
    assert!(packet(&node, &bad, TTL).is_err(), "a node never puts what a client would set aside");
}

/// An address of Tor's version 3 (the Tor Project's own), and its siblings.
const ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

/// The onion service (T-578): its address comes back as the node put it, in
/// lower case; one that is not of version 3, a name under it, or a second
/// one is set aside unsaid, and a node never puts one.
#[test]
fn a_record_of_an_onion_service_names_it_and_sets_a_bad_address_aside() {
    let node = SecretKey::from_bytes(&[0x4a; 32]);
    let roads = Roads { onion: Some(ONION.to_ascii_uppercase()), ..Roads::default() };
    assert!(!roads.is_empty() && roads.said().contains("the onion service"), "{}", roads.said());
    let record = read_back(&node, &packet(&node, &roads, TTL).unwrap()).expect("a record of one road");
    assert_eq!((record.onion.as_deref(), record.tunnel), (Some(ONION), None));
    let quick = format!("quick={QUICK}");
    let version2 = "onion=expyuzz4wqqyqhjn.onion".to_string();
    let not_3 = format!("onion={}a.onion", &ONION[..55]);
    let under = format!("onion=SECRET.{ONION}");
    let alphabet = format!("onion={}1d.onion", &ONION[..54]);
    for bad in [version2.as_str(), not_3.as_str(), under.as_str(), alphabet.as_str(), "onion=example.com"] {
        let record = read_back(&node, &planted(&node, &[bad, quick.as_str()])).unwrap();
        assert_eq!((record.onion, record.quick.as_deref()), (None, Some(QUICK)), "{bad}");
        assert!(record.set_aside.iter().all(|why| !why.contains("SECRET")), "{:?}", record.set_aside);
    }
    let first = format!("onion={ONION}.");
    let two = read_back(&node, &planted(&node, &[first.as_str(), "onion=x.onion"])).unwrap();
    assert_eq!(two.onion.as_deref(), Some(ONION));
    assert!(two.set_aside.iter().any(|why| why.contains("a second onion=")), "{:?}", two.set_aside);
    // A node's roads of today with its onion service fit pkarr's bytes.
    let each = Roads { onion: Some(ONION.into()), ..each_road(&node) };
    let whole = packet(&node, &each, TTL).expect("each road and the onion service fit");
    assert!(whole.encoded_packet().len() <= MAX_DNS_PACKET, "{}", whole.encoded_packet().len());
    assert_eq!(read_back(&node, &whole).unwrap().onion.as_deref(), Some(ONION));
    let bad = Roads { onion: Some("www.torproject.org".into()), ..Roads::default() };
    assert!(packet(&node, &bad, TTL).is_err(), "a node never puts what a client would set aside");
}
