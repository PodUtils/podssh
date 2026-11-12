use super::*;

/// RFC 9204's own example (appendix B.1): `:path /index.html` as a literal
/// with a name of the static table, index 1, encodes as 51 0b and the
/// eleven bytes of the path.
#[test]
fn a_static_name_is_written_as_rfc_9204_s_example() {
    let mut out = Vec::new();
    static_name(&mut out, 1, "/index.html");
    let mut expected = vec![0x51, 0x0b];
    expected.extend_from_slice(b"/index.html");
    assert_eq!(out, expected);
}

/// The request: the prefix, the two indexed lines of RFC 9204's static
/// table (`:method CONNECT` is 15, `:scheme https` 23), the authority and
/// path, then the protocol and capsule-protocol as literal names.
#[test]
fn the_extended_connect_names_its_protocol_and_the_capsule_protocol() {
    let section = request("proxy:443", "/vpn", CONNECT_IP);
    assert_eq!(&section[..4], &[0x00, 0x00, 0xcf, 0xd7]);
    let mut authority = vec![0x50, 0x09];
    authority.extend_from_slice(b"proxy:443");
    assert_eq!(&section[4..15], authority.as_slice());
    let mut path = vec![0x51, 0x04];
    path.extend_from_slice(b"/vpn");
    assert_eq!(&section[15..21], path.as_slice());
    // 0x27: 001, N 0, H 0, then a 3-bit length of 7 with more to come;
    // 9 - 7 = 2 follows.
    let mut protocol = vec![0x27, 0x02];
    protocol.extend_from_slice(b":protocol");
    protocol.push(0x0a);
    protocol.extend_from_slice(b"connect-ip");
    assert_eq!(&section[21..21 + protocol.len()], protocol.as_slice());
    assert!(section.ends_with(b"capsule-protocol\x02?1"));
    assert!(!section.windows(10).any(|w| w == b"user-agent"));
}

/// The control stream: type 0, then SETTINGS (type 4) of H3_DATAGRAM = 1;
/// WARP's adds the draft's 0x276, whose varint takes two bytes, 42 76
/// (RFC 9000, section 16).
#[test]
fn the_control_stream_offers_datagrams() {
    assert_eq!(control_stream(false), [0x00, 0x04, 0x02, 0x33, 0x01]);
    assert_eq!(control_stream(true), [0x00, 0x04, 0x05, 0x33, 0x01, 0x42, 0x76, 0x01]);
}

/// The server's SETTINGS as quic-go's http3 server writes them with
/// datagrams and the extended CONNECT on: QPACK's capacity 0 (0x01), then
/// 0x08 = 1, 0x33 = 1; a setting of a reserved identifier
/// (0x1f * N + 0x21, RFC 9114, section 7.2.4.1) is skipped.
#[test]
fn the_server_s_settings_are_read() {
    let peer = peer_settings(&[0x01, 0x00, 0x08, 0x01, 0x33, 0x01, 0x21, 0x05]).unwrap();
    assert_eq!(peer, Peer { datagrams: true, extended_connect: true });
    let draft = peer_settings(&[0x42, 0x76, 0x01]).unwrap();
    assert_eq!(draft, Peer { datagrams: true, extended_connect: false });
    assert_eq!(peer_settings(&[]).unwrap(), Peer::default());
    assert!(peer_settings(&[0x33]).is_err());
}

/// RFC 9297's Quarter Stream ID is the stream's ID divided by four: the
/// first request stream, 0, gives 00; stream 4 gives 01; stream 256, 64,
/// takes two bytes, 40 40. Then connect-ip-go's `contextIDZero`, 00.
#[test]
fn a_datagram_carries_the_quarter_stream_id_and_context_zero() {
    let packet = [0x45, 0x00, 0x00, 0x14];
    assert_eq!(datagram(0, &packet), [0x00, 0x00, 0x45, 0x00, 0x00, 0x14]);
    assert_eq!(datagram(4, &packet)[..2], [0x01, 0x00]);
    assert_eq!(datagram(256, &packet)[..3], [0x40, 0x40, 0x00]);
    assert_eq!((overhead(0), overhead(256)), (2, 3));
    assert_eq!(packet_of(0, &datagram(0, &packet)), Ok(Some(&packet[..])));
    assert_eq!(packet_of(256, &datagram(256, &packet)), Ok(Some(&packet[..])));
}

/// A datagram of another request, or of another context, is dropped; one
/// cut short is an error.
#[test]
fn another_stream_or_context_is_dropped() {
    assert_eq!(packet_of(4, &[0x00, 0x00, 0x45]), Ok(None));
    assert_eq!(packet_of(0, &[0x00, 0x02, 0x45]), Ok(None));
    assert!(packet_of(0, &[]).is_err());
    assert!(packet_of(0, &[0x00]).is_err());
}

/// connect-ip-go's `TestParseAddressAssignCapsule`: Request ID 1337 with
/// 1.2.3.0/24, and 1338 with 2001:db8::1/128.
#[test]
fn an_address_assign_reads_as_connect_ip_go_writes_it() {
    let mut payload = Vec::new();
    put_varint(&mut payload, 1337);
    payload.extend_from_slice(&[4, 1, 2, 3, 0, 24]);
    put_varint(&mut payload, 1338);
    payload.push(6);
    payload.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
    payload.push(128);
    assert_eq!(&payload[..2], &[0x45, 0x39]);
    let got = assigned(&payload).unwrap();
    let v4: IpAddr = "1.2.3.0".parse().unwrap();
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    assert_eq!(got, vec![(v4, 24), (v6, 128)]);
    assert_eq!(stack_addresses(&got), vec![v4, v6]);
}

/// connect-ip-go's invalid cases: the IP Version 5, and a prefix of 33 bits
/// for IPv4; and a payload cut in its address.
#[test]
fn a_broken_address_assign_is_refused() {
    let five = assigned(&[0x45, 0x39, 5, 1, 2, 3, 4, 32]).unwrap_err();
    assert!(five.contains("IP Version 5"), "{five}");
    let long = assigned(&[0x45, 0x39, 4, 1, 2, 3, 4, 33]).unwrap_err();
    assert!(long.contains("33 bits"), "{long}");
    assert!(assigned(&[0x45, 0x39, 4, 1, 2]).is_err());
}
