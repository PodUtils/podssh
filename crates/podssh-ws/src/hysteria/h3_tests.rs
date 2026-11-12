use super::*;

#[test]
fn varints_take_each_length_of_rfc_9000() {
    // RFC 9000, appendix A.1: the examples of each length.
    let cases: [(u64, &[u8]); 5] = [
        (37, &[0x25]),
        (15_293, &[0x7b, 0xbd]),
        (494_878_333, &[0x9d, 0x7f, 0x3e, 0x7d]),
        (151_288_809_941_952_652, &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
        (0x401, &[0x44, 0x01]),
    ];
    for (v, bytes) in cases {
        let mut out = Vec::new();
        put_varint(&mut out, v);
        assert_eq!(out, bytes, "{v}");
        assert_eq!((varint_len(bytes[0]), varint(bytes)), (bytes.len(), v));
    }
    assert_eq!(frame(HEADERS, b"ab"), [0x01, 0x02, b'a', b'b']);
    assert_eq!(control_stream(), [0x00, 0x04, 0x00], "a control stream, then SETTINGS with none");
}

#[test]
fn the_request_names_post_auth_at_hysteria_with_static_entries_and_plain_literals() {
    let section = auth_request("pw", "xyz");
    let mut want = vec![0x00, 0x00, 0xd4, 0xd7, 0x50, 0x08];
    want.extend_from_slice(b"hysteria");
    want.extend_from_slice(&[0x51, 0x05]);
    want.extend_from_slice(b"/auth");
    // `hysteria-auth` has 13 bytes: 7 in the prefix, 6 after it.
    want.extend_from_slice(&[0x27, 0x06]);
    want.extend_from_slice(b"hysteria-auth");
    want.extend_from_slice(&[0x02, b'p', b'w']);
    assert_eq!(&section[..want.len()], &want[..]);
    assert!(section.ends_with(b"hysteria-padding\x03xyz"), "{section:?}");
    // A padding of 2 KiB takes a length past one byte.
    let long = auth_request("pw", &"a".repeat(300));
    assert!(long.windows(3).any(|w| w == [0x7f, 0xad, 0x01]), "300 is 127 and 173 with a continuation");
}

#[test]
fn huffman_digits_read_the_status_codes_that_quic_go_writes() {
    // HPACK's Huffman code of each status, made from h2's table.
    assert_eq!(huffman_digits(&[0x13, 0x2c, 0xff]).unwrap(), b"233");
    assert_eq!(huffman_digits(&[0x68, 0x0d, 0x7f]).unwrap(), b"404");
    assert_eq!(huffman_digits(&[0x10, 0x01]).unwrap(), b"200");
    // `hysteria`, and a padding of 8 bits or more, are no status.
    assert!(huffman_digits(&[0x9f, 0xd2, 0x12, 0x5b, 0x0c, 0x3f]).is_err());
    assert!(huffman_digits(&[0x13, 0x2c, 0xff, 0xff]).is_err());
}

#[test]
fn the_status_comes_from_a_static_index_or_a_literal_of_its_name() {
    // quic-go's answer to the right password: `:status 233` by the name of
    // index 24 (4-bit prefix: 15, then 9), its value in Huffman's code,
    // then a header of a literal name.
    let ok = [0x00, 0x00, 0x5f, 0x09, 0x83, 0x13, 0x2c, 0xff, 0x2a, 1, 2, 0x81, 3];
    assert_eq!(status(&ok).unwrap(), 233);
    // Its answer to a wrong one, by default: 404, indexed.
    assert_eq!(status(&[0x00, 0x00, 0xc0 | 27]).unwrap(), 404);
    // The status after another field, its value not Huffman-coded.
    let later = [0x00, 0x00, 0x2a, 1, 2, 0x81, 3, 0x5f, 0x09, 0x03, b'2', b'3', b'3'];
    assert_eq!(status(&later).unwrap(), 233);
    // Each reference to a dynamic table, and no status, are broken answers.
    let broken: [&[u8]; 5] = [&[0x01, 0x00, 0xd9], &[0x00, 0x00, 0x80], &[0x00, 0x00, 0x10], &[0x00, 0x00], &[0x00]];
    for section in broken {
        assert!(status(section).is_err(), "{section:?}");
    }
}
