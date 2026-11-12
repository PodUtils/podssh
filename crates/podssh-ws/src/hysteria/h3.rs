//! The little of HTTP/3 (RFC 9114) and QPACK (RFC 9204) that Hysteria 2's
//! authentication takes: QUIC's variable-length integers, the frames of a
//! stream, the client's SETTINGS, the request `POST /auth` with QPACK's
//! static table alone, and the status of its answer. The server's encoder
//! (quic-go's `qpack`) writes each literal in HPACK's Huffman code, and the
//! only value read here is the status, three digits: the decoder knows the
//! codes of the ten digits and nothing else. podssh offers no dynamic table
//! (its SETTINGS say none), so a reference to one is a broken answer.

use std::io;

/// The frame types (RFC 9114, section 7.2).
pub const DATA: u64 = 0x00;
pub const HEADERS: u64 = 0x01;
pub const SETTINGS: u64 = 0x04;
/// The type of a control stream (RFC 9114, section 6.2.1).
pub const CONTROL_STREAM: u64 = 0x00;
/// The most bytes of the answer's HEADERS frame that podssh reads: its
/// padding is 2 KiB at most (`core/internal/protocol/padding.go`).
pub const MOST_HEADERS: u64 = 64 * 1024;

/// QUIC's variable-length integer (RFC 9000, section 16), appended.
pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=0x3f => out.push(v as u8),
        0x40..=0x3fff => out.extend_from_slice(&(0x4000 | v as u16).to_be_bytes()),
        0x4000..=0x3fff_ffff => out.extend_from_slice(&(0x8000_0000 | v as u32).to_be_bytes()),
        _ => out.extend_from_slice(&(0xc000_0000_0000_0000 | v).to_be_bytes()),
    }
}

/// The length of a variable-length integer from its first byte.
pub fn varint_len(first: u8) -> usize {
    1 << (first >> 6)
}

/// A whole variable-length integer from `bytes` (its length is
/// [`varint_len`] of its first byte).
pub fn varint(bytes: &[u8]) -> u64 {
    bytes.iter().enumerate().fold(0, |v, (i, b)| (v << 8) | u64::from(if i == 0 { b & 0x3f } else { *b }))
}

/// A frame: its type, its length and its payload.
pub fn frame(kind: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 16);
    put_varint(&mut out, kind);
    put_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

/// The client's control stream as it opens: its type, then SETTINGS with no
/// setting, so each default holds (no dynamic table of QPACK).
pub fn control_stream() -> Vec<u8> {
    let mut out = Vec::new();
    put_varint(&mut out, CONTROL_STREAM);
    out.extend_from_slice(&frame(SETTINGS, &[]));
    out
}

/// An integer of QPACK with an `n`-bit prefix (RFC 7541, section 5.1), its
/// first byte's high bits `flags`. Public for WARP's connect-ip over HTTP/3
/// (podssh-warp's `h3`), which encodes its request with the same code.
pub fn put_int(out: &mut Vec<u8>, n: u8, flags: u8, v: usize) {
    let max = (1usize << n) - 1;
    if v < max {
        out.push(flags | v as u8);
        return;
    }
    out.push(flags | max as u8);
    let mut rest = v - max;
    while rest >= 0x80 {
        out.push((rest & 0x7f) as u8 | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// A string literal of QPACK, not Huffman-coded: a 7-bit length.
pub fn put_literal(out: &mut Vec<u8>, text: &[u8]) {
    put_int(out, 7, 0x00, text.len());
    out.extend_from_slice(text);
}

/// The field section of `POST /auth` as Hysteria's client sends it
/// (`core/internal/protocol/http.go`): the authority `hysteria`, then the
/// credential, the client's rate (0: podssh does not know it, so the server
/// uses its own congestion control) and a padding. Names in lower case, as
/// HTTP/3 asks.
pub fn auth_request(auth: &str, padding: &str) -> Vec<u8> {
    // The prefix: no insert count, base 0 (no dynamic table).
    let mut out = vec![0x00, 0x00];
    // Indexed, static: 20 is `:method POST`, 23 `:scheme https`.
    out.extend_from_slice(&[0xc0 | 20, 0xc0 | 23]);
    // A literal value with a static name: 0 is `:authority`, 1 `:path`.
    out.push(0x50);
    put_literal(&mut out, b"hysteria");
    out.push(0x51);
    put_literal(&mut out, b"/auth");
    for (name, value) in [("hysteria-auth", auth), ("hysteria-cc-rx", "0"), ("hysteria-padding", padding)] {
        // A literal name, not Huffman-coded: 001N H and a 3-bit length.
        put_int(&mut out, 3, 0x20, name.len());
        out.extend_from_slice(name.as_bytes());
        put_literal(&mut out, value.as_bytes());
    }
    out
}

/// The statuses of QPACK's static table (RFC 9204, appendix A) by index.
fn static_status(index: usize) -> Option<u16> {
    Some(match index {
        24 => 103,
        25 => 200,
        26 => 304,
        27 => 404,
        28 => 503,
        63 => 100,
        64 => 204,
        65 => 206,
        66 => 302,
        67 => 400,
        68 => 403,
        69 => 421,
        70 => 425,
        71 => 500,
        _ => return None,
    })
}

fn broken(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("the server's HTTP/3 answer: {why}"))
}

/// A cursor over a field section.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn byte(&mut self) -> io::Result<u8> {
        let (&b, rest) = self.0.split_first().ok_or_else(|| broken("a field section cut short"))?;
        self.0 = rest;
        Ok(b)
    }

    /// An integer whose first byte, `first`, has an `n`-bit prefix.
    fn int(&mut self, first: u8, n: u8) -> io::Result<usize> {
        let max = (1usize << n) - 1;
        let mut v = usize::from(first) & max;
        if v < max {
            return Ok(v);
        }
        for shift in (0..28).step_by(7) {
            let b = self.byte()?;
            v += usize::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(broken("an integer too long"))
    }

    /// A string literal whose first byte has the Huffman flag at `h` and an
    /// `n`-bit length: its bytes, and whether they are Huffman-coded.
    fn literal(&mut self, first: u8, h: u8, n: u8) -> io::Result<(&'a [u8], bool)> {
        let len = self.int(first, n)?;
        if len > self.0.len() {
            return Err(broken("a literal past the field section"));
        }
        let (text, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok((text, first & h != 0))
    }
}

/// The status of the answer's field section.
pub fn status(section: &[u8]) -> io::Result<u16> {
    let mut c = Cursor(section);
    let insert_count = c.byte()?;
    let _base = c.byte()?;
    if insert_count != 0 {
        return Err(broken("it refers to a dynamic table, which podssh did not offer"));
    }
    while !c.0.is_empty() {
        let first = c.byte()?;
        if first & 0x80 != 0 {
            // Indexed: 1T and a 6-bit index.
            if first & 0x40 == 0 {
                return Err(broken("an indexed field of a dynamic table"));
            }
            if let Some(status) = static_status(c.int(first, 6)?) {
                return Ok(status);
            }
        } else if first & 0x40 != 0 {
            // A literal value with a name reference: 01NT and a 4-bit index.
            if first & 0x10 == 0 {
                return Err(broken("a name of a dynamic table"));
            }
            let index = c.int(first, 4)?;
            let value = c.byte()?;
            let (text, huffman) = c.literal(value, 0x80, 7)?;
            if static_status(index).is_some() {
                return digits(text, huffman);
            }
        } else if first & 0x20 != 0 {
            // A literal name and value: 001N H and a 3-bit length.
            let (name, name_huffman) = c.literal(first, 0x08, 3)?;
            let value = c.byte()?;
            let (text, huffman) = c.literal(value, 0x80, 7)?;
            if !name_huffman && name == b":status" {
                return digits(text, huffman);
            }
        } else {
            return Err(broken("a field after the base, of a dynamic table"));
        }
    }
    Err(broken("no status"))
}

/// Three digits of a status, as they are or in HPACK's Huffman code.
fn digits(text: &[u8], huffman: bool) -> io::Result<u16> {
    let text = match huffman {
        true => huffman_digits(text)?,
        false => text.to_vec(),
    };
    let text = std::str::from_utf8(&text).map_err(|_| broken("a status that is not digits"))?;
    match text.len() == 3 {
        true => text.parse().map_err(|_| broken("a status that is not digits")),
        false => Err(broken("a status that is not three digits")),
    }
}

/// HPACK's Huffman code (RFC 7541, appendix B) of digits alone: `0` to `2`
/// are the 5 bits 00000 to 00010, `3` to `9` the 6 bits 011001 to 011111,
/// and the end is padded with at most 7 bits of 1.
fn huffman_digits(code: &[u8]) -> io::Result<Vec<u8>> {
    let total = code.len() * 8;
    let bit = |at: usize| (code[at / 8] >> (7 - at % 8)) & 1;
    let bits = |at: usize, n: usize| (at..at + n).fold(0u8, |v, i| (v << 1) | bit(i));
    let (mut at, mut out) = (0, Vec::new());
    while at < total {
        let left = total - at;
        if left < 8 && bits(at, left) == (1u8 << left) - 1 {
            return Ok(out);
        }
        match (left >= 5).then(|| bits(at, 5)) {
            Some(five @ 0..=2) => {
                out.push(b'0' + five);
                at += 5;
            }
            Some(_) if left >= 6 && (0b011001..=0b011111).contains(&bits(at, 6)) => {
                out.push(b'3' + bits(at, 6) - 0b011001);
                at += 6;
            }
            _ => return Err(broken("a status whose Huffman code is not digits")),
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "h3_tests.rs"]
mod tests;
