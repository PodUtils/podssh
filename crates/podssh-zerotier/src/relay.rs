//! The framing of ZeroTier's TCP relay, written from `tcp-proxy/tcp-proxy.cpp`
//! and `service/OneService.cpp` of ZeroTierOne (MPL-2.0): records that look
//! like TLS application data (`0x17 0x03 0x03` and a length of 16 bits) on
//! one TCP stream. The client's first record is its HELLO, 4 bytes of its
//! version, which asks for the form where each later record names its
//! address: `4`, the IPv4 address and the port, then the datagram. The relay
//! sends a datagram to a port above 1024 alone, and of 16 bytes or more,
//! else it drops it with no word, so the encoder refuses those itself. A
//! record is at most 65,535 bytes, and the relay keeps 131,072 of them.

use std::net::{Ipv4Addr, SocketAddrV4};

/// The record's header: TLS application data, TLS 1.2.
const HEADER: [u8; 3] = [0x17, 0x03, 0x03];
/// The least datagram that the relay sends.
pub const LEAST: usize = 16;
/// The greatest datagram that the relay takes from UDP (`len < 2048`).
pub const MOST: usize = 2047;

/// The first record of a client: its HELLO with the core's version.
pub fn hello(version: (i32, i32, i32)) -> Vec<u8> {
    let (major, minor, revision) = version;
    let mut out = HEADER.to_vec();
    out.extend_from_slice(&[0, 4, major as u8, minor as u8]);
    out.extend_from_slice(&(revision as u16).to_be_bytes());
    out
}

/// The record that sends `datagram` to `to`; why not, where the relay
/// would drop it.
pub fn encode(to: SocketAddrV4, datagram: &[u8]) -> Result<Vec<u8>, String> {
    if to.port() <= 1024 {
        return Err(format!("the relay sends to a port above 1024 alone, not {}", to.port()));
    }
    if !(LEAST..=MOST).contains(&datagram.len()) {
        return Err(format!("the relay carries {LEAST} to {MOST} bytes, not {}", datagram.len()));
    }
    let len = (7 + datagram.len()) as u16;
    let mut out = Vec::with_capacity(5 + len as usize);
    out.extend_from_slice(&HEADER);
    out.extend_from_slice(&len.to_be_bytes());
    out.push(4);
    out.extend_from_slice(&to.ip().octets());
    out.extend_from_slice(&to.port().to_be_bytes());
    out.extend_from_slice(datagram);
    Ok(out)
}

/// The records of the relay's stream, as they come.
#[derive(Debug, Default)]
pub struct Records {
    pending: Vec<u8>,
}

impl Records {
    /// Each datagram that `bytes` ends, and where it came from; a record of
    /// another form is passed over, as the relay passes over one.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<(SocketAddrV4, Vec<u8>)> {
        self.pending.extend_from_slice(bytes);
        let mut out = Vec::new();
        while self.pending.len() >= 5 {
            let len = u16::from_be_bytes([self.pending[3], self.pending[4]]) as usize;
            if self.pending.len() < 5 + len {
                break;
            }
            let record: Vec<u8> = self.pending.drain(..5 + len).skip(5).collect();
            if record.len() >= 7 && record[0] == 4 {
                let ip = Ipv4Addr::new(record[1], record[2], record[3], record[4]);
                let port = u16::from_be_bytes([record[5], record[6]]);
                out.push((SocketAddrV4::new(ip, port), record[7..].to_vec()));
            }
        }
        out
    }
}

/// Carry a member's wire on `stream`, the relay's TCP connection: the HELLO,
/// then each datagram to an IPv4 address that the relay sends (another is
/// dropped, as a wire may drop it); what comes back goes to the member. The
/// wire's ends close with the stream.
pub fn carry<S>(stream: S, version: (i32, i32, i32)) -> crate::member::Wire
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (to_member, inbound) = tokio::sync::mpsc::channel(1024);
    let (out, mut from_member) = tokio::sync::mpsc::channel::<crate::member::Datagram>(1024);
    let (mut read, mut write) = tokio::io::split(stream);
    tokio::spawn(async move {
        if write.write_all(&hello(version)).await.is_err() {
            return;
        }
        while let Some((to, datagram)) = from_member.recv().await {
            let std::net::SocketAddr::V4(to) = to else { continue };
            let Ok(record) = encode(to, &datagram) else { continue };
            if write.write_all(&record).await.is_err() {
                return;
            }
        }
    });
    tokio::spawn(async move {
        let (mut records, mut buf) = (Records::default(), vec![0u8; 65536]);
        while let Ok(n) = read.read(&mut buf).await {
            if n == 0 {
                return;
            }
            for (from, datagram) in records.push(&buf[..n]) {
                if to_member.send((std::net::SocketAddr::V4(from), datagram)).await.is_err() {
                    return;
                }
            }
        }
    });
    crate::member::Wire { out, inbound }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hello_is_the_service_s_and_a_record_goes_both_ways() {
        assert_eq!(hello((1, 16, 0x0102)), [0x17, 3, 3, 0, 4, 1, 16, 1, 2]);
        let to: SocketAddrV4 = "198.51.100.7:9993".parse().unwrap();
        let datagram = [7u8; 40];
        let record = encode(to, &datagram).unwrap();
        assert_eq!(&record[..10], &[0x17, 3, 3, 0, 47, 4, 198, 51, 100, 7]);
        let mut records = Records::default();
        // In pieces of one byte, as TCP may give them.
        let mut got = Vec::new();
        for byte in &record {
            got.extend(records.push(&[*byte]));
        }
        assert_eq!(got, [(to, datagram.to_vec())]);
    }

    #[test]
    fn a_datagram_that_the_relay_drops_is_refused_here() {
        let low: SocketAddrV4 = "198.51.100.7:1024".parse().unwrap();
        assert!(encode(low, &[0u8; 40]).unwrap_err().contains("above 1024"));
        let to: SocketAddrV4 = "198.51.100.7:9993".parse().unwrap();
        assert!(encode(to, &[0u8; 15]).unwrap_err().contains("16 to 2047"));
        assert!(encode(to, &[0u8; 2048]).is_err());
        // A record of the old form, or a HELLO, carries no datagram.
        assert!(Records::default().push(&hello((1, 16, 0))).is_empty());
    }

    /// The carrier on a stream of memory: its HELLO first, a datagram's
    /// record, an IPv6 one passed over; a record that comes back reaches
    /// the member.
    #[tokio::test]
    async fn the_carrier_writes_the_hello_and_each_record_and_reads_what_comes_back() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (ours, mut theirs) = tokio::io::duplex(65536);
        let mut wire = carry(ours, (1, 16, 2));
        let to: SocketAddrV4 = "198.51.100.7:9993".parse().unwrap();
        wire.out.send(("[2001:db8::1]:9993".parse().unwrap(), vec![1u8; 20])).await.unwrap();
        wire.out.send((to.into(), vec![2u8; 20])).await.unwrap();
        let mut head = vec![0u8; 9 + 5 + 7 + 20];
        theirs.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..9], hello((1, 16, 2)).as_slice());
        assert_eq!(&head[9..], encode(to, &[2u8; 20]).unwrap().as_slice(), "the IPv6 one passed over");
        theirs.write_all(&encode(to, &[3u8; 30]).unwrap()).await.unwrap();
        assert_eq!(wire.inbound.recv().await, Some((to.into(), vec![3u8; 30])));
    }
}
