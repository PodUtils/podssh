//! A KEXINIT's name-lists (RFC 4253, section 7.1), read from its payload,
//! and the host key algorithm that two of them agree on. Pure: the bytes
//! come from the handshake's record.

/// SSH_MSG_KEXINIT.
const KEXINIT: u8 = 20;
/// The message number and the cookie before the first list.
const LISTS_AT: usize = 17;
/// The most bytes of one list: OpenSSH's own whole KEXINIT is under 2 KiB.
const LIST_MAX: usize = 16 * 1024;

/// The ten name-lists of one KEXINIT, in the order of the RFC.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lists {
    pub kex: Vec<String>,
    pub host_keys: Vec<String>,
    pub ciphers_c2s: Vec<String>,
    pub ciphers_s2c: Vec<String>,
    pub macs_c2s: Vec<String>,
    pub macs_s2c: Vec<String>,
    pub compression_c2s: Vec<String>,
    pub compression_s2c: Vec<String>,
}

/// The lists of the KEXINIT `payload` (its message number first); `Err`
/// says why it does not read.
pub fn lists(payload: &[u8]) -> Result<Lists, String> {
    if payload.first() != Some(&KEXINIT) {
        return Err("the packet is no KEXINIT".into());
    }
    let mut at = LISTS_AT;
    let mut ten: Vec<Vec<String>> = Vec::with_capacity(10);
    for i in 0..10 {
        let len = payload
            .get(at..at + 4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
            .ok_or_else(|| format!("the KEXINIT ends before its list {}", i + 1))?;
        if len > LIST_MAX {
            return Err(format!("the KEXINIT's list {} has {len} bytes", i + 1));
        }
        let raw =
            payload.get(at + 4..at + 4 + len).ok_or_else(|| format!("the KEXINIT ends inside its list {}", i + 1))?;
        let text = std::str::from_utf8(raw).map_err(|_| format!("the KEXINIT's list {} is not UTF-8", i + 1))?;
        if !text.is_ascii() || text.chars().any(|c| c.is_ascii_control()) {
            return Err(format!("the KEXINIT's list {} holds a byte that no name has", i + 1));
        }
        ten.push(if text.is_empty() { Vec::new() } else { text.split(',').map(str::to_string).collect() });
        at += 4 + len;
    }
    // The first-packet-follows byte and the reserved word.
    if payload.len() < at + 5 {
        return Err("the KEXINIT ends before its last fields".into());
    }
    let mut it = ten.into_iter();
    let mut next = || it.next().unwrap_or_default();
    Ok(Lists {
        kex: next(),
        host_keys: next(),
        ciphers_c2s: next(),
        ciphers_s2c: next(),
        macs_c2s: next(),
        macs_s2c: next(),
        compression_c2s: next(),
        compression_s2c: next(),
    })
}

/// The host key algorithm that a client's list and a server's agree on:
/// the client's first that the server offers (RFC 4253, section 7.1).
pub fn agreed(client: &[String], server: &[String]) -> Option<String> {
    client.iter().find(|name| server.contains(name)).cloned()
}

const CERT: &str = "-cert-v01@openssh.com";

/// The type of the key that a host key algorithm asks for: the three
/// signatures of RSA are each a key `ssh-rsa`; a certificate's is the
/// certificate of that type; another algorithm names its own type.
pub fn key_type_of(algorithm: &str) -> String {
    let (base, cert) = match algorithm.strip_suffix(CERT) {
        Some(base) => (base, true),
        None => (algorithm, false),
    };
    let base = match base {
        "rsa-sha2-256" | "rsa-sha2-512" => "ssh-rsa",
        other => other,
    };
    if cert {
        format!("{base}{CERT}")
    } else {
        base.to_string()
    }
}
