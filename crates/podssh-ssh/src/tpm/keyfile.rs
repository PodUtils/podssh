//! The key file of a TPM key: `TSS2 PRIVATE KEY` (James Bottomley's
//! draft-bottomley-tpm2-keys, which openssl_tpm2_engine, tpm2-openssl,
//! ssh-tpm-agent and the kernel's trusted keys read). DER inside PEM:
//!
//! ```text
//! TPMKey ::= SEQUENCE {
//!   type        OBJECT IDENTIFIER,          -- id-loadablekey 2.23.133.10.1.3
//!   emptyAuth   [0] EXPLICIT BOOLEAN OPTIONAL,
//!   policy      [1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL,
//!   secret      [2] EXPLICIT OCTET STRING OPTIONAL,
//!   authPolicy  [3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL,
//!   description [4] EXPLICIT UTF8String OPTIONAL,
//!   rsaParent   [5] EXPLICIT BOOLEAN OPTIONAL,
//!   parent      INTEGER,
//!   pubkey      OCTET STRING,               -- TPM2B_PUBLIC
//!   privkey     OCTET STRING }              -- TPM2B_PRIVATE
//! TPMPolicy ::= SEQUENCE { commandCode [0] EXPLICIT INTEGER,
//!                          commandPolicy [1] EXPLICIT OCTET STRING }
//! TPMAuthPolicy ::= SEQUENCE { name [0] EXPLICIT UTF8String OPTIONAL,
//!                              policy [1] EXPLICIT SEQUENCE OF TPMPolicy }
//! ```
//!
//! The private part is the TPM's, wrapped under a key that never leaves
//! the TPM: a copy of the file is useless in another TPM.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// id-loadablekey, and the older OID that early files carry.
const OID_LOADABLE: &[u8] = &[0x67, 0x81, 0x05, 0x0A, 0x01, 0x03];
const OID_LOADABLE_OLD: &[u8] = &[0x67, 0x81, 0x05, 0x0A, 0x02];
const BEGIN: &str = "-----BEGIN TSS2 PRIVATE KEY-----";
const END: &str = "-----END TSS2 PRIVATE KEY-----";
/// A key file is a few hundred bytes; more is no key file of a TPM.
pub const MAX_FILE: usize = 64 * 1024;

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const BOOLEAN: u8 = 0x01;
const OCTETS: u8 = 0x04;
const OID: u8 = 0x06;
const UTF8: u8 = 0x0C;
/// `[n] EXPLICIT`: context-specific and constructed.
const fn explicit(n: u8) -> u8 {
    0xA0 | n
}

/// A loadable key of a TPM, as its file holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFile {
    /// The key needs no authorization value.
    pub empty_auth: bool,
    /// The policy commands, in their order: each command's code and body.
    pub policy: Vec<(u32, Vec<u8>)>,
    /// The signed policies (`authPolicy`), the newest first: each a list of
    /// policy commands that ends with a signed `TPM2_PolicyAuthorize`
    /// (T-839, the offline update).
    pub auth_policies: Vec<AuthPolicy>,
    /// The file names an RSA parent, which podssh does not make.
    pub rsa_parent: bool,
    pub description: Option<String>,
    /// The parent's handle: 0x40000001 for the owner's primary key that
    /// the file's reader makes again from the standard template.
    pub parent: u32,
    /// TPM2B_PUBLIC, its length included.
    pub public: Vec<u8>,
    /// TPM2B_PRIVATE, its length included.
    pub private: Vec<u8>,
}

/// One signed policy of a key file: a name to show, and its commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPolicy {
    pub name: Option<String>,
    pub policy: Vec<(u32, Vec<u8>)>,
}

impl KeyFile {
    /// The PEM text of the file.
    pub fn to_pem(&self) -> String {
        let der = self.to_der();
        let text = STANDARD.encode(der);
        let mut out = String::with_capacity(text.len() + 80);
        out.push_str(BEGIN);
        out.push('\n');
        for line in text.as_bytes().chunks(64) {
            out.push_str(&String::from_utf8_lossy(line));
            out.push('\n');
        }
        out.push_str(END);
        out.push('\n');
        out
    }

    /// The key of a PEM text.
    pub fn from_pem(text: &str) -> Result<KeyFile, String> {
        let start = text.find(BEGIN).ok_or("no line -----BEGIN TSS2 PRIVATE KEY-----: not a key file of a TPM")?;
        let body = &text[start + BEGIN.len()..];
        let end = body.find(END).ok_or("the key file of a TPM has no line -----END TSS2 PRIVATE KEY-----")?;
        let b64: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
        let der = STANDARD.decode(b64).map_err(|e| format!("the key file of a TPM is no base64: {e}"))?;
        KeyFile::from_der(&der)
    }

    /// The DER of the file, in DER's one form.
    pub fn to_der(&self) -> Vec<u8> {
        let mut body = tlv(OID, OID_LOADABLE);
        if self.empty_auth {
            body.extend(tlv(explicit(0), &tlv(BOOLEAN, &[0xFF])));
        }
        if !self.policy.is_empty() {
            body.extend(tlv(explicit(1), &write_policies(&self.policy)));
        }
        if !self.auth_policies.is_empty() {
            let mut list = Vec::new();
            for signed in &self.auth_policies {
                let mut one = Vec::new();
                if let Some(name) = &signed.name {
                    one.extend(tlv(explicit(0), &tlv(UTF8, name.as_bytes())));
                }
                one.extend(tlv(explicit(1), &write_policies(&signed.policy)));
                list.extend(tlv(SEQUENCE, &one));
            }
            body.extend(tlv(explicit(3), &tlv(SEQUENCE, &list)));
        }
        if let Some(text) = &self.description {
            body.extend(tlv(explicit(4), &tlv(UTF8, text.as_bytes())));
        }
        body.extend(integer(self.parent));
        body.extend(tlv(OCTETS, &self.public));
        body.extend(tlv(OCTETS, &self.private));
        tlv(SEQUENCE, &body)
    }

    /// The key of a DER text. Each field the draft names is read; an
    /// unknown optional field after them is passed over, as the draft lets
    /// later versions add them.
    pub fn from_der(der: &[u8]) -> Result<KeyFile, String> {
        let bad = |why: &str| format!("the key file of a TPM is malformed: {why}");
        let (outer, rest) = element(der, SEQUENCE).ok_or_else(|| bad("no SEQUENCE"))?;
        if !rest.is_empty() {
            return Err(bad("bytes after its SEQUENCE"));
        }
        let (oid, mut rest) = element(outer, OID).ok_or_else(|| bad("no type"))?;
        if oid != OID_LOADABLE && oid != OID_LOADABLE_OLD {
            return Err("the key file of a TPM is not a loadable key (an importable or a sealed object)".into());
        }
        let mut file = KeyFile {
            empty_auth: false,
            policy: Vec::new(),
            auth_policies: Vec::new(),
            rsa_parent: false,
            description: None,
            parent: 0,
            public: Vec::new(),
            private: Vec::new(),
        };
        while let Some(&tag) = rest.first() {
            if tag & 0xE0 != 0xA0 {
                break;
            }
            let (inner, after) = element(rest, tag).ok_or_else(|| bad("a field cut short"))?;
            rest = after;
            match tag & 0x1F {
                0 => file.empty_auth = boolean(inner).ok_or_else(|| bad("emptyAuth"))?,
                1 => file.policy = policies(inner).ok_or_else(|| bad("policy"))?,
                2 => return Err("the key file of a TPM is an importable key (it has a secret)".into()),
                3 => file.auth_policies = auth_policies(inner).ok_or_else(|| bad("authPolicy"))?,
                4 => {
                    let (text, _) = element(inner, UTF8).ok_or_else(|| bad("description"))?;
                    file.description = Some(String::from_utf8(text.to_vec()).map_err(|_| bad("description"))?);
                }
                5 => file.rsa_parent = boolean(inner).ok_or_else(|| bad("rsaParent"))?,
                _ => {}
            }
        }
        let (parent, rest) = element(rest, INTEGER).ok_or_else(|| bad("no parent"))?;
        file.parent = unsigned(parent).ok_or_else(|| bad("parent"))?;
        let (public, rest) = element(rest, OCTETS).ok_or_else(|| bad("no pubkey"))?;
        let (private, rest) = element(rest, OCTETS).ok_or_else(|| bad("no privkey"))?;
        if !rest.is_empty() {
            return Err(bad("bytes after privkey"));
        }
        file.public = public.to_vec();
        file.private = private.to_vec();
        Ok(file)
    }
}

/// Whether `text` begins as a key file of a TPM, past blank lines.
pub fn is_pem(text: &[u8]) -> bool {
    let start = text.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(text.len());
    text[start..].starts_with(BEGIN.as_bytes())
}

/// One element of DER: tag, length (short or long form, at most four
/// bytes), contents.
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = contents.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes = (n as u32).to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(contents);
    out
}

/// A non-negative INTEGER, in its fewest bytes.
fn integer(n: u32) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count().min(3);
    let mut contents = Vec::with_capacity(5);
    if bytes[skip] & 0x80 != 0 {
        contents.push(0);
    }
    contents.extend_from_slice(&bytes[skip..]);
    tlv(INTEGER, &contents)
}

/// The element of `tag` at the start of `input`, and what follows it.
fn element(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&found, rest) = input.split_first()?;
    if found != tag {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let length = rest[..count].iter().fold(0usize, |n, b| n << 8 | usize::from(*b));
        (length, &rest[count..])
    };
    (rest.len() >= length).then(|| rest.split_at(length))
}

fn boolean(inner: &[u8]) -> Option<bool> {
    let (value, rest) = element(inner, BOOLEAN)?;
    (value.len() == 1 && rest.is_empty()).then(|| value[0] != 0)
}

/// The value of a non-negative INTEGER that fits 32 bits.
fn unsigned(contents: &[u8]) -> Option<u32> {
    let (first, _) = contents.split_first()?;
    if first & 0x80 != 0 {
        return None;
    }
    let digits = match contents {
        [0, rest @ ..] if !rest.is_empty() => rest,
        _ => contents,
    };
    if digits.len() > 4 {
        return None;
    }
    Some(digits.iter().fold(0u32, |n, b| n << 8 | u32::from(*b)))
}

/// A SEQUENCE OF TPMPolicy.
fn write_policies(steps: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut list = Vec::new();
    for (code, command) in steps {
        let mut step = tlv(explicit(0), &integer(*code));
        step.extend(tlv(explicit(1), &tlv(OCTETS, command)));
        list.extend(tlv(SEQUENCE, &step));
    }
    tlv(SEQUENCE, &list)
}

/// `[3] EXPLICIT SEQUENCE OF TPMAuthPolicy`'s contents; a signed policy
/// with no command is malformed, as go-tpm-keyfiles reads it.
fn auth_policies(inner: &[u8]) -> Option<Vec<AuthPolicy>> {
    let (mut list, rest) = element(inner, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    while !list.is_empty() {
        let (mut one, after) = element(list, SEQUENCE)?;
        list = after;
        let mut name = None;
        if let Some((named, after)) = element(one, explicit(0)) {
            let (text, _) = element(named, UTF8)?;
            name = Some(String::from_utf8(text.to_vec()).ok()?);
            one = after;
        }
        let (steps, after) = element(one, explicit(1))?;
        let policy = policies(steps)?;
        if policy.is_empty() || !after.is_empty() {
            return None;
        }
        out.push(AuthPolicy { name, policy });
    }
    Some(out)
}

/// `[1] EXPLICIT SEQUENCE OF TPMPolicy`'s contents.
fn policies(inner: &[u8]) -> Option<Vec<(u32, Vec<u8>)>> {
    let (mut list, rest) = element(inner, SEQUENCE)?;
    if !rest.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    while !list.is_empty() {
        let (step, after) = element(list, SEQUENCE)?;
        list = after;
        let (code, step) = element(step, explicit(0))?;
        let (code, _) = element(code, INTEGER)?;
        let (body, _) = element(step, explicit(1))?;
        let (body, _) = element(body, OCTETS)?;
        out.push((unsigned(code)?, body.to_vec()));
    }
    Some(out)
}
