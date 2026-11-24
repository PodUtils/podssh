//! The marshalling of TPM 2.0 (TCG TPM 2.0 Library, parts 1 to 3): integers
//! big-endian, sized buffers (TPM2B) with a length of two bytes, and the
//! frame of a command and of its response. Bytes in, bytes out: nothing
//! here talks to a device, so each rule is tested on byte vectors.

use super::rc;

/// A command or a response with no authorization area.
pub(super) const ST_NO_SESSIONS: u16 = 0x8001;
/// A command or a response with one.
pub(super) const ST_SESSIONS: u16 = 0x8002;
/// The password session: an authorization by a value, here the empty one.
pub(super) const RS_PW: u32 = 0x4000_0009;
/// The owner's hierarchy, the parent of podssh's keys.
pub(super) const RH_OWNER: u32 = 0x4000_0001;
/// The handle of nothing.
pub(super) const RH_NULL: u32 = 0x4000_0007;
/// The header of each command and response: a tag, a size, a code.
pub(super) const HEADER: usize = 10;
/// The most bytes of a message that podssh sends or takes: a TPM's
/// `TPM_PT_MAX_COMMAND_SIZE` and `..._RESPONSE_SIZE` are 4096 on each TPM
/// seen, and podssh takes twice that; a larger answer is no TPM's.
pub(super) const MAX_MESSAGE: usize = 8192;

/// A buffer that a command's fields are written to. A sized buffer longer
/// than its length field can say marks the whole as unusable, where a
/// truncated length would send another command than the one meant.
#[derive(Default)]
pub(super) struct Out {
    bytes: Vec<u8>,
    too_long: bool,
}

impl Out {
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes.push(v);
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(b);
        self
    }

    /// A TPM2B: the length in two bytes, then the bytes.
    pub fn sized(&mut self, b: &[u8]) -> &mut Self {
        match u16::try_from(b.len()) {
            Ok(n) => {
                self.u16(n);
                self.raw(b)
            }
            Err(_) => {
                self.too_long = true;
                self
            }
        }
    }

    /// The bytes, or why there are none.
    pub fn finish(self) -> Result<Vec<u8>, String> {
        if self.too_long {
            return Err("a field of the command is longer than a TPM takes".into());
        }
        Ok(self.bytes)
    }
}

/// One entry of a command's authorization area.
pub(super) struct Session<'a> {
    pub handle: u32,
    pub nonce: &'a [u8],
    /// `continueSession` (bit 0) and the rest of TPMA_SESSION.
    pub attributes: u8,
    pub hmac: &'a [u8],
}

/// The password session with the empty value, which the owner's hierarchy
/// and podssh's PCR reads take when nobody set a password.
pub(super) const EMPTY_PASSWORD: Session<'static> = Session { handle: RS_PW, nonce: &[], attributes: 0, hmac: &[] };

/// A command: its header, its handles, its authorization area when it has
/// sessions, and its parameters.
pub(super) fn command(code: u32, handles: &[u32], sessions: &[Session], params: &[u8]) -> Result<Vec<u8>, String> {
    let mut auth = Out::default();
    for s in sessions {
        auth.u32(s.handle).sized(s.nonce).u8(s.attributes).sized(s.hmac);
    }
    let auth = auth.finish()?;
    let mut body = Out::default();
    for h in handles {
        body.u32(*h);
    }
    if !sessions.is_empty() {
        let size = u32::try_from(auth.len()).map_err(|_| "the authorization area is too long".to_string())?;
        body.u32(size).raw(&auth);
    }
    body.raw(params);
    let body = body.finish()?;
    let size = HEADER + body.len();
    if size > MAX_MESSAGE {
        return Err(format!("a command of {size} bytes is longer than a TPM takes"));
    }
    let tag = if sessions.is_empty() { ST_NO_SESSIONS } else { ST_SESSIONS };
    let mut out = Out::default();
    out.u16(tag).u32(size as u32).u32(code).raw(&body);
    out.finish()
}

/// Why a command did not give what it should.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Fault {
    /// The TPM answered with this response code.
    Tpm(u32),
    /// The bytes are no answer of a TPM 2.0 to this command.
    Malformed(String),
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fault::Tpm(code) => f.write_str(&rc::describe(*code)),
            Fault::Malformed(why) => write!(f, "the TPM's answer cannot be read: {why}"),
        }
    }
}

/// A response that succeeded: its handles, then its parameters.
pub(super) struct Response<'a> {
    pub handles: Vec<u32>,
    pub params: In<'a>,
}

/// Read a response that carries `handles` handles. Its size must be the
/// bytes that came, and a code other than success is a [`Fault::Tpm`].
pub(super) fn response(bytes: &[u8], handles: usize) -> Result<Response<'_>, Fault> {
    let mut input = In::new(bytes);
    let bad = |why: String| Fault::Malformed(why);
    let tag = input.u16().map_err(bad)?;
    let size = input.u32().map_err(bad)? as usize;
    let code = input.u32().map_err(bad)?;
    if tag != ST_NO_SESSIONS && tag != ST_SESSIONS {
        return Err(bad(format!("its tag is {tag:#06x}, which no TPM 2.0 gives (a TPM 1.2 gives 0x00c4)")));
    }
    if size != bytes.len() {
        return Err(bad(format!("it says {size} bytes, and {} came", bytes.len())));
    }
    if code != 0 {
        return Err(Fault::Tpm(code));
    }
    let mut out = Vec::with_capacity(handles);
    for _ in 0..handles {
        out.push(input.u32().map_err(bad)?);
    }
    if tag == ST_SESSIONS {
        // The parameters have their own size; the authorization area that
        // follows them is the TPM's and is not read.
        let length = input.u32().map_err(bad)? as usize;
        let params = input.take(length).map_err(bad)?;
        return Ok(Response { handles: out, params: In::new(params) });
    }
    Ok(Response { handles: out, params: input })
}

/// A reader of marshalled fields: each read past the end is an error.
#[derive(Clone)]
pub(super) struct In<'a> {
    rest: &'a [u8],
}

impl<'a> In<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        In { rest: bytes }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.rest.len() < n {
            return Err(format!("{n} bytes were due and {} are left", self.rest.len()));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    pub fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// The bytes of a TPM2B.
    pub fn sized(&mut self) -> Result<&'a [u8], String> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    /// A TPM2B whole, its length included: what a key file keeps.
    pub fn sized_whole(&mut self) -> Result<&'a [u8], String> {
        let start = self.rest;
        let n = self.u16()? as usize;
        self.take(n)?;
        Ok(&start[..2 + n])
    }

    pub fn rest(&self) -> &'a [u8] {
        self.rest
    }

    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }
}
