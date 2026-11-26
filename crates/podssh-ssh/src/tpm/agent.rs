//! The keys sealed to a TPM that `podssh agent` holds (T-839). russh's
//! agent server knows no such key, so the front of the agent keeps them, as
//! it keeps the keys of security keys (`sk/agent.rs`): it takes the
//! extension `tpm-add-key` in the layout of ssh-tpm-agent's `ssh-tpm-add`
//! (which `podssh agent add` sends too), checks that the key signs now,
//! lists the keys after russh's, signs in the TPM and removes them. The
//! agent holds the key file, whose private part only that TPM can load,
//! never a private scalar.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use super::{KeyFile, Opener};
use crate::credential_store::{read_frame, write_frame};
use pod_tpm::Transport;

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const ADD_IDENTITY: u8 = 17;
const REMOVE_IDENTITY: u8 = 18;
const REMOVE_ALL_IDENTITIES: u8 = 19;
const ADD_ID_CONSTRAINED: u8 = 25;
const EXTENSION: u8 = 27;
const EXTENSION_FAILURE: u8 = 28;
const CONSTRAIN_LIFETIME: u8 = 1;
const CONSTRAIN_CONFIRM: u8 = 2;

/// The extension that gives the agent a key of a TPM: ssh-tpm-agent's name.
pub const ADD_EXTENSION: &str = "tpm-add-key";

/// The key type that the extension's message names.
const KEY_TYPE: &[u8] = b"TPMKEY";

/// How long `podssh agent add` waits for the agent, which signs once in the
/// TPM before it keeps a key.
pub const ADD_LIMIT: Duration = Duration::from_secs(120);

/// One key: its public key in SSH's wire format, its file, its comment, and
/// the end of its lifetime.
struct Entry {
    blob: Vec<u8>,
    file: KeyFile,
    comment: String,
    until: Option<Instant>,
}

/// The keys of a TPM that an agent holds, in its memory.
pub struct Held {
    entries: Mutex<Vec<Entry>>,
    open: Opener,
    /// One operation of the TPM at a time: a TPM in software serves one
    /// connection, and a device's commands are queued anyway.
    turn: Arc<Mutex<()>>,
}

impl Default for Held {
    fn default() -> Self {
        Held::with(super::probing())
    }
}

impl Held {
    /// The keys of the TPM that `open` reaches.
    pub(crate) fn with(open: Opener) -> Held {
        Held { entries: Mutex::new(Vec::new()), open, turn: Arc::new(Mutex::new(())) }
    }

    /// The answer to `request`, the body of a client's frame, when it is
    /// about a key of a TPM: to add one, remove one or sign with one. `None`
    /// for each other request. A locked agent refuses each.
    pub async fn answer(&self, request: &[u8], locked: bool) -> Option<Zeroizing<Vec<u8>>> {
        let (&kind, body) = request.split_first()?;
        let mut rest = body;
        match kind {
            SIGN_REQUEST => {
                let blob = take_string(&mut rest)?;
                let data = take_string(&mut rest)?;
                let file = self.find(&blob)?;
                if locked {
                    return Some(reply(FAILURE));
                }
                Some(self.sign(file, data).await)
            }
            REMOVE_IDENTITY => {
                let blob = take_string(&mut rest)?;
                let mut entries = self.entries();
                let at = entries.iter().position(|e| e.blob == blob)?;
                if locked {
                    return Some(reply(FAILURE));
                }
                entries.remove(at);
                Some(reply(SUCCESS))
            }
            EXTENSION => {
                if take_string(&mut rest)? != ADD_EXTENSION.as_bytes() {
                    return None;
                }
                if locked {
                    return Some(reply(FAILURE));
                }
                Some(self.add(rest).await)
            }
            _ => None,
        }
    }

    /// russh's `answer` to a `request` that went to it, with the keys of a
    /// TPM: a list gets them after russh's, and a removal of each key
    /// removes them too.
    pub fn after(&self, request: &[u8], answer: Zeroizing<Vec<u8>>, locked: bool) -> Zeroizing<Vec<u8>> {
        match request.first() {
            Some(&REMOVE_ALL_IDENTITIES) if answer.first() == Some(&SUCCESS) => {
                self.entries().clear();
                answer
            }
            Some(&REQUEST_IDENTITIES) if !locked => self.list(answer),
            _ => answer,
        }
    }

    /// The number of keys of a TPM held.
    pub fn count(&self) -> usize {
        self.entries().len()
    }

    /// Keep the key of an add's `contents` once it signed in the TPM; else
    /// say why on the agent's stderr, and refuse.
    async fn add(&self, contents: &[u8]) -> Zeroizing<Vec<u8>> {
        let checked = match parse_add(contents).and_then(|(file, until)| Ok((super::public_key(&file)?, file, until))) {
            Ok((public, file, until)) => {
                let (tried, key) = (file.clone(), public.clone());
                self.in_tpm(move |t| super::signs_now(t, &tried, &key)).await.map(|()| (file, public, until))
            }
            Err(why) => Err(why),
        };
        let (file, public, until) = match checked {
            Ok(checked) => checked,
            Err(why) => {
                crate::err_line!("podssh agent: refused a key of a TPM: {why}");
                return reply(EXTENSION_FAILURE);
            }
        };
        let Ok(blob) = public.to_bytes() else { return reply(EXTENSION_FAILURE) };
        let comment = file.description.clone().unwrap_or_default();
        let mut entries = self.entries();
        entries.retain(|e| e.blob != blob);
        entries.push(Entry { blob, file, comment, until });
        reply(SUCCESS)
    }

    /// Sign `data` in the TPM: the agent's answer, its signature or FAILURE,
    /// with the reason on the agent's stderr.
    async fn sign(&self, file: KeyFile, data: Vec<u8>) -> Zeroizing<Vec<u8>> {
        match self.in_tpm(move |t| super::sign_with(t, &file, &data)).await {
            Ok(blob) => {
                let mut out = Zeroizing::new(vec![SIGN_RESPONSE]);
                put_string(&mut out, &blob);
                out
            }
            Err(why) => {
                crate::err_line!("podssh agent: the TPM did not sign: {why}");
                reply(FAILURE)
            }
        }
    }

    /// `work` on the TPM, on a thread that may wait, one at a time.
    async fn in_tpm<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut dyn Transport) -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        let (open, turn) = (self.open.clone(), self.turn.clone());
        tokio::task::spawn_blocking(move || {
            let _turn = turn.lock().unwrap_or_else(|e| e.into_inner());
            let mut transport = open()?;
            work(&mut *transport)
        })
        .await
        .map_err(|_| "the thread of the TPM failed".to_string())?
    }

    /// The file of the key whose public key is `blob`, if it is held.
    fn find(&self, blob: &[u8]) -> Option<KeyFile> {
        self.entries().iter().find(|e| e.blob == blob).map(|e| e.file.clone())
    }

    /// russh's answer to a request for the keys, with these keys after its
    /// own (and after the security keys); FAILURE stays as it is.
    fn list(&self, answer: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
        let entries = self.entries();
        let head = answer.get(..5).map(|h| (h[0], u32::from_be_bytes([h[1], h[2], h[3], h[4]])));
        let Some((IDENTITIES_ANSWER, count)) = head else { return answer };
        if entries.is_empty() {
            return answer;
        }
        let mut out = Zeroizing::new(Vec::with_capacity(answer.len() + entries.len() * 128));
        out.push(IDENTITIES_ANSWER);
        out.extend_from_slice(&count.saturating_add(entries.len() as u32).to_be_bytes());
        out.extend_from_slice(&answer[5..]);
        for entry in entries.iter() {
            put_string(&mut out, &entry.blob);
            put_string(&mut out, entry.comment.as_bytes());
        }
        out
    }

    /// The keys, those whose lifetime ended dropped.
    fn entries(&self) -> MutexGuard<'_, Vec<Entry>> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        entries.retain(|e| e.until.is_none_or(|until| now < until));
        entries
    }
}

/// The key file and the end of the lifetime of an add's `contents`, in the
/// layout of ssh-tpm-agent's `TPMKeyMsg`: the code 17 or 25, the type
/// `TPMKEY`, the key file in PEM, a certificate, then the constraints.
fn parse_add(contents: &[u8]) -> Result<(KeyFile, Option<Instant>), String> {
    let bad = || "the request to add a key of a TPM is not in ssh-tpm-agent's layout".to_string();
    let (&kind, mut rest) = contents.split_first().ok_or_else(bad)?;
    if kind != ADD_IDENTITY && kind != ADD_ID_CONSTRAINED {
        return Err(bad());
    }
    if take_string(&mut rest).ok_or_else(bad)? != KEY_TYPE {
        return Err(bad());
    }
    let pem = Zeroizing::new(take_string(&mut rest).ok_or_else(bad)?);
    if !take_string(&mut rest).ok_or_else(bad)?.is_empty() {
        return Err("it comes with a certificate, which podssh agent does not keep for a key of a TPM".into());
    }
    let mut until = None;
    while let Some((&constraint, after)) = rest.split_first() {
        rest = after;
        match constraint {
            CONSTRAIN_LIFETIME => {
                let seconds = take_u32(&mut rest).ok_or_else(bad)?;
                until = Some(Instant::now() + Duration::from_secs(u64::from(seconds)));
            }
            CONSTRAIN_CONFIRM => {
                return Err("it asks for a confirmation of each use, which nobody here can give".into());
            }
            other => return Err(format!("it has a constraint ({other}) that podssh agent does not know")),
        }
    }
    if pem.len() > pod_tpm::keyfile::MAX_PEM {
        return Err(format!("its key file has more than {} bytes", pod_tpm::keyfile::MAX_PEM));
    }
    let text = std::str::from_utf8(&pem).map_err(|_| "its key file is not text".to_string())?;
    Ok((KeyFile::from_pem(text).map_err(|e| podssh_ws::text::said(&e))?, until))
}

/// The body of the request that gives an agent the key of `file`, as
/// ssh-tpm-agent's `ssh-tpm-add` sends it, with a lifetime when given; else
/// why the key file cannot be written (a part over the bounds of the file).
pub fn add_request(file: &KeyFile, lifetime: Option<u32>) -> Result<Zeroizing<Vec<u8>>, String> {
    let pem = Zeroizing::new(file.to_pem().map_err(|e| podssh_ws::text::said(&e))?);
    let mut body = Zeroizing::new(vec![EXTENSION]);
    put_string(&mut body, ADD_EXTENSION.as_bytes());
    // The message's own code: 17 with or without constraints, as Go's
    // ssh.Marshal writes the first of "17|25".
    body.push(ADD_IDENTITY);
    put_string(&mut body, KEY_TYPE);
    put_string(&mut body, pem.as_bytes());
    put_string(&mut body, &[]);
    if let Some(seconds) = lifetime {
        body.push(CONSTRAIN_LIFETIME);
        body.extend_from_slice(&seconds.to_be_bytes());
    }
    Ok(body)
}

/// Give the agent at the other end of `stream` the key of `file`, for
/// `lifetime` seconds when given; else why not, as the end of a sentence.
pub async fn add<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    file: &KeyFile,
    lifetime: Option<u32>,
) -> Result<(), String> {
    let request = add_request(file, lifetime)?;
    let asked = async {
        write_frame(stream, &request).await?;
        read_frame(stream).await
    };
    let answer = match tokio::time::timeout(ADD_LIMIT, asked).await {
        Err(_) => return Err(format!("the agent did not answer within {} s", ADD_LIMIT.as_secs())),
        Ok(Err(e)) => return Err(format!("the agent did not answer: {}", podssh_ws::text::said(&e))),
        Ok(Ok(None)) => return Err("the agent closed the connection: it keeps no key of a TPM".into()),
        Ok(Ok(Some(answer))) => answer,
    };
    match answer.first() {
        Some(&SUCCESS) => Ok(()),
        Some(&FAILURE) => Err("the agent keeps no key of a TPM (it is not podssh agent or ssh-tpm-agent), or it \
                               is locked"
            .into()),
        Some(&EXTENSION_FAILURE) => Err("the agent did not take the key; its own stderr says why".into()),
        _ => Err("the agent's answer is not one of the agent protocol".into()),
    }
}

fn reply(code: u8) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(vec![code])
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn take_u32(rest: &mut &[u8]) -> Option<u32> {
    let (bytes, tail) = rest.split_first_chunk::<4>()?;
    *rest = tail;
    Some(u32::from_be_bytes(*bytes))
}

fn take_string(rest: &mut &[u8]) -> Option<Vec<u8>> {
    let length = take_u32(rest)? as usize;
    if rest.len() < length {
        return None;
    }
    let (value, tail) = rest.split_at(length);
    *rest = tail;
    Some(value.to_vec())
}

#[cfg(test)]
#[path = "agent_tests.rs"]
mod tests;
