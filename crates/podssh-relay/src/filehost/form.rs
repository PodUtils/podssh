//! What `pod-services` says of a file host (its kind `file-host`), and the
//! requests and answers that follow from it: the upload as
//! `multipart/form-data` (RFC 7578) with the host's fields of its shortest
//! life, the URL in its answer, the URL that downloads, and the form that
//! deletes. The forms differ by host (read in `docs/carriers.md`, T-738's
//! reading): a file field and fields of life, an answer that is the URL as
//! text or JSON that holds it, a download by GET or by POST or at a path of
//! its own, and a delete by a token that the upload's answer gave, or none.
//! Each is a fact of the service, so a host whose form changes is a change
//! of `pod-services`, not of this code.

use super::host::{Refusal, Stored};
use crate::session::{Entropy, NoRandom};

/// Where the URL of an upload is in the host's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The body is the URL, as text, maybe with a line end.
    Text,
    /// The body is JSON; the URL is the string at this path of keys.
    Json(Vec<String>),
}

/// How a host lets its uploader delete an upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delete {
    /// It does not: the piece waits for the end of its shortest life.
    Never,
    /// The upload's answer gives a token in the header `header`; a POST to
    /// the file's URL of a form with the token in `token_field` and an
    /// empty `delete_field` deletes it.
    TokenForm { header: String, token_field: String, delete_field: String },
}

/// A file host's form, as `pod-services` holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    /// The service's id in `pod-services`, which a note names.
    pub id: String,
    /// The URL that takes an upload: `https://HOST/PATH`.
    pub upload: String,
    /// The field of the file.
    pub field: String,
    /// The other fields, in order: the shortest life, a hard URL to guess.
    pub fields: Vec<(String, String)>,
    pub answer: Answer,
    /// The hosts whose URLs the answers name (a host may serve its files
    /// from a name of its own).
    pub serves: Vec<String>,
    /// A path segment that goes after the host of the answer's URL to
    /// download the file itself, not its page.
    pub fetch_segment: Option<String>,
    /// The download is a POST to the URL, not a GET.
    pub fetch_post: bool,
    /// Where the answer's URL is a page, the start of the file's link in it
    /// (tmpfiles.org: a signed link of a short life, read before each
    /// download); see [`page_link`].
    pub link_prefix: Option<String>,
    pub delete: Delete,
    /// The most bytes of one upload.
    pub most: usize,
    /// The uploads an hour that it publishes for each user.
    pub per_hour: Option<u32>,
    /// It says that one person runs it.
    pub one_person: bool,
}

/// The name of each piece's file: a word with no meaning, so that a URL or
/// a host's list says nothing of what it holds.
pub const FILE_NAME: &str = "piece.bin";

/// A boundary of a form: letters and digits that no sealed byte can end
/// early, as each part's length is not read by the boundary alone.
pub fn boundary(entropy: &mut dyn Entropy) -> Result<String, NoRandom> {
    let mut bytes = [0u8; 16];
    entropy.fill(&mut bytes)?;
    Ok(format!("podssh{}", super::keys::hex(&bytes)))
}

/// The `Content-Type` of a form with `boundary`.
pub fn content_type(boundary: &str) -> String {
    format!("multipart/form-data; boundary={boundary}")
}

/// One part of a form: its name, its file name for a file, and its bytes.
pub struct Part<'a> {
    pub name: &'a str,
    pub file: Option<&'a str>,
    pub bytes: &'a [u8],
}

/// The body of a form of `parts` (RFC 7578): each part after its boundary,
/// with its disposition, and a file's with a type of bytes.
pub fn multipart(boundary: &str, parts: &[Part<'_>]) -> Vec<u8> {
    let mut body = Vec::new();
    for part in parts {
        let head = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{}\"", part.name);
        body.extend_from_slice(head.as_bytes());
        if let Some(file) = part.file {
            let file = format!("; filename=\"{file}\"\r\nContent-Type: application/octet-stream");
            body.extend_from_slice(file.as_bytes());
        }
        body.extend_from_slice(b"\r\n\r\n");
        body.extend_from_slice(part.bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

/// The body of the upload of `sealed` to `form`'s host: its fields, then
/// the file.
pub fn upload_body(form: &Form, boundary: &str, sealed: &[u8]) -> Vec<u8> {
    let mut parts: Vec<Part<'_>> =
        form.fields.iter().map(|(name, value)| Part { name, file: None, bytes: value.as_bytes() }).collect();
    parts.push(Part { name: &form.field, file: Some(FILE_NAME), bytes: sealed });
    multipart(boundary, &parts)
}

/// The host and the scheme of `url`, lower case: `None` for a URL that is
/// not `https://`, as each road of podssh is TLS.
fn https_host(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host = host.split(':').next()?.to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Whether `url` is one of the hosts that `form` serves its files from.
pub fn owns(form: &Form, url: &str) -> bool {
    https_host(url).is_some_and(|host| form.serves.iter().any(|served| served.eq_ignore_ascii_case(&host)))
}

/// The upload's place, from the host's answer of `status`, its headers and
/// its body. A 429 is the host's word to wait, with its `Retry-After` in
/// seconds where it gives one.
pub fn read_answer(form: &Form, status: u16, headers: &[(String, String)], body: &[u8]) -> Result<Stored, Refusal> {
    let header = |name: &str| headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim());
    if status == 429 || status == 503 {
        let wait = header("retry-after").and_then(|v| v.parse::<u64>().ok()).map(std::time::Duration::from_secs);
        return Err(Refusal::Busy(wait));
    }
    if !(200..300).contains(&status) {
        return Err(Refusal::Failed(format!("{} answered {status} to an upload", form.id)));
    }
    let text = String::from_utf8_lossy(body);
    let url = match &form.answer {
        Answer::Text => text.split_whitespace().find(|w| w.starts_with("https://")).map(str::to_string),
        Answer::Json(path) => serde_json::from_str::<serde_json::Value>(&text).ok().and_then(|value| {
            path.iter().try_fold(value, |v, key| v.get(key).cloned()).and_then(|v| v.as_str().map(str::to_string))
        }),
    };
    let url = url.ok_or_else(|| Refusal::Failed(format!("{}'s answer to an upload names no https:// URL", form.id)))?;
    // An answer that names another place is not a URL of this host's: a
    // page in the way, or a host that changed.
    if !owns(form, &url) {
        return Err(Refusal::Failed(format!("{}'s answer names a URL of another host", form.id)));
    }
    let token = match &form.delete {
        Delete::Never => None,
        Delete::TokenForm { header: name, .. } => header(name).map(str::to_string),
    };
    Ok(Stored { url, token })
}

/// The URL that downloads the file of `url`, the answer's.
pub fn fetch_url(form: &Form, url: &str) -> String {
    let Some(segment) = &form.fetch_segment else { return url.to_string() };
    let Some(rest) = url.strip_prefix("https://") else { return url.to_string() };
    match rest.split_once('/') {
        Some((host, path)) => format!("https://{host}/{segment}/{path}"),
        None => format!("https://{rest}/{segment}"),
    }
}

/// The file's link in `page`, the page at the answer's `url`: the first
/// link that starts with the form's prefix and ends with the path of `url`
/// (`https://tmpfiles.org/dl/EXPIRY.SIGNATURE/ID/NAME` for
/// `https://tmpfiles.org/ID/NAME`). `None` with no prefix, or no such link.
pub fn page_link(form: &Form, url: &str, page: &[u8]) -> Option<String> {
    let prefix = form.link_prefix.as_deref().filter(|p| !p.is_empty())?;
    let path = url.strip_prefix("https://")?.split_once('/').map(|(_, p)| p)?;
    let path = path.split(['?', '#']).next().filter(|p| !p.is_empty())?;
    let text = String::from_utf8_lossy(page);
    let mut rest = text.as_ref();
    while let Some(at) = rest.find(prefix) {
        // A link ends where an attribute's quote, a space or a tag ends it.
        let link = &rest[at..];
        let end = link.find(|c: char| matches!(c, '"' | '\'' | '<' | '>') || c.is_whitespace()).unwrap_or(link.len());
        let link = &link[..end];
        if link.trim_end_matches('/').ends_with(&format!("/{path}")) {
            return Some(link.to_string());
        }
        rest = &rest[at + prefix.len()..];
    }
    None
}

/// The body of the form that deletes `stored`, POSTed to its URL; `None`
/// where the host deletes nothing, or gave no token.
pub fn delete_body(form: &Form, boundary: &str, stored: &Stored) -> Option<Vec<u8>> {
    let Delete::TokenForm { token_field, delete_field, .. } = &form.delete else { return None };
    let token = stored.token.as_deref()?;
    let parts = [
        Part { name: token_field, file: None, bytes: token.as_bytes() },
        Part { name: delete_field, file: None, bytes: b"" },
    ];
    Some(multipart(boundary, &parts))
}

#[cfg(test)]
#[path = "form_tests.rs"]
mod tests;
