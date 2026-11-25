//! `--carrier s3:FILE` (T-725): a bucket of the S3 API as the stream of a
//! carrier, for a host whose one way out is an object store. FILE says
//! where the bucket is and where each end's keys are; no key is on the
//! command line, and no line shows one. The road itself is
//! `podssh_relay::bucket`: each end writes its way's sealed objects under
//! one prefix and reads the other's, the file-host carrier's link above.
//!
//! FILE holds `NAME = VALUE` lines; a line that starts with `#` is a comment:
//!
//! - `endpoint`: `https://HOST[:PORT][/PATH]` of the S3 API (`http://` on
//!   the loopback alone, for a test); `region` (`us-east-1` unless given);
//!   `bucket`; `style`, `path` (the default) or `virtual`;
//! - `up` and `down`: the prefixes of the client's way and the node's, the
//!   same in both ends' files;
//! - `credentials`: a file of the AWS form (`aws_access_key_id`,
//!   `aws_secret_access_key`, `aws_session_token`) for both ways; or
//!   `write-credentials` and `read-credentials` for two key pairs, the
//!   latter `none` for a prefix that anyone may read;
//! - `secret-file`: at least 16 bytes that both ends hold, the pair's key.
//!
//! A relative path is read from FILE's directory.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use podssh_relay::bucket::{self, Credentials, Endpoint, KeyPairs, Place, Style};
use podssh_ws::{ProxyChoice, Trust};
use zeroize::Zeroizing;

use crate::pipe::address::Address;
use crate::relay_settings::Refusal;
use podssh_relay::serve::reverse::carrier::Link;

pub(crate) use podssh_relay::bucket::Side;

/// The kind's word in `--carrier`.
pub(crate) const SCHEME: &str = "s3:";
/// The most bytes of FILE, of a credentials file and of a secret file.
const FILE_MOST: u64 = 64 * 1024;
/// Each direction of the pipe between the role and the road.
const PIPE: usize = 256 * 1024;

/// What `--carrier` names: a stream of `pipe`'s words, a bucket, or the
/// DNS road (T-877).
#[derive(Clone, Debug)]
pub(crate) enum Found {
    Stream(Address),
    Bucket(Arc<Spec>),
    Dns(Arc<crate::carrier_dns::Spec>),
}

impl PartialEq for Found {
    fn eq(&self, other: &Found) -> bool {
        match (self, other) {
            (Found::Stream(a), Found::Stream(b)) => a == b,
            (Found::Bucket(a), Found::Bucket(b)) => a.file == b.file,
            (Found::Dns(a), Found::Dns(b)) => a.file == b.file,
            _ => false,
        }
    }
}

/// A bucket, as FILE describes it, with its keys and its secret read.
pub(crate) struct Spec {
    /// FILE, in the user's words.
    pub file: String,
    pub place: Place,
    pub keys: KeyPairs,
    pub secret: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Spec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Spec").field("file", &self.file).field("place", &self.place).finish_non_exhaustive()
    }
}

fn config(file: &str, why: impl fmt::Display) -> Refusal {
    Refusal::config(format!("--carrier s3:{file}: {why}"))
}

/// The bytes of `path`, at most [`FILE_MOST`]; `what` names it.
fn bytes_of(path: &Path, what: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|e| format!("{what} {}: {e}", path.display()))?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(FILE_MOST + 1).read_to_end(&mut bytes).map_err(|e| format!("{what} {}: {e}", path.display()))?;
    if bytes.len() as u64 > FILE_MOST {
        return Err(format!("{what} {} is over {FILE_MOST} bytes", path.display()));
    }
    Ok(bytes)
}

/// A `NAME = VALUE` line of a file, and its number from 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Line {
    pub at: usize,
    pub name: String,
    pub value: String,
}

/// The `NAME = VALUE` lines of `text`, each with its number: a line that
/// starts with `#` or `;` is a comment, a name twice and an empty name are
/// refused. A byte-order mark that an editor put first is no byte of the
/// first name. The S3 FILE, its credentials files and the DNS FILE share it.
pub(crate) fn numbered(text: &str) -> Result<Vec<Line>, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out: Vec<Line> = Vec::new();
    for (at, line) in text.lines().enumerate() {
        let at = at + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // A section of the AWS form: its first is the one read.
        if line.starts_with('[') {
            if out.is_empty() {
                continue;
            }
            break;
        }
        let Some((name, value)) = line.split_once('=') else {
            return Err(format!("line {at}: not NAME = VALUE"));
        };
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return Err(format!("line {at}: no name before ="));
        }
        if let Some(first) = out.iter().find(|l| l.name == name) {
            return Err(format!("line {at}: {} is given twice (lines {} and {at})", visible(&name, 40), first.at));
        }
        out.push(Line { at, name, value: value.trim().to_string() });
    }
    Ok(out)
}

/// The `NAME = VALUE` lines of `text`, as [`numbered`] reads them.
pub(crate) fn lines(text: &str) -> Result<Vec<(String, String)>, String> {
    Ok(numbered(text)?.into_iter().map(|line| (line.name, line.value)).collect())
}

/// At most `most` characters of `text` for a line of podssh, each control
/// or formatting character written as an escape, so that the line shows
/// what the file holds (a NUL, a BOM) rather than dropping it.
pub(crate) fn visible(text: &str, most: usize) -> String {
    let mut out = String::new();
    for c in text.chars().take(most) {
        let hidden = c.is_control()
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}');
        if hidden {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// A key pair from a file of the AWS form. No word of the file is shown.
pub(crate) fn credentials_of(text: &str) -> Result<Credentials, String> {
    let found = lines(text)?;
    let get = |name: &str| found.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
    let (Some(id), Some(secret)) = (get("aws_access_key_id"), get("aws_secret_access_key")) else {
        return Err("no aws_access_key_id and aws_secret_access_key".into());
    };
    if id.is_empty() || secret.is_empty() || id.contains(char::is_whitespace) {
        return Err("an empty or spaced key".into());
    }
    let mut key = Credentials::new(id, secret);
    key.session_token = get("aws_session_token").filter(|t| !t.is_empty());
    Ok(key)
}

/// FILE read and checked: each name known, each needed one there, each
/// file it names read.
pub(crate) fn read(file: &str) -> Result<Spec, Refusal> {
    let path = PathBuf::from(file);
    let text = bytes_of(&path, "the file").map_err(|why| config(file, why))?;
    let text = String::from_utf8(text.to_vec()).map_err(|_| config(file, "not UTF-8 text"))?;
    let found = lines(&text).map_err(|why| config(file, why))?;
    let known = [
        "endpoint",
        "region",
        "bucket",
        "style",
        "up",
        "down",
        "credentials",
        "write-credentials",
        "read-credentials",
        "secret-file",
    ];
    if let Some((name, _)) = found.iter().find(|(n, _)| !known.contains(&n.as_str())) {
        let name = visible(name, 40);
        return Err(config(file, format!("{name} is no name of a bucket's file; a key goes in its own file")));
    }
    let get = |name: &str| found.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str());
    let need = |name: &str| get(name).filter(|v| !v.is_empty()).ok_or_else(|| config(file, format!("no {name}")));
    let endpoint = Endpoint::parse(need("endpoint")?).map_err(|why| config(file, why))?;
    // Plain HTTP shows each object's name and size on the way: the
    // loopback alone, where a test's stand-in serves.
    if !endpoint.secure && !loopback(&endpoint.host) {
        return Err(config(file, "an endpoint of http:// is for the loopback alone; give https://"));
    }
    let style = match get("style").unwrap_or("path") {
        "path" => Style::Path,
        "virtual" => Style::VirtualHost,
        other => return Err(config(file, format!("style {}: path or virtual", podssh_ws::text::one_line(other)))),
    };
    let place = Place {
        endpoint,
        style,
        region: get("region").unwrap_or("us-east-1").to_string(),
        bucket: need("bucket")?.to_string(),
        up: need("up")?.to_string(),
        down: need("down")?.to_string(),
    };
    place.check().map_err(|why| config(file, why))?;
    let near = |name: &str| -> PathBuf {
        let given = PathBuf::from(name);
        match path.parent() {
            Some(dir) if given.is_relative() => dir.join(given),
            _ => given,
        }
    };
    let key_in = |name: &str| -> Result<Credentials, Refusal> {
        let text = bytes_of(&near(name), "the credentials").map_err(|why| config(file, why))?;
        let text = std::str::from_utf8(&text).map_err(|_| config(file, "a credentials file that is not UTF-8"))?;
        credentials_of(text).map_err(|why| config(file, format!("the credentials {name}: {why}")))
    };
    let keys = match (get("credentials"), get("write-credentials"), get("read-credentials")) {
        (Some(both), None, None) => {
            let key = key_in(both)?;
            KeyPairs { write: key.clone(), read: Some(key) }
        }
        (None, Some(write), Some("none")) => KeyPairs { write: key_in(write)?, read: None },
        (None, Some(write), Some(read)) => KeyPairs { write: key_in(write)?, read: Some(key_in(read)?) },
        _ => {
            return Err(config(file, "give credentials, or write-credentials and read-credentials (or none)"));
        }
    };
    let secret = bytes_of(&near(need("secret-file")?), "the secret").map_err(|why| config(file, why))?;
    // The secret's file may end with a newline that an editor added.
    let secret = Zeroizing::new(secret.trim_ascii_end().to_vec());
    if secret.len() < bucket::SECRET_LEAST {
        return Err(config(
            file,
            format!("the secret holds {} bytes; at least {}", secret.len(), bucket::SECRET_LEAST),
        ));
    }
    Ok(Spec { file: file.to_string(), place, keys, secret })
}

fn loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Where the road's lines go: stderr, as each line of the carrier.
fn say() -> podssh_relay::filehost::Say {
    Arc::new(|line: String| {
        podssh_ssh::err_line!("podssh: the bucket carrier: {line}");
    })
}

/// The link of `side` at the bucket of `spec`: first a read of a name that
/// no note has (a wrong key or signature ends it here), then a client's
/// hello at the node's door, or a node's wait for one, as long as it takes.
async fn link_of(
    spec: &Spec,
    side: Side,
    say: podssh_relay::filehost::Say,
) -> Result<podssh_relay::filehost::Link, String> {
    let dial = bucket::dial_of(&spec.place.endpoint, Trust::Default, ProxyChoice::FromEnvironment);
    if let Some(line) = bucket::probe(&spec.place, side, &spec.keys, dial.clone()).await? {
        say(line);
    }
    let carrier = bucket::carrier(&spec.place, side, spec.keys.clone(), &spec.secret, dial, say)?;
    if side == Side::Client {
        *CLIENT.lock().unwrap_or_else(|e| e.into_inner()) = Some(carrier.clone());
    }
    match side {
        Side::Client => bucket::dial(&carrier).await,
        Side::Node => bucket::accept(&carrier).await,
    }
}

/// The client's carrier of this process, once its road started: one
/// carrier in a process, as a command names one.
static CLIENT: std::sync::Mutex<Option<Arc<podssh_relay::filehost::Carrier>>> = std::sync::Mutex::new(None);

/// How long no write must start before the client's last one is taken as
/// the last: past a link's pipe and its gather.
const QUIET: std::time::Duration = std::time::Duration::from_secs(1);

/// Until the client's last note is on the board, within `limit`: its Close
/// would else be lost with the process. Nothing for a client with no road.
pub(crate) async fn settled(limit: std::time::Duration) {
    let carrier = CLIENT.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(carrier) = carrier {
        carrier.settled(QUIET, limit).await;
    }
}

/// The node's stream, once a client's hello came: the node's socket starts
/// on it then, as its Pings would find no client before (69).
pub(crate) async fn accept(spec: &Spec) -> Result<Link, Refusal> {
    match link_of(spec, Side::Node, say()).await {
        Ok(link) => Ok(Box::new(link)),
        // A bucket that cannot be reached, or refuses the keys (69).
        Err(why) => {
            let code = crate::exitmap::Fault::RelayUnreachable.code();
            Err(Refusal { message: format!("the carrier s3:{}: {why}", spec.file), code })
        }
    }
}

/// The client's stream, in a tokio runtime: a pipe at once, whose far end a
/// task carries over the road once its link opens; the role's Pings wait in
/// it meanwhile. A road that fails says why and ends the pipe, which ends
/// the stream for the role (69). A node's side takes [`accept`]; here it
/// waits in the task the same way.
pub(crate) fn open(spec: Arc<Spec>, side: Side) -> Link {
    let (ours, mut far) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let say = say();
        match link_of(&spec, side, say.clone()).await {
            Ok(mut link) => {
                let _ = tokio::io::copy_bidirectional(&mut far, &mut link).await;
            }
            Err(why) => say(format!("{}: {why}", spec.file)),
        }
    });
    Box::new(ours)
}

#[cfg(test)]
#[path = "carrier_bucket_tests.rs"]
mod tests;
