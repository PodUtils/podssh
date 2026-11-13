//! The answer to each request of an SFTP session: its handles, its calls on
//! the session's thread, and the reply, or the status that says why not.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use russh_sftp::protocol::{
    Attrs, Data, ExtendedReply, File as Named, FileAttributes, Handle, Name, Packet, Status, StatusCode,
};

use super::fs::{self, Dir};
use super::worker::{Failed, Worker};
use super::{FSYNC, LIMITS, MAX_HANDLES, MAX_PACKET, MAX_READ, POSIX_RENAME};

/// A status that is no success: its code and its words.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Refusal {
    pub(super) code: StatusCode,
    pub(super) message: String,
}

impl Refusal {
    pub(super) fn new(code: StatusCode, message: impl Into<String>) -> Refusal {
        Refusal { code, message: message.into() }
    }

    /// A failed call, named by `what`, with the system's words.
    fn io(what: &str, e: &io::Error) -> Refusal {
        Refusal::new(fs::status_of(e), format!("{what}: {}", fs::words(e)))
    }

    fn eof() -> Refusal {
        Refusal::new(StatusCode::Eof, "end of file")
    }

    /// The status packet of this refusal, for the request `id`.
    pub(super) fn packet(self, id: u32) -> Packet {
        status(id, self.code, self.message)
    }
}

/// A status packet.
pub(super) fn status(id: u32, code: StatusCode, message: impl Into<String>) -> Packet {
    Packet::Status(Status { id, status_code: code, error_message: message.into(), language_tag: "en".into() })
}

fn ok(id: u32) -> Packet {
    status(id, StatusCode::Ok, "Success")
}

/// What a handle holds.
enum Held {
    File(Arc<File>),
    Dir(Arc<Mutex<Dir>>),
}

/// The open handles of a session, [`MAX_HANDLES`] at most.
struct Handles {
    next: u64,
    open: HashMap<String, Held>,
}

impl Handles {
    fn room(&self) -> Result<(), Refusal> {
        if self.open.len() >= MAX_HANDLES {
            return Err(Refusal::new(
                StatusCode::Failure,
                format!("{MAX_HANDLES} handles are open, the most for a session: close one first"),
            ));
        }
        Ok(())
    }

    fn add(&mut self, held: Held) -> String {
        self.next += 1;
        let name = self.next.to_string();
        self.open.insert(name.clone(), held);
        name
    }

    fn file(&self, handle: &str) -> Result<Arc<File>, Refusal> {
        match self.open.get(handle) {
            Some(Held::File(file)) => Ok(file.clone()),
            _ => Err(Refusal::new(StatusCode::Failure, format!("no open file has the handle {handle:?}"))),
        }
    }

    fn dir(&self, handle: &str) -> Result<Arc<Mutex<Dir>>, Refusal> {
        match self.open.get(handle) {
            Some(Held::Dir(dir)) => Ok(dir.clone()),
            _ => Err(Refusal::new(StatusCode::Failure, format!("no open directory has the handle {handle:?}"))),
        }
    }
}

/// SSH strings, in order, from an extension's request.
fn strings(data: &[u8], count: usize) -> Option<Vec<String>> {
    let mut out = Vec::with_capacity(count);
    let mut at = 0usize;
    for _ in 0..count {
        let len = u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?) as usize;
        let text = data.get(at + 4..(at + 4).checked_add(len)?)?;
        out.push(String::from_utf8(text.to_vec()).ok()?);
        at += 4 + len;
    }
    Some(out)
}

// std's generic calls as plain functions of a path, for `on_path`.
fn remove_file(path: &Path) -> io::Result<()> {
    std::fs::remove_file(path)
}

fn remove_dir(path: &Path) -> io::Result<()> {
    std::fs::remove_dir(path)
}

/// The seconds since 1970 now, for the long names of a listing.
fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// One session's state after its version exchange.
pub(super) struct Session {
    home: PathBuf,
    worker: Worker,
    handles: Handles,
}

impl Session {
    pub(super) fn new(home: PathBuf, worker: Worker) -> Session {
        Session { home, worker, handles: Handles { next: 0, open: HashMap::new() } }
    }

    /// The calls that this session left stuck.
    pub(super) fn stuck(&self) -> usize {
        self.worker.stuck
    }

    fn path(&self, path: &str) -> PathBuf {
        fs::resolve(&self.home, path)
    }

    /// Run `call` on the session's thread. Past the limit, the reply says
    /// so, and the handle that it used is closed: a client that tried again
    /// on it would only wait again.
    async fn run<T: Send + 'static>(
        &mut self,
        what: &str,
        handle: Option<&str>,
        call: impl FnOnce() -> io::Result<T> + Send + 'static,
    ) -> Result<T, Refusal> {
        match self.worker.call(call).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(e)) => Err(Refusal::io(what, &e)),
            Err(Failed::Stuck(limit)) => {
                let closed = match handle.and_then(|h| self.handles.open.remove(h)) {
                    Some(_) => ", and its handle is closed",
                    None => "",
                };
                Err(Refusal::new(
                    StatusCode::Failure,
                    format!("{what}: the file system gave no answer within {limit:?}{closed}"),
                ))
            }
            Err(Failed::Lost(why)) => Err(Refusal::new(StatusCode::Failure, format!("{what}: {why}"))),
        }
    }

    /// The reply to one request; a request that is no request of a client
    /// is refused as unsupported.
    pub(super) async fn answer(&mut self, packet: Packet) -> Packet {
        let id = packet.get_request_id();
        let answered = match packet {
            Packet::Open(o) => {
                let what = format!("open {}", o.filename);
                let path = self.path(&o.filename);
                match self.handles.room() {
                    Err(refusal) => Err(refusal),
                    Ok(()) => self.run(&what, None, move || fs::open(&path, o.pflags, &o.attrs)).await.map(|file| {
                        Packet::Handle(Handle { id, handle: self.handles.add(Held::File(Arc::new(file))) })
                    }),
                }
            }
            Packet::OpenDir(o) => {
                let what = format!("opendir {}", o.path);
                let path = self.path(&o.path);
                match self.handles.room() {
                    Err(refusal) => Err(refusal),
                    Ok(()) => self.run(&what, None, move || Dir::open(path)).await.map(|dir| {
                        Packet::Handle(Handle { id, handle: self.handles.add(Held::Dir(Arc::new(Mutex::new(dir)))) })
                    }),
                }
            }
            Packet::Close(c) => match self.handles.open.remove(&c.handle) {
                // The close itself runs on the thread: a dead mount can hold it.
                Some(held) => self
                    .run("close", None, move || {
                        drop(held);
                        Ok(())
                    })
                    .await
                    .map(|()| ok(id)),
                None => Err(Refusal::new(StatusCode::Failure, format!("no open handle {:?}", c.handle))),
            },
            Packet::Read(r) => self.read(id, r.handle, r.offset, r.len).await,
            Packet::Write(w) => match self.handles.file(&w.handle) {
                Err(refusal) => Err(refusal),
                Ok(file) => {
                    let what = format!("write at {}", w.offset);
                    let (offset, data) = (w.offset, w.data);
                    self.run(&what, Some(&w.handle), move || fs::write_at(&file, offset, &data)).await.map(|()| ok(id))
                }
            },
            Packet::Stat(s) => self.stat(id, &s.path, true).await,
            Packet::Lstat(s) => self.stat(id, &s.path, false).await,
            Packet::Fstat(f) => match self.handles.file(&f.handle) {
                Err(refusal) => Err(refusal),
                Ok(file) => self
                    .run("fstat", Some(&f.handle), move || file.metadata())
                    .await
                    .map(|m| Packet::Attrs(Attrs { id, attrs: fs::attrs(&m) })),
            },
            Packet::SetStat(s) => {
                let (what, path) = (format!("setstat {}", s.path), self.path(&s.path));
                self.run(&what, None, move || fs::set_path(&path, &s.attrs)).await.map(|()| ok(id))
            }
            Packet::FSetStat(s) => match self.handles.file(&s.handle) {
                Err(refusal) => Err(refusal),
                Ok(file) => {
                    let attrs = s.attrs;
                    self.run("fsetstat", Some(&s.handle), move || fs::set_file(&file, &attrs)).await.map(|()| ok(id))
                }
            },
            Packet::ReadDir(r) => match self.handles.dir(&r.handle) {
                Err(refusal) => Err(refusal),
                Ok(dir) => {
                    let listed = self
                        .run("readdir", Some(&r.handle), move || {
                            let mut guard = dir.lock().map_err(|_| io::Error::other("the listing failed before"))?;
                            guard.next_names(now())
                        })
                        .await;
                    match listed {
                        Ok(files) if files.is_empty() => Err(Refusal::eof()),
                        Ok(files) => Ok(Packet::Name(Name { id, files })),
                        Err(refusal) => Err(refusal),
                    }
                }
            },
            Packet::Remove(r) => self.on_path(id, "remove", &r.filename, remove_file).await,
            Packet::RmDir(r) => self.on_path(id, "rmdir", &r.path, remove_dir).await,
            Packet::MkDir(m) => {
                let (what, path, attrs) = (format!("mkdir {}", m.path), self.path(&m.path), m.attrs);
                self.run(&what, None, move || fs::mkdir(&path, &attrs)).await.map(|()| ok(id))
            }
            Packet::Rename(r) => self.rename(id, &r.oldpath, &r.newpath, false).await,
            Packet::RealPath(r) => {
                let (what, path) = (format!("realpath {}", r.path), self.path(&r.path));
                self.run(&what, None, move || fs::realpath(&path)).await.map(|p| one_name(id, &p))
            }
            Packet::ReadLink(r) => {
                let (what, path) = (format!("readlink {}", r.path), self.path(&r.path));
                self.run(&what, None, move || std::fs::read_link(&path)).await.map(|p| one_name(id, &p))
            }
            // OpenSSH's sftp-server reads the two paths in the other order
            // from the draft, the target first; each client that podssh
            // meets, its own included, sends them so.
            Packet::Symlink(s) => {
                let (target, link) = (PathBuf::from(&s.linkpath), self.path(&s.targetpath));
                let what = format!("symlink {}", s.targetpath);
                self.run(&what, None, move || std::os::unix::fs::symlink(&target, &link)).await.map(|()| ok(id))
            }
            Packet::Extended(e) => self.extended(id, &e.request, &e.data).await,
            _ => Err(Refusal::new(StatusCode::OpUnsupported, "not a request of a client")),
        };
        answered.unwrap_or_else(|refusal| refusal.packet(id))
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Packet, Refusal> {
        let file = self.handles.file(&handle)?;
        // A longer read is cut to the limit, as sftp-server cuts it; the
        // client reads on from where the data ended.
        let len = len.min(MAX_READ);
        let what = format!("read at {offset}");
        let data = self.run(&what, Some(&handle), move || fs::read_at(&file, offset, len)).await?;
        if data.is_empty() {
            return Err(Refusal::eof());
        }
        Ok(Packet::Data(Data { id, data }))
    }

    async fn stat(&mut self, id: u32, path: &str, follow: bool) -> Result<Packet, Refusal> {
        let what = format!("{} {path}", if follow { "stat" } else { "lstat" });
        let path = self.path(path);
        let m = self
            .run(&what, None, move || if follow { std::fs::metadata(&path) } else { std::fs::symlink_metadata(&path) })
            .await?;
        Ok(Packet::Attrs(Attrs { id, attrs: fs::attrs(&m) }))
    }

    async fn on_path(
        &mut self,
        id: u32,
        verb: &str,
        path: &str,
        call: fn(&Path) -> io::Result<()>,
    ) -> Result<Packet, Refusal> {
        let (what, path) = (format!("{verb} {path}"), self.path(path));
        self.run(&what, None, move || call(&path)).await.map(|()| ok(id))
    }

    async fn rename(&mut self, id: u32, from: &str, to: &str, over: bool) -> Result<Packet, Refusal> {
        let what = format!("rename {from} to {to}");
        let (from, to) = (self.path(from), self.path(to));
        let call = move || if over { std::fs::rename(&from, &to) } else { fs::rename_new(&from, &to) };
        self.run(&what, None, call).await.map(|()| ok(id))
    }

    /// The extensions of the version reply; another is unsupported.
    async fn extended(&mut self, id: u32, request: &str, data: &[u8]) -> Result<Packet, Refusal> {
        let bad = || Refusal::new(StatusCode::BadMessage, format!("{request}: its data does not parse"));
        match request {
            POSIX_RENAME => {
                let paths = strings(data, 2).ok_or_else(bad)?;
                self.rename(id, &paths[0], &paths[1], true).await
            }
            FSYNC => {
                let handle = strings(data, 1).ok_or_else(bad)?.remove(0);
                let file = self.handles.file(&handle)?;
                self.run("fsync", Some(&handle), move || file.sync_all()).await.map(|()| ok(id))
            }
            LIMITS => {
                // Packet, read, write and handles, as sftp-server names them.
                let mut data = Vec::with_capacity(32);
                for n in [MAX_PACKET as u64, u64::from(MAX_READ), u64::from(MAX_READ), MAX_HANDLES as u64] {
                    data.extend_from_slice(&n.to_be_bytes());
                }
                Ok(Packet::ExtendedReply(ExtendedReply { id, data }))
            }
            other => Err(Refusal::new(StatusCode::OpUnsupported, format!("the extension {other} is not served here"))),
        }
    }
}

/// A reply of one name: realpath's and readlink's, with no attributes, as
/// sftp-server sends them.
fn one_name(id: u32, path: &Path) -> Packet {
    let name = path.to_string_lossy().into_owned();
    Packet::Name(Name {
        id,
        files: vec![Named { filename: name.clone(), longname: name, attrs: FileAttributes::empty() }],
    })
}
