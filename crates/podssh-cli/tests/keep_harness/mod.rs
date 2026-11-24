//! A stand-in for a far end that keeps shells (T-158), until `podssh serve`
//! exists (T-107, T-159): on the loopback, the resumable layer as `podssh
//! serve` speaks it (its role, and `keep.v1` among its features), and
//! behind it a russh server in the test process whose shells can outlive
//! their client. A shell reads lines: `MARK=VALUE` sets its one variable,
//! `echo M=$MARK` prints it, `echo S=$PODSSH_SHELL_ID` prints the shell's
//! id, and `exit` ends it (status 0); another line comes back as not found.
//! The requests are those of `podssh_ssh::keep`: `detach@podssh` keeps the
//! shell as a name, `attach@podssh`, `take@podssh` and `from@podssh` join it
//! again, and the subsystem `shells@podssh` lists the kept shells. A
//! refusal is its words on stderr and the status 1. As `podssh serve`,
//! it counts each shell's output from its start (T-833): the list gives
//! each offset, `count@podssh OFFSET` replays from there, and an offset
//! past the output, or `reset@podssh yes`, gives serve's line of a reset
//! and the output from its start. `cut TEXT` writes TEXT into the shell's
//! output and ends the connection before it is sent, as a link that died
//! past the resume deadline (T-895). The plants: `Forget` answers a detach
//! and ends the shell, and `NoOffer` names no `keep.v1`.

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::session::keep::Keeper;
use podssh_relay::session::{far, Role, Settings, FEATURES, SHELL_FEATURES};
use podssh_ssh::keep_count::reset_line;
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, Pty};
use tokio::io::DuplexStream;

/// Each direction of the pipe between the layer and the SSH server.
const PIPE: usize = 256 * 1024;
/// The replay memory of the stand-in, as a node's.
const BUDGET: usize = 64 << 20;

/// What the far end does: as it must, or a planted defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plant {
    None,
    /// It answers a detach with SUCCESS, then ends the shell.
    Forget,
    /// Its layer names no `keep.v1`: it keeps no shells.
    NoOffer,
}

/// One shell: its id, the name that it is kept as, its variable, its
/// output from its start, and the client that has it (a connection's
/// number, its handle and its channel).
pub struct Shell {
    pub id: String,
    pub name: Option<String>,
    pub mark: Option<String>,
    pub output: Vec<u8>,
    holder: Option<(u64, server::Handle, ChannelId)>,
}

impl Shell {
    /// Whether a client has the shell.
    pub fn attached(&self) -> bool {
        self.holder.is_some()
    }

    fn held_by(&self, conn: u64, channel: ChannelId) -> bool {
        matches!(&self.holder, Some((c, _, ch)) if *c == conn && *ch == channel)
    }
}

/// The far end's shells, and the counts that the tests read.
pub struct Shells {
    pub plant: Plant,
    pub all: Vec<Shell>,
    pub detaches: usize,
    pub attaches: usize,
    next: u64,
}

impl Shells {
    /// The shell kept as `name`.
    pub fn kept(&self, name: &str) -> Option<&Shell> {
        self.all.iter().find(|s| s.name.as_deref() == Some(name))
    }

    /// A shell kept as `name` with its variable, as after a detach: its id.
    pub fn keep(&mut self, name: &str, mark: &str) -> String {
        self.next += 1;
        let id = format!("shell-{}", self.next);
        let (name, mark) = (Some(name.into()), Some(mark.into()));
        let shell = Shell { id: id.clone(), name, mark, output: Vec::new(), holder: None };
        self.all.push(shell);
        id
    }
}

fn lock(shells: &Mutex<Shells>) -> std::sync::MutexGuard<'_, Shells> {
    shells.lock().unwrap_or_else(|e| e.into_inner())
}

/// Each channel's asks before its shell request.
#[derive(Default)]
struct Asked {
    attach: Option<String>,
    take: bool,
    from: Option<String>,
    count: Option<u64>,
    reset: bool,
}

/// `text` as the shell's output: counted, and sent on `channel`.
fn say(shell: &mut Shell, session: &mut Session, channel: ChannelId, text: &str) -> Result<(), russh::Error> {
    shell.output.extend_from_slice(text.as_bytes());
    session.data(channel, text.as_bytes().to_vec())
}

/// One connection: its number, the asks of each channel, and the channel
/// of each shell that runs, by the shell's id, with the part of a line read.
struct Far {
    shells: Arc<Mutex<Shells>>,
    conn: u64,
    asks: HashMap<ChannelId, Asked>,
    running: HashMap<ChannelId, (String, Vec<u8>)>,
}

/// Answer at once and end: the output, stderr and the status.
fn finish(session: &mut Session, channel: ChannelId, out: &str, err: &str, status: u32) -> Result<(), russh::Error> {
    if !out.is_empty() {
        session.data(channel, out.as_bytes().to_vec())?;
    }
    if !err.is_empty() {
        session.extended_data(channel, 1, err.as_bytes().to_vec())?;
    }
    session.exit_status_request(channel, status)?;
    session.eof(channel)?;
    session.close(channel)
}

impl Far {
    /// `env detach@podssh NAME` on a running shell: keep it as NAME and
    /// close the channel; FAILURE when NAME is another shell's.
    fn detach(&mut self, channel: ChannelId, name: &str, session: &mut Session) -> Result<(), russh::Error> {
        let Some(id) = self.running.get(&channel).map(|(id, _)| id.clone()) else {
            return session.channel_failure(channel);
        };
        let mut shells = lock(&self.shells);
        shells.detaches += 1;
        if shells.all.iter().any(|s| s.name.as_deref() == Some(name) && s.id != id) {
            drop(shells);
            return session.channel_failure(channel);
        }
        if shells.plant == Plant::Forget {
            shells.all.retain(|s| s.id != id);
        } else if let Some(shell) = shells.all.iter_mut().find(|s| s.id == id) {
            shell.name = Some(name.to_string());
            shell.holder = None;
        }
        drop(shells);
        self.running.remove(&channel);
        session.channel_success(channel)?;
        session.eof(channel)?;
        session.close(channel)
    }

    /// The client of `channel` left: its kept shell waits for the next
    /// one, and a shell that was never kept ends.
    fn release(&mut self, channel: ChannelId) {
        let Some((id, _)) = self.running.remove(&channel) else { return };
        let mut shells = lock(&self.shells);
        let Some(at) = shells.all.iter().position(|s| s.id == id) else { return };
        if !shells.all[at].held_by(self.conn, channel) {
            return;
        }
        if shells.all[at].name.is_some() {
            shells.all[at].holder = None;
        } else {
            shells.all.remove(at);
        }
    }

    /// One line of the shell `id`: whether the shell ended.
    fn line(&mut self, id: &str, channel: ChannelId, text: &str, session: &mut Session) -> Result<bool, russh::Error> {
        let mut shells = lock(&self.shells);
        let Some(at) = shells.all.iter().position(|s| s.id == id) else { return Ok(true) };
        // A shell taken by another client: this one's lines go nowhere.
        if !shells.all[at].held_by(self.conn, channel) {
            return Ok(false);
        }
        let shell = &mut shells.all[at];
        if let Some(value) = text.strip_prefix("MARK=") {
            shell.mark = Some(value.to_string());
        } else if text == "echo M=$MARK" {
            let mark = shell.mark.clone().unwrap_or_default();
            say(shell, session, channel, &format!("M={mark}\r\n"))?;
        } else if text == "echo S=$PODSSH_SHELL_ID" {
            say(shell, session, channel, &format!("S={id}\r\n"))?;
        } else if let Some(lost) = text.strip_prefix("cut ") {
            // Output that the dead channel never brings: the far end counted
            // it, and keeps the shell for the next client.
            shell.output.extend_from_slice(format!("{lost}\r\n").as_bytes());
            shell.holder = None;
            drop(shells);
            self.running.remove(&channel);
            return Err(russh::Error::Disconnect);
        } else if text == "exit" {
            shells.all.remove(at);
            drop(shells);
            self.running.remove(&channel);
            finish(session, channel, "", "", 0)?;
            return Ok(true);
        } else {
            say(shell, session, channel, &format!("{text}: not found\r\n"))?;
        }
        Ok(false)
    }
}

impl Drop for Far {
    fn drop(&mut self) {
        let channels: Vec<ChannelId> = self.running.keys().copied().collect();
        for channel in channels {
            self.release(channel);
        }
    }
}

impl server::Handler for Far {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _px_width: u32,
        _px_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "detach@podssh" {
            return self.detach(channel, value, session);
        }
        let asked = self.asks.entry(channel).or_default();
        match name {
            "attach@podssh" => asked.attach = Some(value.to_string()),
            "take@podssh" => asked.take = true,
            "from@podssh" => asked.from = Some(value.to_string()),
            "count@podssh" => match value.parse() {
                Ok(count) => asked.count = Some(count),
                Err(_) => return session.channel_failure(channel),
            },
            "reset@podssh" => asked.reset = value == "yes",
            // The client's own variables: this server keeps none.
            _ => return session.channel_failure(channel),
        }
        session.channel_success(channel)
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let asked = self.asks.remove(&channel).unwrap_or_default();
        let handle = session.handle();
        let mut shells = lock(&self.shells);
        let Some(name) = asked.attach else {
            shells.next += 1;
            let id = format!("shell-{}", shells.next);
            let holder = Some((self.conn, handle, channel));
            let mut shell = Shell { id: id.clone(), name: None, mark: None, output: Vec::new(), holder };
            say(&mut shell, session, channel, "[shell] ready\r\n")?;
            shells.all.push(shell);
            drop(shells);
            self.running.insert(channel, (id, Vec::new()));
            return Ok(());
        };
        let refusal = match shells.kept(&name) {
            None => Some(format!("no kept shell named {name}")),
            Some(shell) if asked.from.as_deref() == Some(shell.id.as_str()) => {
                Some(format!("the attach comes from inside the shell {name}"))
            }
            Some(shell) if shell.attached() && !asked.take => {
                Some(format!("the shell {name} has a client; --take takes it"))
            }
            Some(_) => None,
        };
        if let Some(why) = refusal {
            drop(shells);
            return finish(session, channel, "", &format!("{why}\r\n"), 1);
        }
        shells.attaches += 1;
        let Some(shell) = shells.all.iter_mut().find(|s| s.name.as_deref() == Some(name.as_str())) else {
            return Ok(());
        };
        let id = shell.id.clone();
        // The client that had it loses it, and its session ends.
        if let Some((_, old, old_channel)) = shell.holder.replace((self.conn, handle, channel)) {
            let note = format!("[{name}] taken by another client\r\n");
            tokio::spawn(async move {
                let _ = old.data(old_channel, note.into_bytes()).await;
                let _ = old.eof(old_channel).await;
                let _ = old.close(old_channel).await;
            });
        }
        // Where the replay starts, as serve chooses: the client's count in
        // the output, else a reset; with no count, where the output stands.
        let end = shell.output.len() as u64;
        let (from, reset) = match asked.count {
            _ if asked.reset => (0, true),
            Some(count) if count <= end => (count, false),
            Some(_) => (0, true),
            None => (end, false),
        };
        if reset {
            session.extended_data(channel, 1, reset_line(&name, from).into_bytes())?;
        }
        let replay = shell.output[usize::try_from(from).unwrap()..].to_vec();
        if !replay.is_empty() {
            session.data(channel, replay)?;
        }
        say(shell, session, channel, &format!("[{name}] attached\r\n"))?;
        drop(shells);
        self.running.insert(channel, (id, Vec::new()));
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "shells@podssh" {
            return session.channel_failure(channel);
        }
        session.channel_success(channel)?;
        let mut lines = String::new();
        for shell in lock(&self.shells).all.iter() {
            if let Some(name) = &shell.name {
                let state = if shell.attached() { "attached" } else { "detached" };
                lines.push_str(&format!("{name} {state} {}\n", shell.output.len()));
            }
        }
        finish(session, channel, &lines, "", 0)
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let Some((id, line)) = self.running.get_mut(&channel) else { return Ok(()) };
        line.extend_from_slice(data);
        let id = id.clone();
        loop {
            let Some((_, line)) = self.running.get_mut(&channel) else { return Ok(()) };
            let Some(end) = line.iter().position(|b| *b == b'\r' || *b == b'\n') else { return Ok(()) };
            let read: Vec<u8> = line.drain(..=end).collect();
            let text = String::from_utf8_lossy(&read[..end]).trim().to_string();
            if !text.is_empty() && self.line(&id, channel, &text, session)? {
                return Ok(());
            }
        }
    }

    async fn channel_close(&mut self, channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        self.release(channel);
        Ok(())
    }
}

/// The stand-in on the loopback, on the current runtime, with the host key
/// in `key`: the port of its layer, and its shells.
pub async fn start(key: &Path, plant: Plant) -> (u16, Arc<Mutex<Shells>>) {
    let shells = Arc::new(Mutex::new(Shells { plant, all: Vec::new(), detaches: 0, attaches: 0, next: 0 }));
    let mut config = server::Config::default();
    config.keys.push(russh::keys::load_secret_key(key, None).expect("the host key"));
    config.auth_rejection_time = Duration::from_millis(10);
    config.auth_rejection_time_initial = Some(Duration::ZERO);
    let config = Arc::new(config);
    let keeper: Arc<Keeper<DuplexStream>> = Arc::new(Keeper::new(Duration::from_secs(600)));
    let features = if plant == Plant::NoOffer { FEATURES } else { SHELL_FEATURES };
    let settings = Settings { features, ..Settings::default() };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port on the loopback");
    let port = listener.local_addr().unwrap().port();
    let (shared, connections) = (shells.clone(), Arc::new(AtomicU64::new(0)));
    tokio::spawn(async move {
        while let Ok((link, _)) = listener.accept().await {
            let (keeper, config, shells, connections) =
                (keeper.clone(), config.clone(), shared.clone(), connections.clone());
            tokio::spawn(async move {
                // The SSH server of a new session, after the layer's handshake.
                let open = move || async move {
                    let (ours, theirs) = tokio::io::duplex(PIPE);
                    let conn = connections.fetch_add(1, Ordering::SeqCst);
                    let handler = Far { shells, conn, asks: HashMap::new(), running: HashMap::new() };
                    tokio::spawn(async move {
                        if let Ok(session) = server::run_stream(config, theirs, handler).await {
                            let _ = session.await;
                        }
                    });
                    Ok::<_, String>(ours)
                };
                far::serve(link, Role::SERVE, settings, &keeper, BUDGET, open).await;
            });
        }
    });
    (port, shells)
}
