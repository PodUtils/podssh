//! `podssh serve --gateway net:NAME` (T-902): a gateway whose routes are the
//! section NAME of the net's signed document (`net::gateway`), so that the
//! owner signs each gateway's routes in one place. The document is the one
//! this host holds (`net::store`), which `podssh net take`, a node's
//! channel or `--net-url` keeps; with `--net-url URL --net-owner KEY`, serve
//! fetches it as `podssh node` does (`net::remote`, Q105), with no fetch at
//! the start while the copy from the URL is younger than its TTL, as
//! `--stdio` starts once for each client.
//!
//! The document names each CA by its public half; its private key stays in
//! a file of `--gateway-ca` on this host, and a route whose CA is none of
//! them is left out with one line. A read that fails (no document, a
//! signature that fails) keeps the routes in force, with one line; a newer
//! serial that reads is swapped in, whatever it holds: the owner's removal
//! of a route or of the whole section takes effect, and a section that this
//! podssh does not read lets nobody in by it. A long-lived serve (NAME,
//! `--listen`) looks at the document each [`LOOK`] and on SIGHUP; a document
//! past its end, or a copy of `--net-url` past its stale window, lets
//! nobody in until a newer one comes.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use clap::ArgMatches;
use podssh_ssh::server::gateway::{read_ca, Routes, Source, Table};

use crate::net::doc::check_name;
use crate::net::gateway::{self, Ca};
use crate::net::store::{self, Place};
use crate::relay_settings::Refusal;
use crate::serve::ServeArgs;

/// How often a long-lived gateway looks at the document held for a newer
/// serial: one local file of 60 KiB at most, and its signature.
pub const LOOK: Duration = Duration::from_secs(5);

/// The flags of a gateway of the net, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetFlags {
    /// `--gateway-ca FILE`, each one.
    pub ca: Vec<String>,
    /// `--net-url`, `--net-owner`, `--net-ttl` and `--net-stale`.
    pub url: Option<String>,
    pub owner: Option<String>,
    pub ttl: Option<String>,
    pub stale: Option<String>,
}

impl NetFlags {
    pub fn of(matches: &ArgMatches) -> NetFlags {
        let one = |id: &str| matches.get_one::<String>(id).cloned();
        NetFlags {
            ca: matches.get_many::<String>("gateway-ca").map(|v| v.cloned().collect()).unwrap_or_default(),
            url: one("net-url"),
            owner: one("net-owner"),
            ttl: one("net-ttl"),
            stale: one("net-stale"),
        }
    }

    /// The first of these flags given, for a refusal where none belongs.
    pub fn given(&self) -> Option<&'static str> {
        let given = [
            ("--gateway-ca", !self.ca.is_empty()),
            ("--net-url", self.url.is_some()),
            ("--net-owner", self.owner.is_some()),
            ("--net-ttl", self.ttl.is_some()),
            ("--net-stale", self.stale.is_some()),
        ];
        given.into_iter().find(|(_, set)| *set).map(|(flag, _)| flag)
    }
}

/// The gateway's name of `--gateway net:NAME`; none for a route file. A
/// file whose name begins with `net:` is given as `./net:...`.
pub fn name_of(value: &str) -> Option<&str> {
    value.strip_prefix("net:")
}

/// The routes of the gateway `name` in the document held at `place`.
pub struct NetRoutes {
    name: String,
    place: Place,
    cas: Vec<Ca>,
    /// The serial and the end of the document whose routes are in force.
    in_force: Mutex<Option<(u64, i64)>>,
    /// Now, in seconds since 1970: the process's clock, or a test's.
    now: fn() -> i64,
}

fn lock(state: &Mutex<Option<(u64, i64)>>) -> MutexGuard<'_, Option<(u64, i64)>> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

impl NetRoutes {
    pub fn new(name: &str, place: Place, cas: Vec<Ca>, now: fn() -> i64) -> NetRoutes {
        NetRoutes { name: name.to_string(), place, cas, in_force: Mutex::new(None), now }
    }

    /// The serial whose routes are in force; none before a document read.
    pub fn serial(&self) -> Option<u64> {
        lock(&self.in_force).map(|(serial, _)| serial)
    }

    /// One look at the document held, and the lines to say: none while its
    /// serial is the one in force; the routes of a newer one, swapped into
    /// `table`; or why none reads, once until that changes, the routes in
    /// force staying.
    pub fn look(&self, table: &Table, said: &mut Option<String>) -> Vec<String> {
        let in_force = self.serial();
        let held = match store::held_at(&self.place) {
            Ok(Some(held)) => Ok(held.signed.doc.serial),
            Ok(None) => Err("this host holds no net's document now".to_string()),
            Err(why) => Err(format!("the net's document cannot be trusted: {why}")),
        };
        let failed = match held {
            Ok(serial) if Some(serial) == in_force => {
                *said = None;
                return Vec::new();
            }
            Ok(_) => match table.reload() {
                Ok((count, mut notes)) => {
                    *said = None;
                    let serial = self.serial().map_or("none".to_string(), |s| s.to_string());
                    notes.push(format!("net:{}: the routes of serial {serial} taken, {count} in all", self.name));
                    return notes;
                }
                Err(why) => why,
            },
            Err(why) => why,
        };
        if said.as_deref() == Some(failed.as_str()) {
            return Vec::new();
        }
        *said = Some(failed.clone());
        let before = in_force.map_or("no document".to_string(), |s| format!("serial {s}"));
        vec![format!("net:{}: {failed}; the routes of {before} stay, {} in all", self.name, table.now().len())]
    }
}

impl Source for NetRoutes {
    fn read(&self) -> Result<(Routes, Vec<String>), String> {
        let held = store::held_at(&self.place)
            .map_err(|why| format!("the net's document cannot be trusted: {why}"))?
            .ok_or("this host holds no net's document: take one with podssh net take FILE, or give --net-url")?;
        let doc = &held.signed.doc;
        // A signed section that does not read lets nobody in by it.
        let read = gateway::routes_of(doc, &self.name, &self.cas)
            .unwrap_or_else(|why| (Routes::default(), vec![format!("{why}; nobody passes by net:{}", self.name)]));
        *lock(&self.in_force) = Some((doc.serial, doc.expires));
        Ok(read)
    }

    fn shown(&self) -> String {
        format!("net:{}", self.name)
    }

    fn closed(&self) -> Option<String> {
        if let Some(why) = crate::net::remote::door_closed() {
            return Some(why);
        }
        let (serial, expires) = (*lock(&self.in_force))?;
        (expires <= (self.now)()).then(|| {
            let ended = crate::pairs::utc(expires * 1000);
            format!("the net's document (serial {serial}) ended at {ended}; its owner renews it with podssh net renew")
        })
    }
}

/// The table of `--gateway net:NAME`, read now: its CA keys, the document
/// fetched first where `--net-url` asks, and a look at it each [`LOOK`] for
/// a long-lived serve. No route, or a document past its end, refuses the
/// start (78), as a gateway that nobody can pass is a setup that went wrong.
pub fn open(name: &str, args: &ServeArgs) -> Result<Arc<Table>, Refusal> {
    check_name(name).map_err(|why| Refusal::usage(format!("--gateway net:{name}: the gateway's name {why}")))?;
    if args.net.ca.is_empty() {
        return Err(Refusal::usage(format!(
            "--gateway net:{name} needs --gateway-ca FILE: the document names each CA by its public half, and its \
             private key stays on this host"
        )));
    }
    let mut cas: Vec<Ca> = Vec::new();
    for file in &args.net.ca {
        let path = Path::new(file);
        let key = read_ca(path).map_err(|why| Refusal::config(format!("--gateway-ca {why}")))?;
        cas.push((path.to_path_buf(), Arc::new(key)));
    }
    let place = match store::place() {
        Ok(Place::Off) => {
            return Err(Refusal::config(format!("--gateway net:{name}: {}=no turns the net off", store::ENV)));
        }
        Ok(place) => place,
        Err(why) => return Err(Refusal::config(why)),
    };
    let node = crate::node::NodeArgs {
        net_url: args.net.url.clone(),
        net_owner: args.net.owner.clone(),
        net_ttl: args.net.ttl.clone(),
        net_stale: args.net.stale.clone(),
        ..Default::default()
    };
    let reader = crate::net::remote::Reader { head: "podssh serve".to_string(), fresh_enough: args.stdio };
    crate::net::remote::start_as(&node, reader)?;
    let net = Arc::new(NetRoutes::new(name, place, cas, crate::net::now));
    let refused = |why: String| Refusal::config(format!("--gateway net:{name}: {why}"));
    let (table, notes) = Table::from_source(Box::new(net.clone())).map_err(refused)?;
    if table.now().is_empty() {
        let why = if notes.is_empty() { "no route, so nobody could pass".to_string() } else { notes.join("; ") };
        return Err(refused(why));
    }
    if let Some(why) = table.closed() {
        return Err(refused(why));
    }
    for note in &notes {
        podssh_ssh::err_line!("podssh serve: {note}");
    }
    let serial = net.serial().unwrap_or_default();
    podssh_ssh::err_line!("podssh serve: net:{name}: the routes of serial {serial}, {} in all", table.now().len());
    let table = Arc::new(table);
    // A serve of one connection meets one login: nothing to look for.
    if !args.stdio {
        watch(table.clone(), net)?;
    }
    Ok(table)
}

/// Look at the document held each [`LOOK`], on a thread of its own, for as
/// long as the process runs.
fn watch(table: Arc<Table>, net: Arc<NetRoutes>) -> Result<(), Refusal> {
    let looking = move || {
        let mut said = None;
        loop {
            std::thread::sleep(LOOK);
            for line in net.look(&table, &mut said) {
                podssh_ssh::err_line!("podssh serve: {line}");
            }
        }
    };
    std::thread::Builder::new().name("gateway-net".into()).spawn(looking).map(drop).map_err(|e| {
        Refusal::config(format!("could not start the look at the net's document: {}", podssh_ws::text::said(&e)))
    })
}

// Unix's, as serve is: the modes of the files are Unix's.
#[cfg(all(test, unix))]
#[path = "serve_gateway_net_tests.rs"]
mod tests;
