//! `podssh config import FORMAT FILE` (T-047, T-292): the host list of
//! another tool as `Host` blocks of `ssh_config`, on stdout, with a summary
//! on stderr: an Ansible inventory, or the saved sessions of PuTTY,
//! MobaXterm, Remmina or mRemoteNG. It never writes `~/.ssh/config`; the user adds
//! what it printed. A password or a passphrase is never imported and never
//! printed: it is counted. What has no keyword of `ssh_config` is named in a
//! comment, never dropped silently.

use std::io::Write;

use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::{EX_DATAERR, EX_NOINPUT};

pub mod ansible;
mod mobaxterm;
mod mremoteng;
mod putty;
mod remmina;
mod sessions;

/// A reader of the sessions of one program.
type Reader = fn(&[Input]) -> Result<sessions::Read, String>;

/// A file of another program, as read: its name and its bytes.
pub struct Input {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// The arguments of `podssh config`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigArgs {
    pub subcommand: Option<String>,
    pub args: Vec<String>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

/// The formats that need a real export of their program to be tested
/// against, published under a license that this repository can hold, which
/// podssh does not have yet (T-292, T-328).
const NOT_YET: &[&str] = &["finalshell", "termius", "ansible-yaml"];

/// The largest file read: far above any host list.
const MAX_FILE: u64 = 16 << 20;

/// The formats of `import`, each with what it reads: the help, the refusal
/// of another word and the readers take this one table (T-973).
pub const FORMATS: &[(&str, &str)] = &[
    ("ansible", "an Ansible inventory, INI"),
    ("putty", "PuTTY's sessions, a .reg export or its session files"),
    ("mobaxterm", "MobaXterm's sessions, .mxtsessions or MobaXterm.ini"),
    ("remmina", "Remmina's profiles, .remmina files or their directory"),
    ("mremoteng", "mRemoteNG's connections, confCons.xml"),
];

/// The names of [`FORMATS`] as a line says them: `a, b or c`.
pub fn format_names() -> String {
    let names: Vec<&str> = FORMATS.iter().map(|(name, _)| *name).collect();
    match names.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
        _ => names.join(""),
    }
}

/// The help of `import`'s arguments: each format, with what it reads.
pub fn formats_help() -> String {
    // One sentence for each format, as a sentence of the manual holds 25 words at most.
    let each: Vec<String> = FORMATS.iter().map(|(name, what)| format!("{name} reads {what}.")).collect();
    format!("import: the format, then the file, - for stdin. The format is {}. {}", format_names(), each.join(" "))
}

pub fn run(args: &ConfigArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match (args.subcommand.as_deref(), args.args.as_slice()) {
        (Some("import"), [format, file]) => import(format, file, out, err),
        (Some("import"), _) => usage(err, "give the format and the file: podssh config import ansible FILE"),
        (Some(other), _) => usage(err, &format!("{other}: not a subcommand of config; it has import")),
        (None, _) => usage(err, "give a subcommand: podssh config import FORMAT FILE"),
    }
}

fn usage(err: &mut dyn Write, why: &str) -> i32 {
    let _ = writeln!(err, "podssh config: {why}");
    EXIT_USAGE
}

fn import(format: &str, file: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let format = format.to_ascii_lowercase();
    if NOT_YET.contains(&format.as_str()) {
        return usage(
            err,
            &format!("import {format}: not yet; it waits for a real export of that program to be tested against"),
        );
    }
    // The extension of a program's files in a directory, where it has one.
    let (reader, program, only): (Reader, &str, Option<&str>) = match format.as_str() {
        "ansible" => return inventory(file, out, err),
        "putty" => (putty::read, "PuTTY", None),
        "mobaxterm" => (mobaxterm::read, "MobaXterm", None),
        "remmina" => (remmina::read, "Remmina", Some(remmina::EXTENSION)),
        "mremoteng" => (mremoteng::read, "mRemoteNG", None),
        _ => {
            let why = format!("import {format}: not a format; give {}", format_names());
            return usage(err, &why);
        }
    };
    let (inputs, passed) = match inputs(file, only) {
        Ok(found) => found,
        Err(why) => {
            let _ = writeln!(err, "podssh config import: {file}: {why}");
            return EX_NOINPUT;
        }
    };
    let read = match reader(&inputs) {
        Ok(read) => read,
        Err(why) => {
            let _ = writeln!(err, "podssh config import: {why}");
            return EX_DATAERR;
        }
    };
    let blocks = sessions::write(&read, program, file);
    let _ = out.write_all(blocks.text.as_bytes());
    // A file of the directory that is no file of the program (a backup, a
    // swap file) is named, not read, and stops nothing (T-1064).
    if let Some(ext) = only {
        for name in &passed {
            let _ = writeln!(err, "podssh config import: {name}: passed over: not a .{ext} file");
        }
    }
    let _ = writeln!(err, "{}", blocks.summary(file));
    0
}

/// An Ansible inventory, which is text.
fn inventory(file: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let text = match read(file) {
        Ok(Ok(text)) => text,
        Err(why) => {
            let _ = writeln!(err, "podssh config import: {file}: {why}");
            return EX_NOINPUT;
        }
        // Bytes that are no text are bad data, as each "not UTF-8" of podssh
        // (65), not a file that cannot be read (T-1052).
        Ok(Err(why)) => {
            let _ = writeln!(err, "podssh config import: {file}: {why}");
            return EX_DATAERR;
        }
    };
    // Ansible's YAML or JSON is refused by name, as the word ansible-yaml
    // is, not read as INI into blocks of nonsense (T-1060).
    if let Some((form, line)) = ansible::other_form(&text) {
        let why = format!("an inventory in {form}, which import does not read yet; give its INI form");
        let _ = writeln!(err, "podssh config import: {file}:{line}: {why}");
        return EXIT_USAGE;
    }
    let hosts = match ansible::read(&text) {
        Ok(hosts) => hosts,
        Err(why) => {
            let _ = writeln!(err, "podssh config import: {file}:{why}");
            return EX_DATAERR;
        }
    };
    let blocks = write(&hosts, file);
    let _ = out.write_all(blocks.text.as_bytes());
    for refused in &blocks.refused {
        let _ = writeln!(err, "podssh config import: {refused}: not a name that a Host line can hold; not imported");
    }
    let _ = writeln!(err, "{}", blocks.summary(file));
    0
}

/// A file of text, `-` for stdin: `Err` when it cannot be read, `Ok(Err)`
/// when its bytes are no UTF-8 text.
fn read(file: &str) -> Result<Result<String, String>, String> {
    Ok(String::from_utf8(bytes(file)?).map_err(|_| "not UTF-8 text".into()))
}

/// The bytes of a file, `-` for stdin.
fn bytes(file: &str) -> Result<Vec<u8>, String> {
    if file == "-" {
        read_limited(std::io::stdin())
    } else {
        bytes_path(std::path::Path::new(file))
    }
}

/// The bytes of a file by its path (so non-UTF-8 directory entries still open).
fn bytes_path(path: &std::path::Path) -> Result<Vec<u8>, String> {
    read_limited(std::fs::File::open(path).map_err(|e| podssh_ws::text::said(&e))?)
}

fn read_limited(reader: impl std::io::Read) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    reader.take(MAX_FILE + 1).read_to_end(&mut bytes).map_err(|e| podssh_ws::text::said(&e))?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(format!("larger than {} MiB, which no host list is", MAX_FILE >> 20));
    }
    Ok(bytes)
}

/// The files of FILE: itself, or each file of a directory in the order of
/// their names, as PuTTY on Unix and Remmina keep one file for each session.
/// With `only`, a directory's files of another extension are not read: the
/// second list names them (T-1064). A FILE named is read whatever its name.
fn inputs(file: &str, only: Option<&str>) -> Result<(Vec<Input>, Vec<String>), String> {
    let path = std::path::Path::new(file);
    if file == "-" || !path.is_dir() {
        return Ok((vec![Input { name: file.to_string(), bytes: bytes(file)? }], Vec::new()));
    }
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(path)
        .map_err(|e| podssh_ws::text::said(&e))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    let (files, passed): (Vec<_>, Vec<_>) = files
        .into_iter()
        .partition(|p| only.is_none_or(|ext| p.extension().is_some_and(|e| e.eq_ignore_ascii_case(ext))));
    if files.is_empty() {
        let why =
            only.map_or_else(|| "a directory with no file".into(), |ext| format!("a directory with no .{ext} file"));
        return Err(why);
    }
    let read = files
        .iter()
        .map(|p| {
            let name = p.display().to_string();
            bytes_path(p).map(|bytes| Input { name, bytes }).map_err(|why| format!("{}: {why}", p.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((read, passed.iter().map(|p| p.display().to_string()).collect()))
}

/// The variables of a host that hold a secret: never imported, never
/// printed, counted.
fn secret(name: &str) -> bool {
    name.to_ascii_lowercase().contains("pass")
}

/// The variables whose words Ansible adds to ssh's command line.
const SSH_ARGS: &[&str] = &["ansible_ssh_common_args", "ansible_ssh_extra_args"];

/// The keywords that run a command, which can hold a secret: named in a
/// comment, with no value.
const COMMANDS: &[&str] = &["proxycommand", "localcommand", "remotecommand", "knownhostscommand"];

/// The words that Ansible adds to ssh's command line, as lines of a block:
/// each `-o KEYWORD=VALUE`, and `-J` as `ProxyJump`. A keyword that runs a
/// command, and another flag, are named in a comment, with no value.
fn ssh_args(name: &str, value: &str, out: &mut String) {
    let Ok(words) = ansible::split(value) else {
        out.push_str(&format!("  # {name} is not imported: a quote in it is not closed\n"));
        return;
    };
    let mut words = words.into_iter();
    while let Some(word) = words.next() {
        let option = match word.as_str() {
            "-o" => words.next(),
            "-J" => {
                if let Some(hosts) = words.next() {
                    setting(out, "ProxyJump", &hosts);
                }
                continue;
            }
            w => w.strip_prefix("-o").filter(|o| !o.is_empty()).map(str::to_string),
        };
        let Some(option) = option else {
            if word.starts_with('-') {
                out.push_str(&format!("  # the ssh flag {word} of {name} is not imported\n"));
            }
            continue;
        };
        let at = option.find(|c: char| c == '=' || c.is_whitespace()).unwrap_or(option.len());
        let (keyword, value) =
            (&option[..at], option[at..].trim_start_matches(|c: char| c == '=' || c.is_whitespace()));
        if COMMANDS.contains(&keyword.to_ascii_lowercase().as_str()) {
            out.push_str(&format!("  # {keyword} of {name} is not imported: a command can hold a secret\n"));
        } else {
            setting(out, keyword, value);
        }
    }
}

/// One line of a block, the value quoted when it holds a space.
fn setting(out: &mut String, keyword: &str, value: &str) {
    if value.contains('"') {
        out.push_str(&format!("  # {keyword}: its value holds a double quote, which ssh_config cannot\n"));
    } else if value.contains(char::is_whitespace) {
        out.push_str(&format!("  {keyword} \"{value}\"\n"));
    } else {
        out.push_str(&format!("  {keyword} {value}\n"));
    }
}

/// What `import` wrote.
#[derive(Debug, Default)]
pub struct Blocks {
    pub text: String,
    pub hosts: usize,
    pub secrets: usize,
    pub not_ssh: usize,
    pub refused: Vec<String>,
}

impl Blocks {
    fn summary(&self, file: &str) -> String {
        let mut line = format!("podssh config import: {} {} from {file}", self.hosts, plural(self.hosts, "host"));
        if self.secrets > 0 {
            line.push_str(&format!(
                "; {} {} not imported",
                self.secrets,
                if self.secrets == 1 { "password was" } else { "passwords were" }
            ));
        }
        if self.not_ssh > 0 {
            line.push_str(&format!(
                "; {} {} reached with no SSH, in a comment",
                self.not_ssh,
                plural(self.not_ssh, "host")
            ));
        }
        if !self.refused.is_empty() {
            line.push_str(&format!("; {} refused", self.refused.len()));
        }
        line
    }
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        word.to_string()
    } else {
        format!("{word}s")
    }
}

/// The value of the variable that Ansible's ssh connection takes: the last
/// of `names` that is set wins, as its options read them.
fn connection<'a>(host: &'a ansible::Host, names: &[&str]) -> Option<&'a str> {
    names.iter().rev().find_map(|n| host.vars.get(*n)).map(String::as_str)
}

/// The `Host` blocks of `hosts`, read from `file`.
pub fn write(hosts: &[ansible::Host], file: &str) -> Blocks {
    let mut b = Blocks::default();
    b.text.push_str(&format!("# The Ansible inventory {file}, as podssh config import read it.\n"));
    for host in hosts {
        b.secrets += host.vars.keys().filter(|k| secret(k)).count();
        if host.name.chars().any(|c| c.is_whitespace() || matches!(c, '*' | '?' | '!' | '"' | '#')) {
            b.refused.push(host.name.clone());
            continue;
        }
        let groups = if host.groups.is_empty() { String::new() } else { format!(" (in {})", host.groups.join(", ")) };
        if let Some(other) =
            connection(host, &["ansible_connection"]).filter(|c| !matches!(*c, "ssh" | "smart" | "paramiko"))
        {
            b.not_ssh += 1;
            b.text.push_str(&format!("\n# {}{groups}: ansible_connection={other}, no SSH; no Host block\n", host.name));
            continue;
        }
        b.hosts += 1;
        b.text.push_str(&format!("\n# {}{groups}\nHost {}\n", host.name, host.name));
        let settings = [
            ("HostName", connection(host, &["ansible_host", "ansible_ssh_host"])),
            ("Port", connection(host, &["ansible_port", "ansible_ssh_port"])),
            ("User", connection(host, &["ansible_user", "ansible_ssh_user"])),
            ("IdentityFile", connection(host, &["ansible_private_key_file", "ansible_ssh_private_key_file"])),
        ];
        for (keyword, value) in settings {
            match value {
                None => {}
                Some(v) if keyword == "HostName" && v == host.name => {}
                Some(v) => setting(&mut b.text, keyword, v),
            }
        }
        // After Ansible's own settings, as on its command line, where the
        // first value wins, as in a block.
        for name in SSH_ARGS {
            if let Some(value) = host.vars.get(*name) {
                ssh_args(name, value, &mut b.text);
            }
        }
        if host.vars.contains_key("ansible_ssh_args") {
            b.text.push_str("  # ansible_ssh_args is not imported: it holds ssh's flags for each host\n");
        }
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!("podssh-config-import-mod-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Directory filtering (T-1064): only matching extensions (case-insensitive)
    /// are read; stray files are passed over without being opened; subdirectories
    /// are ignored; an empty or non-matching directory fails cleanly; a single
    /// named file is read regardless of its extension.
    #[test]
    fn directory_inputs_filter_by_extension_and_pass_over_others() {
        let dir = Scratch::new("filter");
        for name in ["a.remmina", "B.REMMINA", "README", ".a.remmina.swp", "a.remmina~", ".remmina"] {
            std::fs::write(dir.0.join(name), name).unwrap();
        }
        std::fs::create_dir_all(dir.0.join("sub")).unwrap();
        let (read, passed) = inputs(&dir.0.display().to_string(), Some(remmina::EXTENSION)).unwrap();
        let base = |list: Vec<String>| -> Vec<String> {
            let mut out: Vec<String> = list
                .iter()
                .map(|p| std::path::Path::new(p).file_name().unwrap().to_string_lossy().into_owned())
                .collect();
            out.sort();
            out
        };
        assert_eq!(base(read.into_iter().map(|i| i.name).collect()), vec!["B.REMMINA", "a.remmina"]);
        assert_eq!(base(passed), vec![".a.remmina.swp", ".remmina", "README", "a.remmina~"]);

        let single = dir.0.join("README").display().to_string();
        let (read, passed) = inputs(&single, Some(remmina::EXTENSION)).unwrap();
        assert_eq!((read.len(), passed.len()), (1, 0));

        let stray = Scratch::new("stray");
        std::fs::write(stray.0.join("README"), "notes").unwrap();
        assert_eq!(
            inputs(&stray.0.display().to_string(), Some(remmina::EXTENSION)).err().as_deref(),
            Some("a directory with no .remmina file")
        );

        let empty = Scratch::new("empty");
        assert_eq!(inputs(&empty.0.display().to_string(), None).err().as_deref(), Some("a directory with no file"));
        assert_eq!(
            inputs(&empty.0.display().to_string(), Some(remmina::EXTENSION)).err().as_deref(),
            Some("a directory with no .remmina file")
        );
    }
}
