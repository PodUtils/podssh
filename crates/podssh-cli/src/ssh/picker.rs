//! A host picker (T-188): `podssh ssh` with no destination, when stdin and
//! stdout are both terminals, lists the literal `Host` names of ssh_config
//! (T-043) with a number each, and logs in to the one picked as if it were
//! typed. In each other case nothing is read, and the run refuses as before
//! (64): a script still gets its usage error. The list is never a guess: no
//! pattern, no negated name, and no name of `known_hosts`, whose names can
//! be hashed. Beside each name it shows what a connection to it resolves
//! (T-832, [`super::list_hosts`]): the user, the host, a port that is not 22
//! and the jump; a text narrows on all of them. Several numbers with a
//! command hand the names to `podssh each`, which runs it on each. With no
//! destination, a word after the flags is the destination, so the command
//! comes by `-o RemoteCommand=COMMAND` or `--snippet NAME` (T-864).

use podssh_ssh::Hop;

use super::args::SshArgs;
use super::config::{Context, Given};
use super::options::Settings;
use super::resolve::Env;
use crate::pager::Tty;
use crate::relay_settings::Refusal;

/// The refusal of a run with no destination, as the resolve words it.
const MISSING: &str = "missing destination: podssh ssh [user@]host [command]";
/// The most answers before the picker gives up.
const ROUNDS: usize = 20;

/// Who answers the picker: the terminal, or a test's answers.
pub trait Keys {
    /// One line typed after `prompt`, which shows the list.
    fn line(&mut self, prompt: &str) -> std::io::Result<String>;
}

/// The controlling terminal, as podssh asks each question there, with the
/// answer echoed; with no terminal it fails, and picks nothing.
pub struct Terminal;

impl Keys for Terminal {
    fn line(&mut self, prompt: &str) -> std::io::Result<String> {
        podssh_ssh::terminal::read_line(prompt, true).map(|line| line.as_str().to_string())
    }
}

/// Whether the picker is shown: no destination, and stdin and stdout both
/// terminals, as a person is there to read the list and to answer it.
pub fn wanted(args: &SshArgs, tty: Tty) -> bool {
    args.destination.is_none() && tty.stdin && tty.stdout
}

/// The literal `Host` names of the ssh_config files of `args` and `env`:
/// `-F`, else `PODSSH_SSH_CONFIG`, else `~/.ssh/config` and the system's
/// file, with their `Include`s, in that order.
pub fn names(args: &SshArgs, env: &Env) -> Result<Vec<String>, String> {
    let source = super::config::file(args.config.as_deref(), env.ssh_config.as_deref(), env.home.as_deref());
    // No host is known yet: `%h` and `%n` of an `Include` are empty.
    let target = Hop { user: None, host: String::new(), port: 22, tls: false };
    let cli = Settings::default();
    let tokens = |file: &Settings| super::tokens::include_tokens(args, &cli, &target, env, file);
    let ctx = Context {
        host: "",
        home: env.home.as_deref(),
        system: env.system_config.as_deref(),
        tokens: &tokens,
        given: Given { local_user: env.user.as_deref(), ..Given::default() },
    };
    let names = super::config::host_names(&source, &ctx)?;
    // A comma, a brace or a leading `@` makes a word of many hosts (T-184):
    // such a name is never one destination, here or typed.
    Ok(names.into_iter().filter(|name| !crate::hosts::is_pattern(name)).collect())
}

/// `args` with the destination picked, when the picker is wanted and
/// ssh_config has names; `None` else, so that the run refuses as before.
/// Each end with no host picked is a refusal (64).
pub fn pick(args: &SshArgs, tty: Tty, env: &Env, keys: &mut dyn Keys) -> Result<Option<SshArgs>, Refusal> {
    if !wanted(args, tty) {
        return Ok(None);
    }
    let names =
        names(args, env).map_err(|why| Refusal::usage(format!("{MISSING}; no list of the Host names: {why}")))?;
    if names.is_empty() {
        return Ok(None);
    }
    let entry = |name: &String| Entry { detail: detail(args, env, name), name: name.clone() };
    let entries: Vec<Entry> = names.iter().map(entry).collect();
    // Several hosts take a command, which `podssh each` runs on each; a
    // shell needs this terminal alone.
    let several = given_command(args);
    let picked = choose_among(&entries, several, keys)?;
    Ok(Some(SshArgs { destination: Some(picked.join(",")), ..args.clone() }))
}

/// Whether the command line gives a command that `podssh each` can run on
/// several hosts: the words after the destination, `--snippet NAME`, or
/// `-o RemoteCommand=COMMAND`. With no destination, only the last two can
/// be given: the first word after the flags is the destination, as in
/// OpenSSH. `RemoteCommand none` is no command, as OpenSSH reads it.
pub fn given_command(args: &SshArgs) -> bool {
    !args.command.is_empty() || args.snippet.is_some() || remote_command(args).is_some()
}

/// The `RemoteCommand` of `-o` and of its long form, the first one given,
/// when it is a command. A bad `-o` is skipped here: the run refuses it
/// where it resolves, with its words.
fn remote_command(args: &SshArgs) -> Option<String> {
    let mut settings = Settings::default();
    for raw in args.options.iter().chain(&args.long_options) {
        let _ = settings.apply(raw);
    }
    settings.remote_command.filter(|c| !c.trim().is_empty() && !c.eq_ignore_ascii_case("none"))
}

/// What the list shows beside `name`: its record's user, host, port and
/// jump, resolved as a run resolves them; nothing when it resolves none, as
/// the run then says why.
fn detail(args: &SshArgs, env: &Env, name: &str) -> String {
    let record = super::list_hosts::record(args, env, name);
    record.resolved.map(|f| super::list_hosts::detail(&f)).unwrap_or_default()
}

/// The run of `podssh each` for the names that the picker gave, when it
/// gave more than one: the names as its comma list, the command and the
/// flags as they are. `None` for one name, which `podssh ssh` takes.
pub fn to_each(picked: &SshArgs) -> Option<crate::each::EachArgs> {
    let word = picked.destination.as_deref().filter(|word| word.contains(','))?;
    // The result of this run is `ssh`'s, which writes it at its end.
    let ssh = SshArgs { destination: None, result_file: None, ..picked.clone() };
    Some(crate::each::EachArgs { hosts: Some(word.to_string()), ssh, ..crate::each::EachArgs::default() })
}

/// One line of the list: a name, and what a connection to it resolves
/// (empty when nothing is shown).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub detail: String,
}

/// One name of `names`, as the person answers: a number of the list picks
/// that name, and other text narrows the list to the names that hold it,
/// case set aside. An empty line, the end of input (Ctrl-D) and a terminal
/// that fails pick none.
pub fn choose(names: &[String], keys: &mut dyn Keys) -> Result<String, Refusal> {
    let entries: Vec<Entry> = names.iter().map(|name| Entry { name: name.clone(), detail: String::new() }).collect();
    let mut picked = choose_among(&entries, false, keys)?;
    Ok(picked.remove(0))
}

/// The names of `entries` that the person picks: a number picks its name;
/// with `several`, numbers parted by commas or blanks pick each (once, in
/// the order typed). Other text narrows the list to the entries whose name
/// or detail holds it, case set aside. An empty line, the end of input and
/// a terminal that fails pick none. Each refusal is 64.
pub fn choose_among(entries: &[Entry], several: bool, keys: &mut dyn Keys) -> Result<Vec<String>, Refusal> {
    let mut list: Vec<&Entry> = entries.iter().collect();
    let mut note = String::new();
    for _ in 0..ROUNDS {
        let prompt = format!("{}{note}{}", lines(&list), question(list.len(), several));
        let line = keys.line(&prompt).map_err(|e| Refusal::usage(format!("{MISSING}; the host picker: {e}")))?;
        let answer = line.trim();
        if answer.is_empty() {
            return Err(Refusal::usage(format!("{MISSING}; no host was picked")));
        }
        if let Some(words) = numbers(answer) {
            let mut picked: Vec<String> = Vec::new();
            let mut outside = None;
            for (word, n) in words {
                match n.checked_sub(1).and_then(|i| list.get(i)) {
                    Some(entry) if picked.contains(&entry.name) => {}
                    Some(entry) => picked.push(entry.name.clone()),
                    None => {
                        outside = Some(word);
                        break;
                    }
                }
            }
            note = match outside {
                Some(word) => format!("{word} is not a number of the list.\n"),
                None if picked.len() > 1 && !several => {
                    "Several hosts take a command (-o RemoteCommand=COMMAND), which podssh each runs on each; \
                     pick one host for a shell.\n"
                        .to_string()
                }
                None => return Ok(picked),
            };
            continue;
        }
        let lower = answer.to_lowercase();
        let holds = |e: &&Entry| e.name.to_lowercase().contains(&lower) || e.detail.to_lowercase().contains(&lower);
        let narrowed: Vec<&Entry> = list.iter().copied().filter(holds).collect();
        if narrowed.is_empty() {
            note = format!("No host of the list holds {answer}.\n");
        } else {
            list = narrowed;
            note.clear();
        }
    }
    Err(Refusal::usage(format!("{MISSING}; no host was picked in {ROUNDS} answers")))
}

/// The list, a number on each line; a detail in a column after the names,
/// and no blank at the end of a line with none.
fn lines(list: &[&Entry]) -> String {
    let width = list.iter().filter(|e| !e.detail.is_empty()).map(|e| e.name.chars().count()).max().unwrap_or(0);
    let mut text = String::new();
    for (i, entry) in list.iter().enumerate() {
        let n = i + 1;
        if entry.detail.is_empty() {
            text.push_str(&format!("{n:>4}  {}\n", entry.name));
        } else {
            text.push_str(&format!("{n:>4}  {:<width$}  {}\n", entry.name, entry.detail));
        }
    }
    text
}

fn question(count: usize, several: bool) -> String {
    if several {
        format!("Host to log in to, 1 to {count}, several numbers for podssh each, or text that narrows the list: ")
    } else {
        format!("Host to log in to, 1 to {count}, or text that narrows the list: ")
    }
}

/// Each word of `answer` with its number, when each word is a number: the
/// words are parted by commas and blanks. `None` when one is not, as the
/// answer is then a text that narrows.
fn numbers(answer: &str) -> Option<Vec<(&str, usize)>> {
    let words: Vec<&str> = answer.split(|c: char| c == ',' || c.is_whitespace()).filter(|w| !w.is_empty()).collect();
    if words.is_empty() {
        return None;
    }
    words.into_iter().map(|w| w.parse::<usize>().ok().map(|n| (w, n))).collect()
}
