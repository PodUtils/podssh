//! `podssh mcp --client-config CLIENT` (T-751, the block "agentanycast 3" of
//! PodUtils/podnet#438): the JSON that an agent's client reads to start
//! this server, for the flags typed. The command is the absolute path of
//! this binary, as a desktop client started from a launcher may not have
//! the shell's `PATH` (Inferred); the arguments are `mcp` and the flags,
//! checked as a run checks them, so that a printed entry is never one that
//! the server refuses, with each path made absolute, as the client starts
//! the server from a directory of its own. It starts no server, and writes
//! no file of the client's: their places change with their releases.

use std::io::Write;
use std::path::Path;

use serde_json::{json, Value};

use super::allow::Allow;
use super::dirs;
use super::McpArgs;
use crate::exitmap::sysexits::{EX_CONFIG, EX_SOFTWARE, EX_USAGE};

/// The clients, and where each one's documents say that it reads the entry.
pub const CLIENTS: &[(&str, &str)] = &[
    ("claude-desktop", "claude_desktop_config.json, under mcpServers"),
    ("cursor", ".cursor/mcp.json of a project, or ~/.cursor/mcp.json, under mcpServers"),
    ("vscode", ".vscode/mcp.json of a workspace, under servers"),
    ("gemini", "~/.gemini/settings.json, under mcpServers"),
];

/// The arguments of the entry: `mcp`, then the flags in the order typed
/// (T-985), with the directories as resolved and `-F`'s file made
/// absolute. With no order kept, the order of the fields.
pub fn arguments(args: &McpArgs, dirs: &[std::path::PathBuf], config: Option<&Path>) -> Vec<String> {
    if args.typed.is_empty() {
        return fixed(args, dirs, config);
    }
    let pair = |flag: &str, value: String| vec![flag.to_string(), value];
    let mut out = vec!["mcp".to_string()];
    let (mut hosts, mut dirs, mut commands) = (args.allow_host.iter(), dirs.iter(), args.allow_command.iter());
    let mut config = config;
    for id in &args.typed {
        let words = match *id {
            "allow-host" => hosts.next().map(|p| pair("--allow-host", p.clone())),
            "allow-dir" => dirs.next().map(|d| pair("--allow-dir", d.display().to_string())),
            "allow-command" => commands.next().map(|p| pair("--allow-command", p.clone())),
            "config" => config.take().map(|f| pair("-F", f.display().to_string())),
            "allow-session" => args.allow_session.then(|| vec!["--allow-session".to_string()]),
            "read-only" => args.read_only.then(|| vec!["--read-only".to_string()]),
            "direct" => args.direct.then(|| vec!["--direct".to_string()]),
            _ => None,
        };
        out.extend(words.into_iter().flatten());
    }
    // What the order did not name still goes, so that no flag is lost.
    out.extend(hosts.flat_map(|p| pair("--allow-host", p.clone())));
    out.extend(dirs.flat_map(|d| pair("--allow-dir", d.display().to_string())));
    out.extend(commands.flat_map(|p| pair("--allow-command", p.clone())));
    out.extend(config.into_iter().flat_map(|f| pair("-F", f.display().to_string())));
    for (on, id, flag) in [
        (args.allow_session, "allow-session", "--allow-session"),
        (args.read_only, "read-only", "--read-only"),
        (args.direct, "direct", "--direct"),
    ] {
        if on && !args.typed.contains(&id) {
            out.push(flag.into());
        }
    }
    out
}

/// The arguments in the order of the fields: a caller that kept no order.
fn fixed(args: &McpArgs, dirs: &[std::path::PathBuf], config: Option<&Path>) -> Vec<String> {
    let mut out = vec!["mcp".to_string()];
    for pattern in &args.allow_host {
        out.extend(["--allow-host".to_string(), pattern.clone()]);
    }
    for dir in dirs {
        out.extend(["--allow-dir".to_string(), dir.display().to_string()]);
    }
    if args.allow_session {
        out.push("--allow-session".into());
    }
    if args.read_only {
        out.push("--read-only".into());
    }
    for pattern in &args.allow_command {
        out.extend(["--allow-command".to_string(), pattern.clone()]);
    }
    if let Some(file) = config {
        out.extend(["-F".to_string(), file.display().to_string()]);
    }
    if args.direct {
        out.push("--direct".into());
    }
    out
}

/// The client's document for `command` and `arguments`: VS Code's `servers`
/// with its `type`, the others' `mcpServers`. None for another client.
pub fn document(client: &str, command: &str, arguments: &[String]) -> Option<Value> {
    match client {
        "vscode" => {
            Some(json!({ "servers": { "podssh": { "type": "stdio", "command": command, "args": arguments } } }))
        }
        "claude-desktop" | "cursor" | "gemini" => {
            Some(json!({ "mcpServers": { "podssh": { "command": command, "args": arguments } } }))
        }
        _ => None,
    }
}

/// Print `client`'s entry to `out`: 0; 64 for another client or a pattern
/// that is not one, 78 for a `-F` file or a directory that is not there.
pub fn print(args: &McpArgs, client: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some((_, place)) = CLIENTS.iter().find(|(name, _)| *name == client) else {
        let names: Vec<&str> = CLIENTS.iter().map(|(name, _)| *name).collect();
        let _ = writeln!(err, "podssh mcp: --client-config {client}: one of {}", names.join(", "));
        return EX_USAGE;
    };
    let allow = match Allow::new(&args.allow_host) {
        Ok(allow) => allow,
        Err(why) => {
            let _ = writeln!(err, "podssh mcp: {why}");
            return EX_USAGE;
        }
    };
    let config = match args.config.as_deref().map(std::fs::canonicalize) {
        Some(Ok(file)) if file.is_file() => Some(file),
        Some(_) => {
            let _ = writeln!(err, "podssh mcp: -F {}: no such file", args.config.as_deref().unwrap_or_default());
            return EX_CONFIG;
        }
        None => None,
    };
    let dirs = match dirs::Dirs::new(&args.allow_dir, &dirs::key_dirs()) {
        Ok(dirs) => dirs,
        Err((code, why)) => {
            let _ = writeln!(err, "podssh mcp: {why}");
            return code;
        }
    };
    let binary = match std::env::current_exe().and_then(std::fs::canonicalize) {
        Ok(binary) => binary.display().to_string(),
        Err(e) => {
            let _ = writeln!(err, "podssh mcp: the path of this program: {}", podssh_ws::text::said(&e));
            return EX_SOFTWARE;
        }
    };
    let arguments = arguments(args, dirs.resolved(), config.as_deref());
    let Some(document) = document(client, &binary, &arguments) else { return EX_USAGE };
    let text = serde_json::to_string_pretty(&document).unwrap_or_default();
    if writeln!(out, "{text}").and_then(|()| out.flush()).is_err() {
        return EX_SOFTWARE;
    }
    let _ = writeln!(
        err,
        "podssh mcp: {client} reads this entry from {place}, as its documents say; this command writes no file"
    );
    if allow.is_empty() {
        let _ = writeln!(err, "podssh mcp: no --allow-host: the server it starts reaches no host");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_client_s_shape_and_the_flags_in_their_order() {
        let args =
            McpArgs { allow_host: vec!["build-*".into()], allow_session: true, direct: true, ..McpArgs::default() };
        let arguments = arguments(&args, &[std::path::PathBuf::from("/srv/out")], Some(Path::new("/etc/ssh_cfg")));
        let want = [
            "mcp",
            "--allow-host",
            "build-*",
            "--allow-dir",
            "/srv/out",
            "--allow-session",
            "-F",
            "/etc/ssh_cfg",
            "--direct",
        ];
        assert_eq!(arguments, want);
        let vscode = document("vscode", "/bin/podssh", &arguments).unwrap();
        assert_eq!(vscode["servers"]["podssh"]["type"], "stdio");
        for client in ["claude-desktop", "cursor", "gemini"] {
            let doc = document(client, "/bin/podssh", &arguments).unwrap();
            assert_eq!(doc["mcpServers"]["podssh"]["command"], "/bin/podssh", "{client}");
        }
        assert!(document("emacs", "/bin/podssh", &arguments).is_none());
    }

    /// The flags in the order typed (T-985): each kind where it stood, the
    /// values of one kind in their own order.
    #[test]
    fn the_flags_keep_the_order_typed() {
        let args = McpArgs {
            allow_host: vec!["b*".into(), "a*".into()],
            allow_command: vec!["uptime".into()],
            direct: true,
            read_only: true,
            typed: vec!["direct", "allow-host", "config", "allow-command", "allow-dir", "read-only", "allow-host"],
            ..McpArgs::default()
        };
        let got = arguments(&args, &[std::path::PathBuf::from("/srv/out")], Some(Path::new("/etc/c")));
        let want = [
            "mcp",
            "--direct",
            "--allow-host",
            "b*",
            "-F",
            "/etc/c",
            "--allow-command",
            "uptime",
            "--allow-dir",
            "/srv/out",
            "--read-only",
            "--allow-host",
            "a*",
        ];
        assert_eq!(got, want);
        // A flag that the order did not name is not lost.
        let missed = McpArgs { allow_session: true, typed: vec!["direct"], direct: true, ..McpArgs::default() };
        assert_eq!(arguments(&missed, &[], None), ["mcp", "--direct", "--allow-session"]);
    }

    #[test]
    fn another_client_and_a_bad_pattern_are_64() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(print(&McpArgs::default(), "emacs", &mut out, &mut err), EX_USAGE);
        assert!(String::from_utf8_lossy(&err).contains("one of claude-desktop, cursor, vscode, gemini"));
        let bad = McpArgs { allow_host: vec![String::new()], ..McpArgs::default() };
        assert_eq!(print(&bad, "cursor", &mut out, &mut Vec::new()), EX_USAGE);
        assert!(out.is_empty(), "nothing printed");
    }
}
