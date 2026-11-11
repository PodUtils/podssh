//! `podssh mcp --client-config CLIENT` (T-751): for each client, the entry
//! that it prints is started as the client starts it, its command and its
//! arguments taken from the JSON, and its `tools/list` is what the flags
//! promise: `ssh_exec` with an `--allow-host`, none without; the copies only
//! with an `--allow-dir`. The command is an absolute path. Another client,
//! or a pattern that is not one, is 64 and prints nothing.

mod cleanup;
mod mcp_harness;
mod ssh_harness;

use std::path::Path;
use std::process::{Command, Stdio};

use mcp_harness::{podssh, scratch, Mcp};
use serde_json::Value;

/// `podssh mcp --client-config CLIENT ARGS`: (code, stdout, stderr).
fn print(dir: &Path, client: &str, args: &[&str]) -> (i32, String, String) {
    let out = podssh(dir)
        .args(["mcp", "--client-config", client])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("podssh runs");
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// The entry's command and arguments, from the client's shape.
fn entry(client: &str, printed: &str) -> (String, Vec<String>) {
    let doc: Value = serde_json::from_str(printed).unwrap_or_else(|_| panic!("JSON: {printed}"));
    let key = if client == "vscode" { "servers" } else { "mcpServers" };
    let server = &doc[key]["podssh"];
    if client == "vscode" {
        assert_eq!(server["type"], "stdio", "{printed}");
    }
    let command = server["command"].as_str().expect("a command").to_string();
    let args = server["args"].as_array().expect("args").iter().map(|a| a.as_str().unwrap().to_string()).collect();
    (command, args)
}

/// The tools of the server that the entry starts.
fn tools(dir: &Path, command: &str, args: &[String]) -> Vec<String> {
    let mut cmd = Command::new(command);
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
    cmd.env("HOME", dir).env("USERPROFILE", dir).env("PODSSH_CACHE_DIR", dir.join("cache"));
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let mut mcp = Mcp::spawn(cmd);
    mcp.initialize();
    let names = mcp.tool_names();
    let _ = mcp.close();
    names
}

#[test]
fn each_client_s_entry_starts_a_server_that_offers_what_its_flags_promise() {
    let dir = scratch("client-config");
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let out_text = out.to_string_lossy().into_owned();
    for client in ["claude-desktop", "cursor", "vscode", "gemini"] {
        let (code, printed, said) = print(&dir, client, &["--allow-host", "build-*", "--allow-dir", &out_text]);
        assert_eq!(code, 0, "{client}: {said}");
        let (command, args) = entry(client, &printed);
        assert!(Path::new(&command).is_absolute() && Path::new(&command).is_file(), "{command}");
        assert!(said.contains("writes no file"), "{said}");
        let names = tools(&dir, &command, &args);
        assert!(names.iter().any(|n| n == "ssh_exec"), "{client}: {names:?}");
        assert!(names.iter().any(|n| n == "cp_put"), "{client}: {names:?}");
    }
    let (code, printed, said) = print(&dir, "cursor", &[]);
    assert_eq!(code, 0, "{said}");
    assert!(said.contains("no --allow-host"), "{said}");
    let (command, args) = entry("cursor", &printed);
    let names = tools(&dir, &command, &args);
    assert!(!names.iter().any(|n| n == "ssh_exec" || n == "cp_put"), "no host, no copy: {names:?}");
}

#[test]
fn another_client_and_a_bad_pattern_are_refused_with_nothing_printed() {
    let dir = scratch("client-config-bad");
    for (client, args) in [("emacs", &[][..]), ("cursor", &["--allow-host", "a b"][..])] {
        let (code, printed, said) = print(&dir, client, args);
        assert_eq!(code, 64, "{client} {args:?}: {said}");
        assert!(printed.is_empty(), "{printed}");
    }
    let (code, _, said) = print(&dir, "cursor", &["-F", dir.join("none").to_str().unwrap()]);
    assert_eq!(code, 78, "{said}");
}
