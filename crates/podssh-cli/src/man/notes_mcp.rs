//! The notes of `podssh mcp` (T-055), apart from the others so that each
//! file stays short.

pub const MCP: &[&str] = &[
    "podssh mcp is a server of the Model Context Protocol on stdin and stdout, for an agent that runs it: each line \
     of stdin is one JSON-RPC message and each line of stdout one answer, and podssh's own words go to stderr. It \
     answers a client of the revision 2026-07-28, whose requests name their version in _meta. It also answers one \
     that opens with initialize (2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05). It ends at the end of stdin, \
     and each call then in flight ends with it. A message that is neither a request nor a response gets JSON-RPC's \
     error Invalid Request (code minus 32600).",
    "The tools: ssh_exec runs one command on a host (destination [user@]host, command, and stdin, timeout_seconds \
     and host_key_fingerprint at will); its result has podssh's exit code, the command's status or signal, how the \
     session ended and why it failed, stdout, stderr and timed_out. stdout and stderr are at most 1 MiB each, \
     truncated says so, and output that is not UTF-8 comes as base64. status, doctor and man give what podssh \
     status, podssh doctor and podssh man give, in their JSON form.",
    "THE RISK: an agent with ssh_exec runs commands on each allowed host, as you, with your keys and your \
     ssh_config. The words of a call come from a model, and text that the model read can ask it for a \
     command or a host; so ssh_exec reaches no host unless --allow-host names it, and is not offered with \
     none. Name each host, or the fewest patterns that hold them; !PATTERN excludes, and a pattern with \
     USER@ needs a destination that names that user. The host is matched as the call names it, before the \
     HostName of your configuration. --allow-command limits ssh_exec alone: job_start and session_start run any \
     command, session_send types any text into a shell, and cp_put writes any file. For an agent that may run only \
     the patterns, add --read-only too: it removes job_start, job_stop, cp_put and each session_ tool. A line on \
     stderr names the tools that a pattern leaves open, at the start.",
    "For an agent that watches and must not change: --read-only offers no tool that changes a host, no job_start, \
     job_stop, cp_put or session_ tool, and refuses a call of one by name; ssh_exec is then offered only with \
     --allow-command. --allow-command PATTERN, repeated, names what ssh_exec may run: a pattern is words, the \
     program as typed and * for one word of any text. A command matches when its words are as many and each the \
     pattern's. A command with a character that the remote shell reads as more than a word's text (; | & $ ` < > ( ) \
     \\ quotes, a newline, ~ # ! = %, and the globs * ? [ ] { }) is refused, as the shell would run more than the \
     pattern says. The patterns are named in ssh_exec's description, and a pattern whose program is * is refused \
     (64).",
    "Each call runs podssh ssh as a child, with BatchMode=yes (no prompt, ever) and StrictHostKeyChecking=yes. So a \
     host whose key known_hosts does not hold is refused, unless host_key_fingerprint names its key, as \
     --host-key-fingerprint. The child has no pty, no escape character, no forwarding of a port, an agent or X11, \
     and no shared connection; these come before -F FILE, so a file cannot undo them. A call past its limit (60 s, \
     or timeout_seconds, at most 3600) ends its session, as a cancelled call does; four calls run at once, and the \
     others wait.",
    "With a host allowed, health and the job_ tools are offered too. Each is a child of its verb with the same \
     options and the same check of --allow-host, and a host key that known_hosts holds: health gives podssh health \
     --json; job_start runs a command in the host's tmux that outlives the call, and gives its id; job_list, job_log \
     (a window of the output: offset, max_bytes, and more when bytes follow), job_wait (until the job ends, at most \
     wait_seconds; a job that runs on is a result, ended false, to call again) and job_stop take that id.",
    "cp_put and cp_get copy with podssh cp between a path of this host and a path of an allowed host. Each file's \
     SHA-256 is checked at both ends; they are offered only with --allow-dir DIR, as --allow-host lets an agent \
     reach a host, not read the files of this one. A local path is resolved, its links followed, and refused unless \
     it lies inside a DIR, before anything runs; a relative one is under the first DIR. A DIR that holds ~/.ssh or \
     podssh's cache, or lies inside one, and the root, are refused (64). A DIR that is not there is 78. cp_put takes \
     content in place of local_path, the bytes of one file in base64, 1 MiB at most; cp_get puts a tree (recursive) \
     only into a path that is not there. A tree goes as podssh cp -r copies it, a link as a link. The result has the \
     exit and the events of podssh cp --jsonl.",
    "--allow-session offers session_start, session_send, session_wait, session_capture and session_stop: a \
     shell with a pty on an allowed host, held by podssh session between the calls. The server drives only \
     the sessions that it started, never one of yours, and stops each as it ends; the text of session_send \
     goes on the child's stdin, never on a command line.",
    "--client-config CLIENT (claude-desktop, cursor, vscode or gemini) prints the JSON entry that the client reads \
     to start this server, and starts none: its command is this binary's absolute path, as a client started from a \
     launcher may not have the shell's PATH. Its args are mcp and the other flags in the order typed, checked as a \
     run checks them (64, 78), each path made absolute. VS Code's entry is under servers with type stdio, the \
     others' under mcpServers. A line on stderr says where the client's documents say that it reads the entry; the command writes \
     no file of the client's. Another CLIENT is 64.",
];
