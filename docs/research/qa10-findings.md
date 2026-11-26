# QA pass 10 (T-809 black-box): job, session, detached/--detach, each, run, config, mcp, play, health, status

Binary: target/debug/podssh 1.1.0-beta.3. Test server: OpenSSH 127.0.0.1:2201. HOME and PODSSH_CACHE_DIR under .work/qa10/.
Every finding below was reproduced at least twice.

## Findings

### 1. `podssh play --speed` with a tiny value panics (exit 101, backtrace)  [defect]
Command: `podssh play --speed 1e-320 rec.cast` (also `5e-324`, and `--speed 1e-310 --idle-limit 1`)
Happened: exit 101, stderr `thread '<unnamed>' panicked at .../core/src/time.rs:962:23: cannot convert float seconds to Duration: value is either too big or NaN` plus a backtrace naming crates/podssh-cli/src/play.rs:87.
Manual (podssh man play; EXIT STATUS): `--speed FACTOR  play this many times as fast, ... (a number above 0)`; the flag check says "--speed 0: a number above 0" (exit 64) and 1e400 is refused with 64, so 1e-320 passes the check. AGENTS rule: no panic reaches the user. A value that makes a wait too long should be refused (64) or clamped; `--idle-limit` does not rescue it (the division is done first).

### 2. `podssh play` of a recording with a huge event time panics (exit 101)  [defect]
Command: `printf '{"version": 2, "width": 80, "height": 24}\n[1e300,"o","x\\n"]\n' > huge.cast; podssh play huge.cast`
Happened: exit 101, same panic (`cannot convert float seconds to Duration`).
Manual (play): "A time below 0 is refused as a bad line (exit 1)" and a file that cannot be played is exit 1. A time of 1e400 is refused (`huge.cast:2: not an event`, exit 1), a time of 1e300 panics. Expected one line, exit 1.

### 3. `podssh run --dry-run | head -c0` exits 74 with "Broken pipe"  [defect]
Command: `podssh run --direct -p 2201 ... --dry-run podtest@127.0.0.1:qa10proj -- x | head -c0` (PIPESTATUS[0])
Happened: stderr `podssh: the plan could not be written to stdout: Broken pipe`, exit 74 (three of three runs).
Manual (EXIT STATUS, 74): "A reader that went away, as head does, is no failure." Every other command tested (job log, each, session capture, health, play, status, config import, run without --dry-run) exits 0 at a closed pipe.

### 4. `podssh config import ansible FILE.yml` accepts a YAML inventory and prints bogus blocks  [defect / documentation]
Command: file `all:\n  hosts:\n    web1:\n` -> `podssh config import ansible y2.yml`
Happened: exit 0, stdout holds `Host all:`, `Host hosts:`, `Host web1:` (names with a colon taken as host:PORT), summary "3 hosts from y2.yml". A fuller YAML (with `ansible_host: 1.2.3.4`) gives exit 65 `inv.yml:4: 1.2.3.4: expected key=value`. A JSON file `{"all":{}}` gives `Host {all:{}}`, exit 0.
Manual (podssh man config): "The formats of FinalShell and Termius, and Ansible's YAML, are refused by name (exit 64)." The refusal exists only for the format word `ansible-yaml` (`config import ansible-yaml F` gives exit 64 "not yet"), a word that neither the usage line, the FORMAT list ("ansible, putty, mobaxterm, remmina or mremoteng") nor the manual gives. A user following the manual (`import ansible inventory.yml`) gets garbage in ~/.ssh/config. Suggest: detect a YAML/JSON inventory (`---`, `key:` lines at top, `{`) and refuse with 64, and name `ansible-yaml` or drop the claim.

### 5. `podssh each --output-dir ''` writes the files into the current directory  [nit]
Command: `cd e2; podssh each ... --output-dir '' HOST -- 'echo hello'` -> exit 0; HOST.out, HOST.err, HOST.status appear in the cwd (twice).
Manual (each): "--output-dir DIR ... The files are made before anything connects (73 when they cannot be)". An empty DIR is no directory; expected a usage error (64) or 73 as for `--output-dir afile` ("afile: File exists", 73).

### 6. `podssh job fetch` with an unwritable local DIR: exit 255 and a line that does not say what failed  [defect (exit code) / nit (message)]
Commands: `podssh job fetch ... HOST ID /proc/nope` ; `... ID /dev/null`
Happened: `podssh: /proc/nope: No such file or directory`, exit 255; `/dev/null: File exists` (it exists; it is not a directory), exit 255 (twice each).
Manual (podssh man job, last para): "255 when the host cannot be reached or logged in to, has no tmux, has no such job, or gives no answer"; EXIT STATUS 73: "podssh cp and mv: the destination cannot be written"; job fetch "copies the job's output to DIR/out, as podssh cp copies a file". The same failure in `podssh cp --timeout 20s ... host:b.txt /proc/nope/x` gives `/proc/nope/x: no such directory: /proc/nope`, exit 73. So fetch (a local fault) shares the code for "host unreachable", and a script cannot tell them apart. The same 255 for a remote file that cannot be opened with `--files '*.txt'` (`open nr.txt: permission denied`).

### 7. `podssh session start --socket BADPATH`: exit 69, internal word `unix-listen:` and an unrelated second line  [nit]
Command: `podssh session start s9 ... --socket /workspace/podssh/.work/qa10/nodir/x.sock HOST` (also `/proc/x.sock`, and a 200-byte name)
Happened (3 of 3): stderr
```
podssh session: unix-listen:/workspace/.../nodir/x.sock: No such file or directory
podssh session: with no listener, podssh ssh -tt HOST COMMAND runs a command with a pty in one call
```
exit 69. The same kind of fault with `--socket DIR` (exists, not a socket) gives exit 64; a too-long path gives 69 ("path must be shorter than SUN_LEN").
Manual (session): "where this host refuses it, start exits 77 with the reason"; "no directory takes the session's socket" is 78 (EXIT STATUS). A missing directory is neither 77 nor 78 here and the codes differ for the same class. The second line is a hint for a run with no listener allowed, not for a bad path; the first names `unix-listen:`, a pipe-address word the user never typed. Also: start does the whole login before it finds the path unusable (the error comes after connecting).

### 8. `podssh session send` and `stop` at a stuck session exit 75, which the manual gives only for start and wait  [documentation]
Commands: `kill -STOP <serve pid>; podssh session send sz hi; podssh session stop sz` -> `podssh session: sz: no answer within 30 s`, exit 75 (both, twice).
Manual (EXIT STATUS 75): "podssh session start and wait: the --timeout passed first." send/stop/capture exits for "no answer" are not listed. Also `session list` for such a session prints `podssh session: sz: no answer within 2 s`, while the manual says "stderr says why: it is there, busy or stuck", and `wait --timeout 3s` says "no answer within 33 s" (more than the 3 s asked; fine, but the line is odd).

### 9. NAME.sock.lock files of ended or failed sessions stay forever  [documentation / nit]
Commands: any `session start` that fails to log in (`dead.sock.lock`), `session stop`, a socket outside the cache (`/nonexist/x.sock.lock` was left in a directory I do not own; I removed it).
Manual (podssh man files, sessions/NAME.sock): "it goes when its session's podssh ends ... Beside a socket's file, NAME.sock.lock, which its podssh holds for its life." After stop the .sock is gone and the .lock stays (10 stale files after this pass; `ls cache/sessions`). Harmless to behavior, but the text says the file is held "for its life" and says nothing of its staying; a failed `start` also leaves one.

### 10. `--allow-command` confines only `ssh_exec`; `job_start` (and session_) run any command  [documentation, security-relevant]
Command: `podssh mcp --allow-host tbox -F cfg --direct --allow-command 'ls *'`, tools/call `job_start {"destination":"tbox","command":"echo x"}` -> isError false, a job id; `ssh_exec` of `ls; echo x` is refused.
Manual (mcp): "--allow-command PATTERN ... names what ssh_exec may run"; `--read-only` is the one that removes job_start. The help for --allow-command is exact, but an operator who wants "an agent that may only run `ls`" gets job_start as an open door unless he also reads that --read-only is needed. Suggest one sentence in THE RISK: "--allow-command does not limit job_start or the session_ tools; add --read-only".

### 11. `podssh status` JSON has a `settings` key that the manual does not describe  [documentation]
Command: `podssh status | python3 -c 'import sys,json; print(sorted(json.load(sys.stdin)))'` -> keys include `settings` (path of the settings file; `.../home/.config/podssh/settings` when absent).
Manual (podssh man status) lists the fields one by one (schema, podssh, relays, relays_from, deployments, pool, token, cache, proxy, offline, attachment, stdin_tty, stdout_tty, host, session_log, relay_failures, relay_opened, relay_rank, relay_order, relay_rank_auto, open_files, pairs, net, keys, exits) and does not name `settings`.

### 12. `-q` is not honoured by `session stop|send` errors  [nit]
Command: `podssh session stop -q nosuch` -> `podssh session: no session nosuch: podssh session list names each one`, exit 69 (3 of 3). `session start -q` with a refused connection, `job list -q`, `each -q`, `run -q`, `health -q` print nothing.
Manual (session): "-q, --quiet  quiet: no messages from podssh itself." (job: "errors included").

### 13. `podssh job log --follow` of a lost tmux job says "neither its runner nor its status is there"  [nit]
Command: kill the job's tmux session (`tmux kill-session -t podssh-job-ID`), then `podssh job log --follow HOST ID` -> `... is lost: neither its runner nor its status is there`. `job wait` of the same job says "neither its tmux session nor its status is there". The manual says a lost job is one where "neither the job's session nor its status is there". The first line names a runner that a tmux job never had; one wording would do.

### 14. `podssh config import remmina DIR` is refused whole when one file is no profile  [nit]
Command: dir with `a.remmina` and `README` -> `podssh config import remmina rd` -> `rd/README: no [remmina] section, so no profile of Remmina`, exit 65, no block printed for the good profile (twice). Manual: "reads one profile of Remmina, or each of a directory (~/.local/share/remmina)". A stray file in the directory (a backup, a .swp) stops the whole import; reading only `*.remmina`, or skipping with a stderr line, would match "each profile of a directory".

### 15. Session and run names: the help says "letters, digits, _ and -, 32 at most", the error says "not first a -"  [documentation]
Command: `podssh session start 'bad name' ...` -> `a session's name has letters, digits, _ and -, not first a -, 32 at most`; `podssh detached status 'bad name'` -> `a run's name ..., not first a -, 64 at most`. `podssh session --help` [NAME] and `--detach-name` help omit "not first a -".

## Checked and passed

- job: start/list/wait/log/fetch/stop on the example flow; wait gives the job's status (3); list --json shape; fetch DIR/out and `--files GLOB` (file, dotfile, subdir, glob); `--files '/etc/*'` and `'../*'` refused 64; fetch of a running job 75 with the documented line; wait --timeout and log --follow --timeout exit 75 and the job runs on; log --follow --jsonl events; --from-end; log without --follow plus --jsonl/--from-end refused 64; closed pipe (`| head -c0`, `-c10` on 300000 lines) exits 0 for log, log --follow, --jsonl.
- job: bad ID (zzzz, 9 hex, 7 hex) 64; upper-case ID accepted; unknown ID 255 with "has no job"; unknown subcommand 64; missing command 64; --slots 0/65/abc 64; bad --timeout 64; submit with a list (`HOST ID` on stdout, host with fewest jobs, unreachable member left out with a line, all unreachable 255 "nothing was queued"); `a b,c`, `web{3..1}`, `@nogroup` refused 64 before connecting; four concurrent starts and four concurrent submits (slots) all fine; --no-tmux start/stop/submit; lost job list/wait/log/fetch/stop; unreachable port 255 "could not connect to 127.0.0.1:2299: Connection refused"; unknown user and missing key 255 with the "no key was offered" line; non-UTF-8 argument 64 with the three-line explanation; INT/TERM/HUP to wait and log --follow end the process by signal and the job runs on.
- session: start (prints the socket), list (text and --json, empty case with the directories read), send with escapes (\x03, \t, \\), unknown escape 64, send from stdin, wait --match / --idle / --timeout 75, wait at an ended session 69 with the status, capture (screen and --raw), COLUMNS/LINES size honoured (`stty size` 7 40), COMMAND form and "ended 4" listing, stop, stop twice 69, duplicate start 69 "is there already", three concurrent starts of one name (one wins, two refuse with the lock line), bad names (space, /, empty, 33 chars) 64, bad --timeout/--idle 64, PODSSH_CACHE_DIR=none and PODSSH_LISTEN=no 78, @abstract socket works, unreachable host 255, missing key 255, new host key without a terminal refused with the accept-new hint, `no-answer` state of a SIGSTOPped session within 2 s.
- detached/--detach: `ssh -f --detach-name`, list (text, --json), status (running, ended, --restart with supervisor and heartbeat), stop (0; second stop 69), second start of a running name 75 with the pid and the lock path, three concurrent starts (one wins, two 75), bad name 64, `-f` with a shell or -W 64, --detach-name without -f 64, unreachable start 255 recorded as "ended, exit 255", unreadable record listed as "ended, its record unreadable" and status 69, `../x` and non-UTF-8 names 64, PODSSH_CACHE_DIR=none lines, closed pipe 0, no-run cases.
- each: example forms; worst status as the exit (2, 5, 7); `HOST: ` prefixes on stdout and stderr; duplicate hosts run once; --json (text, base64 stdout/stderr for non-UTF-8), --result-file (mode 0600), --output-dir files (%XX names, 0 byte-for-byte), `--result-file -` 64, --parallel 0/65/abc 64, `a b`, empty, `,`, backwards range, 1001 hosts, unknown @group 64; group cycle 78 with file:line; groups and @all; --fail-fast marks "not started (--fail-fast)"; unreachable and unknown-user hosts 255 with one line each; --interactive (`:list`, `:help`, `:only`, `:none`, `::`, unknown `:bogus`, host that cannot log in leaves the selection and says how many bytes were not sent); --interactive with --json/COMMAND 64; --snippet (placeholders {{1}}, {{host}}, {{user}}, {{port}}, quoting, count mismatch 64, --yes, question on a tty answered y, no question under BatchMode explained); `-o RemoteCommand=none` 64, RemoteCommand and command precedence; INT gives 130 and a summary; unwritable --output-dir/--result-file 73; closed pipe 0; non-UTF-8 64.
- run: dry-run plan (mkdir, copy, link, run line, excluded count), first copy, second copy "0 copied, N unchanged", default excludes and .podsshignore, -v names each left-out path with its pattern, --no-ignore, --result-file JSON (and refused-before-connect and failed-copy shapes), `-` refused 64, --from missing 66, --from a file 64, --exclude-from missing 64, duplicate --from 64, far-dir parents 0700, exit statuses (9, 44 for 300, 137 for KILL, 255), INT gives 130, copy failure 255 "the command did not run", unreachable 255 (also with --dry-run and --result-file), four concurrent runs into one directory, non-UTF-8 64.
- config import: ansible (groups, ranges, ports, common/extra args to ProxyJump and -o lines, ProxyCommand commented without value, passwords counted and never printed, non-ssh connection comment, bad host name refused by name, bad line number 65, non-UTF-8 65, missing file 66, directory 66, stdin `-`), putty (.reg UTF-8 and UTF-16, Default Settings, ppk comment, port dword), mobaxterm, remmina (file), mremoteng (plain, FullFileEncryption 65, truncated XML 65), unknown format 64, Termius/FinalShell/ansible-yaml 64, closed pipe 0, no output file written.
- mcp: initialize (2025-11-25), tools/list, ssh_exec ok/exit status/timeout (timed_out true, 2 s)/non-UTF-8 base64/1 MiB truncation/destination `-oProxyCommand=..` refused/not allowed host named with the allow list/USER@ pattern semantics/unknown host key refused with fingerprint line/bad `host_key_fingerprint` 64; malformed input (`{}`, `[]`, string, number, null, garbage, batch, bad id, jsonrpc 1.0) gives -32600/-32700 lines with no panic; unknown method -32601; missing version before initialize -32602; unknown tool; bad arguments; `--read-only` tool list and refusal; `--allow-command` (`;` refused, `*` program refused 64, double space matches); cp_put/cp_get inside --allow-dir (sha256 verified, links followed and refused outside, `content` base64 and bad base64), --allow-dir ~/.ssh / HOME / cache / `/` 64, missing dir 78; --client-config for the four clients and `bogus` 64; stdin EOF ends the server with a call in flight; health and status and man tools.
- play: example recordings (timing 1.0 s at speed 1, 2.0 s at 0.5), --idle-limit, file idle_time_limit, input events passed over, out-of-order events, escapes passed through, header-only, empty/garbage/v1/v3 header exit 1, truncated event with line number, negative time refused with the line, directory, missing file, non-UTF-8 stream, --speed 0/abc/nan/inf/1e400/-1 64, closed pipe 0.
- health: text and --json and --preflight (9 ok), unreachable 255 (text, --json with error and exit, --preflight FAIL line), unknown user 255, missing key 255, two hosts 64 pointing at `podssh each`, no host 64, bad --policy file 78 without printing the key's text, closed pipe 0, INT.
- status: one JSON line, exit 0, writes no file (cache and HOME unchanged), token and proxy credentials never printed (`SECRET` not in the output), proxy kinds and the ftp:// error in the proxy field, --keys, `--keys HOST` 64, host key lookup for `[127.0.0.1]:2201` and `127.0.0.1:2201` (known true), `x@y@z` host z, bad --relay-host/--relay-addr 64, bad PODSSH_RELAY/RELAY_ADDR 78, bad settings line 78 with file:line, non-UTF-8 64, closed pipe 0.
- --help versus `podssh man VERB`: flag lists identical for all ten verbs.
