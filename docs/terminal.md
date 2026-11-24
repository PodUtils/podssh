# Terminal handling

This page tells how `podssh ssh` uses the local terminal, and when podssh
must supply the line discipline itself. Some rules come from two sibling
projects that face the same hosts, podvm and sandhome. Their file names on
this page are in those repositories.

## Select a mode

Three inputs select what happens to the keys:

1. Did the server grant a pty (`pty-req` answered SUCCESS)?
2. Are podssh's own stdin and stdout terminals?
3. Does the remote side run a line discipline of its own?

The third input is necessary. The server of podvm never grants a pty, but it
echoes, edits and handles Ctrl-C under `ForceCommand`. A local echo there
shows each key two times.

| Server pty | Local stdin and stdout | podssh does |
| --- | --- | --- |
| granted | terminal | Sets the local terminal to raw mode; bytes pass through; sends the window size, and sends it again after each resize. |
| granted | not a terminal (`-tt`) | Bytes pass through. The size comes from `COLUMNS` and `LINES`, else 80x24. |
| refused | terminal | Keeps the local terminal in its normal mode, so its line discipline gives echo and editing. Prints "no pty on the server" one time on stderr. |
| refused | not a terminal | A plain pipe, as for a command. |

The line discipline in the process (`pod-term` of PodUtils/podcrates, taken by T-684 in the place of `crates/podssh-terminal`) is for the
case that remains: keys arrive raw, and nothing below edits them, neither a
pty nor a line discipline. Three facts choose its mode (`Mode::select`):
a pty below, a line discipline below, and the caller's selection. It
echoes and edits only when it is selected and neither is below; `podssh
serve` with no `/dev/ptmx` selects it (T-111), and a client flag may later.
In each other case the session is transparent: each byte goes both ways as
it came, with no echo and no refusal. The absence of a pty alone never
selects it (T-125). No command uses the crate yet (T-111, milestone M5).

## What podssh reads from the terminal

podssh acts on few bytes of the terminal, and passes each other one
unchanged (T-130). The escapes are one table,
`crates/podssh-ssh/src/escape.rs` (`ESCAPES`), which the input, `~?` and
the manual read; a test holds the manual's note to it.

- **A client with a pty** (the local terminal raw): the escape character,
  `~` unless `-e` names another (`-e none`: none), at the start of a line,
  and the key after it: `~.` ends the session and sends nothing after it,
  `~R` asks for a re-key, `~C` opens OpenSSH's command line (`ssh> `),
  which adds and stops forwards (T-291, [cli.md](cli.md)), `~#` lists the
  forwards with what each carried, `~d` leaves the shell to a far end that
  keeps shells ("Detach and attach again" below) and goes as typed
  elsewhere, `~Z` sends a file by ZMODEM, `~?` lists the escapes, and `~~`
  sends one `~`; another key goes with the `~` before it. A resize sends
  the new size. Each other byte passes unchanged, as the remote side reads
  it: Ctrl-C, Ctrl-Z, Ctrl-D, Ctrl-S, Ctrl-Q, Escape, the sequences of the
  keys, of the mouse and of a bracketed paste; only the line of `~C`, and a
  question or a transfer of ZMODEM, take the keys ("ZMODEM in a session"
  below). The line of `~C` is read from the session's own keys, with echo,
  Backspace and Ctrl-U; Enter ends it, Ctrl-C and Ctrl-D give it up, and
  the keys after its Enter go to the session. No key of the line reaches
  the server.
- **A client with no pty:** podssh reads no byte; stdin is the command's
  data, escapes are off, and Ctrl-C is the local terminal's signal to
  podssh, which sends `signal INT` to the command first ("Ctrl-C with no
  remote pty" below).
- **A session through a control master** (T-039): the master reads its
  escapes, with the escape character that the client sent. It offers no
  `~C`, as OpenSSH's master offers none to a client: `~C` goes to the
  server as typed.
- **The broadcast, `podssh each --interactive`** (T-185): the local
  terminal keeps its normal mode, and podssh reads whole lines; a line
  that starts with `:` is for podssh. The terminal turns two keys into
  signals: `Ctrl-\` (SIGQUIT) on Unix and Ctrl-Break on Windows is the
  emergency stop, and Ctrl-C goes to no host (`docs/cli.md`, "The
  broadcast: `--interactive`"). `--stop-key ^X` makes the terminal's QUIT
  character another key for the run, and puts the old one back (T-322).
- **The line discipline of `podssh serve`**, when serve exists (T-107 to
  T-113): the keys and sequences that it acts on and those that it refuses
  are in "When podssh supplies the line discipline" below; each other byte
  passes unchanged.

## `-t`, `-T` and `RequestTTY`

- The default of OpenSSH is `RequestTTY auto`: a pty for an interactive
  shell when stdin is a terminal, and no pty for a command.
- `-t` is `yes`: a pty when stdin is a terminal.
- `-tt` is `force`: a pty, also with no local terminal.
- `-T` is `no`.
- With stdin and stdout on pipes, the session runs with no pty. A pipe that
  is treated as a terminal puts ANSI codes into data (sandhome did this with
  `jq -r`).

## `pty-req` (RFC 4254, section 6.2)

- It needs no `/dev/ptmx` on the client.
- The dimensions are information only, and zero dimensions are ignored. The
  local terminal is the only source of a window size.
- The reply is SUCCESS or FAILURE, with no reason. After a FAILURE, the
  channel can still run `shell` or `exec`.
- `window-change` has no reply. Send it only after a grant.
- Put a limit on the wait for the reply, and treat no reply as a refusal.
  Never keep the answer for the next session.
- A client refuses a `pty-req` that comes from the server.
- The server side (`podssh serve`, T-110) grants a `pty-req` only where a
  master opens at that request (`/dev/ptmx`, then `/dev/pts/ptmx`), and
  keeps nothing for the next one. A zero size is 80x24 there, an empty
  `TERM` is `xterm-256color`, and the modes are read through the client's
  own table, the other way. Where none opens, the reply is FAILURE, and
  T-111 is the line discipline for that case.

## `TERM`

Send the local `TERM` with no change. When `TERM` is not set or is empty,
send `xterm-256color`. With no usable `TERM`, full-screen programs fail on a
real pty (`less` prints "'unknown': I need something more specific."). The
terminfo database of the server must resolve the name.

## The Windows console

- Raw mode turns off echo, line input and the processing of Ctrl-C, and
  turns on virtual-terminal input and output. podssh then sends Ctrl-C to
  the remote side as a byte.
- podssh restores the console's input and output modes when the session
  ends, and also when podssh panics. Ctrl-Break, a closed window, logoff
  and shutdown end podssh through the console's default handler, which
  runs no destructor: a console control handler puts the modes back first
  (T-295).
- A console has no resize signal, so podssh reads the window size every
  500 ms. On Unix, SIGWINCH gives the change.
- Prompts use `CONIN$` and `CONOUT$`, so they work when stdin and stdout are
  redirected. When none of stdin, stdout and stderr is a terminal, a prompt
  waits 60 s at most for a key, as on Unix (T-588): a console with no
  window, as an agent's, opens, and nobody sees its question. Another event
  of the console (a focus, a mouse, a size) is no answer.
- podssh sets no code page. Output goes to the console through Rust's
  standard output, which writes the console in UTF-16, so text in UTF-8
  shows whatever the code page is. That writer refuses a byte that is not
  UTF-8, so podssh first writes each such sequence as U+FFFD, as a terminal
  of Linux shows it, and keeps a character that the end of a message cuts
  for the next one (T-294). A pipe or a file gets the bytes unchanged.

`scripts/interop-conpty.py` checks these items in a real pseudo console
against a server with a shell, and `crates/podssh-cli/tests/console.rs`
against the test's own server, in each run of the tests on Windows.

What a pseudo console showed (T-132, 2026-10-12, Windows 11,
`crates/podssh-cli/tests/console.rs`):

| Item | Measured | |
| --- | --- | --- |
| Text in UTF-8 that is not ASCII (`héllo € ✓`) | Shows as sent. | No fault. |
| A byte that is not UTF-8 (`0xff`) in the output | Before T-294, the text before it showed, and the byte and each later byte of the session were lost while the session went on: Rust's console writer refuses the byte (`rust-lang/rust:library/std/src/sys/stdio/windows.rs`, `write`), and podssh took the refusal for a stdout that is gone. Since T-294 the byte shows as U+FFFD, and the output goes on. | Fault, repaired: T-294. |
| Ctrl-Break in a session with a pty | podssh ends with `0xC000013A`. Before T-295 the console's input mode stayed raw: `0x3f0`, where it was `0x1f7`; since T-295 it is `0x1f7` again. | Fault, repaired: T-295. |
| `~.` in the same session | The mode is `0x1f7` again. | No fault. |
| A resize | Reaches the server 450 to 505 ms after it. | Kept: the poll costs 500 ms at most; an event of the console would need `ReadConsoleInputW` in place of the stream of bytes that podssh reads. |

### csshw

csshw (`whme/csshw`, at `6dd773b`) is a cluster SSH tool for Windows: it
opens a console window for each host, runs OpenSSH's `ssh` in it, and sends
the keys of its own window to each. Each of its console calls against
podssh (T-132, from GitHub #24):

| csshw | podssh | |
| --- | --- | --- |
| A console window of its own for each host (`CreateProcessW`), with the keys of its window written into each (`WriteConsoleInputW`) | One session, in the console where podssh runs | Not needed: podssh is the SSH client, and drives no window. |
| Keys read as input records (`ReadConsoleInputW`), other events skipped | Keys read as a stream of bytes, with virtual-terminal input | Not needed: the remote pty wants a terminal's bytes, which a key record would need a translation into. |
| `ENABLE_PROCESSED_INPUT` off, so that Ctrl-C reads as a key | The same, in raw mode | Same. |
| At its end, Ctrl-C to each process of a host's console (`GenerateConsoleCtrlEvent`) | Starts no process in its console; a `ProxyCommand` ends with podssh | Not needed. |
| The colour of a whole window by its state (`SetConsoleTextAttribute`, `FillConsoleOutputAttribute`; `disabled_console_color`), and a repaint of the edge that the fill misses (`InvalidateRect`) | No colour of its own: the remote side's colours are escape sequences | Not needed. |
| A clear screen by `ScrollConsoleScreenBufferW` and `SetConsoleCursorPosition` | The remote side clears with escape sequences | Not needed. |
| The title, place, size and border colour of each window, DPI awareness, the version of Windows | None | Not needed: the layout of many windows. |
| No code page set | None set; output in UTF-16 (measured above) | Same. |
| ConPTY, which the report of #24 names | podssh runs in a console or in a pseudo console | csshw has no code for a pseudo console: its hosts' windows are classic consoles. |

No item of csshw is a fault of podssh. The two faults above came from the
measurements that the comparison asked for.

## When podssh supplies the line discipline

These byte rules come from podvm (`crates/podbox-ssh/src/session.rs`):

- DEL and BS erase to the left. Ctrl-U erases the line, Ctrl-W a word.
  Ctrl-A and Ctrl-E go to the start and the end. Up and down recall the
  history; left and right move the cursor.
- Home and End do as Ctrl-A and Ctrl-E, in each form a terminal sends:
  `ESC [ H` and `ESC [ F`, `ESC O H` and `ESC O F`, and the VT220 and rxvt
  `ESC [ 1 ~` or `ESC [ 7 ~` and `ESC [ 4 ~` or `ESC [ 8 ~`. Each of these
  keys moves the screen's cursor with the line's. Delete (`ESC [ 3 ~`)
  deletes the character under the cursor, and never ends input.
- CR and LF both submit the line. The LF of a CRLF pair is ignored.
- On one row, a redraw is `\r`, the prompt, the buffer, `ESC[K`, `\r`, the
  prompt, and the buffer up to the cursor.
- The caller gives the terminal's size: the client measures its terminal,
  and `podssh serve` reads `pty-req` and `window-change`. Raw mode stays in
  `podssh-ssh`. A line wider than the terminal takes several rows, and a
  wide character that does not fit at the end of a row starts the next one.
  The redraw then goes up to the first row (`ESC [ n A`), writes `\r`, the
  prompt and the line, clears below with `ESC [ J`, and moves the cursor back
  by rows and columns. A row that the line fills ends with `\r\n`, so the
  terminal's cursor never waits in the last column. Backspace at the start
  of a row redraws, because `\b` does not go up a row. Enter and Ctrl-C leave
  from the last row. A new width draws the line again on a row of its own.
  With no size, or a width of 0, the redraw stays on one row. A line taller
  than the screen is not drawn right: `ESC [ A` stops at the top row.
- A line holds 65536 bytes or fewer; the extra bytes are dropped with a
  bell. The history keeps 100 entries and skips a repeat of the last entry.
- With `IUTF8` from the modes of `pty-req`, the cursor steps over whole
  characters, and an accent moves with its letter; without it, over bytes,
  as a terminal with no `IUTF8` does. The screen moves by cells
  (`unicode-width`): a wide character takes 2, an accent 0, and a control
  byte or a byte that is not UTF-8 the 1 cell of its echo. Backspace, Ctrl-W,
  Ctrl-D and the arrows act on whole characters, and the arrows write
  `ESC [ n D` or `ESC [ n C` for a step of n cells. The line and the history
  keep the bytes as typed; the cap drops a character whole, never half of it.
- A shell on a pipe prints no prompt and keeps no history. Thus podvm
  prints a static `$ ` and keeps the history itself.

Parse each escape sequence as a whole:

- A CSI is `ESC [`, then parameter bytes 0x30 to 0x3F, intermediate bytes
  0x20 to 0x2F, and a final byte 0x40 to 0x7E.
- `ESC O x` (SS3) is also a sequence, read as a CSI is: some terminals put
  a parameter before the final (`ESC O 2 P`). `ESC O A` to `ESC O D`,
  `ESC O H` and `ESC O F`, the arrows, Home and End of a terminal in
  application mode, act as their CSI forms, and the screen moves by the CSI
  form. On the keypad in application mode, `ESC O M` is Enter, and
  `ESC O j` to `ESC O y` and `ESC O X` type `*+,-./`, the digits and `=`.
- The Linux console sends F1 to F5 as `ESC [ [ A` to `ESC [ [ E`, so
  `ESC [ [` takes one more byte.
- `ESC` starts a new sequence wherever it comes. A control byte ends a
  sequence and is a key of its own: an escape never takes Ctrl-C, Ctrl-D or
  Enter.
- `ESC` and a key with no pause is an Alt key: one bell, and the key is not
  typed, each byte of a UTF-8 character included.
- A lone `ESC`, or a sequence cut short, rings once when no byte came for
  50 ms, and the next key is typed as usual. The crate reads no clock: while
  `Session::waiting` is true, the caller calls `Session::on_idle` after
  50 ms with no byte.
- If podssh does not interpret a sequence, it refuses the whole sequence:
  F1 to F4, in each of these forms, ring once and type nothing. (A parser
  that reads one byte after `ESC [` makes F5, `ESC [ 1 5 ~`, ring the bell
  and then type `5~`.)

A refusal rings the bell and changes nothing, because silence looks like
acceptance:

- Ctrl-Z: with no job control, a stopped shell has nothing to return to,
  and the session stops.
- Ctrl-S and Ctrl-Q: there is no IXON below, so there is nothing to stop.
- Escape sequences other than the arrows, Home, End, Delete and the
  keypad's keys are dropped: Insert, the page keys and F5 and above ring
  once. If `ESC[?1049h` passes through, it corrupts the scrollback.
- A lone Escape, and Alt with a key: no key is bound to them.
- Ctrl-D or Delete after the last character is the only refusal with no
  bell.

`fg`, `bg` and `jobs` go to the shell. `less`, `vi` and `top` need a real
pty; sandhome gave a warning when one of about 20 such command names was
typed. Where `/dev/ptmx` is missing, `podssh serve` makes a tty when a probe
allows it (T-248): a new devpts instance, or a tty in user space that answers
the child's tty system calls.

The program's output while a line is under edit: the line is hidden (up to
its first row, `\r`, and `ESC [ K` or `ESC [ J`), the output is written, and
the prompt and the line are drawn again below it, with the cursor in its
place. Output never lands in the line or changes it. Output that stops
inside a row, such as a program's own prompt or a progress bar drawn with
`\r`, stays as it is, and the line comes back on the next row at the next
key.

Newlines: in the line discipline, each `\n` of the program's output becomes
`\r\n`, as a pty's `ONLCR` makes it: the program writes to a pipe, and the
terminal is raw. Never change newlines when the remote side has a pty, or
for command output that goes to a pipe or a file.

## Ctrl-C with no remote pty

With no remote pty, Ctrl-C is the local terminal's, and it ends podssh;
`0x03` would be only a byte of the command's input. The command on the
server runs on: in the build image, OpenSSH 10.3p1 and Dropbear 2026.91
each still ran `sleep` after their client had ended. The protocol's one
way to stop it is the `signal` request (RFC 4254, section 6.9), which a
server may ignore. `crates/podssh-ssh/tests/signal_request.rs` measures
what a server does with it (T-131): podssh's client logs in, runs a command
with no pty, sends `signal INT` after 1 s, and reads what ends the channel
within 5 s. In `exec sleep 30`, `sleep` is the process that the server
started; in `sleep 30; true`, a shell waits for its child.

| Server, 2026-10-12 | `exec sleep 30` | `sleep 30; true` |
| --- | --- | --- |
| OpenSSH 10.3p1, the build image | Ended by `INT` at once; the channel closed. | The same: sshd signals the session's process group (its log: `session_signal_req: signal INT, killpg(...)`). |
| Dropbear 2026.91, the build image | Ended by `INT` at once; the channel closed. | Ignored: Dropbear signals the process that it started (`kill`, `mkj/dropbear:src/svr-chansession.c`, line 468 at `17549ea`), here the shell, which waits for `sleep`. Both still ran after the client left. |
| russh 0.64.1 with its default handler (the test's own server) | Ignored. | Not run. |
| Tailscale SSH | Not measured: the tailnet's hosts were offline. | |
| `railway.new` | Not measured: it refused an anonymous visitor (Q42). | |

Decision: the client sends `signal INT` on Ctrl-C when the session has no
remote pty and runs a command or a shell (T-293). OpenSSH then stops the
command and each process of its group, and Dropbear a command that is the
process that it started. With a remote pty nothing changes: Ctrl-C is a
byte, and the remote pty's line discipline signals the foreground group.

What podssh does since T-293 (`crates/podssh-ssh/src/terminal/interrupt.rs`):

- In a session with no remote pty that runs a command or a shell (not
  `-N`, `-W` or `-s`: OpenSSH's sshd refuses the request for a subsystem),
  podssh takes SIGINT, or `CTRL_C_EVENT` in a Windows console, while the
  channel is open. Before the session, as at a prompt, Ctrl-C ends podssh
  as before.
- The first Ctrl-C sends `signal INT` and waits 2 s for the channel's end;
  the command's signal or status is then the exit code, as for each
  command: 130 when `INT` ended it.
- A second Ctrl-C, or the end of the wait with no end of the command, ends
  podssh with 130, the code that a shell gives a process that SIGINT ended,
  on Windows too; `--result-file` says `interrupted`. `-v` says each step.
- `--no-signal` keeps OpenSSH's behaviour, whose client sends no request:
  no handler, and Ctrl-C ends podssh at once (on Windows by the console's
  own handler, with `0xC000013A`).
- A SIGINT that was ignored when podssh started (a script's `&` leaves it
  so) stays ignored, as in OpenSSH's client. A Windows process that
  ignores Ctrl-C gets no event.
- A session through a control master is the master's: its client ends at
  SIGINT with 255, as before (T-039).
- A run of `-N`, with or without `--persist`, takes SIGINT too (T-866): it
  sends no request, as there is no command, and ends at once as
  `interrupted`, with 130, so that `--result-file` is written. Before, the
  signal's default action killed podssh with no file; `--no-signal` keeps
  that.

`crates/podssh-cli/tests/ssh_interrupt.rs` runs podssh against the test's
server on the loopback, whose command writes each `signal` request that it
gets and ends by it, or runs on: SIGINT on Unix, and Ctrl-C typed into a
pseudo console on Windows.

## Detach and attach again

A user can leave a shell running and join it again later, from a new
podssh process or from another host, where the far end keeps shells
(T-158). tmux does this on a server that has tmux; a cage usually has none.
The keys and the sequence numbers of the SSH connection live in the client
process, above the resumable layer, so a new process cannot go on with the
connection's bytes: the far end keeps the shell, and a new SSH login joins
it. A client in the background that keeps the connection and takes
attaches over a local socket lost: it needs a listener, and it dies with
the client's host.

- **The offer.** A far end that keeps shells names `keep.v1` in the
  `GREETING` of the resumable layer, and `podssh ssh` names it in its
  `OPEN`; as for each feature, a name counts only when both sides give it.
  A podssh node never names it: its SSH server is another program, which
  keeps no shell. The road of `node://NAME`, raced with `--iroh-ticket`
  too, learns the offer before the SSH login. The iroh road alone
  (`iroh:TICKET`) does not read it, so no shell is kept there.
- **`~d`.** With the offer, in a session of a shell with a pty on a
  terminal, `~d` at the start of a line sends `env detach@podssh NAME` on
  the shell's channel, with a reply asked. NAME is new (8 hexadecimal
  digits), or the name that the session attached. SUCCESS: the far end
  keeps the shell and closes the channel; podssh prints "HOST keeps the
  shell as NAME" and exits 0, and `--result-file` says `detached`.
  FAILURE: a line, and the session goes on. Nothing typed after `~d` in
  the same read is sent. With no offer, `~d` is two bytes for the server,
  as before.
- **`--attach NAME DEST`.** A new login asks for a pty, as `-tt` does,
  and before `shell` sends `env attach@podssh NAME`; with `--take`, `env
  take@podssh yes`; and `env from@podssh ID` when `PODSSH_SHELL_ID` is set
  where podssh runs. Each waits for its reply, and a FAILURE is a far end
  that joins no shell (255). The far end then joins the shell to the
  channel, or refuses with its words on stderr and an exit status, which
  podssh exits with.
- **`--attach DEST`.** The subsystem `shells@podssh`: one line for each
  kept shell, its name, `attached` or `detached`, and from `podssh serve`
  its offset (T-833): the bytes of its output so far, or at the detach.
  `env count@podssh OFFSET` before an attach replays from there, and `env
  reset@podssh yes` asks for the last output from a clean boundary.
- **The far end decides.** One client has a shell at a time; `--take`
  takes it, and the far end ends the other client's channel. The far end
  puts `PODSSH_SHELL_ID` in the environment of each shell that it starts,
  and refuses an attach whose `from@podssh` names the shell to join: a
  shell joined to a client inside it would feed its own output back.
- **The requests are `env` and `subsystem` requests**, which the handler
  of russh's server sees. russh 0.64.1 answers a channel request or a
  global request of another name with FAILURE and calls no handler, so a
  request of podssh's own type would never reach `podssh serve`.
- **Where shells are kept.** `podssh serve NAME` keeps them (T-159): a
  login shell on a pty of the kernel, for `--keep-lease` (24 h by
  default), 4 for each key and 32 in all, found by its key and its name.
  `env keep@podssh NAME` before the shell keeps it if the client is lost
  with no `~d`, and `env lease@podssh SECONDS` asks for a shorter lease. A
  kept shell's output with no client goes to a ring of 256 KiB, and an
  attach gets what came since the detach, from a boundary of the grammar
  where the ring dropped a part (said on stderr). The screen that a
  client finds is T-161's. A lease's end hangs up the shell's process
  group and kills it 10 s later; a restart of serve ends each kept shell,
  and the next start names them from its record (`serve-NAME.kept`).
  Against a standard sshd, `--persist` keeps the shell in tmux (T-178).

`crates/podssh-cli/tests/attach.rs` tests it with a stand-in of the far
end in the test process: the layer as `podssh serve` speaks it, with
`keep.v1`, and a russh server whose shells outlive their client, behind a
node in plain mode on the stand-in relay. In a pseudo console on Windows,
or a pty on Linux, it sets a variable in a shell, types `~d`, lists the
kept shells, attaches by name from a new process, and reads the variable
back.

## Where kept output may start

A far end that keeps a shell keeps a ring of its recent output (T-159:
`podssh serve`'s ring of 256 KiB, `crates/podssh-ssh/src/server/kept.rs`),
and a client that attaches gets what came since its detach, or what the
ring holds where it dropped a part (T-161 decides the screen). A full ring
drops its oldest bytes, and its first byte could then be inside an escape
sequence or a UTF-8 character: the terminal would show the end of the
sequence as text, a full-screen program would draw wrongly, or a part of a
title would show on the command line (GitHub #31). A resume of the
resumable layer never meets this: it sends again each byte that the other
side did not acknowledge (T-152).

`PodUtils/podssh:crates/podssh-terminal/src/grammar.rs` (T-221) reads the output as a
terminal does, and finds each boundary: a place where a terminal that
starts to read shows no part of a sequence. Its ring
(`podssh_terminal::grammar::Ring`) drops bytes only up to a boundary.

- Text is at a boundary at each byte but a UTF-8 continuation byte.
- `ESC` starts a sequence wherever it comes. `ESC` and a byte 0x30 to
  0x7E is one, with intermediate bytes 0x20 to 0x2F between them or not. A
  CSI ends at its final byte, 0x40 to 0x7E; a control byte inside it does
  not end it. An OSC ends with ST (`ESC \`) or BEL; a DCS, SOS, PM and APC
  with ST alone. CAN and SUB end each sequence.
- Where terminals differ, there is no boundary: the byte that cuts a UTF-8
  character short starts none (vte drops it), and 0x9C, the 8-bit ST, ends
  no string (vte ends a DCS with it; a UTF-8 terminal does not).
- A sequence or a character that waits 10 s for its next byte is broken.
  The next boundary is then the byte after the next newline, or the `ESC`
  of the next full repaint: `ESC [ 2 J`, `ESC [ ? 1049 h`, `?1047h`,
  `?47h`, or the reset `ESC c`. The caller gives the time of each chunk.
- The ring keeps a boundary for each 1/256 of its size, the first after a
  broken sequence, and the newest, so a cut drops at most about 1/256 of
  the ring more than it must.

`PodUtils/podssh:crates/podssh-terminal/tests/grammar_boundary.rs` cuts the output that
real programs wrote (vim, and an interactive bash whose prompt sets the
title; `scripts/capture-terminal.py` adds less and top from a pty of
Linux) at each offset, and checks the first byte kept against anstyle-parse,
vte's parser: a terminal that starts there does what the terminal that read
the whole stream does. `podssh serve` holds a ring for each kept shell
(T-159).

`podssh session` (T-186) uses the grammar on this side of a session that
it holds for an agent. `capture --raw` gives the bytes of such a ring of
64 KiB, from a boundary. `wait --idle` counts output that stops inside a
sequence or a character as output that goes on, until the tracker
(`Tracker::open`) calls it broken. `capture` gives the screen of a model of
a terminal (`vt100`, the model of the oracle of T-200), which reads each
byte of the session's output from its first.

## ZMODEM in a session

Some servers give a shell and nothing else: no SFTP, and exec refused. A
file can then cross inside the terminal session, with `sz` and `rz` of
lrzsz on the server and ZMODEM in podssh (T-148). The code is
`crates/podssh-ssh/src/zmodem/`; the protocol is Chuck Forsberg's "The
ZMODEM Inter Application File Transfer Protocol" (1988), and the section
numbers below are its.

- **When podssh watches.** Only in a session with a pty, a raw local
  terminal and a terminal on stdout, and when `PODSSH_ZMODEM` is not `off`.
  With no terminal nothing is watched, so nothing is ever received: the
  bytes go to stdout as they come. A session through a control master is
  not watched, and `~Z` there says so.
- **The start.** `sz` prints `rz\r`, then the hex header ZRQINIT:
  `**`, ZDLE (0x18), `B00` and twelve more hex digits ("may be scanned for
  B00", 8.1). `rz` prints "rz waiting to receive." and the hex header
  ZRINIT, `B01`. A start counts only when its 14 hex digits are whole and
  their CRC-16 holds; text that only looks like one passes unchanged. The
  bytes of a start that the end of a message cut wait for the next message,
  100 ms at most.
- **Receive.** podssh asks where the files go: Enter takes the directory of
  the last answer (the current directory at first), a path changes it (`~`
  at its start is the home directory), and Ctrl-C refuses and sends the
  cancel sequence (eight CAN and ten backspaces, 8.4). A name that the
  server sends counts by its last
  component, which must be one that may be written here. Each file comes
  as T-134 writes a copy: to `.NAME.podssh-RANDOM.part` beside it, with the
  CRC of each subpacket checked; at ZEOF the length must be what came and
  what ZFILE said; then the file gets the server's time and its mode
  (without the write bits of the group and others), and a rename gives it
  its name. A name that is taken is replaced only after the answer `y`;
  else the server's file is skipped (ZSKIP). A transfer that ends before
  ZEOF removes the temporary file.
- **Send.** When `rz` waits, podssh asks for a local file. `~Z` asks first,
  then types `rz` and Enter on the server ("The sending program may send
  the string "rz\r"", 8.1). The file goes as ZFILE (binary, no option for a
  name that exists, so that the server's `rz` keeps its own rule), then
  ZDATA's subpackets of 1024 bytes, ZCRCE and ZEOF; a ZRINIT after ZEOF
  says that it is whole, and ZFIN and "OO" end the session.
- **Limits.** Each wait for a frame has 10 s, the spec's response time
  (8.1); after it the last header goes again, and after 4 waits ("40
  seconds total") the transfer ends with the cancel sequence and the
  session goes on. A ZRPOS at the same place 4 times also ends it. A write
  of podssh's that the server does not take for 40 s (a far end that stops
  reading, so that the channel's window stays shut) ends the transfer the
  same way: `podssh: ZMODEM: the server took nothing that podssh sent for
  40 s`, and the rest of that write is dropped. A file of 4 GiB or more is
  refused: positions have 32 bits. A command from the server (ZCOMMAND,
  `sz -c`) never runs.
- **What ends a transfer** (T-859), each also while podssh waits for the
  server to take its bytes, whatever the far end does: Ctrl-C (`ZMODEM:
  cancelled here (Ctrl-C)`), five CAN typed in a row, in one read or in
  several (`ZMODEM: cancelled here (CAN)`), the limit above, and five CAN
  from the server. Each says one line, sends the cancel sequence, and keeps
  no file that did not end; the session goes on. Each other key is dropped
  during a transfer, as it would land in the protocol's stream. The end of
  the local terminal ends the session too: SIGHUP or SIGTERM, or the end of
  stdin while a question or a transfer holds the keys, cancel the transfer,
  remove its temporary file, and exit 255, as a session that ends with no
  status does; the far `sz` or `rz` ends with its pty when the connection
  closes.
- **What crosses.** Headers in hex, and in binary with CRC-16 or CRC-32 as
  the receiver allows (CANFC32); ZDLE escapes of ZDLE, DLE, XON and XOFF
  with and without the parity bit, and of CR after `@` (7.2), as lrzsz
  sends them; each control character when the receiver asks (ESCCTL).
  podssh's ZRINIT is `B0100000023be50`, the flags of lrzsz's `rz`.

`crates/podssh-ssh/tests/zmodem.rs` checks the search for a start, the
frames and their CRCs against vectors from the spec, the limits, and a
file each way. The gate's check (`scripts/interop-pty.py`, `pty.zmodem.*`)
runs `sz` and `rz` of lrzsz in a real pty; Alpine has no lrzsz package
now, and the check says `env` without one (T-148's Correction).

### Where ZMODEM survives (T-831)

Measured on 2026-11-23 in a Claude Code cloud container:
`podssh ssh --direct` (debug build at `c33214c0`) in a local pty of 24x120, against a
throwaway OpenSSH 9.6p1 on 127.0.0.1, lrzsz 0.12.21rc, tmux 3.4, podman
4.9.3 with runc. Each run is a new session: `sz` of a 1 MiB random file to
podssh, or `rz` of another from podssh, the SHA-256 of both ends compared,
60 s at most. The driver is a copy of `scripts/interop-pty.py`'s ZMODEM
check, kept out of the repository. The time runs from the command's Enter
to podssh's `received` or `sent` line.

| Path, as typed in the far shell | `sz` (far to here) | `rz` (here to far) |
| --- | --- | --- |
| (a) the shell: `sz down.bin`, `rz` | 25 of 25, 0.07 s | 145 of 145, 0.05 s |
| (b) tmux: `tmux -L t831 -f /dev/null new -s t831 'sz down.bin'` (and `'rz'`) | 0 of 5 | 0 of 5 |
| (b) the same with `sz -e` and `rz -e` (each control escaped) | 0 of 5 | 0 of 5 |
| (c) `podman exec -it -w /far t831 sz down.bin` (and `rz`) | 5 of 5, 0.16 s | 5 of 5, 0.15 s |
| (d1) `stty -icrnl -onlcr; sz down.bin; stty sane` | 5 of 5, 0.07 s | 45 of 45, 0.05 s |
| (d2) `stty inlcr igncr ocrnl onlret; sz down.bin; stty sane` | 5 of 5, 0.08 s | 202 of 205, 0.05 s |

- **tmux damages ZMODEM.** tmux is a terminal emulator, not a pipe: it
  reads `sz`'s bytes as screen output and repaints its own screen. ZDLE
  (0x18, CAN in ASCII) cancels an escape sequence there and is dropped, so
  the client sees `**B00000000000000` with no ZDLE, at the place where tmux
  draws it; the CR, LF and XON after the header and every binary byte are
  gone or redrawn. No start is found, nothing is asked, and `sz` or `rz`
  times out in the pane. `-e` does not help: the header itself holds ZDLE.
  In the other way tmux reads podssh's keys as keys (its prefix is 0x02),
  so a binary stream would not reach `rz` either. Another program that
  emulates a terminal (screen, for one; not measured) would do the same; only a carrier of
  printable bytes, re-sent by line, crosses it (T-831, step 2).
- **`podman exec -t` passes ZMODEM.** Its tty path copies bytes, and both
  ttys are raw while `sz` or `rz` runs. lrzsz is not in Alpine and the
  container had no network, so the container ran the host's glibc `sz` and
  `rz` through the host's loader (`/opt/g/ld-linux-x86-64.so.2 --library-path
  /opt/g`), copied in with `podman cp`; the path measured is the tty, not
  the libc.
- **A pty that maps CR and LF passes ZMODEM**, as lrzsz sets its tty raw
  (`-icanon -opost -icrnl -inlcr -igncr`) before the transfer.
- **A stall that is podssh's own.** 3 of 205 runs of (d2) `rz` stopped: podssh showed its question,
  then nothing (twice after `up.bin: 16384 of 1048576 bytes`), for more
  than 80 s, while the far `rz` waited in a read on its raw tty (seen in
  the one run where its tty was read). podssh's 40 s limit did not end it, Ctrl-C and CAN did not
  cancel it, and one such podssh outlived the death of its terminal for 30
  minutes (idle in `epoll_wait`, the file still open at 851,968 bytes). No
  run of (a) or (d1) stopped in 145 and 45. T-859 found the cause, and it
  was no far side's: podssh's send waited for the channel's window and,
  each second with `--direct`, awaited the window's lock in the body of
  its select (T-598's check that the window stays shut 60 s). tokio's lock
  takes its permit and then yields when the task's budget of work is spent,
  so the write that waited could hold the lock while it was not polled; the
  check queued behind it for good, and russh's loop queued behind both at
  the server's next window adjust. Nothing more was sent or read, and the
  send read no key, no signal and no time. The far `rz` waited for the
  next byte. It came in plain `rz` too: 5 of 92 uploads of (a) and 2 of 60
  of (d2) with the debug build at `55386459`. The check now reads the
  window beside the write, never after it, and the send also takes the
  keys, the time and the signals that end a transfer and a session
  (above): with the change, 0 of 90 uploads of (a) and 0 of 180 of (d2)
  stopped (T-859's `## Done`).

### The 7-bit envelope (T-831, step 2): the design for pod-term

podcrates writes the codec as `pod_term::transfer` (PodUtils/podcrates#258, COORD-153, answering
COORD-137, #346); podssh wires it into the session as T-148's ZMODEM is wired. This is the design
that #258 asked for: the trigger, the frames, the flow, the limits and the test vectors. Every byte
that crosses is printable ASCII (0x20 to 0x7E) or CR or LF, so that a terminal emulator between the
far shell and the pty (tmux, above) paints it, and the near side reads it back from the paint.

**Roles.** The far end runs a program that holds the far role of the same codec (which program is
podssh's call, not the codec's); it sets its tty raw with no echo, as lrzsz does. The far end always
starts, by painting the trigger. A *sender* and a *receiver* are the two ends of one file: a download
has the far end as sender, an upload the near end. One trigger moves one file.

**The trigger line.** The far end writes `\r\x1b[K` (to start a clean line), then

```text
#PODSSH-TX<version>:<dir>:<id>:<crc>\r\n
```

- `<version>` is `1`, decimal, 1 to 3 digits; `<dir>` is `S` (the far end sends) or `R` (the far
  end receives); `<id>` is 16 lowercase hex digits, 64 random bits of the far end; `<crc>` is 8 hex
  digits (lowercase sent, either case read), CRC-32/ISO-HDLC (zlib's `crc32`) of the bytes from `#`
  through `<id>`. The line is 39 bytes in version 1; the pane must be at least 48 columns wide, so
  that it never wraps.
- The near side scans the output for `#PODSSH-TX` as `detect.rs` scans for ZPAD: each byte that
  cannot begin the trigger shows at once; a possible trigger that the end of a read cut waits for
  the next read, 100 ms at most (T-148's hold), then shows. The trigger must be contiguous: an
  escape sequence, CR or LF inside it makes it text.
- A whole trigger starts a session only when the CRC holds, the version is 1, and the id was not
  seen before in this session (the codec keeps the last 32 ids). Else its bytes show unchanged: a
  `cat` of a log that holds a trigger, or tmux painting its screen again after a resize, starts
  nothing. A trigger of another version with a CRC that holds also gives `Unsupported`, so that the
  caller can say one line.
- A trigger that starts a session is removed from the display: its bytes and one line end after it
  (CR, LF or CRLF, when it is in the same read). The bytes before it show; the bytes after it belong
  to the session.
- The near side sends nothing until its caller accepts: a false start costs a question, never a key
  typed into the far shell. Each frame starts with `#`, so a frame that lands in a shell (the far
  program died) is a comment.

**The frame.** One frame:

```text
#KIND:<base64>!<crc>
```

- `KIND` is 4 uppercase ASCII letters (the table below). `<base64>` is the payload in the standard
  alphabet (`A-Z a-z 0-9 + /`), sent with no padding; the reader also takes up to two `=` at the end.
  The unused bits of the last character must be zero, and a length of 1 mod 4 is invalid (the decode
  is canonical, so the text and the payload are one to one). `<crc>` is 8 hex digits, CRC-32/ISO-HDLC
  of `KIND`, `:` and the decoded payload.
- **Line ends.** A sender ends each frame with a line end: CRLF from the far end (its tty is raw,
  so it writes CR itself), CR from the near end (the Enter key, which tmux passes as it is). It may
  also break a long frame into physical lines anywhere inside `<base64>`: the far end at the pane's
  width less one (when its stdout is a tty with a known width) and at 1024 bytes otherwise, the near
  end at 1024 bytes (under the 4095 bytes of a canonical tty, should the far tty not be raw). The
  reader drops each CR and LF inside a frame, so CR, LF, CRLF, a lone CR and a wrapped line are all
  one frame; a frame is whole at the eighth hex digit of its CRC, whatever follows.
- **What the reader drops first.** Inside a session the reader removes, before it frames: escape
  sequences (`ESC [` parameters and a final byte 0x40 to 0x7E; `ESC ]` to BEL or `ESC \`; `ESC` and
  one byte otherwise) and each other byte outside 0x20 to 0x7E except CR and LF. tmux draws a
  wrapped line with cursor moves; these are dropped, and the text stays in order. Five CAN in a row
  from the peer are counted before they are dropped (below).
- **Resync.** Outside a frame, bytes are junk until `#`, 4 uppercase letters and `:`. Inside one,
  any byte that is not base64, `=`, CR, LF, or `!` with its 8 hex digits damages it: the frame is
  dropped (`Damaged`), and when that byte is `#` a new frame is parsed from it. This is trzsz's rule
  "resynchronize at the last `#KIND:`", for a stream. A frame whose base64 or CRC fails is damaged
  too.

**The payloads.** Big-endian integers; `str` is a `u16` length and that many bytes of UTF-8. Bytes
after the last field are a protocol error, except in `DATA`.

| KIND | From | Fields | Meaning |
| --- | --- | --- | --- |
| `HELO` | near, then far | `u8` version (1), 8 bytes id, `u32` largest chunk | The near end accepts the trigger; the far end answers with the same id. The chunk cap is the smaller of the two |
| `OFFR` | sender | `u64` size, `u32` mode (the low 12 bits; 0: none), `u64` mtime (seconds since 1970; 0: none), `str` name | One file |
| `TAKE` | receiver | `u64` from (0 in version 1; a resume is for later) | The receiver takes the file |
| `SKIP` | receiver | `str` reason | The receiver refuses the file; the session ends |
| `DATA` | sender | `u64` offset, then 1 to chunk bytes | The file's bytes at offset |
| `ACKN` | receiver | `u64` of (the offset of the `DATA` it answers), `u64` count (bytes received in order) | The echo of the received count |
| `DONE` | sender | `u64` size, 32 bytes SHA-256 | Each byte was sent |
| `KEPT` | receiver | `u64` size | SHA-256 matched and the file has its name; the session ends |
| `STOP` | either | `u8` code, `str` reason | The session ends: 1 cancelled, 2 out of time, 3 the size or the SHA-256 differs, 4 protocol error, 5 a local error (a write, a rename), 6 refused, 7 unsupported |

A well-formed frame of a kind that the role never takes in its state (an echo of its own frame, a
`DATA` to a sender) is dropped as junk. A kind not in the table, a version other than 1, an id that
differs from the trigger's, or a field out of range is a protocol error: `STOP` 4.

**The flow.**

1. The far end paints the trigger and waits 120 s for `HELO` or `STOP` (a person answers the near
   question meanwhile). The near codec gives `Start`; its caller asks, as T-148 asks, and calls
   `accept` (then `HELO`) or `refuse` (then `STOP` 6). The far end answers `HELO`.
2. The sender sends `OFFR`. A receiver near end gives `Offer`: the name is checked first (below),
   then the caller asks about a name that is taken and calls `take` or `skip`.
3. `DATA` and `ACKN`, one `DATA` in flight. The sender sends `DATA` at offset = the last count and
   waits. The receiver writes from its count on: a `DATA` with offset at or below its count takes
   only its bytes past the count (an overlap after a resend), and answers `ACKN { of: offset, count
   }`; a `DATA` past its count is a protocol error. An `ACKN` whose `of` is not the offset in flight
   is stale (a duplicate painted again) and is dropped. One whose `of` matches advances the sender
   to `count` when `count` is larger (a count past the size, or past what was sent, is a protocol
   error), and asks for a resend when `count` equals the offset.
4. **The chunk.** It starts at 1 KiB. The time of an ack runs from the moment `poll_output` handed
   over the frame's last byte. An advancing ack within 500 ms doubles the chunk, up to the cap
   (32 KiB at most); one after more than 2 s halves it, down to 1 KiB; a resend sets it to 1 KiB.
5. **The resend.** With no answer to the frame in flight after `max(1 s, 4 × the last ack time)`,
   at most 5 s, the sender sends the same frame again (the same bytes: the codec keeps the frame in
   flight, so it asks its caller for each offset once, in order). A receiver that gets a damaged
   frame sends nothing; the sender's timer covers it.
6. `DONE`: the receiver compares the size with its count and the SHA-256 with its own hash of the
   bytes it wrote. Equal: it gives `Verified`, its caller fsyncs and renames the temporary file
   (T-134's rule) and calls `kept`, which sends `KEPT`. Not equal: `STOP` 3 and `End`, and no
   `Verified`. An empty file goes `OFFR`, `TAKE`, `DONE` with no `DATA`.
7. After `KEPT`, `SKIP` or `STOP` the session ends on both sides; the far end restores its tty, and
   may clear what it painted (in tmux: its screen keeps the frames until it does). The near codec
   gives the bytes after the last frame in the same read as `End`'s `rest`, for the display, and
   watches for a trigger again.

**The name** (T-148's rule, for a name from the far end): the codec takes the last component after
`/`; it refuses with `STOP` 6 a name of more than 1024 bytes on the wire, not UTF-8, or whose last
component is empty, `.`, `..`, longer than 255 bytes, or holds a control character (C0, DEL, C1).
The caller adds the rules of its platform (Windows' names, `files.rs`'s `check_name`) and calls
`skip` for those. A file comes as T-134 writes a copy: `.NAME.podssh-RANDOM.part` beside it, mode
0600, then SHA-256 and the size, then the rename; the mode loses the write bits of the group and
others. MD5 is not used.

**The limits.**

| What | Limit | Past it |
| --- | --- | --- |
| A trigger cut by a read | 100 ms | its bytes show |
| Ids remembered | the last 32 | an older id starts again (a person still answers) |
| A frame, from `#` to the CRC, CR, LF and escapes not counted | 44,032 bytes (a `DATA` of 32 KiB is 43,717) | `STOP` 4 |
| Junk in a row, with no whole frame | 64 KiB | `STOP` 4, with the last junk in its reason |
| Damaged frames in a row | 8 | `STOP` 4 |
| The chunk | 1 KiB to 32 KiB (and the smaller `HELO` cap) | |
| A name on the wire; its last component | 1024 bytes; 255 bytes | `STOP` 6 |
| A reason in `SKIP` or `STOP` | 200 bytes sent; a longer one read is cut | |
| A size or offset | below 2^63 | `STOP` 4 |
| Each wait for a valid frame from the peer | 20 s (the far end's first wait: 120 s) | `STOP` 2 |
| The resend of the frame in flight | `max(1 s, 4 × ack time)`, at most 5 s | the 20 s wait ends it |

A write of the near end's bytes that the server does not take stays the session's limit (T-859's
40 s), not the codec's.

**The ends.** Each says one line and leaves no file under its final name:

- Ctrl-C typed, or five CAN typed in a row, in one read or in several (T-859): `STOP 1 "cancelled
  here (Ctrl-C)"` or `"(CAN)"`. The codec's `keys` takes each key while a session runs and drops
  the others, as they would land in the frames; outside a session keys pass unchanged.
- Five CAN in a row from the peer (a killed `sz`, the far shell's own cancel): the end, with no
  `STOP` sent.
- `hangup` (the local terminal went: SIGHUP, SIGTERM, stdin's end): `STOP 1 "the local terminal
  went"`; the caller exits 255, as T-859 does.
- A `STOP` from the peer; a wait of 20 s; a protocol error; a local error the caller reports with
  `stop(5, reason)`.
- A receiver's caller removes its temporary file at each `End` that is not `Done`. A sender's `End`
  is `Done` only after `KEPT`.

**The interface** (sans-IO: bytes and the time in, bytes and events out; the shape of T-148's
`Zmodem`):

```text
// Roles: Transfer::near(), Transfer::far_send(offer, id, now), Transfer::far_receive(id, now).
fn feed(&mut self, peer_bytes: &[u8], now: Instant) -> Vec<Event>; // the peer's output
fn keys(&mut self, keys: &[u8], now: Instant) -> Vec<u8>;           // what passes to the peer
fn poll_output(&mut self, now: Instant) -> Vec<u8>;                 // frames for the peer
fn deadline(&self) -> Option<Instant>;  // fn tick(&mut self, now) -> Vec<Event> at it
fn accept(&mut self, now) / refuse(&mut self, reason) / send_file(&mut self, info, now)
fn take(&mut self) / skip(&mut self, reason) / supply(&mut self, bytes) / kept(&mut self)
fn stop(&mut self, code, reason) / hangup(&mut self)

enum Event {
    Show(Vec<u8>),                          // near: output for the terminal, in order
    Start { dir: Dir, id: [u8; 8] },        // near: a trigger; accept() or refuse()
    Unsupported { version: u32 },           // near: its line was shown
    Offer { name: String, size: u64, mode: Option<u32>, mtime: Option<u64> }, // receiver
    NeedData { offset: u64, max: usize },   // sender: supply() at most max bytes
    Write { offset: u64, bytes: Vec<u8> },  // receiver: in order, never twice
    Progress { done: u64, size: u64 },
    Damaged,                                // a frame was dropped (for a count, not a line)
    Verified { size: u64, sha256: [u8; 32] }, // receiver: rename, then kept() or stop(5, ..)
    End { ended: Ended, rest: Vec<u8> },    // Done, or Stopped { code, by_peer, reason }
}
```

**Test vectors.** Id `0123456789abcdef`, the file `a.txt` of 6 bytes `hello\n`, mode 0644, mtime 0,
SHA-256 `5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03`. `\r`, `\n` and `\x1b` are
the bytes 0x0D, 0x0A and 0x1B. The rows T are the near side's scan of the output; the rows F are the
frame reader inside a session (a frame, `Damaged`, or the session's end); the rows X are whole
exchanges. Each frame below was computed with Python's `base64` and
`zlib.crc32`.

| # | Input (bytes; "then" separates reads) | Events or output |
| --- | --- | --- |
| T1 | near idle: `ls\r\n#PODSSH-TX1:S:0123456789abcdef:56fd5108\r\n` | `Show("ls\r\n")`, `Start { S, id }`; nothing sent |
| T2 | near idle: `#PODSSH-TX1:R:0123456789abcdef:b9afe7e9\r\n` | `Start { R, id }` |
| T3 | `#PODSSH-TX1:S:0123` then `456789abcdef:56fd5108\r\n` | first read: no event; second: `Start` |
| T4 | `#PODSSH-TX1:S:0123`, then 100 ms with nothing | `Show("#PODSSH-TX1:S:0123")` at the deadline |
| T5 | `#PODSSH-TX1:S:0123456789abcdef:56fd5109\r\n` (CRC off by one) | `Show` of each byte; no `Start` |
| T6 | `#PODSSH-TX2:S:0123456789abcdef:f9541cc2\r\n` | `Show` of each byte, `Unsupported { 2 }` |
| T7 | T1's trigger again after that session ended | `Show` of each byte; no `Start` (id seen) |
| T8 | `#PODSSH-TX1:S:fedcba9876543210:dac7206b` after T7 | `Start` (a new id) |
| T9 | `#PODSSH-TX1:S:0123\x1b[K456789abcdef:56fd5108\r\n` (an escape inside) | `Show` of each byte (not contiguous) |
| F1 | `#HELO:AQEjRWeJq83vAACAAA!21941b5b\r\n` | `HELO { 1, id, 32768 }` |
| F2 | F1 ending in `\n`, in `\r`, and in nothing | the same frame, each |
| F3 | `#DATA:AAAAAA\r\nAAAABoZWxsbwo!beee1f4d\r\n` (wrapped) | `DATA { 0, "hello\n" }` |
| F4 | `junk\x1b[K#DATA:AAAAAA\x1b[12;1HAAAABoZWxsbwo!beee1f4d` | `DATA { 0, "hello\n" }` (junk and escapes dropped) |
| F5 | `#DATA:AAAAAAAAAABo` then `ZWxsbwo!beee` then `1f4d` | the frame at the third read |
| F6 | `#DATA:AA*AAAAAAABoZWxsbwo!beee1f4d` | `Damaged` |
| F7 | `#DATA:AAAAAAAAAABoZWxsbwo!beee1f40` (CRC) | `Damaged` |
| F8 | `#DATA:AAAAAAAAAABoZWxsbwo=!beee1f4d` | `DATA { 0, "hello\n" }` (padding read) |
| F9 | `#DATA:AAAAAAAAAABoZWxsbwoA!beee1f4d` (length 1 mod 4) | `Damaged` |
| F10 | `#DATA:AAAA#ACKN:AAAAAAAAAAAAAAAAAAAABg!168c223e` | `Damaged`, then `ACKN { 0, 6 }` |
| F11 | `#DATA:` then 44,027 `A` with no `!` | `STOP` 4 sent, `End` |
| F12 | 65,537 bytes of `x` in a session, no frame | `STOP` 4 sent, `End` |
| F13 | `#ZZZZ:` frame with a CRC that holds | `STOP` 4 |

The exchanges; `>` is near to far, `<` far to near; near frames end in `\r`, far frames in `\r\n`:

| # | Download (far `S`) | Upload (far `R`) |
| --- | --- | --- |
| 1 | `<` trigger T1; near `Start`, caller `accept` | `<` trigger T2; near `Start`, caller `send_file(a.txt)` |
| 2 | `>` `#HELO:AQEjRWeJq83vAACAAA!21941b5b` | `>` the same `HELO` |
| 3 | `<` the same `HELO` | `<` the same `HELO` |
| 4 | `<` `#OFFR:AAAAAAAAAAYAAAGkAAAAAAAAAAAABWEudHh0!51054221`; `Offer { "a.txt", 6, 0644, None }`; caller `take` | `>` the same `OFFR` |
| 5 | `>` `#TAKE:AAAAAAAAAAA!5b64f8f9` | `<` the same `TAKE`; near `NeedData { 0, 1024 }`, caller `supply("hello\n")` |
| 6 | `<` `#DATA:AAAAAAAAAABoZWxsbwo!beee1f4d`; `Write { 0, "hello\n" }` | `>` the same `DATA` |
| 7 | `>` `#ACKN:AAAAAAAAAAAAAAAAAAAABg!168c223e` | `<` the same `ACKN` |
| 8 | `<` `#DONE:AAAAAAAAAAZYkbW1ItXfCG0P8LEQ+9nSG7T8cWOvNNCChqLoRva+Aw!6ff6dfbc`; `Verified`; caller `kept` | `>` the same `DONE` |
| 9 | `>` `#KEPT:AAAAAAAAAAY!67cdbc05`; `End { Done }` | `<` the same `KEPT`; `End { Done }` |

| # | Fault | Input after the exchange's step | Must give |
| --- | --- | --- | --- |
| X1 | a lost ack (upload, sender near) | after step 6, no frame for the resend time | `>` step 6's `DATA` again, the same bytes; `<` step 7's `ACKN`; then `DONE`; the chunk is 1 KiB |
| X2 | an ack that does not advance | after step 6: `<` `#ACKN:AAAAAAAAAAAAAAAAAAAAAA!ffef870b` (of 0, count 0) | `>` step 6's `DATA` again |
| X3 | a duplicate `DATA` (tmux painting again; download) | after step 7: `<` step 6's `DATA` again | no `Write`; `>` step 7's `ACKN` again; the sender drops it if it has moved on (stale `of`) |
| X4 | a hash mismatch (download) | step 8 replaced: `<` `#DONE:AAAAAAAAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!b65d2465` | no `Verified`; `>` `#STOP:AwAhU0hBLTI1NiBkaWZmZXJzOyBub3RoaW5nIHdhcyBrZXB0!59691c9e` (3, "SHA-256 differs; nothing was kept"); `End { Stopped(3) }` |
| X5 | Ctrl-C (download) | after step 6: `keys("\x03")` | `keys` returns nothing; `>` `#STOP:AQAXY2FuY2VsbGVkIGhlcmUgKEN0cmwtQyk!7306070e`; `End { Stopped(1) }` |
| X6 | five CAN in two reads | `keys("\x18\x18")`, `keys("\x18\x18\x18")` | as X5, reason `cancelled here (CAN)` |
| X7 | a refusal at the start | after step 1: `refuse` | `>` `#STOP:BgAMcmVmdXNlZCBoZXJl!cffba5b2` (6, "refused here"); `End` |
| X8 | a skip (upload, far refuses) | step 5 replaced: `<` `#SKIP:ABFhLnR4dCBleGlzdHMgaGVyZQ!409966d8` | `End { Stopped(6) }`, reason `a.txt exists here` |
| X9 | a name with a path | step 4: `#OFFR:AAAAAAAAAAYAAAGkAAAAAAAAAAAACWRpci9hLnR4dA!21fcfe26` (`dir/a.txt`) | `Offer { "a.txt", .. }` |
| X10 | a name that names no file | step 4: `#OFFR:AAAAAAAAAAYAAAGkAAAAAAAAAAAAAi4u!4533a1d9` (`..`) | no `Offer`; `STOP` 6; `End` |
| X11 | silence | after step 5, nothing for 20 s | `STOP` 2; `End { Stopped(2) }` |
| X12 | an echo of its own frame | download, after step 5: `<` step 5's `TAKE` | dropped as junk; no event |

## A notice while the far end is silent

With the resumable layer (`ssh node://`, its race with `--iroh-ticket`,
`iroh:`, a podssh node's `cf://` name, and the session after `--upgrade`),
podssh tells a silent far end from a slow program before the layer finds
the link dead (30 s) and resumes the session (T-302); and on the forward
road through the relay, before its pings find the link dead and the session
ends (T-307).

- **The silence.** The layer keeps the time of the far end's last byte, and
  of the oldest question of this side that waits: `DATA` that the far end
  acknowledges within 200 ms, a `PING` that it answers, a resume after a
  loss. Any byte from the far end answers each question. A question that
  waits 5 s makes the far end silent (UNVERIFIED: the value waits for its
  measurement); so a prompt that echoes nothing is no silence, and an idle
  session neither, as its `PING` of each 10 s is answered. A host that
  wakes from a sleep asks at once with a `PING` (T-663): a tick of the
  clocks each second that comes more than 2 s late, by tokio's clock or by
  the time that the host slept (on Linux, `CLOCK_BOOTTIME` against
  `CLOCK_MONOTONIC`; elsewhere the wall clock), is a wake. The monotonic
  clock of the waits stops in a sleep, so with no check a link that the
  sleep took would be asked only at the next key or heartbeat.
- **Where it shows.** With a pty on a terminal, in the window's title:
  `podssh: no word from HOST for N s, ~. ends the session`, counting up each
  second. podssh first saves the title on the terminal's stack
  (XTWINOPS `CSI 22 ; 2 t`), and takes it back (`CSI 23 ; 2 t`) before the
  far end's next bytes, so that a title that a program sets then is kept;
  the screen is never written. It writes its sequences only where the
  session's output left the terminal's parser at its ground state, never
  inside a sequence or a character that a pause cut. While the title shows
  the notice, the layer's lines of a loss and a resume are left out: they
  would be written into the screen. With no pty, where stderr is a
  terminal, a line on stderr, and a line when the far end answers again.
  Never in a pipe, never with `-q`, never for `podssh each`.
- **Only where the terminal keeps a stack of titles.** A terminal with
  none would keep the notice as its title. podssh cannot ask: the answer
  would come on stdin, among the keys. It knows xterm (`XTERM_VERSION`) and
  VTE (`VTE_VERSION`), but inside tmux or screen; `PODSSH_TITLE_STACK=yes`
  or `no` says it for another terminal. Elsewhere there is no notice, and
  the layer's lines stay as before. Which terminals keep the stack (xterm,
  VTE, Windows Terminal, the Windows console) is not measured on
  2026-10-31: `python3 scripts/title-stack.py`, run in each, says it.
- **On the forward road through the relay** (T-307), nothing below SSH
  answers a key: the relay copies the bytes to the target. So with SSH's
  bytes up, while no question waits, a WebSocket Ping of podssh's goes
  too, and any frame of the relay answers it, its Pong or the target's
  bytes; the silence counts from the relay's last frame, with the same
  wait of 5 s and the same places. A key that nothing echoes is then no
  silence. A wake of the host asks the same Ping at once (T-663), so a
  session of `--persist` whose link the sleep took shows the notice 5 s
  after the wake, with no key typed; its link still ends when the relay
  stream's pings find it dead, as SSH there has no layer to move it.
  Measured through the stand-in relay and a proxy that holds each
  byte (`cargo test -p podssh-cli --test silent_notice -- --ignored`): with
  a pause of 20 s, the notice came 6.0 s after it began and went before the
  key's answer at 20.0 s; a pause of 90 s ended the session 40.0 s after it
  began (the relay stream's pings: nothing for 30 s), or 12.0 s after with
  `ServerAliveInterval=4` and `ServerAliveCountMax=2`.
- **With `--direct`** (T-332), and on each road that tells no silence of
  its own (a service of cloudflared on `cf://`), the bytes are SSH's, end
  to end, so the question is SSH's own: with a key from the terminal,
  while no question waits, the session sends `keepalive@openssh.com` with
  a reply asked for (russh's `Handle::send_ping`), and the reply, or any
  message of the session's channel, answers it. A server that knows no
  such request answers with a failure, which is a reply too (RFC 4254,
  section 4). The wait is 5 s, the places the same; the silence counts
  from the server's last word. Through `-J`, the question is the target's
  own, through the hop, as the notice names the target: a hop that answers
  while the target is silent is still silence. A road that tells the
  silence (the relay, the layer) keeps its own word, and SSH then asks
  none. Measured through a proxy that holds each byte
  (`cargo test -p podssh-cli --test silent_notice -- --ignored`): with a
  pause of 20 s, the notice came 6.0 s after it began and went before the
  key's answer at 20.1 s; keys that nothing echoes gave none. Against this
  host's OpenSSH 9.6p1 and Dropbear 2022.83 in a pty, the same: 12 keys
  that nothing echoed gave no notice, and under a pause of 20 s the notice
  came at 6.0 s and went before the echo at 20.1 s and 20.0 s.

## The writer lease of a shared shell (T-862)

With `podssh serve --share` (`docs/cli.md`, "A shell shared by name"),
each writer of a shared shell types through one lease: the holder's bytes
reach the pty, and another writer's wait until the holder was silent for
`LEASE_IDLE` (`crates/podssh-ssh/src/server/share.rs`). Too short, and two
people's keys mix within a word; too long, and the second writer waits
after each of the holder's pauses.

Measured on 2026-11-24 (Linux, the kernel's pty, russh's client over pipes
in memory): two scripted typists under the `rw-` name of one shell under
`cat` with no echo and no line buffer, so the output is the pty's input in
the order the lease let it in. Each types words of 3 to 8 letters, 100 to
400 ms between keys, 400 to 1500 ms between words and a pause of 2 to 4 s
before one word in eight, from a fixed seed: 62.6 s of typing, 22 and 24
words, for each span.

| Lease | Words broken | Waits | Time held | Median | 95th | Longest |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 ms | 41 of 46 | 64 | 3.5 s | 54 ms | 101 ms | 157 ms |
| 200 ms | 41 of 46 | 89 | 16.2 s | 160 ms | 470 ms | 664 ms |
| **400 ms** | **0** | **34** | **26.2 s** | **825 ms** | **2193 ms** | **2319 ms** |
| 500 ms | 0 | 34 | 29.4 s | 925 ms | 1890 ms | 2294 ms |
| 600 ms | 0 | 31 | 37.8 s | 1109 ms | 5285 ms | 5445 ms |
| 800 ms | 0 | 25 | 42.8 s | 1226 ms | 5316 ms | 5486 ms |

A word is broken when a byte of the other typist lands between its first
letter and its end; a wait is a write of a held writer, and its time runs
from the first hold to the write. `LEASE_IDLE` is 400 ms: the least span
that broke no word, and the least waiting of those. A span under the gaps
between a person's keys hands the lease over inside a word, and so broke
nearly every word typed while the other typed; each step past 400 ms only
holds the second writer longer (to 5 s at the 95th from 600 ms, where the
holder's gaps between words no longer pass it on). The margin at 400 ms is
the script's own longest gap between keys; a person slower than that within
a word can still be broken. The command:

```sh
cargo test -p podssh-ssh --test share_lease_measure -- --ignored --nocapture
```

`PODSSH_MEASURE_SECS` sets the typing of each span (default 60 s).

## Shell integration marks of `podssh serve` (T-120)

A terminal finds the commands of a session by OSC 133 (`ESC ] 133 ; A BEL`
before a prompt, `B` after it, `C` where a command's output starts, and
`D[;STATUS]` where the command ended) and the directory by OSC 7
(`ESC ] 7 ; file://HOST/PATH BEL`). Over a node, a shell sends none unless
its start files add them, and a cage image often has none.
`podssh serve --shell-integration` adds them to a login shell on a tty; off
by default, it adds nothing (`crates/podssh-ssh/src/server/marks.rs`).

- **On a pty, or a tty that serve answers.** Only the shell knows where its
  prompt is, so the marks come from its start. bash runs as
  `bash --rcfile FILE -i`, `FILE` a file of serve's own. bash reads
  `--rcfile` only when it is not a login shell, so the file reads the files
  of a login first, in a login bash's order (`/etc/profile`, then the first
  of `~/.bash_profile`, `~/.bash_login`, `~/.profile`). It then adds
  `PROMPT_COMMAND` (the end with `$?`, OSC 7, the start of the prompt), a
  mark at the end of `PS1`, and a `DEBUG` trap for the start of the output.
  A `DEBUG` trap of the user's own stays, and the output then has no start
  mark. The shell is not a login shell for `shopt login_shell` and
  `logout`. zsh keeps its login: it runs with `ZDOTDIR` at a directory of
  serve's own, whose `.zshenv` gives `ZDOTDIR` its value of the session
  back, reads the user's `.zshenv`, and adds `precmd` and `preexec` hooks;
  zsh then reads each later file where it would have. The files are in a
  directory that `mkdtemp` makes (mode 0700) in the child's `TMPDIR`, else
  `/tmp`, and go when the session ends. Invariant: serve writes no file of
  the user's. Another shell gets no marks, and serve's stderr says so, as it
  says a directory that it cannot make; the shell starts either way.
- **On serve's line discipline (T-111).** serve draws the prompt and sees
  each line submitted, so it writes the marks itself: `A`, the prompt, `B`
  at the first prompt. The discipline draws the next prompt with the echo
  of each line, so that echo becomes the line's end, `C`, `D`, `A`, the
  prompt and `B`. With no help from the shell, serve does not see a command
  end: `D` comes at once and has no status, and the command's output is
  drawn above the next prompt, after its marks. A redraw (Ctrl-C, a line
  erased) is not marked. No OSC 7: serve does not read the shell's
  directory.
- **A command** (`exec`, a forced `command=`) gets no marks.

## Local echo for high latency (T-160)

Through the relay, each typed key shows only after a round trip. With
`--predict`, podssh shows each key at once, underlined, where the far end
will echo it, and takes the guess off when the echo comes, as mosh does.
podssh passes the far end's bytes unchanged, so the guesses are drawn over
the terminal and taken off again before each byte of the far end: the
terminal always reads those bytes on the screen that the far end wrote.

- **What podssh knows.** A model of the far end's screen (the `vt100`
  crate, the model of the oracle below) reads each byte of the far end's
  output and nothing else (`crates/podssh-ssh/src/predict/mod.rs`). Which
  keys reached the pty, and whether the pty echoes, only the far end
  knows: `podssh ssh` asks with `env predict@podssh v1`, last before the
  shell or the command, and `podssh serve` takes it on a channel whose pty
  it opened. A shell shared by name and a kept shell send no reports, and
  their guesses never show. Another server refuses the request, and
  nothing is guessed; `-v` says so.
- **The reports.** serve counts the client's bytes that reached the pty's
  master, and sends the count that is 50 ms old (the time a program takes
  to echo, mosh's figure) and the pty's ECHO and ICANON flags, as 10 bytes
  of extended data of the code `0xFE504F44`: RFC 4250 leaves 0xFE000000 to
  0xFFFFFFFF for private use (section 4.4.3). A report goes out of the
  task that copies the pty's output, after each write of output and when a
  count falls due, so it follows each byte of output read before it
  (`crates/podssh-ssh/src/server/predict.rs`). The client judges each guess
  against its model when a report reaches its key, never against a clock.
- **What is guessed.** Printable ASCII, Backspace (DEL or BS) and the left
  and right arrows, on the cursor's row only; the text after the cursor
  moves as a line editor moves it. Nothing in the last column, nothing over
  a wide character. Each other key (Enter, Tab, a control key, another
  sequence, a character that is not ASCII), a read of more than 100 bytes (a
  paste), a wrong guess, a new row of the cursor and a change of the pty's
  flags start a new epoch, and nothing is guessed until the far end has
  read each key sent before.
- **When a guess shows.** Only in an epoch whose first guess the far end
  confirmed: the first key after Enter waits for its echo, and the keys
  typed after that echo show at once. Only while the smoothed round trip is
  120 ms or more, and until it drops under 80 ms. Never while the pty reads
  a line with no echo (ICANON on, ECHO off: getpass, sudo, ssh, `read -s`),
  so a password never shows; never while the far end hides the cursor, and
  never inside a sequence that the far end's last bytes left open.
- **Why not the ECHO flag alone.** A line editor turns ECHO off and echoes
  each key itself: bash's readline, zsh, fish and vim all run with ECHO off.
  Read alone, the flag would turn local echo off where it is wanted most.
  So a line with no echo is ICANON with ECHO off, and a program in raw mode
  that echoes nothing (a password read raw, vim's normal mode) is held by
  the epoch: its first key is never confirmed, so nothing of it shows.
- **How it draws.** Each move is relative, along the cursor's row (`CSI n
  C`, `CSI n D`), never to a place on the screen, which the origin mode
  would move. A guess takes the far end's pen and an underline; taking it
  off writes the model's cell with its own pen, or erases it again (`CSI X`)
  where the far end left it empty, then puts back the far end's pen and
  cursor (`crates/podssh-ssh/src/predict/draw.rs`).
- **When it stops.** A line of podssh's own on the terminal (a message, an
  escape's words, ZMODEM) moves the cursor where the model does not know
  it, so local echo stops for the rest of the session. So do a far end
  that counts bytes never sent and a report of another version. A resize
  takes the guesses off and starts a new epoch. `--expect`, `--sudo`,
  `--su`, `podssh each` and a session through a control master never ask.

## Tests

Linux test hosts grant ptys, so a test must force the paths with no pty:
`sshd -o PermitTTY=no`, a server that never answers `pty-req`, and runs with
no local terminal. Include a shell-only server like podvm's, which refuses
`exec` and has no sftp subsystem.

The terminal oracle (T-200) judges what a terminal shows, not the bytes. A
test that compares bytes with bytes that a person wrote passes when both
share a mistake, such as a wrong column or lines that step down like
stairs. The model is the `vt100` crate, a VT terminal in raw mode, in the
tests only (`PodUtils/podssh:crates/podssh-terminal/tests/screen/mod.rs`); the tests of
podssh-ws and podssh-ssh read the same file. Each test compares rows, the
cursor and the attributes of cells:

- `cargo test -p pod-term --test oracle` (in PodUtils/podcrates): after each key of a run,
  the screen shows the prompt and the line from the first column of a row,
  wrapped as the terminal wraps them, with nothing after them, and the
  cursor in the cell where the next character after the text before the
  line's cursor lands. What the screen must show is the model's own drawing
  of the prompt and the line on an empty screen. The runs come from a fixed
  generator: keys of one and two cells, each editing key in each form,
  output, and a lone Escape, on 8, 16 and 20 columns and with no width.
- `cargo test -p podssh-ws --test terminal_oracle`: hostile text after
  `one_line` stays on its row, the cursor moves by its width, and no cell
  takes an attribute; after `multi_line`, each line is a row.
- `cargo test -p podssh-ssh --test terminal_oracle`: each line of a message
  and of the help of `~?` starts at the first column in raw mode
  (`log::message_text`).
- `cargo test -p podssh-ssh --test silent_notice`: the notice of a silent
  far end over the screen of a full-screen program leaves its rows, its
  cursor and its title, with a model of the stack of titles beside the
  oracle (T-302).
- `cargo test -p podssh-cli --test silent_notice -- --ignored`: the same
  from end to end, through the stand-in relay and a proxy that holds each
  byte, on the reverse road (T-302) and the forward road (T-307); keys
  that nothing echoes give no notice on the forward road; and the end of a
  forward session on a link that stays silent.
- `cargo test -p podssh-ssh --test predict`: local echo against a far
  end in the test at a round trip that the test sets, on the test's own
  clock (T-160). After each step each row but the cursor's is the far end's
  own, and each cell of the cursor's row that differs is an underlined
  guess; once each key was answered, the terminal is the far end's screen,
  cell for cell. At 300 ms a typed letter shows before its echo; after a
  question for a password, or with a program that echoes nothing, no typed
  letter shows. `cargo test -p podssh-ssh --test serve_predict` reads
  serve's reports from a real pty, each after the echo of the keys it
  counts.

The model must agree with tmux before it judges podssh: each sequence of a
fixed corpus (`PodUtils/podssh:crates/podssh-terminal/tests/screen/corpus.txt`) goes
through both, and the rows and the cursor must be the same
(`cargo test -p pod-term --test calibration` in PodUtils/podcrates). `PODSSH_TEST_TMUX`
names tmux; the gate installs it and names it, and with no tmux on the host
the check says that it did not run.
