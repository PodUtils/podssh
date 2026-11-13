# A tty for `podssh serve` where `/dev/ptmx` is missing (T-248)

The study of T-248 (`TODO/serve.md`): which routes give a child of
`podssh serve` a terminal in a cage with no `/dev/ptmx`, what each one
needs, what podssh must answer, what still fails, and which probes at run
time choose the route. It was measured on 2026-11-13 by a drafting agent,
with C probes compiled by `cc` and no build of podssh. The probes and the
script that runs them all are in [serve-tty/](serve-tty/):
[run.sh](serve-tty/run.sh) builds them and runs each route in each cage.

## The host, and the cage that stands for the target

- The host: Linux 6.18.44 (a Firecracker VM, 4 CPUs), Ubuntu 24.04.5,
  glibc 2.39, musl-gcc, bash 5.2.21, dash, vim 9.1, less 590, procps top.
  The session runs as root with each capability, NoNewPrivs=0 and no
  seccomp filter, and has `/dev/ptmx`. So no result here is the target's
  as it stands; the cage makes the target's conditions.
- [cage.c](serve-tty/cage.c) runs a command as the target runs podssh: a
  mount namespace of its own whose `/dev` is a tmpfs with `null`, `zero`,
  `random`, `urandom`, `full`, `shm` and a `tty` (the host's `/dev/null`
  stands for the sandbox's `/dev/tty`, which opens and is no controlling
  terminal), so there is no `/dev/ptmx` and no `/dev/pts`; then uid and gid
  65534 with no supplementary group, which drops each capability;
  then NoNewPrivs=1. Its flags add a seccomp filter of the cage's own, so
  the probe meets what each sandbox refuses:
  - `-n` refuses `unshare`, `mount`, `setns`, `fsopen`, `open_tree` and a
    `clone` with a `CLONE_NEW*` flag with EPERM (`clone3` with ENOSYS), as
    both real sandboxes refuse `unshare`, `mount` and `chroot`
    (`docs/target-environment.md:19`);
  - `-p` refuses `ptrace`, as the host of podvm's issue 114 does
    (`docs/target-environment.md:40`);
  - `-v` refuses `process_vm_readv` and `process_vm_writev`;
  - `-P` hides `/proc` under an empty tmpfs, as a related host has no
    `/proc` (`docs/target-environment.md:51`);
  - `-l` adds a filter with a notification listener of the cage's own (for
    `reboot` only), held open by a process that never reads it: a sandbox
    whose own supervisor uses seccomp user notification.

## The results

| Route, cage | Result |
| --- | --- |
| 1, no flag | **Works.** A pair in 0.5 to 5.8 ms; `test -t 0`, `stty size` gives `43 132` as set on the master, and a resize to 100x30 reaches the shell's `trap ... WINCH`. |
| 1, `-l` | **Works** (route 1 does not touch seccomp). |
| 1, `-n` | Refused: `unshare(CLONE_NEWUSER\|CLONE_NEWNS)`: EPERM. |
| 1, `-P` | Refused at `/proc/self/setgroups` (ENOENT) when the helper maps its uid; **works** with no map at all (`ROUTE1_NOMAP=1`). |
| 1, from a process with a second thread (`ROUTE1_THREAD=1`) | Refused: `unshare`: EINVAL. |
| 2a, no flag, `-n`, `-n -p` | **Works**: `test -t 0`, `stty size` gives `24 80`; the descriptor told by `kcmp`, the answer written by `process_vm_writev`. |
| 2a, `-n -p -v` | **Works**: the answer written through `/proc/PID/mem`. |
| 2a, `-n -p -P` | **Works**: `kcmp` and `process_vm_writev` need no `/proc`; forced to `pidfd_getfd` (`ROUTE2_ID=pidfd`), it works too; forced to `/proc/PID/fd` (`ROUTE2_ID=proc`), nothing is known and the kernel's ENOTTY stands. |
| 2a, `-n -p -v -P` | **Fails**: no way to write the answer; `test -t 0` false, `stty`: "Bad address". |
| 2a, `-n -l` | Refused: `seccomp(SECCOMP_FILTER_FLAG_NEW_LISTENER)`: EBUSY. |
| 2b, `-n`, `-n -l` | **Works**: `test -t 0`, `stty size` gives `24 80`. |
| 2b, `-n -p` | Refused: `PTRACE_TRACEME`: EPERM. |

Route 2a in the cage `-n`, the programs of M5's exit criterion
([run.sh](serve-tty/run.sh) drives each one by keys written to its socket):

| Program | Result | Tty requests that podssh answered |
| --- | --- | --- |
| `isatty` of glibc 2.39, static | true | `TCGETS` |
| `isatty` of musl, static | true | `TIOCGWINSZ` (and stdio's own `TIOCGWINSZ` for line buffering) |
| Python 3.13 | `isatty` true; a resize to 100x30 with SIGWINCH to the group: the handler reads `100x30` | `TCGETS`, `TIOCGWINSZ` |
| `bash --norc -i` | job control on: Ctrl-C (SIGINT to the foreground group) ends `sleep 30`, `$?` 130; Ctrl-Z stops `sleep 31`, `jobs` shows it, `kill -9 %1` then `jobs` shows `Killed`; `exit 7` gives 7. The same keys on a real pty ([realpty.py](serve-tty/realpty.py)) print the same, but for the `^Z` echo, which is the line discipline's. bash opened `/dev/tty` once and got the socket. | `TCGETS`, `TCSETSW`, `TIOCGPGRP`, `TIOCSPGRP`, `TIOCGWINSZ`, `TIOCSWINSZ` |
| `vim -u NONE` | `ihello from vi`, Escape, `:wq`: the file holds the line | `TCGETS`, `TCSETS`, `TCFLSH`, `TIOCGWINSZ` |
| `less /etc/services` | drew the file, quit on `q`; it read its keys from `/dev/tty`, which podssh gave as the socket | `TCGETS`, `TCSETSW`, `TIOCGWINSZ` |
| `top -d 1` | drew `Tasks:`, quit on `q` | `TCGETS`, `TCSETSF`, `TCSBRK`, `TCFLSH`, `TIOCGWINSZ` |

The bash session shows the termios state that podssh must follow: readline
sets `ICANON 0 ECHO 0 ISIG 1` for each prompt, and a command runs with
`ICANON 1 ECHO 1 ISIG 1`; vim sets `ISIG 0`, so its Ctrl-C is a byte.

The cost, `route2 bench-child` in the cage `-n` (20000 calls each, three
runs; the VM's numbers vary): a call that no rule names, 0.13 µs; a call
sent to the supervisor and answered or passed on, 3.4 to 27 µs. Through
ptrace (route 2b), 4.7 to 32 µs. `top` made about 870 opens of `/proc`
in its two seconds, each one sent to the supervisor (at most 25 ms in
all).

## Route 1: a new devpts instance

What it needs, each measured:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNS)` by a process with **one
   thread** (EINVAL otherwise). `podssh serve` runs tokio's threads, so a
   forked child does it: after `fork`, only raw system calls (no
   allocation), as in `pre_exec`.
2. No uid map: devpts mounts in the new user namespace with none, and with
   none no `/proc` is needed. (A map of the uid to itself works too where
   `/proc` is.)
3. `mount("devpts", DIR, "devpts", MS_NOSUID|MS_NOEXEC,
   "newinstance,ptmxmode=0666,mode=0620")` over a directory that exists
   (`/dev/pts`, else `/dev`, else `/tmp`): the mount is the helper's
   own, so nothing is made and nothing is left.
4. `DIR/ptmx` opened, `TIOCSPTLCK` 0, and the slave by `TIOCGPTPEER`
   (Linux 4.13). **Not by `ptsname`**: it says `/dev/pts/0`, a name in the
   host's instance; in the cage it does not exist, and on a host with
   `/dev/pts` it would be another pty.
5. Both descriptors to the parent by `SCM_RIGHTS`; the helper exits and
   its namespaces go with it. The instance lives while a descriptor holds
   it: the child runs in **no namespace of its own**, with the same uid,
   files and mounts as serve's other children, and the slave as its
   controlling terminal (`setsid`, `TIOCSCTTY`), as T-110 does.

What differs from T-110's pty: the slave has no path. `tty` prints "not a
tty", `ttyname` fails, and `/proc/self/fd/0` reads `/0`; so `SSH_TTY` is not
set, and doctor names the instance, not a path.

Where it is refused: each real sandbox (`unshare` refused); a container
under Docker's or Podman's default seccomp profile without `CAP_SYS_ADMIN`
(read: it refuses `unshare` and `clone` of a new namespace then);
`user.max_user_namespaces` 0; Debian's `kernel.unprivileged_userns_clone`
0; Ubuntu's AppArmor rule for unprivileged user namespaces, where `unshare`
passes and the `mount` is refused (read, not measured). The probe runs each
step, so each case is one errno at a named step.

## Route 2a: a tty in user space by seccomp user notification

The child's descriptors 0, 1 and 2 are **one `AF_UNIX` stream socket**, not
pipes: a pty's slave is one file, read and written, and `/dev/tty` must be
a file that both reads and writes. The kernel itself answers `FIONREAD`
and `TIOCOUTQ` on a socket (they are `SIOCINQ` and `SIOCOUTQ`), and
`poll`, `read` and `write` need nothing. stdout and stderr are one stream,
as on a pty.

The child, after `fork` and before `exec`: `setsid`, the socket on 0, 1
and 2, `PR_SET_NO_NEW_PRIVS` (a filter needs it without
`CAP_SYS_ADMIN`; the target has NoNewPrivs=1 anyway), a filter with
`SECCOMP_FILTER_FLAG_NEW_LISTENER`, the listener sent to the parent by
`SCM_RIGHTS` and closed, a wait for the parent's byte, `exec`. The filter
([route2.c](serve-tty/route2.c)): for `AUDIT_ARCH_X86_64`, `ioctl` whose
request has `0x54` in its second byte (each tty request, the termios2
family `TCGETS2` to `TCSETSF2` too), `open` and `openat` go to the
supervisor; each other call to the kernel. The filter is inherited across
`fork` and `exec`: each program that the shell starts has the tty, static
binaries too, and podssh puts no code into any of them.

The supervisor, for each notification:

1. Is the descriptor the child's socket? By the **open file description**,
   never by its number: bash moves its terminal to a high descriptor, and
   `/dev/tty` gives another. `kcmp(KCMP_FILE)` first, then a copy by
   `pidfd_getfd` and `fstat`, then `readlink` of `/proc/PID/fd/N`. Each
   other descriptor, and each request on it, goes on to the kernel
   (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`).
2. The answers, from one state that podssh keeps for the session:
   `TCGETS` writes the kernel's 36-byte `struct termios` (not libc's
   larger struct), `TCGETS2` its 44-byte termios2; the `TCSETS` and
   `TCSETS2` families read it (podssh drains and flushes its own buffers for
   the `W` and `F` forms); `TIOCGWINSZ` and `TIOCSWINSZ` the window (a new
   size sends SIGWINCH to the foreground group, as the kernel does);
   `TIOCGPGRP` and `TIOCSPGRP` the foreground group (the session leader's
   at the start); `TIOCGSID` the leader; `TIOCSCTTY`, `TIOCNOTTY`,
   `TCFLSH`, `TCXONC`, `TCSBRK` and `TCSBRKP` succeed; each other tty
   request on the socket is ENOTTY.
3. The child's memory: `process_vm_readv` and `process_vm_writev`, else
   `/proc/PID/mem`. After each read, `SECCOMP_IOCTL_NOTIF_ID_VALID`: the
   process may have died, and its pid been taken.
4. `open` and `openat` of `/dev/tty`: the path read from the child (16
   bytes are enough), then `SECCOMP_IOCTL_NOTIF_ADDFD` with
   `SECCOMP_ADDFD_FLAG_SEND`, the socket as source and the call's
   `O_CLOEXEC`: the child's call returns a descriptor of the socket. Each
   other path goes on to the kernel. (`CONTINUE` is not safe where the
   filter is a security boundary; here it is none, the child is the
   user's own.)

The kernel features: user notification (5.0), `CONTINUE` (5.5),
`pidfd_getfd` (5.6), `ADDFD` (5.9), `ADDFD_FLAG_SEND` (5.14). The real
sandboxes run Linux 7.2.

Where it is refused, and the way out of each:

- A sandbox whose filter already has a listener: EBUSY (measured). The
  kernel allows one listener in a process's filters. Route 2b remains.
- No `process_vm_writev` and no `/proc`: no answer can be written
  (measured). Route 2b (`PTRACE_POKEDATA`) or route 3.
- A filter of the sandbox that refuses `seccomp` or `prctl`: the probe's
  errno; route 2b or route 3.

## Route 2b: the same by ptrace

`PTRACE_TRACEME` in the child, then a filter that returns
`SECCOMP_RET_TRACE` for the tty requests; the tracer (podssh) reads the
registers at each stop, writes the answer by `PTRACE_POKEDATA`, and skips
the call (`orig_rax` -1, `rax` 0). It works where user notification is
taken (EBUSY) and needs neither `process_vm_writev` nor `/proc`
([route2b.c](serve-tty/route2b.c), measured). It is the fallback, not the
first route:

- a process is traced once: `strace`, `gdb` and a sanitizer cannot attach
  to the child;
- the tracer sees each signal of each process of the session, and must
  pass each one on; job control's stops need `PTRACE_SEIZE` and
  `PTRACE_LISTEN`, or a Ctrl-Z stops nothing (the probe passes SIGSTOP
  over, and does no job control);
- `/dev/tty` needs the `open` call rewritten, as ptrace has no `ADDFD`:
  the path changed in the child's memory to `/proc/self/fd/N` of a copy
  that the child still holds (which needs `/proc` and such a copy), or the
  call made a `dup` of one; the probe does neither;
- with no tracer (podssh's death), `SECCOMP_RET_TRACE` makes each tty call
  ENOSYS.

## What fails on each route 2

- `ttyname` and `tty`: a socket has no tty name ("not a tty", measured);
  `ssh`, `sudo`, `gpg`'s pinentry, `tmux` and `screen` ask for one.
- `fstat` of descriptor 0 says a socket, not a character device; the
  kernel's `tty_nr` of `/proc/PID/stat` is 0, so `ps` prints `?`.
- A background job: the kernel stops a job that reads its terminal with
  SIGTTIN, and one that writes with `TOSTOP` with SIGTTOU; on a socket it
  reads the keys of the foreground job. Only a filter on `read` and
  `write` could stop it, at the cost of each one.
- `VMIN` 0 with `VTIME`: a read of a socket waits; it does not end after
  `VTIME` tenths of a second. Programs that wait with `poll` or `select`
  (vim, less) are not touched.
- A pty that the child makes for itself (`tmux`, `script`, `expect`): no
  `/dev/ptmx`.
- A setuid program: NoNewPrivs=1 in the child takes its power (as on the
  target already).
- `openat2`, and a relative open of `tty` from `/dev`: the filter of the
  probe misses them; the filter of podssh names `openat2` too.
- 32-bit programs (`AUDIT_ARCH_I386`) have other numbers: the filter names
  them too, or they run with no tty.

## Recommendation

**The order of the routes**, each after its probe: the real pty of T-110
(`/dev/ptmx`, `/dev/pts/ptmx`); route 1 (a new devpts instance); route 2a
(user notification); route 2b (ptrace); route 3, T-111's line discipline
with no tty. Route 1 is a pty of the kernel, with each feature of a tty
but a name; route 2a stops a child only at a tty call or an open, and
leaves `ptrace` to the user. On the real sandboxes (no user namespaces),
route 2a is the candidate; whether their filters allow `seccomp` with a
listener, `kcmp` and `process_vm_writev` is what the probes must tell
there.

**T-110** takes route 1 into `pty::open`: one more source after the paths
of `PTMX`, a forked helper, not a path, whose slave is opened by
`TIOCGPTPEER`; the `Pair`'s name says "a devpts instance of podssh"; no
`SSH_TTY`.

**T-111's design.** Route 2's tty is T-111's line discipline with the
termios state that the child sets: the state answered to the child is the
one the discipline reads. So pod-term (PodUtils/podcrates, Rule Q3: an
issue there) needs a mode that follows a termios, beside podvm's fixed
rules:

- `ICANON` with `ECHO`, `ECHOE`, `ECHOK`, `ECHOCTL` and `ECHONL`, the
  characters of `c_cc` (`VERASE`, `VKILL`, `VWERASE`, `VEOF`, `VLNEXT`,
  `VREPRINT`); no prompt and no history of its own: the shell has a tty and
  prints its own (measured: readline drew `$ ` and echoed itself);
- `ISIG` with `VINTR`, `VQUIT` and `VSUSP`: SIGINT, SIGQUIT and SIGTSTP to
  the foreground group that `TIOCSPGRP` set (not the leader's), the input
  flushed unless `NOFLSH`, `^C` echoed with `ECHOCTL` (a real pty echoed
  `^Z`; the probe did not);
- `ICRNL`, `INLCR`, `IGNCR` on input; `OPOST` with `ONLCR` on output;
- with `ICANON` off, each byte straight to the socket (vim, less, top, and
  readline at its prompt);
- the window of `pty-req` and `window-change` is the state's: SIGWINCH to
  the foreground group.

Where no tty route passes, T-111 stays as written (route 3): the
discipline's own prompt, and the line of step 5 for a full-screen
program.

**The probes at run time** (AGENTS.md section 5, rule 1). Each runs in a
forked child that exits at once, gives one line of `podssh doctor` and is
asked again by serve at each `pty-req`, as T-110's `pty::open` is:

| Line | Steps, each named with its errno where it fails |
| --- | --- |
| `pty` | `/dev/ptmx`, `/dev/pts/ptmx`: open, unlock, slave (T-110's probe) |
| `pty devpts` | fork; `unshare(CLONE_NEWUSER\|CLONE_NEWNS)`; `mount` devpts `newinstance` over `/dev/pts`, `/dev` or `/tmp`; open `ptmx`; `TIOCSPTLCK`; `TIOCGPTPEER`; the pair sent back |
| `pty notify` | fork; `PR_SET_NO_NEW_PRIVS`; `seccomp` with a listener; the child's `ioctl(TCGETS)` on its socket; the parent tells the descriptor (`kcmp`, `pidfd_getfd`, `/proc`), writes the answer (`process_vm_writev`, `/proc/PID/mem`) and answers; then an open of `/dev/tty` by `ADDFD`: "ok (kcmp, process_vm_writev, addfd)" |
| `pty ptrace` | fork; `PTRACE_TRACEME`; a `SECCOMP_RET_TRACE` filter; one `TCGETS` answered |

The cost of the probes: route 1's pair came in 0.5 to 5.8 ms (measured);
each other probe is one fork and a few calls (not measured alone).

## The box

The box's seccomp files (`scripts/box/seccomp.json`,
`scripts/box/seccomp-sandbox-a.json`) allow by default and refuse only
`bind` and UDP: `unshare`, `mount`, `ptrace` and `seccomp` pass. The real
sandboxes refuse `unshare` and `mount`, so in the box route 1 would pass
where the target's would not (as podman lets a container make a user
namespace). For Approach item 6, the profiles of T-245 must refuse
`unshare`, `mount`, `setns` and a `clone` of a new namespace (as the cage's
`-n` does), with a variant that refuses `ptrace` (`-p`); and the operator's
agents run the four `pty` lines of doctor in both real sandboxes.
