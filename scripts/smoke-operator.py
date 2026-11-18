#!/usr/bin/env python3
"""Each operator command of podssh, once, against servers on 127.0.0.1 (T-728).

One table of commands: each runs with a limit on its wait, its exit code read
directly, and a check of what it wrote. The server is an OpenSSH sshd on a
free port of the loopback: MSYS2's on Windows (as interop-conpty-msys2.py
starts it), the system's elsewhere. The commands that take the relay run
against `podssh relay serve` on the loopback, with a throwaway CA that
openssl makes; no live service but `update --check`, which reads the
release's page. Each key and file of a run is in one scratch directory under
.work/, deleted at the end, with HOME and the cache there too.

Usage: python scripts/smoke-operator.py --list
       python scripts/smoke-operator.py [--only NAME,...] [--install] PODSSH
       python scripts/smoke-operator.py --plant PODSSH

  --list     print the table: each command and what its row checks.
  --only     run these rows alone (the setup rows run each time).
  --install  install MSYS2's openssh and openssl with pacman first (CI).
  --plant    run with PODSSH_SMOKE_PLANT=proxy-byte: the wrapper of `podssh
             proxy` writes one byte more before the relay's bytes, so the
             OpenSSH client's banner check fails, and exactly the row
             `proxy` must fail.

Exit 0 when each row passes (with --plant, when `proxy` alone fails), 1 when
not, 2 when the rows could not run: a row that did not run is not a pass.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import smoke_servers as servers  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
WINDOWS = sys.platform == "win32"
# The text that each row's remote command echoes.
MARK = "podssh-smoke"


def cannot_run(why):
    print(f"smoke-operator: the rows did not run: {why}", flush=True)
    sys.exit(2)


class Run:
    """The scratch directory, the servers, and the words of each command."""

    def __init__(self, podssh, scratch):
        self.podssh, self.w = str(podssh), scratch
        self.env = servers.isolated_env(scratch)
        self.key = scratch / "id_ed25519"
        self.port = self.user = self.relay = None

    def ssh_opts(self, port_flag="-p"):
        # cp, mv and their kin need --timeout with no terminal.
        timeout = ["--timeout", "60s"] if port_flag == "-P" else []
        return ["--direct", *timeout, port_flag, str(self.port), "-i", str(self.key), "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={self.w / 'known_hosts'}"]

    def host(self, path=None):
        return f"{self.user}@127.0.0.1" + (f":{path}" if path is not None else "")

    def relay_opts(self):
        return ["--relay-host", f"relay.test:{self.relay}", "--relay-addr", "relay.test=127.0.0.1",
                "--ca-file", str(self.w / "ca.pem")]

    def run(self, args, stdin=b"", timeout=90, cwd=None, env=None):
        """`podssh ARGS`: (exit code, stdout, stderr); None on a timeout."""
        try:
            r = subprocess.run([self.podssh, *args], input=stdin, capture_output=True, timeout=timeout,
                               cwd=cwd or self.w, env=env or self.env)
        except subprocess.TimeoutExpired:
            return None
        return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")


def expect(got, code=0, out=None, err=None):
    """Why `got` is not exit `code` (a set of codes allowed) with `out` in
    stdout and `err` in stderr; none when it is."""
    if got is None:
        return "no end within its limit"
    rc, stdout, stderr = got
    codes = code if isinstance(code, set) else {code}
    tail = (stderr.strip().splitlines() or [""])[-1][:200]
    if rc not in codes:
        return f"exit {rc}, not {sorted(codes)}: {tail}"
    if out is not None and out not in stdout:
        return f"stdout lacks {out!r}: {stdout[:200]!r} {tail}"
    if err is not None and err not in stderr:
        return f"stderr lacks {err!r}: {tail}"
    return None


def log_size(path):
    try:
        return Path(path).stat().st_size
    except OSError:
        return 0


# What OpenSSH's sshd logs when its own privilege-separated child dies under
# it; podssh's client cannot cause a reset of that internal pipe.
SSHD_CHILD_DIED = "mm_request_receive: read: Connection reset by peer"


def sshd_child_died(path, since):
    """Whether the sshd's log after byte `since` says its session child died."""
    try:
        with open(path, "rb") as f:
            f.seek(since)
            return SSHD_CHILD_DIED in f.read().decode("utf-8", "replace")
    except OSError:
        return False


def row_keygen(r):
    return expect(r.run(["keygen", "-q", "-t", "ed25519", "-N", "", "-C", "smoke", "-f", str(r.w / "k2")])) or (
        None if (r.w / "k2.pub").is_file() else "no k2.pub")


def row_ssh(r):
    return expect(r.run(["ssh", *r.ssh_opts(), r.host(), "echo", f"{MARK}-ssh"]), out=f"{MARK}-ssh")


def row_each(r):
    return expect(r.run(["each", *r.ssh_opts(), r.host(), "--", "echo", f"{MARK}-each"]), out=f"{MARK}-each")


def row_run(r):
    project = r.w / "project"
    project.mkdir(exist_ok=True)
    (project / "smoke.txt").write_text(f"{MARK}-run\n")
    return expect(r.run(["run", *r.ssh_opts(), r.host(), "--", "cat", "smoke.txt"], cwd=project),
                  out=f"{MARK}-run")


def row_job(r):
    # A host with no tmux: list answers, start and submit refuse (69).
    return expect(r.run(["job", "list", *r.ssh_opts(), r.host()]), code={0, 69})


def row_session(r):
    return expect(r.run(["session", "list"]))


def row_containers(r):
    # 69: the host has none of docker, podman or kubectl.
    return expect(r.run(["containers", *r.ssh_opts(), r.host()]), code={0, 69})


def row_proxy(r):
    """OpenSSH's own client, with `podssh proxy` through the relay as its
    ProxyCommand: Windows' own ssh.exe there."""
    ssh = servers.openssh_client()
    if ssh is None:
        return "no OpenSSH client"
    proxy = servers.command_line([*servers.plant_wrapper(r), *r.relay_opts(), "%h", "%p"])
    args = [ssh, "-F", "none", "-o", f"ProxyCommand={proxy}", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={r.w / 'known_hosts_openssh'}",
            "-o", "IdentitiesOnly=yes", "-i", str(r.key), "-p", str(r.port), r.host(), "echo", f"{MARK}-proxy"]
    try:
        p = subprocess.run(args, capture_output=True, timeout=90, env=r.env, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return "no end within its limit"
    return expect((p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")),
                  out=f"{MARK}-proxy")


def first_bytes(r, args, seconds=30):
    """The first bytes that `podssh ARGS` writes, its stdin left open as a
    client's is, until a line of the sshd's version came; it is stopped
    then. Why not, else none."""
    proc = subprocess.Popen([r.podssh, *args], cwd=r.w, env=r.env, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=open(r.w / "first.err", "wb"))
    got, deadline = b"", time.monotonic() + seconds
    try:
        while b"\n" not in got and time.monotonic() < deadline and proc.poll() is None:
            chunk = servers.read_some(proc.stdout, deadline - time.monotonic())
            if not chunk:
                break
            got += chunk
    finally:
        servers.stop(proc)
    if got.startswith(b"SSH-2.0-"):
        return None
    return f"no version line: {got[:80]!r} {servers.tail(r.w / 'first.err', 3)}"


def row_pipe(r):
    # The sshd's version line, through the relay, on stdout.
    return first_bytes(r, ["pipe", *r.relay_opts(), "stdio", f"relay:127.0.0.1:{r.port}"])


def row_cp(r):
    local = r.w / "cp-up.txt"
    local.write_text(f"{MARK}-cp\n")
    why = expect(r.run(["cp", *r.ssh_opts("-P"), str(local), r.host("smoke-cp.txt")]))
    if why:
        return f"up: {why}"
    back = r.w / "cp-down.txt"
    why = expect(r.run(["cp", *r.ssh_opts("-P"), r.host("smoke-cp.txt"), str(back)]))
    return f"down: {why}" if why else (None if back.read_text() == local.read_text() else "the copy differs")


def row_mv(r):
    moved = r.w / "mv-down.txt"
    why = expect(r.run(["mv", *r.ssh_opts("-P"), r.host("smoke-cp.txt"), str(moved)]))
    return why or (None if moved.read_text() == f"{MARK}-cp\n" else "the moved file differs")


def row_scp(r):
    local = r.w / "scp-up.txt"
    local.write_text(f"{MARK}-scp\n")
    opts = [o for o in r.ssh_opts("-P") if o != "--direct"]
    return expect(r.run(["scp", "--direct", *opts, str(local), r.host("smoke-scp.txt")]))


def row_sftp(r):
    batch = r.w / "sftp.batch"
    batch.write_text(f"get smoke-scp.txt {(r.w / 'sftp-got.txt').as_posix()}\n")
    why = expect(r.run(["sftp", *r.ssh_opts("-P"), "-b", str(batch), r.host()]))
    got = r.w / "sftp-got.txt"
    return why or (None if got.is_file() and got.read_text() == f"{MARK}-scp\n" else "sftp got no file")


def row_edit(r):
    editor = r.w / "editor.py"
    editor.write_text("import sys\nopen(sys.argv[-1], 'a').write('edited\\n')\n")
    env = dict(r.env, EDITOR=servers.command_line([sys.executable, str(editor)]), VISUAL="")
    why = expect(r.run(["edit", "--no-terminal", *r.ssh_opts("-P"),
                        r.host("smoke-scp.txt")], env=env))
    if why:
        return why
    back = r.w / "edit-back.txt"
    why = expect(r.run(["cp", *r.ssh_opts("-P"), r.host("smoke-scp.txt"), str(back)]))
    return why or (None if back.read_text().endswith("edited\n") else "the edit did not go back")


def row_doctor(r):
    return expect(r.run(["doctor", "--tier"], timeout=120), code={0, 1}, out="ok")


def row_status(r):
    got = r.run(["status"])
    why = expect(got)
    if why:
        return why
    try:
        json.loads(got[1].strip().splitlines()[-1])
    except (ValueError, IndexError) as e:
        return f"no JSON line: {e}"
    return None


def row_ping(r):
    return expect(r.run(["ping", *r.relay_opts()], timeout=120))


def row_health(r):
    return expect(r.run(["health", *r.ssh_opts(), r.host()]))


def row_node_operator(r):
    """A pair on the relay, a node of the sshd under it, and the operator's
    session: its first bytes are the sshd's version line."""
    why = expect(r.run(["relay", "pair", "smoke", *r.relay_opts()]))
    if why:
        return f"relay pair: {why}"
    log = open(r.w / "node.log", "wb")
    # The node and the operator find the relay in the pair; the pin and the CA still go.
    reach = r.relay_opts()[2:]
    node = subprocess.Popen([r.podssh, "node", "smoke", f"127.0.0.1:{r.port}", *reach], cwd=r.w,
                            env=r.env, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    try:
        if not servers.wait_for(r.w / "node.log", "online", 60, node):
            return f"the node did not say online: {servers.tail(r.w / 'node.log')}"
        return first_bytes(r, ["operator", "smoke", *reach], 60)
    finally:
        servers.stop(node)
        log.close()


def row_mcp(r):
    ask = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "smoke", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    stdin = "".join(json.dumps(a) + "\n" for a in ask).encode()
    return expect(r.run(["mcp"], stdin=stdin, timeout=60), out='"tools"')


def row_net(r):
    return expect(r.run(["net", "ls"]), code={0, 78})


def row_update(r):
    # The release's page, read: 0 when it answers. A runner with no way out
    # says so in its line.
    return expect(r.run(["update", "--check"], timeout=120), code={0, 1})


# Each row: its name, the command, what it checks, and whether it needs the
# relay. The order matters: cp leaves the file that mv moves, scp the one
# that sftp and edit read.
ROWS = [
    ("keygen", row_keygen, "a key pair, its .pub written", False),
    ("ssh", row_ssh, "a command's output over --direct", False),
    ("each", row_each, "the command on the host, its line", False),
    ("run", row_run, "the project copied, a file of it read there", False),
    ("job", row_job, "the list of jobs (0), or 69 on a host with no tmux", False),
    ("session", row_session, "the list of sessions here", False),
    ("containers", row_containers, "the host's containers, or 69 with no tool there", False),
    ("proxy", row_proxy, "OpenSSH's client with ProxyCommand podssh proxy, through the relay", True),
    ("pipe", row_pipe, "stdio to relay:127.0.0.1:PORT, the sshd's version line", True),
    ("cp", row_cp, "a file up and back, equal", False),
    ("mv", row_mv, "the file moved back, equal", False),
    ("scp", row_scp, "a file up with scp's words", False),
    ("sftp", row_sftp, "a batch's get of that file", False),
    ("edit", row_edit, "an editor's line, back on the host", False),
    ("doctor", row_doctor, "the host's tier, with ok lines", False),
    ("status", row_status, "one line of JSON", False),
    ("ping", row_ping, "each step to the relay", True),
    ("health", row_health, "the host's health over one exec", False),
    ("node", row_node_operator, "relay pair, node online, operator reaches the sshd", True),
    ("mcp", row_mcp, "initialize, then tools/list", False),
    ("net", row_net, "the net held, or 78 for none", False),
    ("update", row_update, "the release's page read (--check)", False),
]


def main(argv):
    if "--list" in argv:
        for name, _, what, relay in ROWS:
            print(f"{name:11} {'relay ' if relay else 'direct'} {what}")
        return 0
    only = None
    if "--only" in argv:
        at = argv.index("--only")
        only = set(argv[at + 1].split(","))
        argv = argv[:at] + argv[at + 2:]
    flags = {a for a in argv if a in ("--install", "--plant")}
    rest = [a for a in argv if a not in flags]
    if len(rest) != 1:
        print(__doc__)
        return 2
    podssh = Path(rest[0]).resolve()
    if not podssh.is_file():
        cannot_run(f"no podssh at {podssh}")
    if "--install" in flags:
        servers.install()
    (ROOT / ".work").mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="smoke-", dir=ROOT / ".work"))
    r = Run(podssh, scratch)
    if "--plant" in flags:
        r.env["PODSSH_SMOKE_PLANT"] = "proxy-byte"
    sshd = relay = None
    failed, passed = [], []
    try:
        if expect(r.run(["keygen", "-q", "-t", "ed25519", "-N", "", "-C", "smoke", "-f", str(r.key)])):
            cannot_run("podssh keygen made no key")
        r.port, r.user, sshd = servers.start_sshd(r)
        r.relay, relay = servers.start_relay(r)
        for name, check, _, _ in ROWS:
            if only and name not in only:
                continue
            started = time.monotonic()
            log_at = log_size(scratch / "sshd.log")
            why = check(r)
            if why and sshd_child_died(scratch / "sshd.log", log_at):
                # MSYS2's sshd on windows-arm lost its own session child after
                # the key was accepted (its monitor read a reset): a fault of
                # that server, seen twice (T-728). Run the row once more, and
                # say so; a second failure stands.
                print(f"note {name:11} the sshd's session child died ({why}); the row runs once more", flush=True)
                log_at = log_size(scratch / "sshd.log")
                why = check(r)
            took = time.monotonic() - started
            if why:
                failed.append(name)
                print(f"FAIL {name:11} {took:5.1f} s  {why}", flush=True)
                # The sshd's words of this row, before later rows push them
                # out of the tail at the end (the ssh row of windows-arm, T-728).
                print(servers.tail(scratch / "sshd.log", 12), flush=True)
            else:
                passed.append(name)
                print(f"ok   {name:11} {took:5.1f} s", flush=True)
    finally:
        servers.stop(relay)
        servers.stop_sshd(r, sshd)
        if failed:
            print(servers.tail(scratch / "sshd.log", 15), servers.tail(scratch / "relay.log", 15), sep="\n")
        shutil.rmtree(scratch, ignore_errors=True)
        print(f"smoke-operator: the keys of this run are deleted ({not scratch.exists()})", flush=True)
    if "--plant" in flags:
        if failed == ["proxy"]:
            print("smoke-operator: the planted byte failed the row proxy and no other, as it must", flush=True)
            return 0
        print(f"smoke-operator: the plant was not caught as it must be (failed: {failed})", flush=True)
        return 1
    print(f"smoke-operator: {len(passed)} passed, {len(failed)} failed ({sys.platform})", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
