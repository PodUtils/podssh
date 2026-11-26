#!/usr/bin/env python3
"""The time from a Ctrl-C to the prompt, under a flood, over a slow link
(T-303, step 1): `podssh ssh -tt` to `podssh serve --listen`, and OpenSSH's
ssh -tt to OpenSSH's sshd as the reference, each through the stand-in proxy
of scripts/fake-proxy.py with a link of scripts/fake_shape.py, each way: by
default 150 ms each way (a round trip of 300 ms) and 64 KiB/s. The bytes of
the SSH connection itself are shaped, as on a slow road.

Each run is one session in a local pty: the far end runs /bin/sh -i with a
known prompt, the script types `yes`, reads the flood for --flood-s seconds
as a terminal would, sends 0x03 (Ctrl-C), and times the prompt that comes
after it. The entry builds its frames only when podssh's median is longer
than three round trips.

Usage: feel_interrupt.py [--podssh PATH] [--runs N] [--delay-ms MS]
                         [--rate BYTES_PER_S] [--queue BYTES] [--flood-s S]
                         [--limit-s S] [--no-openssh]
       feel_interrupt.py --self-test

The far ends, their keys and the proxy are the bench of scripts/feel-matrix.py
(its throwaway keys, its sshd on a free loopback port with a private config),
in its scratch directory, removed at the end, also after a TERM. No root and
no netem. The JSON goes to stdout, one summary line to stderr. The exit is 0
when each client measured, 1 when one failed, 2 when the bench did not start.
"""

import argparse
import fcntl
import importlib.util
import json
import os
import pty
import select
import shutil
import signal
import statistics
import struct
import sys
import termios
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from fake_shape import link_of  # noqa: E402

# The prompt of the far end's shell: set by the command, never typed, so no
# echo of a typed line can match it.
PROMPT = b"FEELP> "
SHELL_COMMAND = "exec env -u ENV PS1='FEELP> ' /bin/sh -i"
# The first lines of the flood, as the far end's pty writes them.
FLOOD = b"y\r\ny\r\n"
# Above this many round trips, step 2 of T-303 is built.
THRESHOLD_TRIPS = 3
# The waits of a session: its connect and its first prompt, the flood's
# start, and the exit.
CONNECT_LIMIT, EXIT_LIMIT = 60.0, 10.0


def load_matrix():
    """scripts/feel-matrix.py, whose name holds a dash: its Bench and its
    Setup, imported, not copied."""
    spec = importlib.util.spec_from_file_location("feel_matrix", HERE / "feel-matrix.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def link(delay_ms, rate, queue):
    """The mode of fake_shape for this link, checked by fake_shape itself:
    no loss, seed 1."""
    if delay_ms < 0 or rate <= 0 or queue < 0:
        raise ValueError("the delay and the queue are 0 or more, the rate above 0")
    mode = f"link:{delay_ms}:{rate}:{queue}:0:1"
    link_of(mode)
    return mode


def stats(samples, delay_ms):
    """min, median and max in ms, and in round trips of the link; {} for
    none."""
    if not samples:
        return {}
    trip = 2 * delay_ms
    figures = {"min_ms": min(samples), "median_ms": statistics.median(samples), "max_ms": max(samples)}
    if trip > 0:
        figures.update({k.replace("_ms", "_trips"): round(v / trip, 2) for k, v in list(figures.items())})
    return figures


class Matcher:
    """Whether NEEDLE came in the bytes fed so far, across the edges of the
    reads: a tail of the last read is kept, never the whole flood."""

    def __init__(self, needle):
        self.needle, self.tail = needle, b""

    def feed(self, chunk):
        window = self.tail + chunk
        found = self.needle in window
        self.tail = window[-(len(self.needle) - 1):] if len(self.needle) > 1 else b""
        return found


class Failed(Exception):
    """A session with no figure, and why."""


class Session:
    """One client in a local pty of 80x24, read as a terminal reads it."""

    def __init__(self, argv, env):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            try:
                os.execve(argv[0], argv, env)
            finally:
                os._exit(127)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        # The last bytes read, for the error of a session that failed.
        self.last = b""

    def read(self, timeout):
        """One read within `timeout`: the bytes, b"" for none, None at the
        end."""
        ready, _, _ = select.select([self.fd], [], [], max(0.0, timeout))
        if not ready:
            return b""
        try:
            chunk = os.read(self.fd, 65536)
        except OSError:
            return None
        if not chunk:
            return None
        self.last = (self.last + chunk)[-400:]
        return chunk

    def until(self, needle, limit, what):
        """Read until NEEDLE comes, within `limit` seconds; the time it came
        and the bytes read."""
        matcher, deadline, got = Matcher(needle), time.monotonic() + limit, 0
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise Failed(f"{what}: not within {limit:.0f} s; last bytes {self.last[-120:]!r}")
            chunk = self.read(min(left, 0.5))
            if chunk is None:
                raise Failed(f"{what}: the client ended (exit {self.reap(1.0)}); last bytes {self.last[-120:]!r}")
            got += len(chunk)
            if chunk and matcher.feed(chunk):
                return time.monotonic(), got

    def drain(self, until):
        """Read as a terminal does until the monotonic time `until`; the bytes
        read."""
        got = 0
        while (left := until - time.monotonic()) > 0:
            chunk = self.read(min(left, 0.5))
            if chunk is None:
                raise Failed(f"the flood: the client ended (exit {self.reap(1.0)})")
            got += len(chunk)
        return got

    def send(self, data):
        os.write(self.fd, data)

    def reap(self, limit):
        """The client's exit status within `limit`, else None."""
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.pid = None
                return os.waitstatus_to_exitcode(status)
            self.read(0.05)
        return None

    def close(self):
        """Exit the shell, then the client; killed past the limit."""
        if self.pid is not None:
            try:
                # A Ctrl-C first, for a session that failed in its flood.
                self.send(b"\x03")
                time.sleep(0.2)
                self.send(b"exit\r")
            except OSError:
                pass
            if self.reap(EXIT_LIMIT) is None and self.pid is not None:
                os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
                self.pid = None
        os.close(self.fd)


def one_run(argv, env, flood_s, limit):
    """One session: the prompt, the flood for `flood_s` seconds, then Ctrl-C
    and the time until the prompt after it."""
    started = time.monotonic()
    session = Session(argv, env)
    try:
        prompted, _ = session.until(PROMPT, CONNECT_LIMIT, "the first prompt")
        session.send(b"yes\r")
        flooding, _ = session.until(FLOOD, CONNECT_LIMIT, "the flood")
        flood = session.drain(flooding + flood_s)
        sent = time.monotonic()
        session.send(b"\x03")
        shown, after = session.until(PROMPT, limit, "the prompt after Ctrl-C")
        return {"interrupt_ms": round((shown - sent) * 1000, 1), "connect_ms": round((prompted - started) * 1000, 1),
                "flood_bytes": flood, "after_bytes": after}
    finally:
        session.close()


def measure(argv, env, runs, flood_s, limit, delay_ms):
    """The runs of one client, and their figures; the first failure ends
    them, with its reason."""
    doc = {"argv": argv, "runs": [], "error": None}
    for run in range(1, runs + 1):
        try:
            doc["runs"].append(one_run(argv, env, flood_s, limit))
        except (Failed, OSError) as e:
            doc["error"] = f"run {run} of {runs}: {e}"
            break
    doc.update(stats([r["interrupt_ms"] for r in doc["runs"]], delay_ms))
    return doc


def start_serve(bench, matrix, port):
    """podssh serve on 127.0.0.1:PORT, with the bench's host key and its
    user's key alone."""
    log = bench.work / "serve.log"
    argv = [bench.podssh, "serve", "--listen", f"127.0.0.1:{port}", "--host-key", str(bench.work / "host_key"),
            "--authorized-keys", str(bench.work / "authorized_keys"), "--shell", "/bin/sh"]
    bench.spawn(argv, log, bench.env())
    matrix.wait_until(lambda: "listening on" in log.read_text(errors="replace"), 15, "podssh serve did not listen")


def start_proxy(bench, matrix, mode, maps):
    """The stand-in proxy, its tunnels shaped by `mode`, each way."""
    port_file = bench.work / "proxy-port"
    argv = [sys.executable, str(HERE / "fake-proxy.py"), "--port-file", str(port_file),
            "--log", str(bench.work / "proxy.log"), "--shape", mode]
    for name, port in maps.items():
        argv += ["--map", f"{name}=127.0.0.1:{port}"]
    bench.spawn(argv, bench.work / "proxy.err")
    matrix.wait_until(lambda: port_file.exists() and port_file.read_text().strip(), 10, "the proxy did not start")
    return int(port_file.read_text().strip())


def tail(path, lines=5):
    try:
        return " | ".join(path.read_text(errors="replace").strip().splitlines()[-lines:])
    except OSError:
        return ""


def run(args):
    matrix = load_matrix()
    mode = link(args.delay_ms, args.rate, args.queue)
    podssh = os.path.abspath(shutil.which(args.podssh) or args.podssh)
    if not os.access(podssh, os.X_OK):
        print(f"feel_interrupt: {args.podssh}: not a program (build it first)", file=sys.stderr)
        return 2
    os.environ.pop("SSH_AUTH_SOCK", None)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    # The bench's cells write no files here: the JSON goes to stdout.
    bench = matrix.Bench(podssh, None, args.runs)
    doc = {"schema": 1, "entry": "T-303", "link": {"mode": mode, "delay_ms_each_way": args.delay_ms,
           "round_trip_ms": 2 * args.delay_ms, "rate_bytes_s": args.rate, "queue_bytes": args.queue},
           "flood_s": args.flood_s, "prompt_limit_s": args.limit_s, "threshold_trips": THRESHOLD_TRIPS,
           "clients": {}}
    code = 0
    try:
        bench.keys()
        serve_port = matrix.free_port()
        start_serve(bench, matrix, serve_port)
        maps = {"serve.test": serve_port}
        openssh_why = "--no-openssh" if args.no_openssh else ("" if shutil.which("ssh") else "no ssh here")
        if not openssh_why:
            try:
                bench.sshd()
                maps["sshd.test"] = bench.sshd_port
            except matrix.Setup as e:
                openssh_why = str(e)
        proxy_port = start_proxy(bench, matrix, mode, maps)
        common = bench.common(bench.work / "known_hosts")
        podssh_argv = [podssh, "ssh", "--direct", "-p", str(serve_port)] + common + [
            "-tt", f"{bench.user}@serve.test", SHELL_COMMAND]
        env = bench.env(HTTPS_PROXY=f"http://127.0.0.1:{proxy_port}", TERM="xterm-256color")
        doc["clients"]["podssh"] = measure(podssh_argv, env, args.runs, args.flood_s, args.limit_s, args.delay_ms)
        if doc["clients"]["podssh"]["error"]:
            doc["clients"]["podssh"]["serve_log"] = tail(bench.work / "serve.log")
        if openssh_why:
            doc["clients"]["openssh"] = {"runs": [], "error": f"not run: {openssh_why}"}
        else:
            via = f"{sys.executable} -I {HERE / 'feel_openssh.py'} --connect-via 127.0.0.1:{proxy_port} %h %p"
            ssh = shutil.which("ssh")
            openssh_argv = [ssh, "-F", "/dev/null", "-o", "LogLevel=ERROR", "-o", "IdentityAgent=none",
                            "-o", f"ProxyCommand={via}", "-p", str(bench.sshd_port)] + common + [
                "-tt", f"{bench.user}@sshd.test", SHELL_COMMAND]
            doc["clients"]["openssh"] = measure(openssh_argv, bench.env(TERM="xterm-256color"), args.runs,
                                                args.flood_s, args.limit_s, args.delay_ms)
            if doc["clients"]["openssh"]["error"]:
                doc["clients"]["openssh"]["sshd_log"] = tail(bench.work / "sshd.log")
        code = 1 if doc["clients"]["podssh"]["error"] else 0
        theirs = doc["clients"]["openssh"]
        if theirs["error"] and not theirs["error"].startswith("not run"):
            code = 1
    except matrix.Setup as e:
        doc["error"], code = str(e), 2
    finally:
        bench.stop()
    doc["exit"] = code
    ours = doc["clients"].get("podssh", {})
    if "median_trips" in ours:
        doc["verdict"] = ("build step 2: the median is longer than three round trips"
                          if ours["median_trips"] > THRESHOLD_TRIPS else "no build: within three round trips")
    json.dump(doc, sys.stdout, indent=1)
    sys.stdout.write("\n")
    print(f"feel_interrupt: {summary_line(doc)}", file=sys.stderr)
    return code


def summary_line(doc):
    """One line: each client's median and range, in ms and in round trips."""
    if doc.get("error"):
        return f"the bench did not start: {doc['error']}"
    parts = []
    for name, client in doc["clients"].items():
        if "median_ms" in client:
            parts.append(f"{name} median {client['median_ms']:.0f} ms ({client.get('median_trips', '-')} round "
                         f"trips), {client['min_ms']:.0f} to {client['max_ms']:.0f} ms in {len(client['runs'])} runs")
        else:
            parts.append(f"{name}: {client['error']}")
    link_ = doc["link"]
    head = f"Ctrl-C to the prompt at {link_['round_trip_ms']} ms and {link_['rate_bytes_s']} B/s"
    return f"{head}: " + "; ".join(parts) + (f"; {doc['verdict']}" if "verdict" in doc else "")


def self_test():
    """The parts that need no podssh: the link, the figures, the matcher, the
    summary, and the pty driver on this host's /bin/sh."""
    assert link(150, 65536, 1500000) == "link:150:65536:1500000:0:1"
    for bad in ((150, 0, 0), (-1, 65536, 0), (150, 65536, -1)):
        try:
            link(*bad)
        except ValueError:
            continue
        raise AssertionError(f"link{bad} was taken")
    assert stats([], 150) == {}
    got = stats([900.0, 300.0, 600.0], 150)
    assert got["min_ms"] == 300.0 and got["median_ms"] == 600.0 and got["max_ms"] == 900.0, got
    assert got["min_trips"] == 1.0 and got["median_trips"] == 2.0 and got["max_trips"] == 3.0, got
    assert "median_trips" not in stats([5.0], 0)
    # The prompt across two reads, after a flood and the echo of ^C.
    m = Matcher(PROMPT)
    assert not m.feed(b"y\r\n" * 5000 + b"y^C\r\nFEE")
    assert m.feed(b"LP> ")
    # A flood alone, and a typed line that sets a prompt, never match.
    m = Matcher(PROMPT)
    assert not any(m.feed(c) for c in (b"y\r\ny\r\n", b"PS1='FEEL''P> '\r\n", b"FEELP>", b"\r\n"))
    # One byte at a time.
    m = Matcher(PROMPT)
    assert [m.feed(bytes([b])) for b in b"xFEELP> "][-1]
    assert Matcher(b"y").feed(b"y")
    assert PROMPT.decode() in SHELL_COMMAND
    doc = {"link": {"round_trip_ms": 300, "rate_bytes_s": 65536},
           "clients": {"podssh": {"runs": [{}] * 3, **stats([900.0, 300.0, 600.0], 150)},
                       "openssh": {"runs": [], "error": "not run: no ssh here"}},
           "verdict": "no build: within three round trips"}
    line = summary_line(doc)
    assert "podssh median 600 ms (2.0 round trips)" in line and "openssh: not run" in line, line
    assert load_matrix().Bench is not None
    # The pty driver end to end on this host's own shell, no link and no
    # podssh: the prompt, the flood, Ctrl-C and the prompt again.
    local = one_run(["/bin/sh", "-c", SHELL_COMMAND], dict(os.environ, TERM="xterm-256color"), 0.3, 10.0)
    assert local["flood_bytes"] > 0 and 0 <= local["interrupt_ms"] < 5000, local
    print("feel_interrupt: self-test ok")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Ctrl-C to the prompt under a flood, over a slow link (T-303).")
    parser.add_argument("--podssh", default=str(HERE.parent / "target" / "debug" / "podssh"))
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--delay-ms", type=int, default=150, help="each way (default 150: a round trip of 300 ms)")
    parser.add_argument("--rate", type=int, default=64 * 1024, help="bytes a second, each way (default 65536)")
    parser.add_argument("--queue", type=int, default=1500000,
                        help="bytes that may wait in the link, each way (default 1500000, netem's 1000 packets)")
    parser.add_argument("--flood-s", type=float, default=3.0)
    parser.add_argument("--limit-s", type=float, default=180.0, help="the wait for the prompt after Ctrl-C")
    parser.add_argument("--no-openssh", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not 1 <= args.runs <= 20:
        parser.error("--runs: from 1 to 20")
    if not 0 < args.flood_s <= 60 or not 0 < args.limit_s <= 600:
        parser.error("--flood-s: above 0 and at most 60; --limit-s: above 0 and at most 600")
    try:
        link(args.delay_ms, args.rate, args.queue)
    except ValueError as e:
        parser.error(str(e))
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
