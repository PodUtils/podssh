#!/usr/bin/env python3
"""A stand-in for the relay, for fault injection in the interop harness.

It serves the forward path the way the live relay does (docs/relay.md):
TLS 1.3, `POST /v1/mint`, `GET /health`, and `GET /connect/<host>/<port>`
upgraded to a WebSocket whose binary frames carry the TCP stream, with an
empty binary frame as keepalive and Pings answered. Its diagnostics have the
live relay's shapes (2026-10-11, T-058): `GET /relays.json`, with this
stand-in as its one pool host, and `GET /trace`, whose dial of a target needs
the token in `X-Relay-Token`, as the live relay's does. And the reverse road
(scripts/fake_reverse.py, T-156): pairs, nodes and operators. Each instance can be told
to fail in one way, so podssh's failover, liveness and close handling are
tested against real OpenSSH without waiting for the real relay to fail.

Usage: fake-relay.py --cert CERT --key KEY --port-file FILE [--mode MODE]
                     [--keepalive SECONDS] [--half-closed SECONDS]

A client's Close is its half-close, as at the live relay and podssh's role
(docs/relay.md, T-1018): the target's writing side is shut, and its bytes
still come until it closes, or until it is quiet for --half-closed seconds
(15); then the Close is `1000 client half-closed, target idle for 15s`.

Modes:
  normal           behave
  tls12            behave, over TLS 1.2 alone, as a proxy that intercepts
                   TLS can (T-067)
  refuse:STATUS    answer every upgrade with HTTP STATUS
  policy           answer each upgrade 403, naming its target `not in the
                   ALLOW list`, as the relay refuses a target of its policy,
                   and dial no target (T-367)
  blackhole        accept TCP and never start TLS
  noupgrade        answer each WebSocket upgrade 403 in a proxy's words, as
                   a proxy that ends TLS and refuses upgrades does (T-451)
  fault1003        behave, but close the first socket of each pair's node
                   with 1003 "unknown session id" (T-409)
  noready          behave, but take each operator's socket and never send
                   it ready, with no node asked and no limit (T-589)
  silent           finish TLS, then never answer a request
  stall:SECONDS    SECONDS after the upgrade, stop: no frames, no Pongs
  close:BYTES:CODE after BYTES from the target, Close with CODE and the
                   relay's reason for it
  closeall:BYTES:CODE
                   the same after BYTES both ways together, as the relay
                   counts its session byte cap
  delay:MS         each byte, each way, MS milliseconds late
  jitter:MIN:MAX:SEED
                   each chunk, each way, late by MIN to MAX milliseconds,
                   from a generator seeded with SEED, so that a run repeats;
                   a chunk never passes the one before it
  rate:BYTES       each way, BYTES a second at most
  link:DELAY:RATE:QUEUE:LOSS:SEED
                   each way, a link of scripts/fake_shape.py: the bytes wait
                   for RATE behind those before them in a queue of QUEUE
                   bytes, then DELAY; LOSS delays a lost segment (T-660)
  profile:NAME     one of osewa's four links: far, cellular, wifi, slow
  cut:BYTES        after BYTES both ways together, the TCP connection to the
                   client ends, with no Close frame: a host that stops
  pause:AFTER:FOR  AFTER seconds after the upgrade, each byte both ways,
                   Pongs and keepalives too, is held for FOR seconds, then
                   let through: a stall that ends
  dropfirst:BYTES:CODE
                   the first session only: after BYTES from the target,
                   Close with CODE and its reason (CODE 0: the TCP
                   connection ends with no Close); each later session
                   behaves (T-025)
  dropfirstat:SECONDS:CODE
                   the same, SECONDS after the first session's upgrade
  slowopen:MS      behave, with each upgrade answered MS milliseconds late:
                   a host that opens after another (T-220)
  access           behave behind a gate like Cloudflare Access: each request
                   without the stand-in's service token (ACCESS_ID and
                   ACCESS_SECRET in CF-Access-Client-Id and -Secret) gets
                   403, as the gate answers (T-718)
  badaccept        answer each upgrade with a 101 whose Sec-WebSocket-Accept
                   is not the key's, and dial no target: a hop that answers
                   in the relay's place (T-324)
  hangup:MS        answer each upgrade with a valid 101, MS milliseconds
                   later end the TCP connection with no frame, and dial no
                   target: a hop that drops the upgraded stream (T-324)
  backlog:BYTES:RATE
                   to the client at RATE bytes a second, from a queue with
                   no bound, as a relay that reads its target at once; once
                   more than BYTES wait in it, Close 1013 `client receive
                   backlog`, the relay's check of a slow client, and drop
                   what waits (T-062)
  v6close          an IPv6 target (an address, or `?family=6`) is upgraded
                   and dialed never, and at the client's first bytes the
                   session gets Close 1011 `target closed before sending
                   anything`, as the default relay did on 2026-10-08; an IPv4
                   target behaves (T-253)
  wrongclose       behave, but answer a client's Close before the dial of
                   ?dial=lazy with 1011, a planted fault of the close codes
                   for podssh relay conform (scripts/fake_conform.py, T-713)
  querytoken       behave, and mint a token of one session at
                   /v1/mint?once=1 too, but take a token in the query string
                   of /connect/ as well as in its header: a planted fault
                   for podssh relay conform (T-713)
  buffer, bodybuffer, bodycap:BYTES, idle:SECONDS
                   the probes of `podssh doctor --stream` (T-325), served in
                   each mode at /v1/probe/drip and /v1/probe/anything, with a
                   fault of a path between the client and them: a response
                   held until its end, a body held until its end, a cap on a
                   body, a quiet stream ended (scripts/fake_stream.py)

Each mint, each upgrade and each Close from the client is a line on stdout
(`mint`, `upgrade`, `close CODE`), so a harness counts them (T-220). Each
connect with the token is `connect MS PATH` too, its query in PATH, and the
end of a session that dialed `ended MS PATH`, MS on the stand-in's clock;
with `?dial=lazy` the target is dialed on the client's first byte alone
(scripts/fake_lazy.py), so a harness sees each probe and its time (T-608).
"""

import argparse
import asyncio
import json
import ssl
import time
import urllib.parse

import fake_conform
import fake_diag
import fake_lazy
import fake_reverse
import fake_stream
import fake_v6
from fake_shape import SHAPED, Shaper
from fake_ws import close_frame, frame, read_frame, response, upgraded

TOKEN = "fake-relay-token-for-the-interop-harness"
# The service token of the gate of mode `access`: made-up values of the tests.
ACCESS_ID = "id-of-the-stand-in.access"
ACCESS_SECRET = "secret-of-the-stand-in-7c1e"
# The relay's own reasons for each code (docs/relay.md, forward path).
# The sessions upgraded so far, for the modes that drop only the first.
UPGRADED = {"count": 0}

REASONS = {
    1001: "idle timeout",
    1009: "session byte cap",
    1011: "write failed: fault injection",
    1013: "target write backlog",
}

args = None
STARTED = time.monotonic()


def event(line):
    """One line on stdout, as it happens, for the harness to count."""
    print(line, flush=True)


def clock():
    """The ms since the stand-in started, for the times of its lines."""
    return int((time.monotonic() - STARTED) * 1000)


async def handle(reader, writer):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
        if args.mode == "silent":
            await reader.read()  # until the client gives up
            return
        lines = head.decode("latin-1").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        if args.mode == "access" and (headers.get("cf-access-client-id"), headers.get("cf-access-client-secret")) != (
            ACCESS_ID,
            ACCESS_SECRET,
        ):
            event(f"access refused {path}")
            writer.write(response(403, "Forbidden", b"Forbidden: this application is behind Cloudflare Access"))
        elif args.mode == "noupgrade" and headers.get("upgrade", "").lower() == "websocket":
            event(f"upgrade refused {path}")
            writer.write(response(403, "Forbidden", b"Forbidden: WebSocket upgrades are not allowed by policy"))
        elif await fake_reverse.handle(method, path, headers, reader, writer):
            pass
        elif await fake_stream.handle(method, path, headers, reader, writer):
            pass
        elif method == "POST" and fake_conform.is_mint(path):
            await reader.readexactly(int(headers.get("content-length", "0")))
            event("mint")
            body = json.dumps(fake_conform.minted(path, TOKEN, int(time.time() * 1000) + 3600_000)).encode()
            writer.write(response(200, "OK", body, [("Content-Type", "application/json")]))
        elif method == "GET" and path == "/health":
            body = json.dumps({"ok": True, "service": "tcp-ssh-relay", "version": "fake",
                               "relay": {"edge_colo": "TEST"}}).encode()
            writer.write(response(200, "OK", body, [("Content-Type", "application/json")]))
        elif method == "GET" and path.split("?")[0] == "/relays.json":
            body = fake_diag.relays_json(path, headers)
            writer.write(response(200, "OK", body, [("Content-Type", "application/json")]))
        elif method == "GET" and path.split("?")[0] == "/trace":
            await fake_diag.trace(writer, path, headers, TOKEN)
        elif method == "GET" and path.startswith("/connect/"):
            await connect(reader, writer, path, headers)
        else:
            writer.write(response(404, "Not Found", f"{path}: not found".encode()))
        await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, ssl.SSLError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def connect(reader, writer, path, headers):
    if not fake_conform.token_ok(path, headers, TOKEN):
        writer.write(response(403, "Forbidden", b"forward: missing or wrong token"))
        return
    event(f"connect {clock()} {path}")
    if args.mode.startswith("refuse:"):
        status = int(args.mode.split(":")[1])
        writer.write(response(status, "Refused", b"connect: refused by fault injection"))
        return
    if args.mode == "badaccept":
        writer.write(upgraded({"sec-websocket-key": "not the key that the client sent"}))
        await writer.drain()
        event("upgrade")
        return
    if args.mode.startswith("hangup:"):
        writer.write(upgraded(headers))
        await writer.drain()
        event("upgrade")
        await asyncio.sleep(int(args.mode.split(":")[1]) / 1000)
        writer.transport.abort()
        return
    parts = path.split("?")[0].split("/")
    host, port = parts[2], int(parts[3])
    if args.mode == "policy" or fake_conform.link_local(host):
        writer.write(response(403, "Forbidden", f"forward: {host}:{port} is not in the ALLOW list".encode()))
        return
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
    if args.mode == "v6close" and (":" in host or query.get("family") == ["6"]):
        await fake_v6.close_unreached(reader, writer, headers, event)
        return
    if query.get("dial") == ["lazy"]:
        await fake_lazy.serve(reader, writer, headers, (host, port), event, clock, pump)
        return
    try:
        t_reader, t_writer = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
    except (OSError, asyncio.TimeoutError) as e:
        writer.write(response(502, "Bad Gateway", f"relay: cannot reach {host}:{port}: {e}".encode()))
        return
    if args.mode.startswith("slowopen:"):
        await asyncio.sleep(int(args.mode.split(":")[1]) / 1000)
    writer.write(upgraded(headers))
    await writer.drain()
    event("upgrade")
    UPGRADED["count"] += 1
    await pump(reader, writer, t_reader, t_writer, first=UPGRADED["count"] == 1)
    event(f"ended {clock()} {path}")


async def pump(reader, writer, t_reader, t_writer, first=False):
    stalled = asyncio.Event()
    done = asyncio.Event()
    started = time.monotonic()
    # When the target's last byte came, for the quiet after a client's Close.
    heard = {"at": started}
    # dropfirst and dropfirstat: the first session ends, as a relay that
    # drops it; the later ones behave.
    drop = {"bytes": None, "seconds": None, "code": None}
    kind, _, rest = args.mode.partition(":")
    if first and kind in ("dropfirst", "dropfirstat"):
        when, code = rest.split(":")
        drop["code"] = int(code)
        drop["bytes" if kind == "dropfirst" else "seconds"] = float(when)

    async def write_client(data):
        writer.write(data)
        await writer.drain()

    async def write_target(data):
        t_writer.write(data)
        await t_writer.drain()

    shaped = args.mode.startswith(SHAPED)
    # backlog: only the bytes to the client wait, as at a slow client.
    backlog = args.mode.startswith("backlog:")
    to_client = Shaper(write_client, args.mode, started, 0) if shaped else None
    to_target = Shaper(write_target, args.mode, started, 1) if shaped and not backlog else None

    async def send_client(data, last=False):
        """A frame to the client, through the shaper when there is one."""
        if to_client is None:
            await write_client(data)
            return
        await to_client.put(data)
        if last:
            await to_client.flush()

    async def send_target(data):
        if to_target is None:
            await write_target(data)
        else:
            await to_target.put(data)

    # cut: the connection to the client ends, with no Close frame.
    cut = int(args.mode.split(":")[1]) if args.mode.startswith("cut:") else None
    # closeall: the bytes of both directions together, as the relay counts
    # its session byte cap.
    both = {"limit": None, "code": None, "count": 0}
    if args.mode.startswith("closeall:"):
        _, limit, code = args.mode.split(":")
        both["limit"], both["code"] = int(limit), int(code)

    async def counted(n):
        """Count n payload bytes; at the limit, close as the relay would,
        or end the connection with no Close."""
        both["count"] += n
        if cut is not None and both["count"] >= cut:
            writer.transport.abort()
            return True
        if both["limit"] is not None and both["count"] >= both["limit"]:
            await send_client(close_frame(both["code"], REASONS.get(both["code"], "fault injection")), last=True)
            return True
        return False

    async def drop_now():
        """End the first session: a Close with the code's reason, or with
        code 0 no Close at all."""
        if drop["code"] == 0:
            writer.transport.abort()
        else:
            await send_client(close_frame(drop["code"], REASONS.get(drop["code"], "fault injection")), last=True)

    async def drop_clock():
        if drop["seconds"] is None:
            await asyncio.Event().wait()  # no clock: it never ends the session
        await asyncio.sleep(drop["seconds"])
        await drop_now()

    async def stall_clock():
        if args.mode.startswith("stall:"):
            await asyncio.sleep(float(args.mode.split(":")[1]))
            stalled.set()

    async def keepalive():
        while not done.is_set():
            await asyncio.sleep(args.keepalive)
            if not stalled.is_set() and not done.is_set():
                await send_client(frame(0x2))

    async def up():  # client to target
        while True:
            opcode, data = await read_frame(reader)
            if stalled.is_set():
                continue  # swallowed: a stalled relay answers nothing
            if opcode in (0x0, 0x2):  # binary, or its continuation
                await send_target(data)
                if await counted(len(data)):
                    return
            elif opcode == 0x9:
                await send_client(frame(0xA, data))
            elif opcode == 0x8:
                event(f"close {int.from_bytes(data[:2], 'big') if len(data) >= 2 else 1005}")
                await half_closed()
                return
            elif opcode == 0x1:
                await send_client(close_frame(1003, "text frames are not accepted"), last=True)
                return

    async def half_closed():
        """The client's Close: the target's writing side shut, and its bytes
        still sent by down() until it closes, or until it is quiet; Pings
        are still answered, so that the client's watch of the link holds."""
        if to_target is not None:
            await to_target.flush()
        try:
            t_writer.write_eof()
        except (OSError, RuntimeError):
            pass

        async def pings():
            while True:
                opcode, data = await read_frame(reader)
                if opcode == 0x9:
                    await send_client(frame(0xA, data))

        answering = asyncio.ensure_future(pings())
        try:
            while not answering.done():
                left = args.half_closed - (time.monotonic() - heard["at"])
                if left <= 0:
                    why = f"client half-closed, target idle for {args.half_closed:g}s"
                    await send_client(close_frame(1000, why), last=True)
                    return
                await asyncio.sleep(min(left, 0.2))
        finally:
            answering.cancel()

    async def down():  # target to client
        sent = 0
        limit, code = None, None
        if args.mode.startswith("close:"):
            _, limit, code = args.mode.split(":")
            limit, code = int(limit), int(code)
        while True:
            data = await t_reader.read(65536)
            if stalled.is_set():
                await asyncio.Event().wait()  # hold the connection open, silent
            if not data:
                await send_client(close_frame(1000, "target closed"), last=True)
                return
            await send_client(frame(0x2, data))
            heard["at"] = time.monotonic()
            if to_client is not None and to_client.over():
                # What waits is dropped; the Close goes after the last
                # whole frame.
                to_client.task.cancel()
                await write_client(close_frame(1013, "client receive backlog"))
                return
            if await counted(len(data)):
                return
            sent += len(data)
            if drop["bytes"] is not None and sent >= drop["bytes"]:
                await drop_now()
                return
            if limit is not None and sent >= limit:
                await send_client(close_frame(code, REASONS.get(code, "fault injection")), last=True)
                return

    tasks = [asyncio.ensure_future(t()) for t in (up, down, drop_clock)]
    extras = [asyncio.ensure_future(t()) for t in (stall_clock, keepalive)]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except Exception:  # noqa: BLE001
        pass
    done.set()
    for t in tasks + extras:
        t.cancel()
    # The bytes for the target that the shaper still holds, then the end.
    if to_target is not None:
        try:
            await asyncio.wait_for(to_target.flush(), 30)
        except (asyncio.TimeoutError, OSError):
            pass
    if to_client is not None:
        to_client.task.cancel()
    t_writer.close()


async def hold(reader, writer):
    """Blackhole: read whatever comes and never answer."""
    try:
        while await reader.read(65536):
            pass
    except OSError:
        pass
    writer.close()


async def main():
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--mode", default="normal")
    parser.add_argument("--keepalive", type=float, default=25.0)
    parser.add_argument("--half-closed", type=float, default=15.0)
    args = parser.parse_args()
    fake_reverse.MODE = args.mode
    fake_stream.MODE = args.mode
    fake_lazy.MODE = args.mode
    fake_conform.MODE = args.mode
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if args.mode == "tls12":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(args.cert, args.key)
    if args.mode == "blackhole":
        server = await asyncio.start_server(hold, "127.0.0.1", 0)
    else:
        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    with open(args.port_file, "w", encoding="utf-8") as f:
        f.write(str(server.sockets[0].getsockname()[1]))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
