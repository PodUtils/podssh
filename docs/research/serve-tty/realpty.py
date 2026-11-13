"""The keys of run.sh's bash session on a real pty of the host (forkpty), so
that what bash itself prints can be told from what route 2a changes (T-248).
Run outside the cage: python3 realpty.py"""
import os, sys, time, signal, select
pid, fd = os.forkpty()
if pid == 0:
    os.execvpe("bash", ["bash", "--norc", "--noprofile", "-i"], dict(os.environ, PS1="$ ", HOME="/tmp"))
def drain(t):
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try: sys.stdout.write(os.read(fd, 4096).decode(errors="replace").replace("\x1b", "^["))
            except OSError: return
for step in ["sleep 31\r", "\x1a", "jobs\r", "kill -9 %1\r", "jobs\r", "exit 7\r"]:
    drain(0.6); os.write(fd, step.encode())
drain(1.5)
print("\nexit", os.waitpid(pid, 0)[1] >> 8)
