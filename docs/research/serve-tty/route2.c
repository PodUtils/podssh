/*
 * route2: a tty in user space by seccomp user notification (T-248, route 2a).
 * The child's descriptors 0, 1 and 2 are one AF_UNIX stream socket (both
 * ways, as a pty's slave); a filter of the child's own sends each tty ioctl
 * (request 0x54xx, TCGETS2's family among them) and each open/openat to this
 * supervisor, which answers the tty calls on that socket from its own
 * termios state, gives a copy of the socket for "/dev/tty", and lets each
 * other call go on to the kernel. No code goes into the child.
 *
 *   cc -O2 -o route2 route2.c
 *   ./route2 [-s SCRIPT] -- COMMAND...
 *   ./route2 bench-child           (run under route2: the cost of each kind of call)
 *
 * SCRIPT: steps split by '|': w:TEXT (write; \r \n \e \xNN), p:MS (pause),
 * i (Ctrl-C: SIGINT to the foreground group when ISIG is on, else the
 * byte), z (Ctrl-Z: SIGTSTP), r:COLSxROWS (resize, SIGWINCH to the group).
 * Env: ROUTE2_ID=kcmp|pidfd|proc and ROUTE2_MEM=vm|proc force one way.
 */
#define _GNU_SOURCE
#include "route2.h"

static int tty_child = -1, tty_mine = -1;
static pid_t leader, fg;
static struct kt term;
static struct winsize win = { .ws_row = 24, .ws_col = 80 };
static long seen[8]; /* by kind: see the names in report() */
static long cmds[0x60], other_cmds;
static const char *id_way = "", *mem_way = "";

/* Whether descriptor FD of PID is the child's socket: kcmp, else a copy
 * by pidfd_getfd, else /proc/PID/fd/FD. */
static int ours(pid_t pid, int fd) {
    const char *force = getenv("ROUTE2_ID");
    if (!force || !strcmp(force, "kcmp")) {
        long r = syscall(SYS_kcmp, getpid(), pid, KCMP_FILE, tty_child, fd);
        if (r >= 0) { id_way = "kcmp"; return r == 0; }
    }
    struct stat a, b;
    fstat(tty_child, &a);
    if (!force || !strcmp(force, "pidfd")) {
        int pfd = syscall(SYS_pidfd_open, pid, 0);
        if (pfd >= 0) {
            int copy = syscall(SYS_pidfd_getfd, pfd, fd, 0);
            close(pfd);
            if (copy >= 0) {
                int same = fstat(copy, &b) == 0 && a.st_ino == b.st_ino && a.st_dev == b.st_dev;
                close(copy);
                id_way = "pidfd_getfd";
                return same;
            }
            if (errno == EBADF) return 0;
        }
    }
    char path[64], link[64], want[64];
    snprintf(path, sizeof path, "/proc/%d/fd/%d", (int)pid, fd);
    ssize_t n = readlink(path, link, sizeof link - 1);
    if (n < 0) { id_way = "none"; return -1; }
    link[n] = 0;
    snprintf(want, sizeof want, "socket:[%lu]", (unsigned long)a.st_ino);
    id_way = "/proc/PID/fd";
    return strcmp(link, want) == 0;
}

/* Copy between this process and PID: process_vm_*, else /proc/PID/mem. */
static int mem(pid_t pid, unsigned long addr, void *buf, size_t len, int write_it) {
    const char *force = getenv("ROUTE2_MEM");
    if (!force || !strcmp(force, "vm")) {
        struct iovec l = { buf, len }, r = { (void *)addr, len };
        ssize_t n = write_it ? process_vm_writev(pid, &l, 1, &r, 1, 0) : process_vm_readv(pid, &l, 1, &r, 1, 0);
        if (n == (ssize_t)len) { mem_way = write_it ? "process_vm_writev" : mem_way; return 0; }
        if (n >= 0) return -1;
    }
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/mem", (int)pid);
    int fd = open(path, write_it ? O_WRONLY : O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = write_it ? pwrite(fd, buf, len, addr) : pread(fd, buf, len, addr);
    close(fd);
    if (n == (ssize_t)len && write_it) mem_way = "/proc/PID/mem";
    return n == (ssize_t)len ? 0 : -1;
}

static void reply(int lfd, struct seccomp_notif *n, long val, int err, int cont) {
    struct seccomp_notif_resp r = { .id = n->id, .val = val, .error = err ? -err : 0,
                                    .flags = cont ? SECCOMP_USER_NOTIF_FLAG_CONTINUE : 0 };
    if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, &r) && errno != ENOENT) perror("NOTIF_SEND");
}

static void lflag_changed(unsigned before, unsigned after) {
    if (before == after) return;
    fprintf(stderr, "[route2] lflag: ICANON %d ECHO %d ISIG %d (from pid's TCSETS)\n",
            !!(after & ICANON), !!(after & ECHO), !!(after & ISIG));
}

static void tty_call(int lfd, struct seccomp_notif *n) {
    pid_t pid = n->pid;
    unsigned cmd = (unsigned)n->data.args[1];
    unsigned long arg = n->data.args[2];
    int fd = (int)n->data.args[0];
    if (cmd == FIONREAD || cmd == TIOCOUTQ) { seen[1]++; reply(lfd, n, 0, 0, 1); return; } /* a socket's own */
    int mine = ours(pid, fd);
    if (mine <= 0) { seen[1]++; reply(lfd, n, 0, 0, 1); return; } /* not ours, or not known: the kernel answers */
    seen[0]++;
    if ((cmd & 0xff) < 0x60 && (cmd & 0xffff0000) == 0) cmds[cmd & 0xff]++; else other_cmds++;
    struct kt t;
    int pg, rc = 0;
    switch (cmd) {
    case TCGETS: rc = mem(pid, arg, &term, KT_SIZE, 1); break;
    case TCGETS2: rc = mem(pid, arg, &term, sizeof term, 1); break;
    case TCSETS: case TCSETSW: case TCSETSF:
    case TCSETS2: case TCSETSW2: case TCSETSF2: {
        size_t len = (cmd == TCSETS || cmd == TCSETSW || cmd == TCSETSF) ? KT_SIZE : sizeof t;
        t = term;
        rc = mem(pid, arg, &t, len, 0);
        if (!rc && ioctl(lfd, SECCOMP_IOCTL_NOTIF_ID_VALID, &n->id) == 0) { lflag_changed(term.lflag, t.lflag); term = t; }
        break;
    }
    case TIOCGWINSZ: rc = mem(pid, arg, &win, sizeof win, 1); break;
    case TIOCSWINSZ: {
        struct winsize w;
        rc = mem(pid, arg, &w, sizeof w, 0);
        if (!rc && memcmp(&w, &win, sizeof w)) { win = w; kill(-fg, SIGWINCH); }
        break;
    }
    case TIOCGPGRP: rc = mem(pid, arg, &fg, sizeof fg, 1); break;
    case TIOCSPGRP:
        rc = mem(pid, arg, &pg, sizeof pg, 0);
        if (!rc) { fprintf(stderr, "[route2] foreground group %d -> %d\n", fg, pg); fg = pg; }
        break;
    case TIOCGSID: rc = mem(pid, arg, &leader, sizeof leader, 1); break;
    case TIOCSCTTY: case TIOCNOTTY: case TCFLSH: case TCXONC: case TCSBRK: case TCSBRKP: break;
    default:
        fprintf(stderr, "[route2] tty ioctl 0x%x on the socket: ENOTTY\n", cmd);
        reply(lfd, n, 0, ENOTTY, 0);
        return;
    }
    reply(lfd, n, 0, rc ? EFAULT : 0, 0);
}

/* open/openat: "/dev/tty" becomes a copy of the socket; each other path
 * goes on to the kernel. */
static void open_call(int lfd, struct seccomp_notif *n) {
    int at = n->data.nr == SYS_openat;
    unsigned long addr = n->data.args[at ? 1 : 0];
    int flags = (int)n->data.args[at ? 2 : 1];
    char path[16] = "";
    /* "/dev/tty" and its NUL; a read short of a page's end is retried shorter. */
    size_t len = sizeof path - 1;
    while (len > 0 && mem(n->pid, addr, path, len, 0)) len /= 2;
    path[len] = 0;
    if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_ID_VALID, &n->id)) return;
    if (strcmp(path, "/dev/tty") != 0) { seen[3]++; reply(lfd, n, 0, 0, 1); return; }
    seen[2]++;
    struct seccomp_notif_addfd a = { .id = n->id, .flags = SECCOMP_ADDFD_FLAG_SEND, .srcfd = tty_child,
                                     .newfd_flags = flags & O_CLOEXEC };
    if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_ADDFD, &a) < 0) { perror("NOTIF_ADDFD"); reply(lfd, n, 0, ENXIO, 0); }
}

static int install(void) {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 6, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_open, 5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ioctl, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xff00),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5400, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    };
    struct sock_fprog prog = { .len = sizeof f / sizeof f[0], .filter = f };
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

static void unescape(const char *s, char *out, size_t *len) {
    size_t k = 0;
    for (; *s; s++) {
        if (*s != '\\') { out[k++] = *s; continue; }
        s++;
        if (*s == 'r') out[k++] = '\r'; else if (*s == 'n') out[k++] = '\n';
        else if (*s == 'e') out[k++] = 27;
        else if (*s == 'x') { char h[3] = { s[1], s[2], 0 }; out[k++] = (char)strtol(h, NULL, 16); s += 2; }
        else out[k++] = *s;
    }
    *len = k;
}

static void key(char byte, int sig) {
    if (term.lflag & ISIG) { fprintf(stderr, "[route2] signal %d to group %d\n", sig, fg); kill(-fg, sig); }
    else if (write(tty_mine, &byte, 1) != 1) perror("write");
}

/* One step of the script; returns the ms to wait after it. */
static int step(char *s) {
    char buf[512];
    size_t len;
    if (s[0] == 'w' && s[1] == ':') { unescape(s + 2, buf, &len); if (write(tty_mine, buf, len) < 0) perror("write"); return 0; }
    if (s[0] == 'p' && s[1] == ':') return atoi(s + 2);
    if (s[0] == 'i') key(3, SIGINT);
    if (s[0] == 'z') key(26, SIGTSTP);
    if (s[0] == 'r' && s[1] == ':') {
        win.ws_col = (unsigned short)atoi(s + 2);
        win.ws_row = (unsigned short)atoi(strchr(s, 'x') + 1);
        fprintf(stderr, "[route2] resize %ux%u, SIGWINCH to group %d\n", win.ws_col, win.ws_row, fg);
        kill(-fg, SIGWINCH);
    }
    return 0;
}

static void report(int status) {
    fprintf(stderr, "\n[route2] child exit %d; ids by %s, answers written by %s\n",
            WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status), id_way, mem_way);
    fprintf(stderr, "[route2] answered %ld tty ioctls, passed %ld; /dev/tty given %ld, other opens passed %ld\n",
            seen[0], seen[1], seen[2], seen[3]);
    fprintf(stderr, "[route2] answered requests:");
    for (int k = 0; k < 0x60; k++) if (cmds[k]) fprintf(stderr, " 0x54%02x x%ld", k, cmds[k]);
    fprintf(stderr, " other x%ld\n", other_cmds);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "bench-child")) return bench();
    char *script = NULL;
    int i = 1;
    if (i + 1 < argc && !strcmp(argv[i], "-s")) { script = argv[i + 1]; i += 2; }
    if (i < argc && !strcmp(argv[i], "--")) i++;
    if (i >= argc) { fprintf(stderr, "usage: route2 [-s SCRIPT] -- CMD...\n"); return 64; }
    setvbuf(stdout, NULL, _IONBF, 0);
    term = default_termios();
    int tty[2], ctl[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, tty) || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ctl)) return 1;
    tty_mine = tty[0];
    tty_child = tty[1];
    fcntl(tty_mine, F_SETFD, FD_CLOEXEC);
    leader = fork();
    if (leader == 0) {
        setsid();
        dup2(tty[1], 0); dup2(tty[1], 1); dup2(tty[1], 2);
        close(tty[0]); close(tty[1]); close(ctl[0]);
        if (!prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)) prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        int lfd = install();
        if (lfd < 0) { dprintf(ctl[1], "E%d", errno); _exit(126); }
        if (send_fd(ctl[1], lfd)) _exit(126);
        close(lfd);
        char ack;
        if (read(ctl[1], &ack, 1) != 1) _exit(126);
        execvp(argv[i], argv + i);
        _exit(127);
    }
    close(ctl[1]);
    fg = leader;
    int lfd = recv_fd(ctl[0]);
    if (lfd < 0) { fprintf(stderr, "route 2a: refused here: %s\n", strerror(-lfd)); return 2; }
    if (write(ctl[0], "g", 1) != 1) return 1;
    struct seccomp_notif_sizes sz;
    syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sz);
    struct seccomp_notif *n = calloc(1, sz.seccomp_notif > sizeof *n ? sz.seccomp_notif : sizeof *n);
    double end = now() + 20, next = now() + 0.5;
    int status = 0, done = 0;
    char *save = NULL, *cur = script ? strtok_r(script, "|", &save) : NULL;
    while (!done) {
        if (now() > end) { fprintf(stderr, "[route2] timeout: SIGKILL to the session\n"); kill(-leader, SIGKILL); }
        if (cur && now() >= next) { next = now() + step(cur) / 1e3 + 0.05; cur = strtok_r(NULL, "|", &save); }
        struct pollfd p[2] = { { lfd, POLLIN, 0 }, { tty_mine, POLLIN, 0 } };
        if (poll(p, 2, 20) > 0) {
            if (p[0].revents & POLLIN) {
                memset(n, 0, sz.seccomp_notif);
                if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, n) == 0) {
                    if (n->data.nr == SYS_ioctl) tty_call(lfd, n); else open_call(lfd, n);
                }
            }
            if (p[1].revents & POLLIN) {
                char out[4096];
                ssize_t k = read(tty_mine, out, sizeof out);
                if (k > 0) show(out, k);
            }
        }
        if (waitpid(leader, &status, WNOHANG) == leader) done = 1;
    }
    /* What the child wrote last. */
    struct pollfd p = { tty_mine, POLLIN, 0 };
    char out[4096];
    ssize_t k;
    while (poll(&p, 1, 100) > 0 && (k = read(tty_mine, out, sizeof out)) > 0) show(out, k);
    report(status);
    return 0;
}
