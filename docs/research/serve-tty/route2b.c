/*
 * route2b: the same tty in user space by ptrace (T-248, route 2b): the
 * child asks PTRACE_TRACEME, adds a filter that returns SECCOMP_RET_TRACE
 * for each tty ioctl (request 0x54xx), and runs COMMAND; this tracer
 * answers TCGETS and TIOCGWINSZ on the child's socket by writing the reply
 * into the child and skipping the call, and lets each other call go on.
 * It follows each fork, as the shell's commands are its children.
 *
 *   cc -O2 -o route2b route2b.c
 *   ./route2b COMMAND...
 */
#define _GNU_SOURCE
#define ROUTE2_TRACER
#include "route2.h"
#include <sys/ptrace.h>
#include <sys/user.h>

static int tty_child;
static long answered, passed;

static void on_alarm(int sig) { (void)sig; }

static void answer(pid_t pid) {
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, 0, &r)) return;
    int fd = (int)r.rdi;
    unsigned cmd = (unsigned)r.rsi;
    long same = syscall(SYS_kcmp, getpid(), pid, KCMP_FILE, tty_child, fd);
    if (same != 0 || (cmd != TCGETS && cmd != TIOCGWINSZ)) { passed++; return; }
    struct kt t = default_termios();
    struct winsize w = { .ws_row = 24, .ws_col = 80 };
    const void *src = cmd == TCGETS ? (const void *)&t : (const void *)&w;
    size_t len = cmd == TCGETS ? KT_SIZE : sizeof w;
    /* Word by word with PTRACE_POKEDATA: no other syscall is needed. */
    for (size_t off = 0; off < len; off += sizeof(long)) {
        long word = ptrace(PTRACE_PEEKDATA, pid, r.rdx + off, 0);
        memcpy(&word, (const char *)src + off, len - off < sizeof(long) ? len - off : sizeof(long));
        ptrace(PTRACE_POKEDATA, pid, r.rdx + off, word);
    }
    r.orig_rax = -1; /* skip the call */
    r.rax = 0;
    ptrace(PTRACE_SETREGS, pid, 0, &r);
    answered++;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: route2b CMD...\n"); return 64; }
    setvbuf(stdout, NULL, _IONBF, 0);
    int tty[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, tty)) return 1;
    tty_child = tty[1];
    pid_t c = fork();
    if (c == 0) {
        setsid();
        dup2(tty[1], 0); dup2(tty[1], 1); dup2(tty[1], 2);
        close(tty[0]); close(tty[1]);
        if (ptrace(PTRACE_TRACEME, 0, 0, 0)) { dprintf(2, "PTRACE_TRACEME: %s\n", strerror(errno)); _exit(126); }
        raise(SIGSTOP);
        if (!prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)) prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        struct sock_filter f[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ioctl, 0, 3),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
            BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xff00),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x5400, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        };
        struct sock_fprog prog = { .len = sizeof f / sizeof f[0], .filter = f };
        if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) _exit(126);
        execvp(argv[1], argv + 1);
        _exit(127);
    }
    /* The tracer keeps its copy of the child's end: kcmp compares with it. */
    int st;
    if (waitpid(c, &st, __WALL) != c || !WIFSTOPPED(st)) {
        char out[256];
        ssize_t k = read(tty[0], out, sizeof out);
        printf("route 2b: refused here: %.*s", (int)(k > 0 ? k : 0), out);
        return 2;
    }
    ptrace(PTRACE_SETOPTIONS, c, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_EXITKILL | PTRACE_O_TRACEFORK |
                                    PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);
    ptrace(PTRACE_CONT, c, 0, 0);
    struct sigaction quiet = { .sa_handler = on_alarm };
    sigaction(SIGALRM, &quiet, NULL);
    int status = 0;
    double end = now() + 20;
    for (;;) {
        struct pollfd p = { tty[0], POLLIN, 0 };
        char out[4096];
        while (poll(&p, 1, 0) > 0) { ssize_t k = read(tty[0], out, sizeof out); if (k <= 0) break; show(out, k); }
        /* A blocking wait: the time limit is alarm()'s, whose signal ends
         * the wait with EINTR. The output is read between stops, so a child
         * that writes more than a socket's buffer would block (not here). */
        if (now() > end) kill(c, SIGKILL);
        alarm(1);
        pid_t pid = waitpid(-1, &st, __WALL);
        alarm(0);
        if (pid < 0 && errno == EINTR) continue;
        if (pid < 0) break;
        if (WIFEXITED(st) || WIFSIGNALED(st)) { if (pid == c) { status = st; break; } continue; }
        int sig = 0, ev = st >> 16;
        if (ev == PTRACE_EVENT_SECCOMP) answer(pid);
        else if (ev == 0 && WSTOPSIG(st) != SIGSTOP && WSTOPSIG(st) != SIGTRAP) sig = WSTOPSIG(st);
        ptrace(PTRACE_CONT, pid, 0, sig);
    }
    struct pollfd p = { tty[0], POLLIN, 0 };
    char out[4096];
    ssize_t k;
    while (poll(&p, 1, 100) > 0 && (k = read(tty[0], out, sizeof out)) > 0) show(out, k);
    printf("\n[route2b] child exit %d; answered %ld tty ioctls, passed %ld\n",
           WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status), answered, passed);
    return 0;
}
