/*
 * route1: a pty of a new devpts instance, made in a user namespace by a
 * short-lived helper, for a child that runs outside that namespace (T-248).
 *
 *   cc -O2 -pthread -o route1 route1.c
 *   ./route1 [COMMAND...]     (default: sh -c 'tty; test -t 0 && echo ISATTY; stty size')
 *
 * Steps, each printed with its result:
 *   1. fork a helper; it calls unshare(CLONE_NEWUSER | CLONE_NEWNS), maps
 *      its own uid and gid to themselves (setgroups deny), mounts devpts
 *      with newinstance over an existing directory (/dev/pts, /dev or
 *      /tmp, in its own mount namespace), opens its ptmx, unlocks it,
 *      and opens the slave by TIOCGPTPEER (ptsname names /dev/pts/N, the
 *      host's instance, not this one);
 *   2. the helper sends both descriptors to the parent with SCM_RIGHTS and
 *      exits: its namespaces die with it;
 *   3. the parent (no namespace of its own) sets 132x43 on the master, and
 *      starts COMMAND in a new session with the slave as its controlling
 *      terminal (TIOCSCTTY), then prints what came out of the master.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#ifndef TIOCGPTPEER
#define TIOCGPTPEER _IO('T', 0x41)
#endif

static int put(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, text, strlen(text));
    int e = errno;
    close(fd);
    errno = e;
    return n == (ssize_t)strlen(text) ? 0 : -1;
}

#define STEP(ok, ...) do { printf(__VA_ARGS__); if (ok) printf(": ok\n"); else { printf(": %s\n", strerror(errno)); fflush(stdout); _exit(1); } fflush(stdout); } while (0)

static void *idle(void *arg) { for (;;) pause(); return arg; }

static void helper(int sock) {
    uid_t uid = getuid();
    gid_t gid = getgid();
    char map[64], path[96];
    /* An existing directory, covered in the helper's own mount namespace
     * only: nothing is made, and nothing is left behind. */
    const char *dirs[] = { "/dev/pts", "/dev", "/tmp" }, *dir = NULL;
    struct stat sb;
    for (unsigned k = 0; k < 3 && !dir; k++)
        if (stat(dirs[k], &sb) == 0 && S_ISDIR(sb.st_mode)) dir = dirs[k];
    STEP(dir != NULL, "helper: a directory to cover: %s", dir ? dir : "none");
    if (getenv("ROUTE1_THREAD")) {
        /* As serve's own process would be: a second thread. */
        pthread_t t;
        pthread_create(&t, NULL, idle, NULL);
        printf("helper: a second thread runs (ROUTE1_THREAD)\n");
    }
    STEP(unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0, "helper: unshare(CLONE_NEWUSER|CLONE_NEWNS)");
    if (getenv("ROUTE1_NOMAP")) {
        printf("helper: no uid_map written (ROUTE1_NOMAP)\n");
    } else {
        STEP(put("/proc/self/setgroups", "deny") == 0, "helper: setgroups deny");
        snprintf(map, sizeof map, "%u %u 1", uid, uid);
        STEP(put("/proc/self/uid_map", map) == 0, "helper: uid_map %s", map);
        snprintf(map, sizeof map, "%u %u 1", gid, gid);
        STEP(put("/proc/self/gid_map", map) == 0, "helper: gid_map %s", map);
    }
    STEP(mount("devpts", dir, "devpts", MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620") == 0,
         "helper: mount devpts newinstance on %s", dir);
    snprintf(path, sizeof path, "%s/ptmx", dir);
    int master = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    STEP(master >= 0, "helper: open %s", path);
    int unlock = 0;
    STEP(ioctl(master, TIOCSPTLCK, &unlock) == 0, "helper: unlock");
    char name[64] = "";
    int r = ptsname_r(master, name, sizeof name);
    printf("helper: ptsname says %s (%s)\n", r ? "nothing" : name, r ? strerror(r) : "the host's /dev/pts, not this instance");
    int byname = open(name, O_RDWR | O_NOCTTY);
    printf("helper: open(%s) by that name: %s\n", name, byname >= 0 ? "opens (another instance's)" : strerror(errno));
    int slave = ioctl(master, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_CLOEXEC);
    STEP(slave >= 0, "helper: TIOCGPTPEER");
    char buf[CMSG_SPACE(2 * sizeof(int))];
    memset(buf, 0, sizeof buf);
    char one = 'x';
    struct iovec iov = { &one, 1 };
    struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = buf, .msg_controllen = sizeof buf };
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(2 * sizeof(int));
    int fds[2] = { master, slave };
    memcpy(CMSG_DATA(c), fds, sizeof fds);
    STEP(sendmsg(sock, &m, 0) == 1, "helper: send master and slave");
    /* The mount goes with the namespace; the files keep the instance. */
    _exit(0);
}

static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) { perror("socketpair"); return 1; }
    double t0 = now();
    pid_t h = fork();
    if (h == 0) { close(sv[0]); helper(sv[1]); }
    close(sv[1]);
    int st;
    waitpid(h, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st)) { printf("route 1: refused here (helper exit %d)\n", WEXITSTATUS(st)); return 2; }
    char buf[CMSG_SPACE(2 * sizeof(int))], one;
    struct iovec iov = { &one, 1 };
    struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = buf, .msg_controllen = sizeof buf };
    if (recvmsg(sv[0], &m, 0) != 1) { perror("recvmsg"); return 1; }
    int fds[2];
    memcpy(fds, CMSG_DATA(CMSG_FIRSTHDR(&m)), sizeof fds);
    printf("parent: a pair in %.1f ms; the helper and its namespaces are gone\n", (now() - t0) * 1e3);
    struct winsize ws = { .ws_row = 43, .ws_col = 132 };
    if (ioctl(fds[0], TIOCSWINSZ, &ws)) perror("TIOCSWINSZ");
    pid_t c = fork();
    if (c == 0) {
        setsid();
        if (ioctl(fds[1], TIOCSCTTY, 0)) { perror("TIOCSCTTY"); _exit(1); }
        dup2(fds[1], 0); dup2(fds[1], 1); dup2(fds[1], 2);
        if (argc > 1) execvp(argv[1], argv + 1);
        execl("/bin/sh", "sh", "-c",
              "tty; test -t 0 && echo ISATTY; stty size; ls -l /proc/self/fd/0; "
              "sleep 0.3; kill -WINCH $$; trap 'echo WINCH $(stty size)' WINCH; sleep 1; echo END", (char *)0);
        _exit(127);
    }
    close(fds[1]);
    double end = now() + 10;
    int resized = 0;
    for (;;) {
        struct pollfd p = { fds[0], POLLIN, 0 };
        if (now() > end) { printf("parent: timeout\n"); kill(c, SIGKILL); break; }
        if (!resized && now() - t0 > 0.6) {
            ws.ws_row = 30; ws.ws_col = 100;
            ioctl(fds[0], TIOCSWINSZ, &ws); /* the kernel sends SIGWINCH */
            resized = 1;
        }
        if (poll(&p, 1, 100) <= 0) continue;
        char out[512];
        ssize_t n = read(fds[0], out, sizeof out);
        if (n <= 0) break; /* EIO when the last slave closes */
        fwrite(out, 1, n, stdout);
    }
    waitpid(c, &st, 0);
    printf("parent: child exit %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st));
    return 0;
}
