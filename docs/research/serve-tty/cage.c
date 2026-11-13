/*
 * cage: run a command as the target sandbox runs podssh (T-248): no
 * /dev/ptmx and no /dev/pts, uid 65534, no capabilities, NoNewPrivs=1, and
 * a seccomp filter that refuses what the flags name. Run as root on the
 * measuring host; the command then has none of root's powers.
 *
 *   cc -O2 -o cage cage.c
 *   ./cage [-n] [-p] [-v] [-P] [-l] -- COMMAND ARGS...
 *
 *   -n  refuse unshare, mount, setns and a clone of a new namespace (EPERM),
 *       as both real sandboxes refuse them
 *   -p  refuse ptrace (EPERM), as podvm's host of issue 114 refuses it
 *   -v  refuse process_vm_readv and process_vm_writev (EPERM)
 *   -P  hide /proc under an empty tmpfs, as a related host has no /proc
 *   -l  a filter of the cage's own with a notification listener (for
 *       reboot only, which nothing calls), as a sandbox whose supervisor
 *       uses seccomp user notification itself
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static void die(const char *what) { perror(what); exit(111); }

/* A file of the new /dev, bound from the host's. */
static void bind_dev(const char *name, const char *from) {
    char to[128], src[128];
    snprintf(to, sizeof to, "/tmp/t248dev/%s", name);
    snprintf(src, sizeof src, "/dev/%s", from);
    int fd = open(to, O_CREAT | O_WRONLY, 0666);
    if (fd < 0) die(to);
    close(fd);
    if (mount(src, to, NULL, MS_BIND, NULL)) die(src);
}

#define DENY(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)

static void filter(int ns, int pt, int vm) {
    struct sock_filter f[64];
    int n = 0;
    struct sock_filter head[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    };
    memcpy(f + n, head, sizeof head); n += 1;
    if (ns) {
        struct sock_filter d[] = { DENY(SYS_unshare), DENY(SYS_mount), DENY(SYS_setns),
                                   DENY(SYS_fsopen), DENY(SYS_open_tree),
                                   /* ENOSYS, so that libc falls back to clone */
                                   BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1),
                                   BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
                                   /* clone with any CLONE_NEW* flag: arg 0 */
                                   BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 3),
                                   BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
                                   BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x7E020000, 0, 1),
                                   BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
                                   BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)) };
        memcpy(f + n, d, sizeof d); n += sizeof d / sizeof d[0];
    }
    if (pt) { struct sock_filter d[] = { DENY(SYS_ptrace) }; memcpy(f + n, d, sizeof d); n += 2; }
    if (vm) {
        struct sock_filter d[] = { DENY(SYS_process_vm_readv), DENY(SYS_process_vm_writev) };
        memcpy(f + n, d, sizeof d); n += 4;
    }
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    struct sock_fprog prog = { .len = (unsigned short)n, .filter = f };
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) die("seccomp");
}

/* The listener is closed on exec, which would end it (and the kernel's
 * refusal of a second one): a holder process keeps it open, and nobody
 * reads it. The holder goes when the cage's command ends. */
static void listener(void) {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_reboot, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = 4, .filter = f };
    int fd = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (fd < 0) die("listener");
    if (fork() == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        for (;;) pause();
    }
    close(fd);
}

int main(int argc, char **argv) {
    int ns = 0, pt = 0, vm = 0, noproc = 0, lis = 0, i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        if (!strcmp(argv[i], "--")) { i++; break; }
        for (char *c = argv[i] + 1; *c; c++) {
            if (*c == 'n') ns = 1; else if (*c == 'p') pt = 1;
            else if (*c == 'v') vm = 1; else if (*c == 'P') noproc = 1;
            else if (*c == 'l') lis = 1;
        }
    }
    if (i >= argc) { fprintf(stderr, "usage: cage [-npvPl] -- CMD...\n"); return 64; }
    if (unshare(CLONE_NEWNS)) die("unshare(CLONE_NEWNS)");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) die("make-rprivate");
    mkdir("/tmp/t248dev", 0755);
    if (mount("tmpfs", "/tmp/t248dev", "tmpfs", 0, "mode=0755")) die("tmpfs");
    const char *files[] = { "null", "zero", "random", "urandom", "full" };
    for (unsigned k = 0; k < sizeof files / sizeof files[0]; k++) bind_dev(files[k], files[k]);
    /* The sandbox's /dev/tty opens and is no controlling terminal; /dev/null
     * stands for it here (a read gives EOF where the sandbox's blocks). */
    bind_dev("tty", "null");
    mkdir("/tmp/t248dev/shm", 01777);
    if (symlink("/proc/self/fd", "/tmp/t248dev/fd")) die("fd link");
    if (mount("/tmp/t248dev", "/dev", NULL, MS_MOVE, NULL)) die("move /dev");
    if (noproc && mount("tmpfs", "/proc", "tmpfs", 0, "mode=0555")) die("hide /proc");
    if (setgroups(0, NULL)) die("setgroups");
    if (setresgid(65534, 65534, 65534)) die("setresgid");
    if (setresuid(65534, 65534, 65534)) die("setresuid");
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) die("no_new_privs");
    if (ns || pt || vm) filter(ns, pt, vm);
    if (lis) listener();
    execvp(argv[i], argv + i);
    die(argv[i]);
}
