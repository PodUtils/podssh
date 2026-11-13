/*
 * The box's helper for its profile sandbox-a (T-245): sandbox A refuses a
 * bind of AF_INET with EACCES and allows one of AF_UNIX. A seccomp filter
 * cannot read the address behind bind's pointer, so the TCP refusal is
 * Landlock's (its right to bind TCP, ABI 4, Linux 6.7), set here before the
 * box's commands start; UDP stays refused at socket() by the seccomp file.
 * It belongs to the box, never to podssh.
 *
 *   bindjail run CMD [ARG...]        deny each TCP bind, then exec CMD
 *   bindjail abi                     print Landlock's ABI (0: none)
 *   bindjail try unix PATH           one bind of a socket at PATH
 *   bindjail try abstract NAME       one bind in the abstract namespace
 *   bindjail try tcp PORT            one bind of 127.0.0.1:PORT
 *
 * try prints "bound" or the error's text, and exits 0 or 1.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/landlock.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

static long abi(void) {
    long v = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    return v < 0 ? 0 : v;
}

/* No rule is added: each TCP bind is refused, each other right untouched. */
static int deny_tcp_bind(void) {
    long v = abi();
    if (v < 4) {
        /* No silent fall back to the profile strict: the box would stand
         * for a sandbox that it is not. */
        fprintf(stderr, "bindjail: Landlock ABI %ld here, and the right to bind TCP needs 4 (Linux 6.7)\n", v);
        return 69;
    }
    struct landlock_ruleset_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP;
    /* The size of the fields that ABI 4 knows: a newer header's own
     * fields would be refused by an older kernel. */
    size_t size = offsetof(struct landlock_ruleset_attr, handled_access_net) + sizeof attr.handled_access_net;
    int fd = (int)syscall(SYS_landlock_create_ruleset, &attr, size, 0);
    if (fd < 0) {
        fprintf(stderr, "bindjail: landlock_create_ruleset: %s\n", strerror(errno));
        return 71;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || syscall(SYS_landlock_restrict_self, fd, 0) != 0) {
        fprintf(stderr, "bindjail: landlock_restrict_self: %s\n", strerror(errno));
        close(fd);
        return 71;
    }
    close(fd);
    return 0;
}

static int try_bind(const char *kind, const char *what) {
    int fd;
    int rc;
    if (strcmp(kind, "tcp") == 0) {
        struct sockaddr_in in;
        memset(&in, 0, sizeof in);
        in.sin_family = AF_INET;
        in.sin_port = htons((uint16_t)atoi(what));
        in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { printf("%s\n", strerror(errno)); return 1; }
        rc = bind(fd, (struct sockaddr *)&in, sizeof in);
    } else {
        struct sockaddr_un un;
        memset(&un, 0, sizeof un);
        un.sun_family = AF_UNIX;
        size_t n = strlen(what);
        if (n + 2 > sizeof un.sun_path) { printf("a name too long\n"); return 1; }
        socklen_t len;
        if (strcmp(kind, "abstract") == 0) {
            /* The abstract namespace: a first byte of 0, no file. */
            memcpy(un.sun_path + 1, what, n);
            len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
        } else if (strcmp(kind, "unix") == 0) {
            memcpy(un.sun_path, what, n);
            len = (socklen_t)sizeof un;
        } else {
            fprintf(stderr, "bindjail: try takes unix, abstract or tcp, not %s\n", kind);
            return 64;
        }
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) { printf("%s\n", strerror(errno)); return 1; }
        rc = bind(fd, (struct sockaddr *)&un, len);
        if (rc == 0 && strcmp(kind, "unix") == 0) unlink(what);
    }
    if (rc != 0) { printf("%s\n", strerror(errno)); close(fd); return 1; }
    printf("bound\n");
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "run") == 0) {
        int rc = deny_tcp_bind();
        if (rc != 0) return rc;
        execvp(argv[2], argv + 2);
        fprintf(stderr, "bindjail: %s: %s\n", argv[2], strerror(errno));
        return 127;
    }
    if (argc == 2 && strcmp(argv[1], "abi") == 0) {
        printf("%ld\n", abi());
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "try") == 0) return try_bind(argv[2], argv[3]);
    fprintf(stderr, "usage: bindjail run CMD [ARG...] | abi | try unix PATH | try abstract NAME | try tcp PORT\n");
    return 64;
}
