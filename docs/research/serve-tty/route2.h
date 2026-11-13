/* The plumbing of route2.c (T-248): the kernel's termios, the passing of a
 * descriptor, the output shown, and the bench that runs as the child. */
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/kcmp.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* The kernel's struct termios2 on x86_64; its first 36 bytes are the
 * struct termios of TCGETS (libc's own struct is larger and differs). */
struct kt {
    unsigned iflag, oflag, cflag, lflag;
    unsigned char line, cc[19];
    unsigned ispeed, ospeed;
};
#define KT_SIZE 36
/* The termios2 family by value: the headers name an incomplete struct. */
#undef TCGETS2
#undef TCSETS2
#undef TCSETSW2
#undef TCSETSF2
#define TCGETS2 0x802c542aU
#define TCSETS2 0x402c542bU
#define TCSETSW2 0x402c542cU
#define TCSETSF2 0x402c542dU

/* A fresh pty's state on Linux: cooked, echo, signals, 38400 baud. */
static struct kt default_termios(void) {
    struct kt t = { .iflag = ICRNL | IXON | IUTF8, .oflag = OPOST | ONLCR,
                    .cflag = B38400 | CS8 | CREAD | HUPCL, .ispeed = 38400, .ospeed = 38400,
                    .lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN | ECHOCTL | ECHOKE };
    const unsigned char cc[19] = { 3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0 };
    memcpy(t.cc, cc, sizeof cc);
    return t;
}

static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }

#ifndef ROUTE2_TRACER
static int send_fd(int sock, int fd) {
    char buf[CMSG_SPACE(sizeof(int))], one = 'F';
    memset(buf, 0, sizeof buf);
    struct iovec iov = { &one, 1 };
    struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = buf, .msg_controllen = sizeof buf };
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof fd);
    return sendmsg(sock, &m, 0) == 1 ? 0 : -1;
}

/* The descriptor, or -errno that the child sent as "E<errno>". */
static int recv_fd(int sock) {
    char buf[CMSG_SPACE(sizeof(int))], data[16] = "";
    struct iovec iov = { data, sizeof data - 1 };
    struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = buf, .msg_controllen = sizeof buf };
    ssize_t n = recvmsg(sock, &m, 0);
    if (n <= 0) return -EPIPE;
    if (data[0] == 'E') return -atoi(data + 1);
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    if (!c) return -EPROTO;
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof fd);
    return fd;
}

#endif

/* The child's output, ESC as ^[ so that a screen reads as text. */
static void show(const char *out, ssize_t k) {
    for (ssize_t j = 0; j < k; j++) {
        if (out[j] == 27) fputs("^[", stdout);
        else putchar(out[j]);
    }
}

#define LOOP(label, n, call) do { \
        double t0 = now(); \
        for (int k = 0; k < (n); k++) { call; } \
        printf("%-44s %8.2f us\n", label, (now() - t0) * 1e6 / (n)); \
    } while (0)

#ifndef ROUTE2_TRACER
/* The cost of each kind of call, run as the child of route2. */
static int bench(void) {
    struct termios t;
    int q, nul = open("/dev/null", O_RDONLY);
    const int n = 20000;
    printf("isatty(0) %d, isatty(/dev/null) %d\n", isatty(0), isatty(nul));
    LOOP("getpid (no filter rule)", n, syscall(SYS_getpid));
    LOOP("ioctl FIONREAD on 0 (notified, passed)", n, ioctl(0, FIONREAD, &q));
    LOOP("tcgetattr(0) (notified, answered)", n, tcgetattr(0, &t));
    LOOP("tcgetattr(/dev/null) (notified, passed)", n, tcgetattr(nul, &t));
    LOOP("open+close /etc/hostname (notified, passed)", n / 4, close(open("/etc/hostname", O_RDONLY)));
    int tty = open("/dev/tty", O_RDWR);
    printf("open(/dev/tty) gives %d; isatty %d\n", tty, tty >= 0 ? isatty(tty) : -1);
    return 0;
}
#endif
