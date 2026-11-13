/* isatty(0) and tcgetattr(0) of one libc, to read under route2 which tty
 * request each one makes (T-248): cc -static -o isatty-glibc isatty.c;
 * musl-gcc -static -o isatty-musl isatty.c. */
#include <stdio.h>
#include <termios.h>
#include <unistd.h>

int main(void) {
    struct termios t;
    int a = isatty(0);
    printf("isatty(0) %d\n", a);
    fflush(stdout);
    printf("tcgetattr(0) %d\n", tcgetattr(0, &t));
    return 0;
}
