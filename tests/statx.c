#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "../sfakeroot.h"

int test(int argc __attribute__((unused)), char *argv[])
{
#if USE_STATX
    struct stat st_expected;
    struct statx stxbuf;

    if (stat(argv[0], &st_expected) == -1)
    {
        fprintf(stderr, "stat failed\n");
        return 1;
    }

    if (statx(AT_FDCWD, argv[0], 0, 0, &stxbuf) == -1) {
        fprintf(stderr, "statx failed\n");
        return 1;
    }

    if (stxbuf.stx_uid == 0
    && stxbuf.stx_gid == 0
    && stxbuf.stx_ino == st_expected.st_ino) {
        return 0;
    }

    return 1;
#else
    (void) argv;
    return 0;
#endif
}

int main(int argc __attribute__((unused)), char *argv[])
{
#if USE_STATX
    return 0;
#else
    return test(argc, argv);
#endif
}
