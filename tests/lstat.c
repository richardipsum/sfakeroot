#include <stdio.h>
#include <sys/stat.h>

int main(int argc __attribute__((unused)), char *argv[])
{
    struct stat st_expected;
    struct stat st_actual;

    if (stat(argv[0], &st_expected) == -1)
    {
        fprintf(stderr, "stat failed\n");
        return 1;
    }


    if (lstat(argv[0], &st_actual) == -1)
    {
        fprintf(stderr, "stat failed\n");
        return 1;
    }

    if (st_expected.st_uid == 0
    && st_expected.st_gid == 0
    && st_expected.st_ino == st_actual.st_ino) {
        return 0;
    }

    return 1;
}
