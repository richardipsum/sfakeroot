#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int main(void)
{
    char *template = "/tmp/sfakeroot.test.XXXXXX";
    char path[strlen(template) + 1];
    struct stat st_before;
    struct stat st_after;

    strcpy(path, template);
    printf("test making path %s\n", mktemp(path));

    if (symlink("foobar", path) == -1) {
        fprintf(stderr, "symlink '%s' failed: %s\n", path, strerror(errno));
        return 1;
    }

    if (lstat(path, &st_before) == -1)
    {
        fprintf(stderr, "stat failed\n");
        return 1;
    }
    if (st_before.st_uid != 0 || st_before.st_gid != 0) {
        fprintf(stderr, "uid/gid not 0\n");
        return 1;
    }

    if (lchown(path, 42, 43) == -1) {
        fprintf(stderr, "chown '%s' failed: %s\n", path, strerror(errno));
        return 1;
    }

    if (lstat(path, &st_after) == -1)
    {
        fprintf(stderr, "stat failed\n");
        return 1;
    }
    if (st_after.st_uid != 42) {
        fprintf(stderr, "uid not 42\n");
        return 1;
    }
    if (st_after.st_gid != 43) {
        fprintf(stderr, "gid not 43\n");
        return 1;
    }

    return 0;
}
