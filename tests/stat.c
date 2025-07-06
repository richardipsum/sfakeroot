#include <stdio.h>
#include <sys/stat.h>

int main(int argc __attribute__((unused)), char *argv[])
{
    struct stat st;

    if (stat(argv[0], &st) == -1)
    {
        fprintf(stderr, "stat failed\n");
        return 1;
    }
#if defined(__linux__)
    printf("stat %s: ino: %lu uid: %d gid: %d\n", argv[0], st.st_ino, st.st_uid, st.st_gid);
#else
    printf("stat %s: ino: %llu uid: %d gid: %d\n", argv[0], st.st_ino, st.st_uid, st.st_gid);
#endif
    return 0;
}
