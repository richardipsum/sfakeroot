/* sfakeroot
 *
 * Copyright © 2020 Richard Ipsum
 *
 * This file is part of sfakeroot.
 *
 * sfakeroot is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * sfakeroot is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with sfakeroot.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>

#include "sfakeroot.h"

int sfakeroot_readwriten(int fd, char bytes[], size_t len, bool is_write)
{
    ssize_t n;
    size_t remaining = len;

    while (remaining > 0) {
        n = is_write ? write(fd, bytes, remaining) : read(fd, bytes, remaining);
        switch (n) {
            case 0:
                if (is_write) {
                    /* not necessarily an error if we're writing... */
                    continue;
                }
                fprintf(stderr, "sfakeroot: %s: data truncated, remaining: %zu\n",
                        is_write ? "write" : "read", remaining);
                return -1;
            case -1:
                if (errno == EINTR) {
                    continue;
                }
                fprintf(stderr, "sfakeroot: %s: %s\n",
                        is_write ? "write" : "read", strerror(errno));
                return -1;
            default:
                remaining -= n;
                bytes += n;
        }
    }

    return len - remaining;
}

int sfakeroot_recvmsg(int fd, struct sfakeroot_msg *m)
{
    if (sfakeroot_readwriten(fd, (char *) m, sizeof (*m), false) != sizeof (*m)) {
        fprintf(stderr, "sfakeroot_recvmsg: error reading message\n");
        return -1;
    }

    return 0;
}

int sfakeroot_sendmsg(int fd, struct sfakeroot_msg *m)
{
    if (sfakeroot_readwriten(fd, (char *) m, sizeof (*m), true) != sizeof (*m)) {
        fprintf(stderr, "sfakeroot_sendmsg: error writing message\n");
        return -1;
    }

    return 0;
}

static int sfakeroot__session_open_internal(bool session_expected)
{
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    int sockfd;
    socklen_t socklen;
    char *sockpath = getenv("SFAKEROOT_SOCKET_PATH");

    if (sockpath == NULL) {
        fprintf(stderr, "environment variable SFAKEROOT_SOCKET_PATH not set!\n");
        return -1;
    }

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return -1;
    }

    strlcpy(sa.sun_path, sockpath, sizeof (sa.sun_path));
    socklen = strlen(sa.sun_path) + 1 + sizeof (sa.sun_family);

    if (connect(sockfd, (struct sockaddr *) &sa, socklen) == -1) {
        if (session_expected) {
            fprintf(stderr, "connect: %s\n", strerror(errno));
        }
        return -1;
    }

    return sockfd;
}

int sfakeroot_session_open(void)
{
    return sfakeroot__session_open_internal(true);
}

bool sfakeroot_daemon_running(void)
{
    int sockfd = sfakeroot__session_open_internal(false);
    close(sockfd);
    return sockfd != -1;
}

static int sfakeroot__call(struct sfakeroot_msg *m)
{
    int sockfd;
    char *wd;

    sockfd = sfakeroot_session_open();
    if (sockfd == -1) {
        return -1;
    }

    if ((wd = getcwd(NULL, 0)) == NULL) {
        return -1;
    }

    strlcpy(m->working_dir, wd, sizeof (m->working_dir));
    free(wd);

    if (sfakeroot_sendmsg(sockfd, m) == -1) {
        return -1;
    }
    if (sfakeroot_recvmsg(sockfd, m) == -1) {
        return -1;
    }

    close(sockfd);
    errno = m->reterrno;
    return m->retcode;
}

int chmod(const char *path, mode_t mode)
{
    struct sfakeroot_msg m = {.type = SFAKEROOT_MSG_CHMOD, .mode = mode};
    debug("chmod %s %o\n", path, mode);
    strlcpy(m.path, path, sizeof (m.path));
    return sfakeroot__call(&m);
}

int chown(const char *path, uid_t uid, gid_t gid)
{
    struct sfakeroot_msg m = {.type = SFAKEROOT_MSG_CHOWN, .uid = uid, .gid = gid};
    strlcpy(m.path, path, sizeof (m.path));
    debug("chown: path: %s, uid: %d, gid: %d\n", path, (int) uid, (int) gid);
    return sfakeroot__call(&m);
}

int lchown(const char *path, uid_t uid, gid_t gid)
{
    struct sfakeroot_msg m = {.type = SFAKEROOT_MSG_LCHOWN, .uid = uid, .gid = gid};
    strlcpy(m.path, path, sizeof (m.path));
    debug("lchown: path: %s, uid: %d, gid: %d\n", path, (int) uid, (int) gid);
    return sfakeroot__call(&m);
}

int fchown(int fd, uid_t uid, gid_t gid)
{
    struct sfakeroot_msg m = {
        .type = SFAKEROOT_MSG_FCHOWN,
        .fd = fd,
        .uid = uid,
        .gid = gid
    };
    return sfakeroot__call(&m);
}

int fchownat(int fd, const char *path, uid_t uid, gid_t gid, int flag)
{
    struct sfakeroot_msg m = {
        .type = SFAKEROOT_MSG_FCHOWNAT,
        .fd = fd,
        .flag = flag,
        .uid = uid,
        .gid = gid
    };
    debug("fchownat %d %s %u %u %u\n", fd, path, uid, gid, flag);
    strlcpy(m.path, path, sizeof (m.path));
    return sfakeroot__call(&m);
}

static int sfakeroot__stat(struct sfakeroot_msg *m, struct stat *s)
{
    int ret;
    if ((ret = sfakeroot__call(m)) == -1) {
        return -1;
    }
    *s = m->st;
    return ret;
}

int stat(const char *path, struct stat *s)
{
    struct sfakeroot_msg m = {.type = SFAKEROOT_MSG_STAT};
    debug("stat\n");
    strlcpy(m.path, path, sizeof (m.path));
    return sfakeroot__stat(&m, s);
}

int __xstat(int ver, const char *path, struct stat *s)
{
    (void) ver;
    return stat(path, s);
}

int lstat(const char *path, struct stat *s)
{
    struct sfakeroot_msg m = {.type = SFAKEROOT_MSG_LSTAT};
    debug("lstat\n");
    strlcpy(m.path, path, sizeof (m.path));
    return sfakeroot__stat(&m, s);
}

int __lxstat(int ver, const char *path, struct stat *s)
{
    (void) ver;
    return lstat(path, s);
}

int fstat(int fd, struct stat *s)
{
    struct sfakeroot_msg m = {.type = SFAKEROOT_MSG_FSTAT, .fd = fd};
    return sfakeroot__stat(&m, s);
}

int __fxstat(int ver, int fd, struct stat *sb)
{
    (void) ver;
    return fstat(fd, sb);
}

int fstatat(int fd, const char *path, struct stat *s, int flag)
{
    struct sfakeroot_msg m = {
        .type = SFAKEROOT_MSG_FSTATAT,
        .fd = fd,
        .flag = flag,
    };
    strlcpy(m.path, path, sizeof (m.path));
    return sfakeroot__stat(&m, s);
}

#undef __xstat
#undef __fxstat
#undef __lxstat
#undef __xstat64
#undef __fxstat64
#undef __lxstat64
#undef _FILE_OFFSET_BITS

// TODO:
// int
// utimes(const char *path, const struct timeval *times);
//
// int
// futimes(int fd, const struct timeval *times);
