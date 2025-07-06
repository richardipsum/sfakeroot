/* sfakeroot
 *
 * Copyright © 2020 - 2025 Richard Ipsum
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
#include "sfakeroot_inline.h"

static int sfakeroot__call(struct sfakeroot_msg *m)
{
    int sockfd;
    int sendfds[1];
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
    if (m->fd >= 0) {
        sendfds[0] = m->fd;
    }
    if (sfakeroot_sendmsg(sockfd, m, m->fd >= 0 ? sendfds : NULL, m->fd >= 0 ? 1 : 0) == -1) {
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
    struct sfakeroot_msg m = {.type = SFAKEROOT_MSG_CHMOD, .mode = mode, .fd = -1};
    debug("chmod %s %o\n", path, mode);
    strlcpy(m.path, path, sizeof (m.path));
    return sfakeroot__call(&m);
}

int chown(const char *path, uid_t uid, gid_t gid)
{
    struct sfakeroot_msg m = {.type = SFAKEROOT_MSG_CHOWN, .uid = uid, .gid = gid, .fd = -1};
    strlcpy(m.path, path, sizeof (m.path));
    debug("chown: path: %s, uid: %d, gid: %d\n", path, (int) uid, (int) gid);
    return sfakeroot__call(&m);
}

int lchown(const char *path, uid_t uid, gid_t gid)
{
    struct sfakeroot_msg m = {.type = SFAKEROOT_MSG_LCHOWN, .uid = uid, .gid = gid, .fd = -1};
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
    struct sfakeroot_msg m = {.type = SFAKEROOT_MSG_STAT, .fd = -1};
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
    struct sfakeroot_msg m = {.type = SFAKEROOT_MSG_LSTAT, .fd = -1};
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

#if USE_STATX
int statx(int dirfd, const char *path, int flags, unsigned int mask,
          struct statx *statxbuf)
{
    struct sfakeroot_msg m = {
        .type = SFAKEROOT_MSG_STATX,
        .fd = dirfd,
        .flag = flags,
        .mask = mask
    };
    int ret;
    strlcpy(m.path, path, sizeof (m.path));
    if ((ret = sfakeroot__call(&m)) == -1) {
        return -1;
    }
    *statxbuf = m.statxbuf;
    return ret;
}
#endif

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
