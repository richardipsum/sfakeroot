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

#pragma once

#include <stdarg.h>
#include <sys/stat.h>

#define SOCK_PATH ".sfakeroot_socket"
#define MAX_PATHLEN 8192

static void debug(const char *fmt, ...)
{
#ifdef DEBUG
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
#else
    (void) fmt;
#endif
}

struct sfakeroot_ent {
    struct stat st;
    struct sfakeroot_ent *next;
    bool stale;
};

enum sfakeroot_msg_type {
    SFAKEROOT_MSG_STAT,
    SFAKEROOT_MSG_LSTAT,
    SFAKEROOT_MSG_FSTAT,
    SFAKEROOT_MSG_FSTATAT,
    SFAKEROOT_MSG_CHOWN,
    SFAKEROOT_MSG_LCHOWN,
    SFAKEROOT_MSG_FCHOWN,
    SFAKEROOT_MSG_FCHOWNAT,
    SFAKEROOT_MSG_CHMOD,
    SFAKEROOT_MSG_FINISH
};

struct sfakeroot_msg {
    /* message type */
    enum sfakeroot_msg_type type;

    /* current working directory of client process */
    char working_dir[MAX_PATHLEN];

    /* system call parameters */
    char path[MAX_PATHLEN];
    int fd;
    int flag;
    struct stat st;
    uid_t uid;
    gid_t gid;
    mode_t mode;

    /* system call return data */
    int retcode;
    int reterrno;
};

int sfakeroot_recvmsg(int fd, struct sfakeroot_msg *m);
int sfakeroot_sendmsg(int fd, struct sfakeroot_msg *m);

int sfakeroot_stat(const char *path, struct stat *s, bool lstat);
bool sfakeroot_daemon_running(void);

size_t strlcpy(char *, const char *, size_t);
