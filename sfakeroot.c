/* sfakeroot: manipulate files faking root privileges
 *
 * Copyright © 2020 Richard Ipsum
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <signal.h>

#include "sfakeroot.h"

#include <sys/syscall.h>

#define FALLBACK_SHELL "/bin/sh"
#define SONAME "libsfakeroot.so"

#ifdef __linux__
#ifndef __x86_64__
#error "Architectures other than amd64 are not supported on Linux"
#endif
/*./x86_64-linux-gnu/asm/unistd_64.h:#define __NR_newfstatat 262 */
#define SYS_fstatat 262
#define SESSION_FILE_LINE_FMT "%lu,%u,%u,%u\n"
#else
#define SESSION_FILE_LINE_FMT "%llu,%u,%u,%u\n"
#endif

static char *argv0;

struct sfakeroot_list {
    struct sfakeroot_ent *first;
    struct sfakeroot_ent *last;
};

struct sfakeroot_list ents;

struct cmdline_options {
    bool require_session_file;
    char *session_file;
};

struct cmdline_arguments {
    struct cmdline_options options;
    char **args;
    size_t args_len;
};

static void xsend(int sockfd, struct sfakeroot_msg *m)
{
    if (sfakeroot_sendmsg(sockfd, m) == -1) {
        exit(1);
    }
}

static struct sfakeroot_ent *lookupent(struct sfakeroot_list *list, ino_t st_ino)
{
    for (struct sfakeroot_ent *e = list->first; e != NULL; e = e->next) {
        debug("checking st_ino %llu\n", e->st.st_ino);
        if (e->st.st_ino == st_ino) {
            return e;
        }
    }

    return NULL;
}

static struct sfakeroot_ent *addent(struct sfakeroot_list *list,
                                    const struct stat *s, bool stale)
{
    struct sfakeroot_ent *ent;

    ent = malloc(sizeof (*ent));
    if (ent == NULL) {
        return NULL;
    }

    debug("add ent: %llu\n", s->st_ino);

    ent->stale = stale;
    ent->next = NULL;
    ent->st = *s;

    if (list->first == NULL) {
        list->first = ent;
        goto out;
    }

    if (list->last != NULL) {
        list->last->next = ent;
    }

out:
    list->last = ent;
    return ent;
}

static int real_stat_internal(int fd, const char *path, struct stat *sb,
                              int flag, const char *working_dir, int *errno_out,
                              int sysno)
{
    int cwdfd, ret;
    DIR *cwd = opendir(".");

    if (cwd == NULL) {
        *errno_out = errno;
        return -1;
    }

    debug("chdir %s\n", working_dir);
    cwdfd = dirfd(cwd);
    if (chdir(working_dir) == -1) {
        *errno_out = errno;
        closedir(cwd);
        return -1;
    }

    debug("do syscall\n");
    switch (sysno) {
        case SYS_fstatat:
            ret = syscall(sysno, fd, path, sb, flag);
            break;
        case SYS_stat:
        case SYS_lstat:
            ret = syscall(sysno, path, sb);
            break;
        default:
            ret = -1;
            errno = EINVAL;
            break;
    }

    *errno_out = errno;
    fchdir(cwdfd);
    closedir(cwd);
    return ret;
}

static int real_stat(const char *path, struct stat *sb, bool islstat,
                     char *working_dir, int *errno_out)
{
    int sysno = islstat ? SYS_lstat : SYS_stat;
    return real_stat_internal(-1, path, sb, 0, working_dir, errno_out, sysno);
}

static int real_fstatat(int fd, const char *path, struct stat *sb, int flag,
                        const char *working_dir, int *errno_out)
{
    return real_stat_internal(fd, path, sb, flag, working_dir,
                              errno_out, SYS_fstatat);
}

static int real_fstat(int fd, struct stat *sb, int *errno_out)
{
    int ret = syscall(SYS_fstat, fd, sb);
    *errno_out = errno;
    return ret;
}

static void handle_stat(struct sfakeroot_msg *m)
{
    struct sfakeroot_ent *ent;
    int errno_sv = 0;

    debug("handle_fstat\n");

    switch (m->type) {
        case SFAKEROOT_MSG_FSTAT:
            m->retcode = real_fstat(m->fd, &m->st, &errno_sv);
            break;
        case SFAKEROOT_MSG_STAT:
        case SFAKEROOT_MSG_LSTAT:
            m->retcode = real_stat(m->path, &m->st,
                                   m->type == SFAKEROOT_MSG_LSTAT,
                                   m->working_dir, &errno_sv);
            break;
        case SFAKEROOT_MSG_FSTATAT:
            m->retcode = real_fstatat(m->fd, m->path, &m->st, m->flag,
                                      m->working_dir, &errno_sv);
            break;
        default:
            debug("non stat message in handle_stat\n");
            return;
    }

    if (m->retcode != 0) {
        m->reterrno = errno_sv;
        return;
    }

    if ((ent = lookupent(&ents, m->st.st_ino)) != NULL) {
        if (ent->stale) {
            /* update the entry with the new stat data */
            m->st.st_uid = ent->st.st_uid;
            m->st.st_gid = ent->st.st_gid;
            m->st.st_mode = ent->st.st_mode;
            ent->st = m->st;
            ent->stale = false;
        }
        else {
            m->st = ent->st;
        }
        if ((int) m->st.st_uid == -1) {
            m->st.st_uid = 0;
        }
        if ((int) m->st.st_gid == -1) {
            m->st.st_gid = 0;
        }
        return;
    }

    m->st.st_uid = 0;
    m->st.st_gid = 0;
}

static void handle_perms_change(struct sfakeroot_msg *m)
{
    struct stat s;
    int errno_sv;
    struct sfakeroot_ent *ent;

    debug("handle_perms_change: m->path: %s, m->working_dir: %s\n",
          m->path, m->working_dir);

    switch (m->type) {
        case SFAKEROOT_MSG_LCHOWN:
            m->retcode = real_stat(m->path, &s, true, m->working_dir, &errno_sv);
            break;
        case SFAKEROOT_MSG_CHOWN:
        case SFAKEROOT_MSG_CHMOD:
            m->retcode = real_stat(m->path, &s, false, m->working_dir, &errno_sv);
            break;
        case SFAKEROOT_MSG_FCHOWNAT:
            m->retcode = real_fstatat(m->fd, m->path, &s, m->flag,
                                      m->working_dir, &errno_sv);
            break;
        case SFAKEROOT_MSG_FCHOWN:
            m->retcode = real_fstat(m->fd, &s, &errno_sv);
            break;
        default:
            debug("non chown/chmod message in handle_perms_change\n");
            return;
    }

    if (m->retcode == -1) {
        debug("stat returned error\n");
        m->reterrno = errno_sv;
        return;
    }

    /* path exists */
    switch (m->type) {
        case SFAKEROOT_MSG_LCHOWN:
        case SFAKEROOT_MSG_CHOWN:
        case SFAKEROOT_MSG_FCHOWNAT:
            s.st_uid = m->uid;
            s.st_gid = m->gid;
            break;
        case SFAKEROOT_MSG_CHMOD:
            s.st_mode = (s.st_mode & S_IFMT) | m->mode;
            break;
        default:
            debug("non chown/chmod message in handle_perms_change\n");
            return;
    }

    if ((ent = lookupent(&ents, s.st_ino)) != NULL) {
        uid_t u = ent->st.st_uid;
        gid_t g = ent->st.st_gid;
        ent->st = s;
        ent->st.st_uid = ((int) m->uid == -1) ? u : m->uid;
        ent->st.st_gid = ((int) m->gid == -1) ? g : m->gid;
        m->retcode = 0;
        return;
    }

    s.st_uid = m->uid;
    s.st_gid = m->gid;

    if (addent(&ents, &s, false) == NULL) {
        m->reterrno = ENOMEM;
        m->retcode = -1;
        return;
    }

    m->retcode = 0;
}

/* listen for new connections */
static int sfakeroot_create_listener(const char *session_socket_path)
{
    static struct sockaddr_un sa = {.sun_family = AF_UNIX};
    socklen_t sock_namelen;
    int sock;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        fprintf(stderr, "%s: socket: %s\n", argv0, strerror(errno));
        exit(1);
    }

    strlcpy(sa.sun_path, session_socket_path, sizeof (sa.sun_path));
    if (unlink(session_socket_path) == -1 && errno != ENOENT) {
        fprintf(stderr, "%s: unlink \"%s\" failed: %s\n",
                argv0, sa.sun_path, strerror(errno));
        exit(1);
    }

    sock_namelen = strlen(sa.sun_path) + 1 + sizeof (sa.sun_family);
    if (bind(sock, (struct sockaddr *) &sa, sock_namelen) == -1) {
        fprintf(stderr, "%s: bind: %s\n", argv0, strerror(errno));
        exit(1);
    }

    if (listen(sock, 21) == -1) {
        fprintf(stderr, "%s: listen: %s\n", argv0, strerror(errno));
        exit(1);
    }

    return sock;
}

static int write_session_to_file(const char *save_path)
{
    FILE *f = fopen(save_path, "w");

    debug("write session to `%s'\n", save_path);

    if (f == NULL) {
        goto error;
    }

    for (struct sfakeroot_ent *p = ents.first; p != NULL; p = p->next) {
        struct stat *s = &p->st;
        if (fprintf(f, SESSION_FILE_LINE_FMT, s->st_ino, s->st_uid, s->st_gid, s->st_mode) < 0) {
            goto error;
        }
        debug(SESSION_FILE_LINE_FMT, s->st_ino, s->st_uid, s->st_gid, s->st_mode);
    }

    if (fclose(f) != 0) {
        goto error;
    }

    return 0;

error:
    fprintf(stderr, "%s: error saving session to `%s': %s\n",
            argv0, save_path, strerror(errno));
    return -1;
}

static int sfakeroot_finish_session(const struct cmdline_arguments *args)
{
    if (args->options.session_file != NULL) {
        if (write_session_to_file(args->options.session_file) == -1) {
            return -1;
        }
    }

    return 0;
}

int estrtol(const char *s, long *out)
{
    char *e;

    long n = strtol(s, &e, 10);

    if (*s == '\0' || *e != '\0') {
        fprintf(stderr, "%s: estrtol: `%s' not a number\n", argv0, s);
        return -1;
    }

    if ((errno == ERANGE && (n == LONG_MIN || n == LONG_MAX))) {
        fprintf(stderr, "%s: estrtol: `%s' out of range\n", argv0, s);
        return -1;
    }

    *out = n;
    return 0;
}

static int sfakeroot_load_session_from_file(const struct cmdline_arguments *args)
{
    char *line = NULL, *session_filepath;
    size_t n = 0;
    ssize_t count;
    FILE *f;

    session_filepath = args->options.session_file;
    f = fopen(session_filepath, "r");
    if (f == NULL) {
        char *errfmt = "%s: couldn't open session file `%s': %s\n";
        debug(errfmt, argv0, session_filepath, strerror(errno));
        if (args->options.require_session_file) {
            fprintf(stderr, errfmt, argv0, session_filepath, strerror(errno));
            return -1;
        }
        return 0;
    }

    debug("loading session from `%s'\n", session_filepath);

    while ((count = getline(&line, &n, f)) != -1) {
        struct stat s = {0};
        long values[4];
        int i = 0;
        line[count - 1] = '\0'; /* strip '\n' */
        for (char *s = strtok(line, ","); s != NULL && i < 4; s = strtok(NULL, ","), i++) {
            if (estrtol(s, values + i) == -1) {
                free(line);
                return -1;
            }
        }
        s.st_ino = (ino_t) values[0];
        s.st_uid = (uid_t) values[1];
        s.st_gid = (gid_t) values[2];
        s.st_mode = (mode_t) values[3];
        addent(&ents, &s, true);
    }

    if (ferror(f)) {
        fprintf(stderr, "%s: error reading from `%s': %s\n",
                argv0, session_filepath, strerror(errno));
        free(line);
        return -1;
    }

    free(line);
    return 0;
}

static void sfakeroot_server(int pipewfd, const char *session_socket_path,
                             const struct cmdline_arguments *args)
{
    static struct sockaddr_un sa;
    int listen_sock, sock;
    socklen_t namelen;

    if (args->options.session_file != NULL) {
        if (sfakeroot_load_session_from_file(args) == -1) {
            exit(1);
        }
    }

    listen_sock = sfakeroot_create_listener(session_socket_path);

    /* close write end of pipe to indicate to parent process that we
     * are now ready to accept incoming connections
     */
    close(pipewfd);

    for (;;) {
        struct sfakeroot_msg m;

        sock = accept(listen_sock, (struct sockaddr *) &sa, &namelen);
        if (sock == -1) {
            fprintf(stderr, "%s: accept: %s\n", argv0, strerror(errno));
            exit(1);
        }
        if (sfakeroot_recvmsg(sock, &m) == -1) {
            fprintf(stderr, "eof?\n");
            continue;
        }

        switch (m.type) {
            case SFAKEROOT_MSG_FSTAT:
            case SFAKEROOT_MSG_LSTAT:
            case SFAKEROOT_MSG_STAT:
            case SFAKEROOT_MSG_FSTATAT:
                handle_stat(&m);
                break;
            case SFAKEROOT_MSG_CHOWN:
            case SFAKEROOT_MSG_LCHOWN:
            case SFAKEROOT_MSG_CHMOD:
            // TODO: fchmod
            // TODO: fchmodat
            case SFAKEROOT_MSG_FCHOWN:
            case SFAKEROOT_MSG_FCHOWNAT:
                handle_perms_change(&m);
                break;
            case SFAKEROOT_MSG_FINISH:
                if (sfakeroot_finish_session(args) == -1) {
                    exit(1);
                }
                exit(0);
        }
        xsend(sock, &m);
        close(sock);
    }
}

static int sfakeroot_daemon(const char *session_socket_path,
                            const struct cmdline_arguments *args)
{
    int pipefds[2];
    char buf[1];
    pid_t pid;
    int status;

    if (pipe(pipefds) == -1) {
        fprintf(stderr, "%s: pipe: %s\n", argv0, strerror(errno));
        return -1;
    }

    switch ((pid = fork())) {
        case 0:
            /* child */
            close(pipefds[0]); /* close read end */
            if (daemon(1, 1) == -1) {
                fprintf(stderr, "%s: failed to daemonise: %s\n",
                        argv0, strerror(errno));
                exit(1);
            }
            sfakeroot_server(pipefds[1], session_socket_path, args);
            break;
        case -1:
            fprintf(stderr, "%s: fork: %s\n", argv0, strerror(errno));
            return -1;
        default:
            /* parent */
            close(pipefds[1]); /* close write end */
            /* This read will block until the child process signals it
             * is ready, i.e. it's ready to accept connections from us.
             */
            if (read(pipefds[0], buf, sizeof (buf)) == -1) {
                fprintf(stderr, "%s: error reading from pipe: %s\n",
                        argv0, strerror(errno));
                return -1;
            }
            if (waitpid(pid, &status, 0) == -1) {
                fprintf(stderr, "%s: waitpid: %s\n", argv0, strerror(errno));
                return -1;
            }
            if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
                fprintf(stderr, "%s: sfakeroot daemon unexpected condition\n",
                        argv0);
                return -1;
            }
    }

    return 0;
}

int sfakeroot_session_open(void);

static int setenvvars(const char *session_socket_path)
{
    char *wd = SFAKEROOT_LIBDIR, *path = NULL;
    size_t len;

    len = snprintf(NULL, 0, "%s/%s", wd, SONAME);
    path = malloc(len + 1);
    if (path == NULL) {
        goto error;
    }
    snprintf(path, len + 1, "%s/%s", wd, SONAME);

    if (setenv("LD_PRELOAD", path, 1) == -1) {
        goto error;
    }
    free(path);

    if (setenv("SFAKEROOT_SOCKET_PATH", session_socket_path, 1) == -1) {
        goto error;
    }

    return 0;

error:
    fprintf(stderr, "%s: setenv: %s\n", argv0, strerror(errno));
    return -1;
}

static void usage(void)
{
    fprintf(stderr, "usage: %s [-Ff file]\n", argv0);
}

static void parse_options(int argc, char *argv[], struct cmdline_arguments *args)
{
    int ch;
    extern int optind;
    extern char *optarg;

    while ((ch = getopt(argc, argv, "F:f:")) != -1) {
        switch (ch) {
            case 'F':
                args->options.require_session_file = true;
                /* fallthrough */
            case 'f':
                args->options.session_file = optarg;
                break;
            default:
                usage();
                exit(1);
        }
    }

    args->args = argv + optind;
    args->args_len = argc - optind;
}

int main(int argc, char *argv[])
{
    int sockfd, status, exit_status, len;
    pid_t pid;
    struct sfakeroot_msg m;
    char *sargv[] = {FALLBACK_SHELL, NULL}, *shell, **exec_argvp;
    char tempdir_path[8192] = "/tmp/sfakeroot.XXXXXXXXXX";
    char session_socket_path[8192];
    static struct cmdline_arguments args;

    argv0 = argv[0];
    parse_options(argc, argv, &args);

    if ((shell = getenv("SHELL")) != NULL) {
        sargv[0] = shell;
    }

    if (mkdtemp(tempdir_path) == NULL) {
        fprintf(stderr, "%s: mkdtemp: %s\n", argv0, strerror(errno));
        exit_status = 1;
        goto cleanup;
    }

    len = snprintf(session_socket_path, sizeof (session_socket_path), "%s/%s",
                   tempdir_path, "uds.sock");
    if (len == -1) {
        fprintf(stderr, "%s: snprintf\n", argv0);
        exit_status = 1;
        goto cleanup;
    }
    else if ((size_t) len > sizeof (session_socket_path)) {
        fprintf(stderr, "%s: path too long\n", argv0);
        exit_status = 1;
        goto cleanup;
    }

    if (setenvvars(session_socket_path) == -1) {
        exit_status = 1;
        goto cleanup;
    }

    if (!sfakeroot_daemon_running()) {
        if (sfakeroot_daemon(session_socket_path, &args) == -1) {
            exit_status = 1;
            goto cleanup;
        }
    }

    exec_argvp = args.args_len > 0 ? args.args : sargv;
    switch (pid = fork()) {
        case 0:
            execvp(exec_argvp[0], exec_argvp);
            fprintf(stderr, "%s: exec `%s': %s\n",
                    argv0, exec_argvp[0], strerror(errno));
            switch (errno) {
                case EACCES:
                    exit_status = 126;
                    goto cleanup;
                case ENOENT:
                    exit_status = 127;
                    goto cleanup;
                default:
                    exit_status = 1;
                    goto cleanup;
            }
        case -1:
            fprintf(stderr, "%s: fork: %s\n", argv0, strerror(errno));
            exit_status = 1;
            goto cleanup;
        default:
            waitpid(pid, &status, 0);
            debug("instructing daemon to finish...\n");
            m.type = SFAKEROOT_MSG_FINISH;
            sockfd = sfakeroot_session_open();
            if (sockfd == -1) {
                fprintf(stderr, "%s: failed to open session\n", argv0);
                exit_status = 1;
                goto cleanup;
            }
            if (sfakeroot_sendmsg(sockfd, &m) == -1) {
                exit_status = 1;
                goto cleanup;
            }
            close(sockfd);
            if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
                exit_status = WEXITSTATUS(status);
                goto cleanup;
            }
            if (WIFSIGNALED(status)) {
                exit_status = 127 + WTERMSIG(status);
                goto cleanup;
            }
            else if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
                exit_status = 1;
                goto cleanup;
            }
            break;
    }

    exit_status = 0;

cleanup:
    unlink(session_socket_path);
    rmdir(tempdir_path);
    return exit_status;
}
