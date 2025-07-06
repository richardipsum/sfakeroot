#include <sys/socket.h>
#include <sys/un.h>

#include "sfakeroot.h"

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

int sfakeroot_recvmsg(int fd, struct sfakeroot_msg *m)
{
    union {
        char buf[CMSG_SPACE(253)]; // 253 SCM_MAX_FD
        struct cmsghdr align;
    } u;
    struct iovec io = {
        .iov_base = m,
        .iov_len = sizeof (*m)
    };
    struct msghdr msg = {
        .msg_iov = &io,
        .msg_iovlen = 1,
        .msg_control = u.buf,
        .msg_controllen = sizeof (u.buf)
    };
    if (recvmsg(fd, &msg, 0) == -1) {
        fprintf(stderr, "sfakeroot_recvmsg: error reading message\n");
        return -1;
    }
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_type == SCM_RIGHTS) {
        debug("got an fd!!!\n");
        memcpy(&m->fd, CMSG_DATA(cmsg), sizeof (int));
    }

    return 0;
}

int sfakeroot_sendmsg(int fd, struct sfakeroot_msg *m, int send_fds[], int send_fds_len)
{
    union {
        char *buf;
        struct cmsghdr align;
    } u;
    int ret = -1;
    struct iovec io = {
        .iov_base = m,
        .iov_len = sizeof (*m)
    };
    struct msghdr msg = {
        .msg_iov = &io,
        .msg_iovlen = 1,
    };
    if (send_fds_len > 0) {
        size_t buflen = CMSG_SPACE(send_fds_len * sizeof(int));
        u.buf = malloc(buflen);
        if (u.buf == NULL) {
            fprintf(stderr, "sfakeroot_sendmsg: out of memory: %s\n", strerror(errno));
            goto cleanup;
        }
        msg.msg_control = u.buf;
        msg.msg_controllen = buflen;
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(send_fds_len * sizeof (int));
        memcpy(CMSG_DATA(cmsg), send_fds, send_fds_len * sizeof (int));
    }
    if (sendmsg(fd, &msg, 0) == -1) {
        fprintf(stderr, "sfakeroot_sendmsg: error writing message: %s\n", strerror(errno));
        goto cleanup;
    }
    ret = 0;
cleanup:
    if (send_fds_len > 0) {
        free(u.buf);
    }
    return ret;
}
