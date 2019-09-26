/*
 * POSIX file descriptor based virtual network interface feature for
 * LKL Copyright (c) 2015,2016 Ryo Nakamura, Hajime Tazaki
 * 
 * Copyright 2016, 2017, 2018 Imperial College London
 *
 * Author: Ryo Nakamura <upa@wide.ad.jp>
 *         Hajime Tazaki <thehajime@gmail.com>
 *         Octavian Purdila <octavian.purdila@intel.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/uio.h>

#include "lkl/virtio.h"
#include "lkl/virtio_net.h"

#include "sgx_hostcalls.h"
#include "sgxlkl_util.h"
#include "lthread.h"

struct lkl_netdev_fd {
    struct lkl_netdev dev;
    /* file-descriptor based device */
    int fd;
    /*
     * Controlls the poll mask for fd. Can be acccessed concurrently from
     * poll, tx, or rx routines but there is no need for syncronization
     * because:
     *
     * (a) TX and RX routines set different variables so even if they update
     * at the same time there is no race condition
     *
     * (b) Even if poll and TX / RX update at the same time poll cannot
     * stall: when poll resets the poll variable we know that TX / RX will
     * run which means that eventually the poll variable will be set.
     */
    int poll_tx, poll_rx;
    /* controle pipe */
    int pipe[2];
    /* SGX-LKL: Set to 1 to busy wait for I/O request to finish rather than
     * yield.
     */
    int wait_on_io;
};

static int sgxlkl_fd_net_tx(struct lkl_netdev *nd, struct iovec *iov, int cnt) {
    int ret;
    struct lkl_netdev_fd *nd_fd =
        container_of(nd, struct lkl_netdev_fd, dev);

    struct lthread *lt = lthread_self();
    // Remember old state of lthread
    int lt_old_state = lt->attr.state;
    // Pin lthread
    if (nd_fd->wait_on_io)
        lt->attr.state = lt->attr.state | BIT(LT_ST_PINNED);
    do {
        ret = host_syscall_SYS_writev(nd_fd->fd, iov, cnt);
    } while (ret == -EINTR);
    // Restore lthread state
    lt->attr.state = lt_old_state;

    if (ret < 0) {
        if (ret != -EAGAIN) {
            fprintf(stderr, "[    SGX-LKL   ] Write to virtio net fd failed: %s", strerror(-ret));
        } else {
            char tmp;

            nd_fd->poll_tx = 1;
            // Remember old state of lthread
            int lt_old_state = lt->attr.state;
            // Pin lthread
            if (nd_fd->wait_on_io)
                lt->attr.state = lt->attr.state | BIT(LT_ST_PINNED);
            int pipe_ret = host_syscall_SYS_write(nd_fd->pipe[1], &tmp, 1);
            // Restore lthread state
            lt->attr.state = lt_old_state;
            if (pipe_ret <= 0)
                fprintf(stderr, "[    SGX-LKL   ] Write to virtio net fd pipe failed: %s", strerror(-pipe_ret));
        }
    }
    return ret;
}

static int sgxlkl_fd_net_rx(struct lkl_netdev *nd, struct iovec *iov, int cnt) {
    int ret;
    struct lkl_netdev_fd *nd_fd =
        container_of(nd, struct lkl_netdev_fd, dev);

    struct lthread *lt = lthread_self();
    // Remember old state of lthread
    int lt_old_state = lt->attr.state;
    // Pin lthread
    if (nd_fd->wait_on_io)
        lt->attr.state = lt->attr.state | BIT(LT_ST_PINNED);
    do {
        ret = host_syscall_SYS_readv(nd_fd->fd, iov, cnt);
    } while (ret == -EINTR);
    // Restore lthread state
    lt->attr.state = lt_old_state;

    if (ret < 0) {
        if (ret != -EAGAIN) {
            fprintf(stderr, "[    SGX-LKL   ] Read from virtio net fd failed: %s", strerror(-ret));
        } else {
            char tmp;

            nd_fd->poll_rx = 1;
            // Remember old state of lthread
            int lt_old_state = lt->attr.state;
            // Pin lthread
            if (nd_fd->wait_on_io)
                lt->attr.state = lt->attr.state | BIT(LT_ST_PINNED);
            int pipe_ret = host_syscall_SYS_write(nd_fd->pipe[1], &tmp, 1);
            // Restore lthread state
            lt->attr.state = lt_old_state;
            if (pipe_ret < 0)
                fprintf(stderr, "[    SGX-LKL   ] Write to virtio net fd pipe failed: %s", strerror(-pipe_ret));
        }
    }
    return ret;
}

static int sgxlkl_fd_net_poll(struct lkl_netdev *nd) {
    struct lkl_netdev_fd *nd_fd =
        container_of(nd, struct lkl_netdev_fd, dev);
    struct pollfd pfds[2] = {
        {
            .fd = nd_fd->fd,
        },
        {
            .fd = nd_fd->pipe[0],
            .events = POLLIN,
        },
    };
    int ret;

    if (nd_fd->poll_rx)
        pfds[0].events |= POLLIN|POLLPRI;
    if (nd_fd->poll_tx)
        pfds[0].events |= POLLOUT;

    do {
        ret = host_syscall_SYS_poll(pfds, 2, -1);
    } while (ret == -EINTR);

    if (ret < 0) {
        fprintf(stderr, "[    SGX-LKL   ] Poll from virtio net fd failed: %s", strerror(-ret));
        return 0;
    }

    if (pfds[1].revents & (POLLHUP|POLLNVAL))
        return LKL_DEV_NET_POLL_HUP;

    if (pfds[1].revents & POLLIN) {
        char tmp[PIPE_BUF];

        struct lthread *lt = lthread_self();
        // Remember old state of lthread
        int lt_old_state = lt->attr.state;
        // Pin lthread
        if (nd_fd->wait_on_io)
            lt->attr.state = lt->attr.state | BIT(LT_ST_PINNED);
        ret = host_syscall_SYS_read(nd_fd->pipe[0], tmp, PIPE_BUF);
        // Restore lthread state
        lt->attr.state = lt_old_state;
        if (ret == 0)
            return LKL_DEV_NET_POLL_HUP;
        if (ret < 0)
            fprintf(stderr, "[    SGX-LKL   ] Read from virtio net fd failed: %s", strerror(-ret));
    }

    ret = 0;

    if (pfds[0].revents & (POLLIN|POLLPRI)) {
        nd_fd->poll_rx = 0;
        ret |= LKL_DEV_NET_POLL_RX;
    }

    if (pfds[0].revents & POLLOUT) {
        nd_fd->poll_tx = 0;
        ret |= LKL_DEV_NET_POLL_TX;
    }

    return ret;
}

static void sgxlkl_fd_net_poll_hup(struct lkl_netdev *nd) {
    struct lkl_netdev_fd *nd_fd =
        container_of(nd, struct lkl_netdev_fd, dev);

    /* this will cause a POLLHUP / POLLNVAL in the poll function */
    host_syscall_SYS_close(nd_fd->pipe[0]);
    host_syscall_SYS_close(nd_fd->pipe[1]);
}

static void sgxlkl_fd_net_free(struct lkl_netdev *nd) {
    struct lkl_netdev_fd *nd_fd =
        container_of(nd, struct lkl_netdev_fd, dev);

    host_syscall_SYS_close(nd_fd->fd);
    free(nd_fd);
}

struct lkl_dev_net_ops sgxlkl_fd_net_ops = {
    .tx = sgxlkl_fd_net_tx,
    .rx = sgxlkl_fd_net_rx,
    .poll = sgxlkl_fd_net_poll,
    .poll_hup = sgxlkl_fd_net_poll_hup,
    .free = sgxlkl_fd_net_free,
};

struct lkl_netdev* sgxlkl_register_netdev_fd(int fd, int wait_on_io) {
    struct lkl_netdev_fd *nd;

    nd = malloc(sizeof(*nd));
    if (!nd) {
        fprintf(stderr, "[    SGX-LKL   ] Failed to allocate memory for LKL netdev struct: %s\n", strerror(errno));
        return NULL;
    }

    memset(nd, 0, sizeof(*nd));

    nd->fd = fd;
    nd->wait_on_io = wait_on_io;
    int ret = host_syscall_SYS_pipe(nd->pipe);
    if (ret < 0) {
        fprintf(stderr, "[    SGX-LKL   ] virtio net pipe call failed: %s", strerror(-ret));
        free(nd);
        return NULL;
    }

    ret = host_syscall_SYS_fcntl(nd->pipe[0], F_SETFL, O_NONBLOCK);
    if (ret < 0) {
        fprintf(stderr, "[    SGX-LKL   ] virtio net fnctl call failed: %s", strerror(-ret));
        host_syscall_SYS_close(nd->pipe[0]);
        host_syscall_SYS_close(nd->pipe[1]);
        free(nd);
        return NULL;
    }

    nd->dev.ops = &sgxlkl_fd_net_ops;
    return &nd->dev;
}
