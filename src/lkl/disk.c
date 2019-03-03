/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */
#include "lkl/disk.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "syscall.h"

static int fd_get_capacity(struct lkl_disk disk, unsigned long long *res) {
    off_t off;

    off = host_syscall_SYS_lseek(disk.fd, 0, SEEK_END);
    if (off < 0)
        return -1;

    *res = off;
    return 0;
}

// Reads and write requests sent to the following functions are always sector-
// aligned (on 512 bytes). Unaligned requests are fixed by the virtio backend.

static int do_plain_rw(ssize_t (*fn)(), struct lkl_disk disk, struct lkl_blk_req *req) {
    off_t off = req->sector * 512;
    char *addr;
    int len;
    int i;
    int ret = 0;
    for (i = 0; i < req->count; i++) {
        addr = req->buf[i].iov_base;
        len = req->buf[i].iov_len;
        do {
            ret = fn(disk.fd, addr, len, off);
            if (ret <= 0)
                return ret;
            addr += ret;
            len -= ret;
            off += ret;
        } while (len > 0);
    }
    return ret;
}

static int blk_plaintext_request(struct lkl_disk disk, struct lkl_blk_req *req) {
    int err = 0;
    switch (req->type) {
    case LKL_DEV_BLK_TYPE_READ:
        err = do_plain_rw(&host_syscall_SYS_pread64, disk, req);
        // Uncomment the following and comment the previous line if
        // you need scatter-gather I/O functions.
        /*err = host_syscall_SYS_preadv(disk.fd, (struct iovec*)(req->buf), req->count,
            (long)(req->sector*512), // offset low 32 bits
            (long)((req->sector*512)>>32) // offset high 32 bits
        );*/
        break;
    case LKL_DEV_BLK_TYPE_WRITE:
        err = do_plain_rw(&host_syscall_SYS_pwrite64, disk, req);
        /*err = host_syscall_SYS_pwritev(disk.fd, (struct iovec*)(req->buf), req->count,
            (long)(req->sector*512),
            (long)((req->sector*512)>>32)
        );*/
        break;
    case LKL_DEV_BLK_TYPE_FLUSH:
    case LKL_DEV_BLK_TYPE_FLUSH_OUT:
        err = host_syscall_SYS_fdatasync(disk.fd);
        break;
    default:
        return LKL_DEV_BLK_STATUS_UNSUP;
    }

    if (err < 0)
        return LKL_DEV_BLK_STATUS_IOERR;
    return LKL_DEV_BLK_STATUS_OK;
}

struct lkl_dev_blk_ops sgxlkl_dev_plaintext_blk_ops = {
    .get_capacity = fd_get_capacity,
    .request = blk_plaintext_request,
};

