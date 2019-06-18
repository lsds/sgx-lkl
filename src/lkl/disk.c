/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */
#include "lkl/disk.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "syscall.h"

#include "sgx_enclave_config.h"

extern size_t num_disks;
extern struct enclave_disk_config *disks;

static struct enclave_disk_config *get_disk_config(int fd) {
    for (int i = 0; i < num_disks; i++) {
        if (disks[i].fd == fd)
            return &disks[i];
    }
    return NULL;
}

static int fd_get_capacity(struct lkl_disk disk, unsigned long long *res) {
    off_t off;

    struct enclave_disk_config *disk_config;
    if (disk_config = get_disk_config(disk.fd)) {
        *res = disk_config->capacity;
        return 0;
    }
    return -1;
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

static int blk_request(struct lkl_disk disk, struct lkl_blk_req *req) {
    int err = 0;
    switch (req->type) {
    case LKL_DEV_BLK_TYPE_READ:
        err = do_plain_rw(&host_syscall_SYS_pread64, disk, req);
        break;
    case LKL_DEV_BLK_TYPE_WRITE:
        err = do_plain_rw(&host_syscall_SYS_pwrite64, disk, req);
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

struct lkl_dev_blk_ops sgxlkl_dev_blk_ops = {
    .get_capacity = fd_get_capacity,
    .request = blk_request,
};

