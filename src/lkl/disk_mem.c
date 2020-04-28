#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "lkl/disk.h"
#include "syscall.h"

#include "shared/sgxlkl_config.h"

extern size_t num_disks;
extern struct enclave_disk_config* disks;

static struct enclave_disk_config* get_disk_config(int fd)
{
    for (int i = 0; i < num_disks; i++)
    {
        if (disks[i].fd == fd)
            return &disks[i];
    }
    return NULL;
}

static int fd_get_capacity(struct lkl_disk disk, unsigned long long* res)
{
    off_t off;

    struct enclave_disk_config* disk_config;
    if (disk_config = get_disk_config(disk.fd))
    {
        *res = disk_config->capacity;
        return 0;
    }
    return -1;
}

// Reads and write requests sent to the following functions are always sector-
// aligned (on 512 bytes). Unaligned requests are fixed by the virtio backend.

static int do_read(struct lkl_disk disk, struct lkl_blk_req* req)
{
    off_t off = req->sector * 512;
    struct enclave_disk_config* disk_config = get_disk_config(disk.fd);
    if (!disk_config)
    {
        errno = EINVAL;
        return -1;
    }
    for (int i = 0; i < req->count; i++)
    {
        char* addr = req->buf[i].iov_base;
        int len = req->buf[i].iov_len;
        memcpy(addr, &disk_config->mmap[off], len);
    }
    return 0;
}

static int do_write(struct lkl_disk disk, struct lkl_blk_req* req)
{
    off_t off = req->sector * 512;
    struct enclave_disk_config* disk_config = get_disk_config(disk.fd);
    if (!disk_config)
    {
        errno = EINVAL;
        return -1;
    }
    for (int i = 0; i < req->count; i++)
    {
        char* addr = req->buf[i].iov_base;
        int len = req->buf[i].iov_len;
        memcpy(&disk_config->mmap[off], addr, len);
    }
    return 0;
}

static int blk_request(struct lkl_disk disk, struct lkl_blk_req* req)
{
    int err = 0;
    struct enclave_disk_config* disk_config;
    switch (req->type)
    {
        case LKL_DEV_BLK_TYPE_READ:
            err = do_read(disk, req);
            break;
        case LKL_DEV_BLK_TYPE_WRITE:
            err = do_write(disk, req);
            break;
        case LKL_DEV_BLK_TYPE_FLUSH:
        case LKL_DEV_BLK_TYPE_FLUSH_OUT:
            disk_config = get_disk_config(disk.fd);
            if (disk_config)
            {
                void* addr = disk_config->mmap;
                size_t len = disk_config->capacity;
                err = syscall_SYS_msync(addr, len, MS_SYNC);
            }
            else
                err = -EINVAL;
            break;
        default:
            return LKL_DEV_BLK_STATUS_UNSUP;
    }

    if (err < 0)
        return LKL_DEV_BLK_STATUS_IOERR;
    return LKL_DEV_BLK_STATUS_OK;
}

struct lkl_dev_blk_ops sgxlkl_dev_blk_mem_ops = {
    .get_capacity = fd_get_capacity,
    .request = blk_request,
};
