#include <vic.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/fs.h>

#include "strings.h"
#include "raise.h"
#include "malloc.h"

#define MAGIC 0xf3fcef718ce744bd

#define DEFAULT_BLOCK_SIZE 512

typedef struct _blockdev
{
    vic_blockdev_t base;
    uint64_t magic;
    char path[PATH_MAX];
    size_t full_size;
    size_t size;
    size_t offset;
    size_t block_size;
    uint32_t flags;
    int fd;
}
blockdev_t;

static bool _is_power_of_two(size_t x)
{
    for (size_t i = 0; i < sizeof(size_t) * 8; i++)
    {
        if (x == ((size_t)1 << i))
            return true;
    }

    return false;
}

static bool _valid_blockdev(const blockdev_t* bd)
{
    return bd && bd->magic == MAGIC;
}

/* Check that device size is a multiple of the block size */
static vic_result_t _check_block_multiple(blockdev_t* bd, size_t block_size)
{
    vic_result_t result = VIC_OK;

    if (bd->size % block_size)
        RAISE(VIC_NOT_BLOCK_MULTIPLE);

done:
    return result;
}

static vic_result_t _get_full_size(int fd, size_t* size_out)
{
    vic_result_t result = VIC_OK;
    struct stat st;
    size_t size;

    if (fstat(fd, &st) != 0)
        RAISE(VIC_STAT_FAILED);

    if (S_ISREG(st.st_mode))
        size = st.st_size;
    else if (ioctl(fd, BLKGETSIZE64, &size) != 0)
        RAISE(VIC_IOCTL_FAILED);

    *size_out = size;

done:

    return result;
}

static vic_result_t _bd_set_offset(vic_blockdev_t* bd_, size_t offset)
{
    vic_result_t result = VIC_OK;
    blockdev_t* bd = (blockdev_t*)bd_;

    if (!_valid_blockdev(bd))
        RAISE(VIC_BAD_PARAMETER);

    /* offset must be a multiple of the block size */
    if (offset % bd->block_size)
        RAISE(VIC_BAD_PARAMETER);

    /* Check that offset is within the file */
    if (offset > bd->size)
        RAISE(VIC_BAD_PARAMETER);

    bd->offset = offset;

done:
    return result;
}

static vic_result_t _bd_get_offset(vic_blockdev_t* bd_, size_t* offset)
{
    vic_result_t result = VIC_OK;
    blockdev_t* bd = (blockdev_t*)bd_;

    if (!_valid_blockdev(bd))
        RAISE(VIC_BAD_PARAMETER);

    *offset = bd->offset;

done:
    return result;
}

static vic_result_t _bd_set_size(vic_blockdev_t* bd_, size_t size)
{
    vic_result_t result = VIC_OK;
    blockdev_t* bd = (blockdev_t*)bd_;

    if (!_valid_blockdev(bd))
        RAISE(VIC_BAD_PARAMETER);

    /* size must be a multiple of the block size */
    if (size % bd->block_size)
        RAISE(VIC_BAD_PARAMETER);

    /* Check that size is within range */
    if (size > bd->full_size)
        RAISE(VIC_BAD_PARAMETER);

    bd->size = size;

done:
    return result;
}

static vic_result_t _bd_get_path(
    const vic_blockdev_t* bd_,
    char path[PATH_MAX])
{
    vic_result_t result = VIC_OK;
    const blockdev_t* bd = (const blockdev_t*)bd_;

    if (!_valid_blockdev(bd))
        RAISE(VIC_BAD_BLOCK_DEVICE);

    if (!path)
        RAISE(VIC_BAD_PARAMETER);

    vic_strlcpy(path, bd->path, PATH_MAX);

done:
    return result;
}

static vic_result_t _bd_get_block_size(
    const vic_blockdev_t* bd_,
    size_t* block_size)
{
    vic_result_t result = VIC_OK;
    const blockdev_t* bd = (const blockdev_t*)bd_;

    if (!_valid_blockdev(bd) || !block_size)
        RAISE(VIC_BAD_PARAMETER);

    *block_size = bd->block_size;

done:
    return result;
}

static vic_result_t _bd_get_size(const vic_blockdev_t* bd_, size_t* size)
{
    vic_result_t result = VIC_OK;
    const blockdev_t* bd = (const blockdev_t*)bd_;

    if (!_valid_blockdev(bd) || !size)
        RAISE(VIC_BAD_BLOCK_DEVICE);

    *size = bd->size - bd->offset;

done:
    return result;
}

static vic_result_t _bd_set_block_size(
    vic_blockdev_t* bd_,
    size_t block_size)
{
    vic_result_t result = VIC_OK;
    blockdev_t* bd = (blockdev_t*)bd_;

    if (!_valid_blockdev(bd))
        RAISE(VIC_BAD_PARAMETER);

    if (!block_size || !_is_power_of_two(block_size))
        RAISE(VIC_BAD_PARAMETER);

    CHECK(_check_block_multiple(bd, block_size));

    bd->block_size = block_size;

done:
    return result;
}

static vic_result_t _bd_get_num_blocks(
    const vic_blockdev_t* bd_,
    size_t* num_blocks)
{
    vic_result_t result = VIC_OK;
    const blockdev_t* bd = (const blockdev_t*)bd_;

    if (!_valid_blockdev(bd))
        RAISE(VIC_BAD_BLOCK_DEVICE);

    if (!num_blocks)
        RAISE(VIC_BAD_PARAMETER);

    *num_blocks = (bd->size - bd->offset) / bd->block_size;

done:

    return result;
}

static vic_result_t _bd_get(
    vic_blockdev_t* bd_,
    uint64_t blkno,
    void* blocks,
    size_t nblocks)
{
    vic_result_t result = VIC_OK;
    blockdev_t* bd = (blockdev_t*)bd_;
    off_t off;
    size_t size;

    if (!_valid_blockdev(bd))
        RAISE(VIC_BAD_BLOCK_DEVICE);

    if (!blocks)
        RAISE(VIC_BAD_PARAMETER);

    off = (blkno * bd->block_size) + bd->offset;;
    size = nblocks * bd->block_size;

    if (off + size > bd->size)
        RAISE(VIC_SEEK_FAILED);

    if (lseek(bd->fd, off, SEEK_SET) != off)
        RAISE(VIC_SEEK_FAILED);

    if (read(bd->fd, blocks, size) != (ssize_t)size)
        RAISE(VIC_READ_FAILED);

done:
    return result;
}

static vic_result_t _bd_put(
    vic_blockdev_t* bd_,
    uint64_t blkno,
    const void* blocks,
    size_t nblocks)
{
    vic_result_t result = VIC_OK;
    blockdev_t* bd = (blockdev_t*)bd_;
    off_t off;
    size_t size;

    if (!_valid_blockdev(bd))
        RAISE(VIC_BAD_BLOCK_DEVICE);

    if (!blocks)
        RAISE(VIC_BAD_PARAMETER);

    off = (blkno * bd->block_size) + bd->offset;;
    size = nblocks * bd->block_size;

    if (!(bd->flags & VIC_CREATE) && (off + size) > bd->size)
        RAISE(VIC_SEEK_FAILED);

    if (lseek(bd->fd, off, SEEK_SET) != off)
        RAISE(VIC_SEEK_FAILED);

    if (write(bd->fd, blocks, size) != (ssize_t)size)
        RAISE(VIC_READ_FAILED);

    if ((bd->flags & VIC_CREATE) && (off + size) > bd->size)
        bd->size = off + size;

done:
    return result;
}

static vic_result_t _bd_same(
    vic_blockdev_t* bd1_,
    vic_blockdev_t* bd2_,
    bool* same)
{
    vic_result_t result = VIC_OK;
    blockdev_t* bd1 = (blockdev_t*)bd1_;
    blockdev_t* bd2 = (blockdev_t*)bd2_;
    struct stat st1;
    struct stat st2;

    if (same)
        *same = false;

    if (!_valid_blockdev(bd1) || !_valid_blockdev(bd2) || !same)
        RAISE(VIC_BAD_PARAMETER);

    if (bd1->fd < 0 || bd1->fd < 0)
        RAISE(VIC_BAD_PARAMETER);

    if (fstat(bd1->fd, &st1) != 0 || fstat(bd2->fd, &st2) != 0)
        RAISE(VIC_STAT_FAILED);

    if (st1.st_ino == st2.st_ino)
        *same = true;

done:
    return result;
}

static vic_result_t _bd_close(vic_blockdev_t* bd_)
{
    vic_result_t result = VIC_OK;
    blockdev_t* bd = (blockdev_t*)bd_;

    if (!_valid_blockdev(bd))
        RAISE(VIC_BAD_BLOCK_DEVICE);

    close(bd->fd);
    memset(bd, 0, sizeof(blockdev_t));
    vic_free(bd);

done:
    return result;
}

vic_result_t vic_blockdev_open(
    const char* path,
    uint32_t flags,
    size_t block_size,
    vic_blockdev_t** dev_out)
{
    vic_result_t result = VIC_OK;
    blockdev_t* bd = NULL;
    int open_flags = 0;
    int mode = 0;

    /* Resolve the open() flags and mode */
    {
        if (flags & VIC_RDWR)
        {
            if ((flags & VIC_RDONLY) || ((flags & VIC_WRONLY)))
                RAISE(VIC_BAD_FLAGS);

            open_flags |= O_RDWR;
        }

        if (flags & VIC_RDONLY)
        {
            if ((flags & VIC_RDWR) || ((flags & VIC_WRONLY)))
                RAISE(VIC_BAD_FLAGS);

            open_flags |= O_RDONLY;
        }

        if (flags & VIC_WRONLY)
        {
            if ((flags & VIC_RDWR) || ((flags & VIC_RDONLY)))
                RAISE(VIC_BAD_FLAGS);

            open_flags |= O_WRONLY;
        }

        if (flags & VIC_CREATE)
        {
            open_flags |= O_CREAT;
            mode = 0600;
        }

        if (flags & VIC_TRUNC)
            open_flags |= O_TRUNC;
    }

    if (block_size == 0)
        block_size = DEFAULT_BLOCK_SIZE;

    if (!path || !_is_power_of_two(block_size) || !dev_out)
        RAISE(VIC_BAD_PARAMETER);

    if (!(bd = vic_calloc(1, sizeof(blockdev_t))))
        RAISE(VIC_OUT_OF_MEMORY);

    bd->magic = MAGIC;

    if (vic_strlcpy(bd->path, path, PATH_MAX) >= PATH_MAX)
        RAISE(VIC_UNEXPECTED);

    if ((bd->fd = open(path, open_flags, mode)) < 0)
        RAISE(VIC_OPEN_FAILED);

    CHECK(_get_full_size(bd->fd, &bd->full_size));
    bd->size = bd->full_size;
    bd->block_size = block_size;
    bd->flags = flags;

    bd->base.bd_set_size = _bd_set_size;
    bd->base.bd_set_offset = _bd_set_offset;
    bd->base.bd_get_offset = _bd_get_offset;
    bd->base.bd_get_path = _bd_get_path;
    bd->base.bd_get = _bd_get;
    bd->base.bd_put = _bd_put;
    bd->base.bd_get_size = _bd_get_size;
    bd->base.bd_get_num_blocks = _bd_get_num_blocks;
    bd->base.bd_get_block_size = _bd_get_block_size;
    bd->base.bd_set_block_size = _bd_set_block_size;
    bd->base.bd_same = _bd_same;
    bd->base.bd_close = _bd_close;

    CHECK(_check_block_multiple(bd, block_size));

    *dev_out = &bd->base;
    bd = NULL;

done:

    if (bd)
        vic_free(bd);

    return result;
}

vic_result_t vic_blockdev_get_path(
    const vic_blockdev_t* bd,
    char path[PATH_MAX])
{
    vic_result_t result = VIC_OK;

    if (!bd)
        RAISE(result);

    CHECK(bd->bd_get_path(bd, path));

done:
    return result;
}

vic_result_t vic_blockdev_get_block_size(
    const vic_blockdev_t* bd,
    size_t* block_size)
{
    vic_result_t result = VIC_OK;

    if (!bd)
        RAISE(result);

    CHECK(bd->bd_get_block_size(bd, block_size));

done:
    return result;
}

vic_result_t vic_blockdev_set_block_size(
    vic_blockdev_t* bd,
    size_t block_size)
{
    vic_result_t result = VIC_OK;

    if (!bd)
        RAISE(result);

    CHECK(bd->bd_set_block_size(bd, block_size));

done:
    return result;
}

vic_result_t vic_blockdev_get_size(
    const vic_blockdev_t* bd,
    size_t* size)
{
    vic_result_t result = VIC_OK;

    if (!bd)
        RAISE(result);

    CHECK(bd->bd_get_size(bd, size));

done:
    return result;
}

vic_result_t vic_blockdev_get_num_blocks(
    vic_blockdev_t* bd,
    size_t* num_blocks)
{
    vic_result_t result = VIC_OK;

    if (!bd)
        RAISE(result);

    CHECK(bd->bd_get_num_blocks(bd, num_blocks));

done:
    return result;
}

vic_result_t vic_blockdev_get(
    vic_blockdev_t* bd,
    uint64_t blkno,
    void* blocks,
    size_t nblocks)
{
    vic_result_t result = VIC_OK;

    if (!bd)
        RAISE(result);

    CHECK(bd->bd_get(bd, blkno, blocks, nblocks));

done:
    return result;
}

vic_result_t vic_blockdev_put(
    vic_blockdev_t* bd,
    uint64_t blkno,
    const void* blocks,
    size_t nblocks)
{
    vic_result_t result = VIC_OK;

    if (!bd)
        RAISE(result);

    CHECK(bd->bd_put(bd, blkno, blocks, nblocks));

done:
    return result;
}

vic_result_t vic_blockdev_close(vic_blockdev_t* bd)
{
    vic_result_t result = VIC_OK;

    if (!bd || !bd->bd_close)
        RAISE(VIC_BAD_PARAMETER);

    CHECK(bd->bd_close(bd));

done:
    return result;
}

vic_result_t vic_blockdev_same(
    vic_blockdev_t* bd1,
    vic_blockdev_t* bd2,
    bool* same)
{
    vic_result_t result = VIC_OK;

    if (!bd1 || !bd2 || !bd1->bd_same || !bd2->bd_same)
        RAISE(VIC_BAD_PARAMETER);

    CHECK(bd1->bd_same(bd1, bd2, same));

done:
    return result;
}

vic_result_t vic_blockdev_set_offset(vic_blockdev_t* bd, size_t offset)
{
    vic_result_t result = VIC_OK;

    if (!bd || !bd->bd_set_offset)
        RAISE(VIC_BAD_PARAMETER);

    CHECK(bd->bd_set_offset(bd, offset));

done:
    return result;
}

vic_result_t vic_blockdev_get_offset(vic_blockdev_t* bd, size_t* offset)
{
    vic_result_t result = VIC_OK;

    if (!bd || !bd->bd_get_offset)
        RAISE(VIC_BAD_PARAMETER);

    CHECK(bd->bd_get_offset(bd, offset));

done:
    return result;
}

vic_result_t vic_blockdev_set_size(vic_blockdev_t* bd, size_t size)
{
    vic_result_t result = VIC_OK;

    if (!bd || !bd->bd_set_size)
        RAISE(VIC_BAD_PARAMETER);

    CHECK(bd->bd_set_size(bd, size));

done:
    return result;
}

size_t vic_blockdev_get_size_from_path(const char* path)
{
    size_t ret = (size_t)-1;
    int fd = -1;
    size_t size;
    struct stat st;

    if (!path)
        goto done;

    if ((fd = open(path, O_RDONLY)) < 0)
        goto done;

    if (fstat(fd, &st) != 0)
        goto done;

    if (S_ISREG(st.st_mode))
    {
        size = st.st_size;
    }
    else
    {
        if (ioctl(fd, BLKGETSIZE64, &size) != 0)
            goto done;
    }

    ret = size;

done:

    if (fd >= 0)
        close(fd);

    return ret;
}
