#include <stdio.h>
#include <string.h>
#include <sys/types.h>

// errcode_t is part of the com_err library, but we use -DOMIT_COM_ERR to avoid
// the dependency. The ext2fs.h header file should define errcode_t if
// OMIT_COM_ERR is defined.
typedef long errcode_t;
#include <ext2fs/ext2fs.h>

#include "enclave/enclave_util.h"
#include "lkl/ext4_create.h"

#define HANDLE_ERR(fn_name)                       \
    if (retval)                                   \
    {                                             \
        sgxlkl_fail(#fn_name "()=%ld\n", retval); \
    }

// Bytes-per-inode ratio. 16 KB is the default used by mke2fs (see
// /etc/mke2fs.conf).
#define INODE_RATIO 16384

// Creates parameters for an ext4 filesystem that does not use any advanced
// features like a journal or directory indexes. Only one superblock is used
// without backups. This allows to store all filesystem metadata at the
// beginning of the image with the rest being all zeros (which comes in handy
// for sparse images).
static struct ext2_super_block create_params(int block_size, int num_blocks)
{
    struct ext2_super_block p;
    memset(&p, 0, sizeof(struct ext2_super_block));

    ext2fs_set_feature_sparse_super(&p);
    ext2fs_set_feature_sparse_super2(&p);
    ext2fs_set_feature_large_file(&p);
    ext2fs_set_feature_filetype(&p);
    ext2fs_set_feature_xattr(&p);
    ext2fs_set_feature_extents(&p);
    ext2fs_set_feature_64bit(&p);
    ext2fs_set_feature_dir_nlink(&p);
    ext2fs_set_feature_extra_isize(&p);

    p.s_rev_level = EXT2_DYNAMIC_REV;
    p.s_desc_size = EXT2_MIN_DESC_SIZE_64BIT;
    p.s_log_block_size = int_log2(block_size >> EXT2_MIN_BLOCK_LOG_SIZE);
    p.s_log_cluster_size = p.s_log_block_size;
    p.s_inode_size = 256;
    ext2fs_blocks_count_set(&p, num_blocks);
    p.s_inodes_count = (ext2fs_blocks_count(&p) * block_size) / INODE_RATIO;
    p.s_default_mount_opts = EXT2_DEFM_ACL | EXT2_DEFM_XATTR_USER;
    p.s_max_mnt_count = -1;

    return p;
}

// Creates an empty ext4 filesystem.
static int make_ext4(ext2_filsys fs, struct ext2_super_block* params)
{
    errcode_t retval = 0;

    // Allocate/initialize inode tables.
    retval = ext2fs_allocate_tables(fs);
    HANDLE_ERR(ext2fs_allocate_tables)

    // As we always start from an empty file, we can declare the
    // inode tables to be zeroed already.
    for (dgrp_t i = 0; i < fs->group_desc_count; i++)
        ext2fs_bg_flags_set(fs, i, EXT2_BG_INODE_ZEROED);

    // Create bad block inode (inode number 1).
    ext2fs_mark_inode_bitmap2(fs->inode_map, EXT2_BAD_INO);
    ext2fs_inode_alloc_stats2(fs, EXT2_BAD_INO, 1, 0);
    retval = ext2fs_update_bb_inode(fs, NULL);
    HANDLE_ERR(ext2fs_update_bb_inode)

    // Create root directory at root inode (inode number 2).
    retval = ext2fs_mkdir(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, 0);
    HANDLE_ERR(ext2fs_mkdir)

    // Reserve other "special" inodes after root inode until first user inode.
    for (ext2_ino_t i = EXT2_ROOT_INO + 1; i < fs->super->s_first_ino; i++)
        ext2fs_inode_alloc_stats2(fs, i, 1, 0);

    return 0;
}

typedef uint64_t bitmap_word_t;

// Internal data of the custom unix_wipe_io io_manager implemented below.
struct unix_wipe_private_data
{
    io_channel unix_io_channel;
    size_t real_block_size; // see unix_wipe_set_blksize()
    bitmap_word_t* wipe_bitmap;
    size_t wipe_bitmap_size;
};

#define BITS_PER_WORD (sizeof(bitmap_word_t) * 8)
#define WORD_OFFSET(b) ((b) / BITS_PER_WORD)
#define BIT_OFFSET(b) ((b) % BITS_PER_WORD)

// Marks a block in the given bitmap as wiped.
static void mark_wiped(bitmap_word_t* wipe_bitmap, unsigned long i)
{
    wipe_bitmap[WORD_OFFSET(i)] |= ((bitmap_word_t)1 << BIT_OFFSET(i));
}

// Returns whether a block in the given bitmap is marked as wiped.
static int is_wiped(bitmap_word_t* wipe_bitmap, unsigned long i)
{
    bitmap_word_t bit =
        wipe_bitmap[WORD_OFFSET(i)] & ((bitmap_word_t)1 << BIT_OFFSET(i));
    return bit != 0;
}

// Given a filesystem area ranging from offset to offset + size in bytes,
// wipes all corresponding blocks that have not been wiped yet.
static errcode_t wipe_unwiped_blocks(
    io_channel channel,
    unsigned long offset,
    int size)
{
    errcode_t retval;
    struct unix_wipe_private_data* data =
        (struct unix_wipe_private_data*)channel->private_data;
    int block_size = data->real_block_size;
    SGXLKL_ASSERT(block_size > 0);

    bitmap_word_t* bitmap = data->wipe_bitmap;

    size_t bitmap_size = data->wipe_bitmap_size;
    size_t last_block = (offset + size - 1) / block_size;
    size_t required_bitmap_size = last_block / BITS_PER_WORD + 1;
    if (required_bitmap_size > bitmap_size)
    {
        size_t new_bitmap_size = required_bitmap_size + 1024;
        data->wipe_bitmap_size = new_bitmap_size;
        bitmap = realloc(bitmap, sizeof(bitmap_word_t) * new_bitmap_size);
        if (bitmap == NULL)
        {
            return EXT2_ET_NO_MEMORY;
        }
        data->wipe_bitmap = bitmap;
    }

    char empty[block_size];
    memset(empty, 0, block_size);

    for (unsigned long block = offset / block_size; block <= last_block;
         block++)
    {
        if (is_wiped(bitmap, block))
            continue;
        if (channel->block_size != data->real_block_size)
        {
            retval = unix_io_manager->set_blksize(
                data->unix_io_channel, data->real_block_size);
            if (retval)
                return retval;
        }
        retval =
            unix_io_manager->write_blk(data->unix_io_channel, block, 1, empty);
        if (retval)
            return retval;
        if (channel->block_size != data->real_block_size)
        {
            retval = unix_io_manager->set_blksize(
                data->unix_io_channel, channel->block_size);
            if (retval)
                return retval;
        }
        mark_wiped(bitmap, block);
    }
    return 0;
}

// The following functions implement a new io_manager named "unix_wipe_io".
// This manager wraps the existing unix_io io_manager and proxies all calls to it
// while ensuring that all reads/writes happen on previously wiped blocks.
// This custom io_manager was implemented to work around issues with
// directly writing to an unwiped/sparse dm-integrity device.

static io_manager unix_wipe_io_manager;

static errcode_t unix_wipe_open(
    const char* name,
    int flags,
    io_channel* channel)
{
    errcode_t retval;

    struct unix_wipe_private_data* data = NULL;
    retval = ext2fs_get_mem(sizeof(struct unix_wipe_private_data), &data);
    if (retval)
        return EXT2_ET_NO_MEMORY;
    memset(data, 0, sizeof(struct unix_wipe_private_data));
    unix_io_manager->open(name, flags, &data->unix_io_channel);
    // corresponds to 4 GB with 4 KB blocks, expanded on-demand
    data->wipe_bitmap_size = 16384;
    data->wipe_bitmap = calloc(data->wipe_bitmap_size, sizeof(bitmap_word_t));

    io_channel io = NULL;
    retval = ext2fs_get_mem(sizeof(struct struct_io_channel), &io);
    if (retval)
        return EXT2_ET_NO_MEMORY;
    memset(io, 0, sizeof(struct struct_io_channel));
    io->magic = EXT2_ET_MAGIC_IO_CHANNEL;
    io->manager = unix_wipe_io_manager;
    io->refcount = 1;
    io->block_size = data->unix_io_channel->block_size;
    io->private_data = data;

    *channel = io;
    return 0;
}

static errcode_t unix_wipe_close(io_channel channel)
{
    errcode_t retval;
    EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
    if (--channel->refcount > 0)
        return 0;
    struct unix_wipe_private_data* data =
        (struct unix_wipe_private_data*)channel->private_data;
    retval = unix_io_manager->close(data->unix_io_channel);
    free(data->wipe_bitmap);
    return retval;
}

static errcode_t unix_wipe_set_blksize(io_channel channel, int blksize)
{
    EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
    struct unix_wipe_private_data* data =
        (struct unix_wipe_private_data*)channel->private_data;
    errcode_t retval =
        unix_io_manager->set_blksize(data->unix_io_channel, blksize);
    channel->block_size = data->unix_io_channel->block_size;
    // libext2fs sets the block size directly after open to the fs block size.
    // It changes the block size temporarily at the end when writing the
    // super block (to the size of the super block, 1024).
    // Wiping needs to happen on the real block size, so remember it.
    if (data->real_block_size == 0)
        data->real_block_size = blksize;
    return retval;
}

static errcode_t unix_wipe_read_blk64(
    io_channel channel,
    unsigned long long block,
    int count,
    void* buf)
{
    errcode_t retval;
    EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
    struct unix_wipe_private_data* data =
        (struct unix_wipe_private_data*)channel->private_data;
    size_t size = count < 0 ? -count : (ext2_loff_t)count * channel->block_size;
    size_t offset = (ext2_loff_t)block * channel->block_size;
    retval = wipe_unwiped_blocks(channel, offset, size);
    if (retval)
        return retval;
    retval =
        unix_io_manager->read_blk64(data->unix_io_channel, block, count, buf);
    return retval;
}

static errcode_t unix_wipe_read_blk(
    io_channel channel,
    unsigned long block,
    int count,
    void* buf)
{
    errcode_t retval;
    EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
    struct unix_wipe_private_data* data =
        (struct unix_wipe_private_data*)channel->private_data;
    size_t size = count < 0 ? -count : (ext2_loff_t)count * channel->block_size;
    size_t offset = (ext2_loff_t)block * channel->block_size;
    retval = wipe_unwiped_blocks(channel, offset, size);
    if (retval)
        return retval;
    retval =
        unix_io_manager->read_blk(data->unix_io_channel, block, count, buf);
    return retval;
}

static errcode_t unix_wipe_write_byte(
    io_channel channel,
    unsigned long offset,
    int size,
    const void* buf)
{
    errcode_t retval;
    EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
    struct unix_wipe_private_data* data =
        (struct unix_wipe_private_data*)channel->private_data;
    retval = wipe_unwiped_blocks(channel, offset, size);
    if (retval)
        return retval;
    retval =
        unix_io_manager->write_byte(data->unix_io_channel, offset, size, buf);
    return retval;
}

static errcode_t unix_wipe_write_blk64(
    io_channel channel,
    unsigned long long block,
    int count,
    const void* buf)
{
    errcode_t retval;
    EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
    struct unix_wipe_private_data* data =
        (struct unix_wipe_private_data*)channel->private_data;
    size_t size = count < 0 ? -count : (ext2_loff_t)count * channel->block_size;
    size_t offset = (ext2_loff_t)block * channel->block_size;
    retval = wipe_unwiped_blocks(channel, offset, size);
    if (retval)
        return retval;
    retval =
        unix_io_manager->write_blk64(data->unix_io_channel, block, count, buf);
    return retval;
}

static errcode_t unix_wipe_write_blk(
    io_channel channel,
    unsigned long block,
    int count,
    const void* buf)
{
    errcode_t retval;
    EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
    struct unix_wipe_private_data* data =
        (struct unix_wipe_private_data*)channel->private_data;
    size_t size = count < 0 ? -count : (ext2_loff_t)count * channel->block_size;
    size_t offset = (ext2_loff_t)block * channel->block_size;
    retval = wipe_unwiped_blocks(channel, offset, size);
    if (retval)
        return retval;
    retval =
        unix_io_manager->write_blk(data->unix_io_channel, block, count, buf);
    return retval;
}

static errcode_t unix_wipe_flush(io_channel channel)
{
    EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
    struct unix_wipe_private_data* data =
        (struct unix_wipe_private_data*)channel->private_data;
    errcode_t retval = unix_io_manager->flush(data->unix_io_channel);
    return retval;
}

static errcode_t unix_wipe_set_option(
    io_channel channel,
    const char* option,
    const char* arg)
{
    EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
    struct unix_wipe_private_data* data =
        (struct unix_wipe_private_data*)channel->private_data;
    errcode_t retval =
        unix_io_manager->set_option(data->unix_io_channel, option, arg);
    return retval;
}

static errcode_t unix_wipe_get_stats(io_channel channel, io_stats* stats)
{
    EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
    struct unix_wipe_private_data* data =
        (struct unix_wipe_private_data*)channel->private_data;
    errcode_t retval = unix_io_manager->get_stats(data->unix_io_channel, stats);
    return retval;
}

static errcode_t unix_wipe_discard(
    io_channel channel,
    unsigned long long block,
    unsigned long long count)
{
    EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
    struct unix_wipe_private_data* data =
        (struct unix_wipe_private_data*)channel->private_data;
    errcode_t retval =
        unix_io_manager->discard(data->unix_io_channel, block, count);
    return retval;
}

static errcode_t unix_wipe_cache_readahead(
    io_channel channel,
    unsigned long long block,
    unsigned long long count)
{
    EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
    struct unix_wipe_private_data* data =
        (struct unix_wipe_private_data*)channel->private_data;
    errcode_t retval =
        unix_io_manager->cache_readahead(data->unix_io_channel, block, count);
    return retval;
}

static errcode_t unix_wipe_zeroout(
    io_channel channel,
    unsigned long long block,
    unsigned long long count)
{
    EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);
    struct unix_wipe_private_data* data =
        (struct unix_wipe_private_data*)channel->private_data;
    errcode_t retval =
        unix_io_manager->zeroout(data->unix_io_channel, block, count);
    return retval;
}

static struct struct_io_manager struct_unix_wipe_manager = {
    .magic = EXT2_ET_MAGIC_IO_MANAGER,
    .name = "Unix I/O Manager with lazy block-level wiping",
    .open = unix_wipe_open,
    .close = unix_wipe_close,
    .set_blksize = unix_wipe_set_blksize,
    .read_blk = unix_wipe_read_blk,
    .write_blk = unix_wipe_write_blk,
    .flush = unix_wipe_flush,
    .write_byte = unix_wipe_write_byte,
    .set_option = unix_wipe_set_option,
    .get_stats = unix_wipe_get_stats,
    .read_blk64 = unix_wipe_read_blk64,
    .write_blk64 = unix_wipe_write_blk64,
    .discard = unix_wipe_discard,
    .cache_readahead = unix_wipe_cache_readahead,
    .zeroout = unix_wipe_zeroout,
};

static io_manager unix_wipe_io_manager = &struct_unix_wipe_manager;

// Creates an ext4 filesystem image on the given device.
int make_ext4_dev(
    const char* device_name,
    int block_size,
    unsigned long long num_blocks)
{
    errcode_t retval = 0;

    struct ext2_super_block params = create_params(block_size, num_blocks);

    int flags = EXT2_FLAG_EXCLUSIVE | EXT2_FLAG_64BITS;
    io_manager io_mgr = unix_wipe_io_manager;
    ext2_filsys fs;

    retval = ext2fs_initialize(device_name, flags, &params, io_mgr, &fs);
    HANDLE_ERR(ext2fs_initialize)

    retval = make_ext4(fs, &params);
    if (retval)
        return retval;

    retval = ext2fs_close_free(&fs);
    HANDLE_ERR(ext2fs_close_free)
    return 0;
}
