#include "verity.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "crypto.h"
#include "dm.h"
#include "hash.h"
#include "hexdump.h"
#include "raise.h"
#include "round.h"
#include "uuid.h"
#include "vic.h"

#define MIN_HASH_FILE_SIZE 4096
#define MIN_BLKSZ 512
#define MAX_BLKSZ 4096
#define DEFAULT_BLKSZ 4096

void vic_verity_dump_sb(vic_verity_sb_t* sb)
{
    if (sb)
    {
        char uuid[VIC_UUID_STRING_SIZE];

        vic_uuid_bin2str(sb->uuid, uuid);

        printf("UUID:\t\t\t%s\n", uuid);
        printf("Hash type:\t\t%u\n", sb->hash_type);
        printf("Data blocks:\t\t%lu\n", sb->data_blocks);
        printf("Data block size:\t%u\n", sb->data_block_size);
        printf("Hash block size:\t%u\n", sb->hash_block_size);
        printf("Hash algorithm:\t\t%s\n", sb->algorithm);
        printf("Salt:\t\t\t");
        vic_hexdump_flat(sb->salt, sb->salt_size);
        printf("\n");
    }
}

vic_result_t vic_verity_format(
    vic_blockdev_t* data_dev,
    vic_blockdev_t* hash_dev,
    const char* hash_algorithm,
    const char* uuid,
    const uint8_t* salt,
    size_t salt_size,
    bool need_superblock,
    uint64_t data_block_size,
    uint64_t hash_block_size,
    uint8_t* root_hash,
    size_t* root_hash_size)
{
    vic_result_t result = VIC_OK;
    const size_t blksz = data_block_size ? data_block_size : DEFAULT_BLKSZ;
    size_t nblks;
    size_t digests_per_blk;
    size_t hsize;
    uint8_t salt_buf[VIC_VERITY_MAX_SALT_SIZE];
    char uuid_buf[VIC_UUID_STRING_SIZE];
    size_t nleaves;
    size_t nnodes[32];
    size_t levels = 0;
    size_t total_nodes = 0;
    vic_hash_type_t htype;
    const size_t min_data_file_size = blksz * 2;
    uint8_t last_node[blksz];

    if (!data_dev || !hash_dev || !root_hash || !root_hash_size)
        RAISE(VIC_BAD_PARAMETER);

    if (salt)
    {
        if (salt_size <= 0 || salt_size > VIC_VERITY_MAX_SALT_SIZE)
            RAISE(VIC_BAD_PARAMETER);
    }
    else if (salt_size != 0)
    {
        RAISE(VIC_BAD_PARAMETER);
    }

    if (hash_algorithm)
    {
        if ((htype = vic_hash_type(hash_algorithm)) == VIC_HASH_NONE)
            RAISE(VIC_BAD_PARAMETER);

        if ((hsize = vic_hash_size(hash_algorithm)) == (size_t)-1)
            RAISE(VIC_BAD_PARAMETER);
    }
    else
    {
        htype = VIC_HASH_SHA256;
        hsize = VIC_SHA256_SIZE;
    }

    /* Handle the salt parameter or generate a salt if none */
    if (!salt)
    {
        salt_size = hsize;
        vic_random(salt_buf, salt_size);
        salt = salt_buf;
    }

    /* Handle the uuid_buf parameter or generate a new UUID */
    if (uuid)
    {
        if (!vic_uuid_valid(uuid))
            RAISE(VIC_BAD_UUID);

        strcpy(uuid_buf, uuid);
    }
    else
    {
        vic_uuid_generate(uuid_buf);
    }

    if (!data_block_size)
        data_block_size = DEFAULT_BLKSZ;

    if (!hash_block_size)
        hash_block_size = DEFAULT_BLKSZ;

    if (data_block_size != hash_block_size)
        RAISE(VIC_FAILED);

    if (blksz < MIN_BLKSZ || blksz > MAX_BLKSZ)
        RAISE(VIC_FAILED);

    CHECK(vic_blockdev_set_block_size(data_dev, blksz));
    CHECK(vic_blockdev_set_block_size(hash_dev, blksz));

    /* Calculate the number of data blocks */
    {
        size_t size;

        CHECK(vic_blockdev_get_size(data_dev, &size));

        /* File must be a multiple of the block size */
        if (size % blksz)
            RAISE(VIC_NOT_BLOCK_MULTIPLE);

        if (size < min_data_file_size)
            RAISE(VIC_FILE_TOO_SMALL);

        nblks = size / blksz;
    }

    /* Calculate the number of digests per blocks */
    digests_per_blk = blksz / hsize;

    /* Calculate the number of leaf nodes */
    nleaves = vic_round_up(nblks, digests_per_blk) / digests_per_blk;
    nnodes[levels++] = nleaves;

    /* Save the nodes at the leaf levels */
    size_t n = nleaves;

    /* Calculate the number of interior nodes at each levels */
    while (n > 1)
    {
        n = vic_round_up(n, digests_per_blk) / digests_per_blk;
        nnodes[levels++] = n;
    }

    /* Calculate the total number of nodes at all levels */
    for (size_t i = 0; i < levels; i++)
        total_nodes += nnodes[i];

    /* Fill the hash file with zero blocks */
    {
        uint8_t zeros[blksz];
        size_t nblks = total_nodes;
        size_t hash_file_size;

        if (need_superblock)
            nblks++;

        memset(zeros, 0, blksz);

        for (size_t i = 0; i < nblks; i++)
            CHECK(vic_blockdev_put(hash_dev, i, zeros, 1));

        hash_file_size = nblks * blksz;

        /* Pad hash file out to MIN_HASH_FILE_SIZE */
        if (hash_file_size < MIN_HASH_FILE_SIZE)
        {
            size_t extra_bytes = MIN_HASH_FILE_SIZE - hash_file_size;
            size_t extra_blocks = extra_bytes / blksz;

            for (size_t i = nblks; i < nblks + extra_blocks; i++)
                CHECK(vic_blockdev_put(hash_dev, i, zeros, 1));
        }
    }

    /* Write the leaf nodes */
    {
        uint8_t blk[blksz];
        uint8_t node[blksz];
        size_t node_offset = 0;
        size_t offset;
        size_t nblocks;

        CHECK(vic_blockdev_get_num_blocks(data_dev, &nblocks));

        /* Calculate the hash file offset to the first leaf node block */
        offset = (total_nodes - nleaves) * blksz;

        if (need_superblock)
            offset += blksz;

        /* Zero out the node */
        memset(node, 0, blksz);

        /* For each block in the file */
        for (size_t i = 0; i < nblocks; i++)
        {
            vic_hash_t h;

            /* Read the next block */
            CHECK(vic_blockdev_get(data_dev, i, blk, 1));

            /* Compute the hash of the current block */
            if (vic_hash2(htype, salt, salt_size, &blk, blksz, &h) != 0)
                RAISE(VIC_UNEXPECTED);

            /* Write out the node if full */
            if (node_offset + hsize > blksz)
            {
                assert((offset % blksz) == 0);
                const size_t blkno = offset / blksz;
                CHECK(vic_blockdev_put(hash_dev, blkno, node, 1));
                memcpy(last_node, node, blksz);
                offset += blksz;
                memset(node, 0, blksz);
                node_offset = 0;
            }

            memcpy(node + node_offset, h.u.buf, hsize);
            node_offset += hsize;
        }

        /* Write the final hash file block if any */
        if (node_offset > 0)
        {
            assert((offset % blksz) == 0);
            const size_t blkno = offset / blksz;
            CHECK(vic_blockdev_put(hash_dev, blkno, node, 1));
            memcpy(last_node, node, blksz);
        }
    }

    /* Write the interior nodes */
    for (size_t i = 1; i < levels; i++)
    {
        size_t write_offset = 0;
        size_t read_offset = 0;
        size_t num_to_read;
        size_t num_to_write;

        /* Compute the hash file read offset */
        for (size_t j = i; j < levels; j++)
            read_offset += nnodes[j] * blksz;

        if (need_superblock)
            read_offset += blksz;

        /* Compute the hash file write offset */
        for (size_t j = i + 1; j < levels; j++)
            write_offset += nnodes[j] * blksz;

        if (need_superblock)
            write_offset += blksz;

        num_to_read = nnodes[i - 1];
        num_to_write = nnodes[i];

        /* For each interior node at this level */
        for (size_t j = 0; j < num_to_write; j++)
        {
            uint8_t node[blksz];
            size_t node_offset = 0;

            /* Zero out the next interior node */
            memset(node, 0, blksz);

            /* Fill the interior node with hashes */
            while (num_to_read && (node_offset + hsize) <= blksz)
            {
                char blk[blksz];
                vic_hash_t h;

                /* Read the next block */
                {
                    assert((read_offset % blksz) == 0);
                    const size_t blkno = read_offset / blksz;
                    CHECK(vic_blockdev_get(hash_dev, blkno, blk, 1));
                    read_offset += blksz;
                }

                /* Compute the hash of this block */
                if (vic_hash2(htype, salt, salt_size, &blk, blksz, &h) != 0)
                    RAISE(VIC_UNEXPECTED);

                /* Copy this hash to the new node */
                memcpy(node + node_offset, h.u.buf, hsize);
                node_offset += hsize;

                num_to_read--;
            }

            /* Write out this interior node */
            {
                assert((write_offset % blksz) == 0);
                const size_t blkno = write_offset / blksz;
                CHECK(vic_blockdev_put(hash_dev, blkno, node, 1));
                memcpy(last_node, node, blksz);
                write_offset += blksz;
            }
        }
    }

    /* Compute the root hash (from the last block written) */
    {
        vic_hash_t h;

        if (vic_hash2(htype, salt, salt_size, &last_node, blksz, &h) != 0)
            RAISE(VIC_UNEXPECTED);

        if (*root_hash_size < hsize)
            RAISE(VIC_BUFFER_TOO_SMALL);

        memcpy(root_hash, &h, hsize);
        *root_hash_size = hsize;
    }

    /* Write the superblock */
    {
        vic_verity_sb_t sb;

        memset(&sb, 0, sizeof(sb));

        memcpy(sb.signature, "verity\0\0", 8);
        sb.version = 1;
        sb.hash_type = 1;

        if (vic_uuid_str2bin(uuid_buf, sb.uuid) != 0)
            RAISE(VIC_UNEXPECTED);

        strcpy(sb.algorithm, vic_hash_name(htype));
        sb.data_block_size = blksz;
        sb.hash_block_size = blksz;
        sb.data_blocks = nblks;
        memcpy(sb.salt, salt, salt_size);
        sb.salt_size = salt_size;

        if (need_superblock)
        {
            uint8_t blk[blksz];

            memset(blk, 0, blksz);
            memcpy(blk, &sb, sizeof(vic_verity_sb_t));
            CHECK(vic_blockdev_put(hash_dev, 0, blk, 1));
        }
    }

done:
    return result;
}

vic_result_t vic_verity_read_superblock(
    vic_blockdev_t* dev,
    vic_verity_sb_t* sb)
{
    vic_result_t result = VIC_OK;
    char block[MAX_BLKSZ];

    if (!dev || !sb)
        RAISE(VIC_BAD_PARAMETER);

    CHECK(vic_blockdev_get(dev, 0, block, 1));

    memcpy(sb, block, sizeof(vic_verity_sb_t));

    if (memcmp(sb->signature, "verity\0\0", 8) != 0)
        RAISE(VIC_BAD_SIGNATURE);

done:

    return result;
}

vic_result_t vic_verity_open(
    const char* dm_name,
    vic_blockdev_t* data_dev,
    vic_blockdev_t* hash_dev,
    const void* root_hash,
    size_t root_hash_size)
{
    vic_result_t result = VIC_OK;
    size_t data_dev_size;
    vic_verity_sb_t sb;
    size_t num_blocks;
    char data_dev_path[PATH_MAX];
    char hash_dev_path[PATH_MAX];
    size_t hash_offset;

    if (!dm_name || !data_dev || !hash_dev || !root_hash || !root_hash_size)
        RAISE(VIC_BAD_PARAMETER);

    CHECK(vic_blockdev_get_size(data_dev, &data_dev_size));

    CHECK(vic_verity_read_superblock(hash_dev, &sb));

    CHECK(vic_blockdev_set_block_size(data_dev, sb.data_block_size));
    CHECK(vic_blockdev_set_block_size(hash_dev, sb.hash_block_size));

    num_blocks = data_dev_size / sb.data_block_size;

    CHECK(vic_blockdev_get_path(data_dev, data_dev_path));
    CHECK(vic_blockdev_get_path(hash_dev, hash_dev_path));
    CHECK(vic_blockdev_get_offset(hash_dev, &hash_offset));

    /* Hash offset is expressed in blocks */
    hash_offset /= sb.hash_block_size;

    /* Skip over the superblock block */
    hash_offset++;

    CHECK(vic_dm_create_verity(
        dm_name,
        data_dev_path,
        hash_dev_path,
        sb.data_block_size,
        sb.hash_block_size,
        num_blocks,
        sb.version,
        hash_offset,
        sb.algorithm,
        root_hash,
        root_hash_size,
        sb.salt,
        sb.salt_size));

done:

    return result;
}

vic_result_t vic_verity_dump(vic_blockdev_t* hash_dev)
{
    vic_result_t result = VIC_OK;
    vic_verity_sb_t sb;
    uint8_t hash_block[MAX_BLKSZ];
    size_t blksz;

    if (!hash_dev)
        RAISE(VIC_BAD_PARAMETER);

    CHECK(vic_verity_read_superblock(hash_dev, &sb));

    vic_verity_dump_sb(&sb);

    if (sb.hash_block_size > sizeof(hash_block))
        RAISE(VIC_UNEXPECTED);

    CHECK(vic_blockdev_get_block_size(hash_dev, &blksz));

    if (blksz != sb.hash_block_size)
    {
        CHECK(vic_blockdev_set_block_size(hash_dev, sb.hash_block_size));
        CHECK(vic_blockdev_get_block_size(hash_dev, &blksz));

        if (blksz != sb.hash_block_size)
            RAISE(VIC_BAD_BLOCK_SIZE);
    }

    CHECK(vic_blockdev_get(hash_dev, 1, hash_block, 1));

    /* Print the root hash */
    {
        vic_hash_type_t htype;
        size_t hsize;
        vic_hash_t h;

        if ((htype = vic_hash_type(sb.algorithm)) == VIC_HASH_NONE)
            RAISE(VIC_UNEXPECTED);

        if ((hsize = vic_hash_size(sb.algorithm)) == VIC_HASH_NONE)
            RAISE(VIC_UNEXPECTED);

        if (vic_hash2(
                htype,
                sb.salt,
                sb.salt_size,
                hash_block,
                sb.hash_block_size,
                &h) != 0)
        {
            RAISE(VIC_UNEXPECTED);
        }

        printf("Root hash:\t\t");
        vic_hexdump_flat(h.u.buf, hsize);
        printf("\n");
    }

done:

    return result;
}

vic_result_t vic_verity_close(const char* name)
{
    return vic_dm_remove(name);
}
