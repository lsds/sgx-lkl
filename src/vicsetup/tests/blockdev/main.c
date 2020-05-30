#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <vic.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include "../../libvicsetup/hexdump.h"

static bool _check_block_size(vic_blockdev_t* bd, size_t n)
{
    size_t m;

    if (vic_blockdev_get_block_size(bd, &m) != VIC_OK)
        return false;

    return m == n;
}

static bool _check_num_blocks(vic_blockdev_t* bd, size_t n)
{
    size_t m;

    if (vic_blockdev_get_num_blocks(bd, &m) != VIC_OK)
        return false;

    return m == n;
}

static bool _check_size(vic_blockdev_t* bd, size_t n)
{
    size_t m;

    if (vic_blockdev_get_size(bd, &m) != VIC_OK)
        return false;

    return m == n;
}

static bool _check_offset(vic_blockdev_t* bd, size_t n)
{
    size_t m;

    if (vic_blockdev_get_offset(bd, &m) != VIC_OK)
        return false;

    return m == n;
}

int main(int argc, const char* argv[])
{
    struct stat st;
    const size_t blksz = 4096;
    const size_t nblocks = 8;
    const size_t nblocks1 = 3;
    const size_t nblocks2 = 5;
    const size_t filesz = nblocks * blksz;
    const size_t filesz1 = nblocks1 * blksz;
    const size_t filesz2 = nblocks2 * blksz;
    vic_blockdev_t* bd1;
    vic_blockdev_t* bd2;
    uint8_t blocks[nblocks][blksz];
    uint8_t blocks1[nblocks1][blksz];
    uint8_t blocks2[nblocks2][blksz];

    memset(blocks, 0, sizeof(blocks));
    memset(blocks1, 0, sizeof(blocks1));
    memset(blocks2, 0, sizeof(blocks2));

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <path>\n", argv[0]);
        exit(1);
    }

    const char* path = argv[1];

    if (stat(path, &st) != 0)
    {
        fprintf(stderr, "%s: stat() failed: %s\n", argv[0], path);
        exit(1);
    }

    if ((size_t)st.st_size != filesz)
    {
        fprintf(stderr, "%s: file wrong size\n", argv[0]);
        exit(1);
    }

    if (vic_blockdev_open(path, VIC_RDONLY, blksz, &bd1) != VIC_OK)
    {
        fprintf(stderr, "%s: vic_blockdev_open() failed\n", argv[0]);
        exit(1);
    }

    if (vic_blockdev_open(path, VIC_RDONLY, blksz, &bd2) != VIC_OK)
    {
        fprintf(stderr, "%s: vic_blockdev_open() failed\n", argv[0]);
        exit(1);
    }

    bool same;
    assert(vic_blockdev_same(bd1, bd2, &same) == VIC_OK && same);

    assert(_check_block_size(bd1, blksz));
    assert(_check_num_blocks(bd1, nblocks));
    assert(_check_size(bd1, filesz));
    assert(_check_offset(bd1, 0));

    assert(_check_block_size(bd2, blksz));
    assert(_check_num_blocks(bd2, nblocks));
    assert(_check_size(bd2, filesz));
    assert(_check_offset(bd2, 0));

    /* Read in all the blocks */
    {
        memset(blocks, 0, sizeof(blocks));

        for (size_t i = 0; i < nblocks; i++)
            assert(vic_blockdev_get(bd1, i, blocks[i], 1) == VIC_OK);
    }

    /* Partition the device into two subfiles */
    assert(vic_blockdev_set_size(bd1, filesz1) == VIC_OK);
    assert(_check_block_size(bd1, blksz));
    assert(_check_num_blocks(bd1, nblocks1));
    assert(_check_size(bd1, filesz1));
    assert(_check_offset(bd1, 0));

    assert(vic_blockdev_set_offset(bd2, filesz1) == VIC_OK);
    assert(_check_block_size(bd2, blksz));
    assert(_check_num_blocks(bd2, nblocks2));
    assert(_check_offset(bd2, filesz1));
    assert(_check_size(bd2, filesz2));

    /* Read in all the blocks form device 1 */
    for (size_t i = 0; i < nblocks1; i++)
        assert(vic_blockdev_get(bd1, i, blocks1[i], 1) == VIC_OK);

    /* Read in all the blocks form device 2 */
    for (size_t i = 0; i < nblocks2; i++)
        assert(vic_blockdev_get(bd2, i, blocks2[i], 1) == VIC_OK);

    /* Check the blocks */
    {
        uint8_t tmp[nblocks][blksz];

        memcpy(tmp, blocks1, filesz1);
        memcpy((uint8_t*)tmp + filesz1, blocks2, filesz2);

        assert(sizeof(blocks) == sizeof(tmp));
        assert(sizeof(blocks) == filesz);
        assert(memcmp(blocks, tmp, sizeof(blocks)) == 0);
#if 0
        vic_hexdump(blocks, sizeof(blocks));
        vic_hexdump(tmp, sizeof(tmp));
#endif
    }

    vic_blockdev_close(bd1);
    vic_blockdev_close(bd2);

    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
