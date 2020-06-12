#ifndef _VIC_VERITY_H
#define _VIC_VERITY_H

#include <stdint.h>
#include "defs.h"
#include "vic.h"

#define VIC_VERITY_MAX_SALT_SIZE 256

VIC_PACK_BEGIN
typedef struct _vic_verity_sb
{
    /* (0) "verity\0\0" */
    uint8_t  signature[8];

    /* (8) superblock version, 1 */
    uint32_t version;

    /* (12) 0 - Chrome OS, 1 - normal */
    uint32_t hash_type;

    /* (16) UUID of hash device */
    uint8_t uuid[16];

    /* (32) Name of the hash algorithm (e.g., sha256) */
    char algorithm[32];

    /* (64) The data block size in bytes */
    uint32_t data_block_size;

    /* (68) The hash block size in bytes */
    uint32_t hash_block_size;

    /* (72) The number of data blocks */
    uint64_t data_blocks;

    /* (80) Size of the salt */
    uint16_t salt_size;

    /* (82) Padding */
    uint8_t  _pad1[6];

    /* (88) The salt */
    uint8_t  salt[VIC_VERITY_MAX_SALT_SIZE];

    /* Padding */
    uint8_t  _pad2[168];
}
vic_verity_sb_t;
VIC_PACK_END

VIC_STATIC_ASSERT(sizeof(vic_verity_sb_t) == 512);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, signature) == 0);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, version) == 8);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, hash_type) == 12);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, uuid) == 16);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, algorithm) == 32);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, data_block_size) == 64);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, hash_block_size) == 68);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, data_blocks) == 72);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, salt_size) == 80);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, _pad1) == 82);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, salt) == 88);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, _pad2) == 344);

void vic_verity_dump_sb(vic_verity_sb_t* sb);

vic_result_t vic_verity_read_superblock(
    vic_blockdev_t* dev,
    vic_verity_sb_t* sb);

#endif /* _VIC_VERITY_H */
