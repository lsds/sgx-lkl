#ifndef _VIC_DM_H
#define _VIC_DM_H

#include <stdint.h>
#include "vic.h"

vic_result_t vic_dm_create_crypt(
    const char* name,           /* /dev/mapper name */
    const char* device,         /* device name: example: /dev/loop0  */
    const char* uuid,           /* LUKS UUID */
    uint64_t start,             /* the starting sector number */
    uint64_t size,              /* the number of payload sectors */
    const char* integrity,      /* integrity type (or empty) */
    const char* cipher,         /* cipher name */
    const uint8_t* key,         /* the LUKS master key */
    uint64_t key_bytes,         /* length of the LUKS master key */
    uint64_t iv_offset,         /* offset to initialization vector */
    uint64_t offset);           /* offset to encrypted data (payload) */

vic_result_t vic_dm_create_integrity(
    const char* name,
    const char* path,
    uint64_t start,
    uint64_t size,
    uint64_t offset,
    char mode,
    const char* integrity);

vic_result_t vic_dm_create_verity(
    const char* dm_name,
    const char* data_dev,
    const char* hash_dev,
    size_t data_block_size,
    size_t hash_block_size,
    size_t num_blocks,
    uint32_t version,
    uint32_t hash_type,
    const char* hash_alg,
    const uint8_t* root_digest,
    size_t root_digest_size,
    const uint8_t* salt,
    size_t salt_size);

vic_result_t vic_dm_remove(const char* name);

#endif /* _VIC_DM_H */
