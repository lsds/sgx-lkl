#ifndef _VIC_LUKSCOMMON_H
#define _VIC_LUKSCOMMON_H

#include <stdint.h>
#include <stdbool.h>
#include "uuid.h"

#define LUKS_VERSION_1 1
#define LUKS_VERSION_2 2
#define LUKS_MAGIC_1ST { 'L', 'U', 'K', 'S', 0xba, 0xbe }
#define LUKS_MAGIC_2ND { 'S', 'K', 'U', 'L', 0xba, 0xbe }
#define LUKS_MAGIC_SIZE 6
#define VIC_HASH_SPEC_SIZE 32
#define LUKS_SALT_SIZE 32

#define LUKS_MIN_MK_ITERATIONS 1000
#define LUKS_MIN_SLOT_ITERATIONS 1000

#define LUKS_DEFAULT_CIPHER "aes-xts-plain64"

/* Common fields for both LUKS1 and LUKS2 headers */
typedef struct vic_luks_hdr
{
    uint8_t magic[LUKS_MAGIC_SIZE];
    uint16_t version;
    uint8_t padding1[160];
    char uuid[VIC_UUID_STRING_SIZE];
    uint8_t padding2[304];
}
vic_luks_hdr_t;

int vic_luks_read_hdr(vic_blockdev_t* device, vic_luks_hdr_t* hdr);

#endif /* _VIC_LUKSCOMMON_H */
