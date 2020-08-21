#ifndef _VIC_LUKS2_H
#define _VIC_LUKS2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "defs.h"
#include "hash.h"
#include "lukscommon.h"
#include "vic.h"

#define LUKS2_LABEL_SIZE 48
#define LUKS2_SALT_SIZE 64
#define LUKS2_CSUM_ALG_SIZE 32
#define LUKS2_CSUM_SIZE 64

VIC_PACK_BEGIN
typedef struct luks2_hdr
{
    char magic[LUKS_MAGIC_SIZE];        /* LUKS2_MAGIC_1ST or LUKS2_MAGIC_2ND */
    uint16_t version;                   /* Version 2 */
    uint64_t hdr_size;                  /* size including JSON area [ bytes ] */
    uint64_t seqid;                     /* sequence ID , increased on update */
    char label[LUKS2_LABEL_SIZE];       /* ASCII label or empty */
    char csum_alg[LUKS2_CSUM_ALG_SIZE]; /* checksum algorithm , "sha256" */
    uint8_t salt[LUKS2_SALT_SIZE];      /* salt , unique for every header */
    char uuid[VIC_UUID_STRING_SIZE];    /* UUID of device */
    char subsystem[LUKS2_LABEL_SIZE];   /* owner subsystem label or empty */
    uint64_t hdr_offset;                /* offset from device start [bytes] */
    char _padding[184];                 /* must be zeroed */
    uint8_t csum[LUKS2_CSUM_SIZE];      /* header checksum */
    char _padding4096[7 * 512];         /* Padding , must be zeroed */
    /* luks2_ext_hdr follows */
} luks2_hdr_t;
VIC_PACK_END

VIC_STATIC_ASSERT(sizeof(luks2_hdr_t) == 4096);

#define LUKS2_TYPE_SIZE 32
#define LUKS2_ENCRYPTION_SIZE 32
#define LUKS2_NUM_KEYSLOTS 64
#define LUKS2_NUM_SEGMENTS 1
#define LUKS2_NUM_DIGESTS (LUKS2_NUM_KEYSLOTS + LUKS2_NUM_SEGMENTS)
#define LUKS2_NUM_CONFIGS 1
#define LUKS2_DIGEST_SIZE VIC_MAX_HASH_SIZE
#define LUKS2_INTEGRITY_SIZE 32

typedef struct luks2_keyslot
{
    char type[LUKS2_TYPE_SIZE];
    uint64_t key_size;
    struct
    {
        char type[LUKS2_TYPE_SIZE];
        uint8_t salt[LUKS_SALT_SIZE];

        /* For type 'pbkdf2' */
        char hash[VIC_HASH_SPEC_SIZE];
        uint64_t iterations;

        /* For type 'argon2i' or 'argon2id' */
        uint64_t time;
        uint64_t memory;
        uint64_t cpus;
    } kdf;
    struct
    {
        char type[LUKS2_TYPE_SIZE];
        char hash[VIC_HASH_SPEC_SIZE];
        uint64_t stripes;
    } af;
    struct
    {
        char type[LUKS2_TYPE_SIZE];
        char encryption[LUKS2_ENCRYPTION_SIZE];
        uint64_t key_size;
        uint64_t offset;
        uint64_t size;
    } area;
} luks2_keyslot_t;

typedef struct luks2_segment
{
    /* only "crypt" supported */
    char type[LUKS2_TYPE_SIZE];

    /* offset in bytes */
    uint64_t offset;

    /* starting offset for the initialization vector */
    uint64_t iv_tweak;

    /* (uint64_t)-1 indicates dynamic */
    uint64_t size;

    /* example: "aes-xts-plain64" */
    char encryption[LUKS2_ENCRYPTION_SIZE];

    /* 512, 1024, 2048, 4096 */
    uint64_t sector_size;

    /* Data integrity type */
    struct
    {
        char type[LUKS2_INTEGRITY_SIZE];
        char journal_encryption[LUKS2_ENCRYPTION_SIZE];
        char journal_integrity[LUKS2_INTEGRITY_SIZE];
    } integrity;
} luks2_segment_t;

typedef struct luks2_digest
{
    /* Example: "pbkdf2" */
    char type[LUKS2_TYPE_SIZE];

    /* Keyslots that are used are non-zero in this array */
    uint8_t keyslots[LUKS2_NUM_KEYSLOTS];

    /* Segments that are used are non-zero in this array */
    uint8_t segments[LUKS2_NUM_SEGMENTS];

    /* Example: "sha256" */
    char hash[VIC_HASH_SPEC_SIZE];

    uint64_t iterations;

    uint8_t salt[LUKS_SALT_SIZE];

    uint8_t digest[LUKS2_DIGEST_SIZE];
} luks2_digest_t;

typedef struct luks2_config
{
    uint64_t json_size;
    uint64_t keyslots_size;
} luks2_config_t;

typedef struct _luks2_ext_hdr
{
    /* Primary header */
    luks2_hdr_t phdr;

    /* Secondary header */
    luks2_hdr_t shdr;

    /* Binary representation of JSON objects */
    luks2_keyslot_t keyslots[LUKS2_NUM_KEYSLOTS];
    luks2_segment_t segments[LUKS2_NUM_SEGMENTS];
    luks2_digest_t digests[LUKS2_NUM_DIGESTS];
    luks2_config_t config;

    /* JSON script (associated with primary header) */
    size_t json_size;
    char json_data[];
} luks2_ext_hdr_t;

VIC_STATIC_ASSERT(sizeof(luks2_hdr_t) == 4096);

int luks2_read_hdr(vic_blockdev_t* device, luks2_hdr_t** hdr_out);

int luks2_dump_hdr(const luks2_hdr_t* hdr);

vic_result_t luks2_recover_master_key(
    vic_blockdev_t* device,
    const char* pwd,
    size_t pwd_size,
    vic_key_t* master_key,
    size_t* master_key_bytes);

vic_result_t luks2_format(
    vic_blockdev_t* device,
    const char* label,
    const char* subsystem,
    const char* cipher,
    const char* uuid,
    const char* hash,
    uint64_t iterations,
    const vic_key_t* master_key,
    size_t master_key_bytes,
    const char* integrity);

vic_result_t luks2_add_key(
    vic_blockdev_t* device,
    const char* keyslot_cipher,
    const char* kdf_type,
    vic_kdf_t* kdf,
    const char* pwd,
    size_t pwd_size,
    const char* new_pwd,
    size_t new_pwd_size);

vic_result_t luks2_add_key_by_master_key(
    vic_blockdev_t* device,
    const char* keyslot_cipher,
    const char* kdf_type,
    vic_kdf_t* kdf,
    const vic_key_t* master_key,
    size_t master_key_bytes,
    const char* pwd,
    size_t pwd_size);

vic_result_t luks2_change_key(
    vic_blockdev_t* device,
    const char* old_pwd,
    size_t old_pwd_size,
    const char* new_pwd,
    size_t new_pwd_size);

vic_result_t luks2_remove_key(
    vic_blockdev_t* device,
    const char* pwd,
    size_t pwd_size);

vic_result_t luks2_stat(vic_blockdev_t* device, vic_luks_stat_t* buf);

vic_result_t luks2_open(
    vic_blockdev_t* device,
    const char* path,
    const char* name,
    const vic_key_t* master_key,
    size_t master_key_bytes);

vic_result_t luks2_open_by_passphrase(
    vic_blockdev_t* dev,
    luks2_hdr_t* hdr,
    const char* path,
    const char* name,
    const char* pwd,
    size_t pwd_size);

#endif /* _VIC_LUKS2_H */
