#ifndef _VIC_LUKS1_H
#define _VIC_LUKS1_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "defs.h"
#include "vic.h"
#include "lukscommon.h"

#define LUKS_CIPHER_NAME_AES "aes"
#define LUKS_CIPHER_NAME_TWOFISH "twofish"
#define LUKS_CIPHER_NAME_SERPENT "serpent"
#define LUKS_CIPHER_NAME_CAST5 "cast5"
#define LUKS_CIPHER_NAME_CAST6 "cast6"

#define LUKS_CIPHER_MODE_ECB "ecb"
#define LUKS_CIPHER_MODE_CBC_PLAIN "cbc-plain"
#define LUKS_CIPHER_MODE_CBC_ESSIV "cbc-essiv:"
#define LUKS_CIPHER_MODE_CBC_ESSIV_SHA1 "cbc-essiv:sha1"
#define LUKS_CIPHER_MODE_CBC_ESSIV_SHA256 "cbc-essiv:sha256"
#define LUKS_CIPHER_MODE_CBC_ESSIV_SHA512 "cbc-essiv:sha512"
#define LUKS_CIPHER_MODE_CBC_ESSIV_RIPEMD160 "cbc-essiv:ripemd160"
#define LUKS_CIPHER_MODE_XTS_PLAIN64 "xts-plain64"

#define LUKS_CIPHER_NAME_SIZE 32
#define LUKS_CIPHER_MODE_SIZE 32
#define LUKS_DIGEST_SIZE 20
#define LUKS_NUM_KEYS 8

typedef struct vic_luks_keyslot
{
    uint32_t active;
    uint32_t iterations;
    uint8_t salt[LUKS_SALT_SIZE];
    uint32_t key_material_offset;
    uint32_t stripes;
}
vic_luks_keyslot_t;

VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_luks_keyslot_t, active) == 0);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_luks_keyslot_t, iterations) == 4);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_luks_keyslot_t, salt) == 8);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_luks_keyslot_t, key_material_offset) == 40);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_luks_keyslot_t, stripes) == 44);
VIC_STATIC_ASSERT(sizeof(vic_luks_keyslot_t) == 48);

typedef struct luks1_hdr
{
    uint8_t magic[LUKS_MAGIC_SIZE];
    uint16_t version;
    char cipher_name[LUKS_CIPHER_NAME_SIZE];
    char cipher_mode[LUKS_CIPHER_MODE_SIZE];
    char hash_spec[VIC_HASH_SPEC_SIZE];
    uint32_t payload_offset;
    uint32_t key_bytes;
    uint8_t mk_digest[LUKS_DIGEST_SIZE];
    uint8_t mk_digest_salt[LUKS_SALT_SIZE];
    uint32_t mk_digest_iter;
    char uuid[VIC_UUID_STRING_SIZE];
    vic_luks_keyslot_t keyslots[LUKS_NUM_KEYS];
}
luks1_hdr_t;

VIC_STATIC_ASSERT(VIC_OFFSETOF(luks1_hdr_t, magic) == 0);
VIC_STATIC_ASSERT(VIC_OFFSETOF(luks1_hdr_t, version) == 6);
VIC_STATIC_ASSERT(VIC_OFFSETOF(luks1_hdr_t, cipher_name) == 8);
VIC_STATIC_ASSERT(VIC_OFFSETOF(luks1_hdr_t, cipher_mode) == 40);
VIC_STATIC_ASSERT(VIC_OFFSETOF(luks1_hdr_t, hash_spec) == 72);
VIC_STATIC_ASSERT(VIC_OFFSETOF(luks1_hdr_t, payload_offset) == 104);
VIC_STATIC_ASSERT(VIC_OFFSETOF(luks1_hdr_t, key_bytes) == 108);
VIC_STATIC_ASSERT(VIC_OFFSETOF(luks1_hdr_t, mk_digest) == 112);
VIC_STATIC_ASSERT(VIC_OFFSETOF(luks1_hdr_t, mk_digest_salt) == 132);
VIC_STATIC_ASSERT(VIC_OFFSETOF(luks1_hdr_t, mk_digest_iter) == 164);
VIC_STATIC_ASSERT(VIC_OFFSETOF(luks1_hdr_t, uuid) == 168);
VIC_STATIC_ASSERT(VIC_OFFSETOF(luks1_hdr_t, keyslots) == 208);
VIC_STATIC_ASSERT(sizeof(luks1_hdr_t) == 592);

/* These fields have common offsets */
VIC_CHECK_FIELD(vic_luks_hdr_t, luks1_hdr_t, magic);
VIC_CHECK_FIELD(vic_luks_hdr_t, luks1_hdr_t, version);
VIC_CHECK_FIELD(vic_luks_hdr_t, luks1_hdr_t, uuid);

vic_result_t luks1_format(
    vic_blockdev_t* device,
    const char* cipher_name,
    const char* cipher_mode,
    const char* uuid,
    const char* hash,
    uint64_t mk_iterations,
    const vic_key_t* master_key,
    size_t master_key_bytes);

int luks1_read_hdr(vic_blockdev_t* device, luks1_hdr_t** hdr_out);

int luks1_dump_hdr(const luks1_hdr_t* hdr);

vic_result_t luks1_recover_master_key(
    vic_blockdev_t* device,
    const char* pwd,
    size_t pwd_size,
    vic_key_t* master_key,
    size_t* master_key_bytes);

vic_result_t luks1_add_key(
    vic_blockdev_t* device,
    uint64_t slot_iterations,
    const char* pwd,
    size_t pwd_size,
    const char* new_pwd,
    size_t new_pwd_size);

vic_result_t luks1_add_key_by_master_key(
    vic_blockdev_t* device,
    uint64_t slot_iterations,
    const vic_key_t* master_key,
    size_t master_key_bytes,
    const char* pwd,
    size_t pwd_size);

vic_result_t luks1_change_key(
    vic_blockdev_t* device,
    const char* old_pwd,
    size_t old_pwd_size,
    const char* new_pwd,
    size_t new_pwd_size);

vic_result_t luks1_remove_key(
    vic_blockdev_t* device,
    const char* pwd,
    size_t pwd_size);

vic_result_t luks1_stat(vic_blockdev_t* device, vic_luks_stat_t* buf);

vic_result_t luks1_open(
    vic_blockdev_t* device,
    const char* path,
    const char* name,
    const vic_key_t* master_key,
    size_t master_key_bytes);

#endif /* _VIC_LUKS1_H */
