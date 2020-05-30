#ifndef _VIC_LIBCRYPTSETUP_H
#define _VIC_LIBCRYPTSETUP_H

/*
**==============================================================================
**
** libcryptsetup compatibility interface:
**
**==============================================================================
*/

#include <stddef.h>
#include <stdint.h>

#define CRYPT_LUKS NULL
#define CRYPT_LUKS1 "LUKS1"
#define CRYPT_LUKS2 "LUKS2"
#define CRYPT_VERITY "VERITY"
#define CRYPT_INTEGRITY "INTEGRITY"

#define CRYPT_ANY_SLOT -1

#define CRYPT_ACTIVATE_READONLY (1 << 0)
#define CRYPT_ACTIVATE_NO_UUID (1 << 1)
#define CRYPT_ACTIVATE_SHARED (1 << 2)
#define CRYPT_ACTIVATE_ALLOW_DISCARDS (1 << 3)
#define CRYPT_ACTIVATE_PRIVATE (1 << 4)
#define CRYPT_ACTIVATE_CORRUPTED (1 << 5)
#define CRYPT_ACTIVATE_SAME_CPU_CRYPT (1 << 6)
#define CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS (1 << 7)
#define CRYPT_ACTIVATE_IGNORE_CORRUPTION (1 << 8)
#define CRYPT_ACTIVATE_RESTART_ON_CORRUPTION (1 << 9)
#define CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS (1 << 10)
#define CRYPT_ACTIVATE_KEYRING_KEY (1 << 11)
#define CRYPT_ACTIVATE_NO_JOURNAL (1 << 12)
#define CRYPT_ACTIVATE_RECOVERY (1 << 13)
#define CRYPT_ACTIVATE_IGNORE_PERSISTENT (1 << 14)
#define CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE (1 << 15)
#define CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY (1 << 16)
#define CRYPT_ACTIVATE_RECALCULATE (1 << 17)
#define CRYPT_ACTIVATE_REFRESH (1 << 18)
#define CRYPT_ACTIVATE_SERIALIZE_MEMORY_HARD_PBKDF (1 << 19)
#define CRYPT_ACTIVATE_NO_JOURNAL_BITMAP (1 << 20)
#define CRYPT_ACTIVATE_SUSPENDED (1 << 21)

#define CRYPT_PBKDF_ITER_TIME_SET (1 << 0)
#define CRYPT_PBKDF_NO_BENCHMARK (1 << 1)

#define CRYPT_DEBUG_ALL -1
#define CRYPT_DEBUG_JSON -2
#define CRYPT_DEBUG_NONE 0

struct crypt_device;


struct crypt_params_luks1
{
    const char* hash;
    size_t data_alignment;
    const char* data_device;
};

struct crypt_pbkdf_type
{
    const char* type;
    const char* hash;
    uint32_t time_ms;
    uint32_t iterations;
    uint32_t max_memory_kb;
    uint32_t parallel_threads;
    uint32_t flags;
};

struct crypt_params_integrity
{
    uint64_t journal_size;
    unsigned int journal_watermark;
    unsigned int journal_commit_time;
    uint32_t interleave_sectors;
    uint32_t tag_size;
    uint32_t sector_size;
    uint32_t buffer_sectors;
    const char* integrity;
    uint32_t integrity_key_size;
    const char* journal_integrity;
    const char* journal_integrity_key;
    uint32_t journal_integrity_key_size;
    const char* journal_crypt;
    const char* journal_crypt_key;
    uint32_t journal_crypt_key_size;
};

struct crypt_params_luks2
{
    const struct crypt_pbkdf_type* pbkdf;
    const char* integrity;
    const struct crypt_params_integrity* integrity_params; // unsupported
    size_t data_alignment;
    const char* data_device;
    uint32_t sector_size;
    const char* label;
    const char* subsystem;
};

struct crypt_params_verity
{
    const char* hash_name;
    const char* data_device;
    const char* hash_device;
    const char* fec_device; // unsupported
    const char* salt;
    uint32_t salt_size;
    uint32_t hash_type;
    uint32_t data_block_size;
    uint32_t hash_block_size;
    uint64_t data_size;
    uint64_t hash_area_offset;
    uint64_t fec_area_offset;
    uint32_t fec_roots;
    uint32_t flags;
};

/*
**==============================================================================
**
** Internal functions (please do not call directly)
**
**==============================================================================
*/

int __crypt_init(struct crypt_device** cd, const char* device);

void __crypt_free(struct crypt_device* cd);

int __crypt_format(
    struct crypt_device* cd,
    const char* type,
    const char* cipher,
    const char* cipher_mode,
    const char* uuid,
    const char* volume_key,
    size_t volume_key_size,
    void* params);

int __crypt_load(
    struct crypt_device* cd,
    const char* requested_type,
    void* params);

int __crypt_activate_by_volume_key(
    struct crypt_device* cd,
    const char* name,
    const char* volume_key,
    size_t volume_key_size,
    uint32_t flags);

int __crypt_activate_by_passphrase(
    struct crypt_device* cd,
    const char* name,
    int keyslot,
    const char* passphrase,
    size_t passphrase_size,
    uint32_t flags);

int __crypt_keyslot_add_by_key(
    struct crypt_device* cd,
    int keyslot,
    const char* volume_key,
    size_t volume_key_size,
    const char* passphrase,
    size_t passphrase_size,
    uint32_t flags);

int __crypt_get_volume_key_size(struct crypt_device* cd);

void __crypt_set_debug_level(int level);

/*
**==============================================================================
**
** Public interface:
**
**     These inline functions are used to prevent emission of symbols which
**     could conflict with the official libcryptsetup library symbols if also
**     linked.
**
**==============================================================================
*/

static __inline__ int crypt_init(struct crypt_device** cd, const char* device)
{
    return __crypt_init(cd, device);
}

static __inline__ void crypt_free(struct crypt_device* cd)
{
    return __crypt_free(cd);
}

static __inline__ int crypt_format(
    struct crypt_device* cd,
    const char* type,
    const char* cipher,
    const char* cipher_mode,
    const char* uuid,
    const char* volume_key,
    size_t volume_key_size,
    void* params)
{
    return __crypt_format(cd, type, cipher, cipher_mode, uuid, volume_key,
        volume_key_size, params);
}

static __inline__ int crypt_load(
    struct crypt_device* cd,
    const char* requested_type,
    void* params)
{
    return __crypt_load(cd, requested_type, params);
}

static __inline__ int crypt_activate_by_volume_key(
    struct crypt_device* cd,
    const char* name,
    const char* volume_key,
    size_t volume_key_size,
    uint32_t flags)
{
    return __crypt_activate_by_volume_key(cd, name, volume_key, volume_key_size,
        flags);
}

static __inline__ int crypt_activate_by_passphrase(
    struct crypt_device* cd,
    const char* name,
    int keyslot,
    const char* passphrase,
    size_t passphrase_size,
    uint32_t flags)
{
    return __crypt_activate_by_passphrase(cd, name, keyslot, passphrase,
        passphrase_size, flags);
}

static __inline__ int crypt_keyslot_add_by_key(
    struct crypt_device* cd,
    int keyslot,
    const char* volume_key,
    size_t volume_key_size,
    const char* passphrase,
    size_t passphrase_size,
    uint32_t flags)
{
    return __crypt_keyslot_add_by_key(cd, keyslot, volume_key, volume_key_size,
        passphrase, passphrase_size, flags);
}

static __inline__ int crypt_get_volume_key_size(struct crypt_device* cd)
{
    return __crypt_get_volume_key_size(cd);
}

static __inline__ void crypt_set_debug_level(int level)
{
    return __crypt_set_debug_level(level);
}

#endif /* _VIC_LIBCRYPTSETUP_H */
