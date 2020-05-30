#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>

#include "vic.h"
#include "lukscommon.h"
#include "byteorder.h"
#include "luks2.h"
#include "luks1.h"
#include "raise.h"
#include "hexdump.h"
#include "integrity.h"
#include "dm.h"
#include "strings.h"
#include "malloc.h"

VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_luks_hdr_t, magic) == 0);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_luks_hdr_t, version) == 6);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_luks_hdr_t, uuid) == 168);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_luks_hdr_t, padding2) == 208);
VIC_STATIC_ASSERT(sizeof(vic_luks_hdr_t) == 512);
VIC_STATIC_ASSERT(sizeof(vic_luks_hdr_t) == VIC_SECTOR_SIZE);

/* These fields have common offsets */
VIC_CHECK_FIELD(luks2_hdr_t, luks1_hdr_t, magic);
VIC_CHECK_FIELD(luks2_hdr_t, luks1_hdr_t, version);
VIC_CHECK_FIELD(luks2_hdr_t, luks1_hdr_t, uuid);

static uint8_t _magic_1st[LUKS_MAGIC_SIZE] = LUKS_MAGIC_1ST;

static uint8_t _magic_2nd[LUKS_MAGIC_SIZE] = LUKS_MAGIC_2ND;

static bool _is_valid_device(vic_blockdev_t* dev)
{
    size_t block_size;

    if (!dev)
        return false;

    if (vic_blockdev_get_block_size(dev, &block_size) != VIC_OK)
        return false;

    if (block_size != VIC_SECTOR_SIZE)
        return false;

    return true;
}

int vic_luks_read_hdr(vic_blockdev_t* device, vic_luks_hdr_t* hdr)
{
    int ret = -1;
    uint8_t block[VIC_SECTOR_SIZE];
    size_t block_size;

    if (vic_blockdev_get_block_size(device, &block_size) != VIC_OK)
        goto done;

    if (block_size != VIC_SECTOR_SIZE)
        goto done;

    /* Reject null parameters */
    if (!_is_valid_device(device) || !hdr)
        goto done;;

    /* Read one blocks to obtain enough bytes for the header */
    if (vic_blockdev_get(device, 0, block, 1) != VIC_OK)
        goto done;;

    VIC_STATIC_ASSERT(sizeof(vic_luks_hdr_t) <= sizeof(block));
    memcpy(hdr, &block, sizeof(vic_luks_hdr_t));

    if (memcmp(hdr->magic, _magic_1st, sizeof(_magic_1st)) != 0 &&
        memcmp(hdr->magic, _magic_2nd, sizeof(_magic_2nd)) != 0)
    {
        goto done;;
    }

    /* Adjust byte order from big-endian to native */
    hdr->version = vic_swap_u16(hdr->version);

    ret = 0;

done:
    return ret;
}

vic_result_t vic_luks_dump(vic_blockdev_t* device)
{
    vic_result_t result = VIC_OK;
    vic_luks_hdr_t hdr;
    luks1_hdr_t* hdr1 = NULL;
    luks2_hdr_t* hdr2 = NULL;

    if (!_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        if (luks1_read_hdr(device, &hdr1) != 0)
            RAISE(VIC_FAILED);

        if (luks1_dump_hdr(hdr1) != 0)
            RAISE(VIC_FAILED);
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        if (luks2_read_hdr(device, &hdr2) != 0)
            RAISE(VIC_FAILED);

        if (luks2_dump_hdr(hdr2) != 0)
            RAISE(VIC_FAILED);

        /* dump integrity header (if any) */
        {
            luks2_ext_hdr_t* ext = (luks2_ext_hdr_t*)hdr2;
            vic_integrity_sb_t sb;
            const uint64_t offset = ext->segments[0].offset;
            vic_result_t r;

            r = vic_integrity_read_sb(device, offset, &sb);

            if (r == VIC_OK)
                vic_integrity_dump_sb(&sb);
            else if (r != VIC_NOT_FOUND)
                RAISE(r);
        }
    }
    else
    {
        RAISE(VIC_BAD_VERSION);
    }

done:

    if (hdr1)
        vic_free(hdr1);

    if (hdr2)
        vic_free(hdr2);

    return result;
}

vic_result_t vic_luks_recover_master_key(
    vic_blockdev_t* device,
    const char* pwd,
    size_t pwd_size,
    vic_key_t* master_key,
    size_t* master_key_bytes)
{
    vic_result_t result = VIC_OK;
    vic_luks_hdr_t hdr;

    if (!_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        CHECK(luks1_recover_master_key(
            device,
            pwd,
            pwd_size,
            master_key,
            master_key_bytes));
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        CHECK(luks2_recover_master_key(
            device,
            pwd,
            pwd_size,
            master_key,
            master_key_bytes));
    }
    else
    {
        RAISE(VIC_BAD_VERSION);
    }

done:

    return result;
}

static vic_result_t _split_cipher(
    const char* cipher,
    char cipher_name[LUKS_CIPHER_NAME_SIZE],
    char cipher_mode[LUKS_CIPHER_MODE_SIZE])
{
    vic_result_t result = VIC_OK;
    size_t offset;

    if (!cipher | !cipher_name || !cipher_mode)
        RAISE(VIC_BAD_PARAMETER);

    /* Find the index of the first '-' character */
    {
        const char* p;

        if (!(p = strchr(cipher, '-')))
            RAISE(VIC_BAD_CIPHER);

        offset = p - cipher;

        if (offset >= LUKS_CIPHER_NAME_SIZE)
            RAISE(VIC_BAD_CIPHER);
    }

    vic_strlcpy(cipher_name, cipher, LUKS_CIPHER_NAME_SIZE);
    cipher_name[offset] = '\0';

    vic_strlcpy(cipher_mode, &cipher[offset+1], LUKS_CIPHER_MODE_SIZE);

done:
    return result;
}

vic_result_t vic_luks_format(
    vic_blockdev_t* device,
    vic_luks_version_t version,
    const char* cipher,
    const char* uuid,
    const char* hash,
    uint64_t mk_iterations,
    const vic_key_t* master_key,
    size_t master_key_bytes,
    const char* integrity)
{
    vic_result_t result = VIC_OK;

    if (!cipher)
        cipher = LUKS_DEFAULT_CIPHER;

    if (version == LUKS_VERSION_1)
    {
        char cipher_name[LUKS_CIPHER_NAME_SIZE];
        char cipher_mode[LUKS_CIPHER_MODE_SIZE];

        CHECK(_split_cipher(cipher, cipher_name, cipher_mode));

        CHECK(luks1_format(
            device,
            cipher_name,
            cipher_mode,
            uuid,
            hash,
            mk_iterations,
            master_key,
            master_key_bytes));
    }
    else if (version == LUKS_VERSION_2)
    {
        CHECK(luks2_format(
            device,
            NULL, /* label */
            NULL, /* subsystem */
            cipher,
            uuid,
            hash,
            mk_iterations,
            master_key,
            master_key_bytes,
            integrity));
    }
    else
    {
        RAISE(VIC_BAD_VERSION);
    }

done:
    return result;
}

vic_result_t vic_luks_add_key(
    vic_blockdev_t* device,
    const char* keyslot_cipher,
    const char* kdf_type,
    vic_kdf_t* kdf,
    const char* pwd,
    size_t pwd_size,
    const char* new_pwd,
    size_t new_pwd_size)
{
    vic_result_t result = VIC_OK;
    vic_luks_hdr_t hdr;

    if (!_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        if (kdf_type && strcmp(kdf_type, "pbkdf2") != 0)
            RAISE(VIC_BAD_PARAMETER);

        CHECK(luks1_add_key(
            device,
            kdf ? kdf->iterations : 0,
            pwd,
            pwd_size,
            new_pwd,
            new_pwd_size));
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        CHECK(luks2_add_key(
            device,
            keyslot_cipher,
            kdf_type,
            kdf,
            pwd,
            pwd_size,
            new_pwd,
            new_pwd_size));
    }
    else
    {
        RAISE(VIC_BAD_VERSION);
    }

done:
    return result;
}

vic_result_t vic_luks_remove_key(
    vic_blockdev_t* device,
    const char* pwd,
    size_t pwd_size)
{
    vic_result_t result = VIC_OK;
    vic_luks_hdr_t hdr;

    if (!_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        CHECK(luks1_remove_key(device, pwd, pwd_size));
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        CHECK(luks2_remove_key(device, pwd, pwd_size));
    }
    else
    {
        RAISE(VIC_BAD_VERSION);
    }

done:
    return result;
}

vic_result_t vic_luks_change_key(
    vic_blockdev_t* device,
    const char* old_pwd,
    size_t old_pwd_size,
    const char* new_pwd,
    size_t new_pwd_size)
{
    vic_result_t result = VIC_OK;
    vic_luks_hdr_t hdr;

    if (!_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        CHECK(luks1_change_key(device, old_pwd, old_pwd_size, new_pwd,
            new_pwd_size));
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        CHECK(luks2_change_key(device, old_pwd, old_pwd_size, new_pwd,
            new_pwd_size));
    }
    else
    {
        RAISE(VIC_BAD_VERSION);
    }

done:
    return result;
}

vic_result_t vic_luks_load_key(
    const char* path,
    vic_key_t* key,
    size_t* key_size)
{
    vic_result_t result = VIC_OK;
    struct stat st;
    FILE* is = NULL;

    if (!path || !key || !key_size)
        RAISE(VIC_BAD_PARAMETER);

    if (stat(path, &st) != 0)
        RAISE(VIC_FAILED);

    if ((size_t)st.st_size > sizeof(vic_key_t))
        goto done;

    if (!(is = fopen(path, "rb")))
        RAISE(VIC_FAILED);

    if (fread(key, 1, st.st_size, is) != (size_t)st.st_size)
        RAISE(VIC_FAILED);

    *key_size = st.st_size;

done:

    if (is)
        fclose(is);

    return result;
}

vic_result_t vic_luks_stat(vic_blockdev_t* device, vic_luks_stat_t* buf)
{
    vic_result_t result = VIC_OK;
    vic_luks_hdr_t hdr;

    if (!_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        CHECK(luks1_stat(device, buf));
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        CHECK(luks2_stat(device, buf));
    }
    else
    {
        RAISE(VIC_BAD_VERSION);
    }

done:
    return result;
}

vic_result_t vic_luks_open(
    const char* path,
    const char* name,
    const vic_key_t* master_key,
    size_t master_key_bytes)
{
    vic_result_t result = VIC_OK;
    vic_luks_hdr_t hdr;
    vic_blockdev_t* device = NULL;

    CHECK(vic_blockdev_open(path, VIC_RDWR, VIC_SECTOR_SIZE, &device));

    if (!_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        CHECK(luks1_open(device, path, name, master_key, master_key_bytes));
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        CHECK(luks2_open(device, path, name, master_key, master_key_bytes));
    }
    else
    {
        RAISE(VIC_BAD_VERSION);
    }

done:

    if (device)
        vic_blockdev_close(device);

    return result;
}

vic_result_t vic_luks_close(const char* name)
{
    vic_result_t result = VIC_OK;

    if (!name)
        RAISE(VIC_BAD_PARAMETER);

    /* Remove the <name> device */
    CHECK(vic_dm_remove(name));

    /* Remove the <name>_dif device if it exists */
    {
        char name_dif[PATH_MAX];
        char dmpath[PATH_MAX];

        /* Format the name of the integrity device */
        if (snprintf(name_dif, sizeof(name_dif), "%s_dif", name) >= PATH_MAX)
            RAISE(VIC_BUFFER_TOO_SMALL);

        /* Format the name of the integrity device (under /dev/mapper) */
        snprintf(dmpath, sizeof(dmpath), "/dev/mapper/%s", name_dif);

        if (access(dmpath, R_OK) == 0)
            CHECK(vic_dm_remove(name_dif));
    }

done:
    return result;
}


vic_result_t vic_luks_add_key_by_master_key(
    vic_blockdev_t* device,
    const char* keyslot_cipher,
    const char* kdf_type,
    vic_kdf_t* kdf,
    const vic_key_t* master_key,
    size_t master_key_bytes,
    const char* pwd,
    size_t pwd_size)
{
    vic_result_t result = VIC_OK;
    vic_luks_hdr_t hdr;

    if (!_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        if (kdf_type && strcmp(kdf_type, "pbkdf2") != 0)
            RAISE(VIC_BAD_PARAMETER);

        CHECK(luks1_add_key_by_master_key(
            device,
            kdf ? kdf->iterations : 0,
            master_key,
            master_key_bytes,
            pwd,
            pwd_size));
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        CHECK(luks2_add_key_by_master_key(
            device,
            keyslot_cipher,
            kdf_type,
            kdf,
            master_key,
            master_key_bytes,
            pwd,
            pwd_size));
    }
    else
    {
        RAISE(VIC_BAD_VERSION);
    }

done:
    return result;
}
