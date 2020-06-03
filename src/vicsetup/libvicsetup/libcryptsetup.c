#include <libcryptsetup.h>
#include <vic.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "eraise.h"
#include "luks1.h"
#include "luks2.h"
#include "integrity.h"
#include "strings.h"
#include "crypto.h"
#include "verity.h"
#include "trace.h"
#include "malloc.h"

#define MAGIC 0xa8ea23c6

#define __FLF__ __FILE__, __LINE__, __FUNCTION__

#if 0
#define ENTER printf("ENTER: %s(%u): %s()\n", __FLF__);
#define LEAVE printf("LEAVE: %s(%u): %s()\n", __FLF__);
#else
#define ENTER
#define LEAVE
#endif


struct crypt_device
{
    uint32_t magic;
    char type[16];
    char dm_name[PATH_MAX];
    vic_blockdev_t* bd;
    vic_blockdev_t* hbd; /* hash block device */
    char path[PATH_MAX];
    bool readonly;

    /* Cached volume key for LUKS1 and LUKS2 */
    vic_key_t volume_key;
    size_t volume_key_size;

    struct
    {
        luks1_hdr_t* hdr;
    }
    luks1;
    struct
    {
        char cipher[LUKS2_ENCRYPTION_SIZE];
        struct crypt_pbkdf_type pbkdf;
        char pbkdf_type_buf[32];
        char pbkdf_hash_buf[VIC_MAX_HASH_SIZE];
        luks2_hdr_t* hdr;
    }
    luks2;
    struct
    {
        vic_verity_sb_t sb;
    }
    verity;
};

static int _set_pbkdf_type(
    struct crypt_device* cd,
    const struct crypt_pbkdf_type* pbkdf)
{
    int ret = 0;

    if (!cd || !pbkdf)
        ERAISE(EINVAL);

    cd->luks2.pbkdf = *pbkdf;

    if (pbkdf->type)
    {
        ECHECK(STRLCPY(cd->luks2.pbkdf_type_buf, pbkdf->type));
        cd->luks2.pbkdf.type = cd->luks2.pbkdf_type_buf;
    }

    if (pbkdf->hash)
    {
        ECHECK(STRLCPY(cd->luks2.pbkdf_hash_buf, pbkdf->hash));
        cd->luks2.pbkdf.hash = cd->luks2.pbkdf_hash_buf;
    }

done:
    return ret;
}

static bool _valid_cd(const struct crypt_device* cd)
{
    return cd && cd->magic == MAGIC;
}

static bool _is_luks1(const char* type)
{
    return type && strcmp(type, CRYPT_LUKS1) == 0;
}

static bool _is_luks2(const char* type)
{
    return type && strcmp(type, CRYPT_LUKS2) == 0;
}

static bool _is_verity(const char* type)
{
    return type && strcmp(type, CRYPT_VERITY) == 0;
}

static bool _is_integrity(const char* type)
{
    return type && strcmp(type, CRYPT_INTEGRITY) == 0;
}

static bool _valid_type(const char* s)
{
    return _is_luks1(s) || _is_luks2(s) || _is_verity(s) || _is_integrity(s);
}

int __crypt_init(struct crypt_device** cd_out, const char* device)
{
    int ret = 0;
    struct crypt_device* cd = NULL;

    ENTER;

    if (!cd_out || !device || strlen(device) >= PATH_MAX)
    {
        ret = -EINVAL;
        goto done;
    }

    if (!(cd = vic_calloc(sizeof(struct crypt_device), 1)))
    {
        ret = -ENOMEM;
        goto done;
    }

    strcpy(cd->path, device);

    /* Open device initially for read only */
    if (vic_blockdev_open(cd->path, VIC_RDONLY, 0, &cd->bd) != VIC_OK)
    {
        ret = -ENOENT;
        goto done;
    }

#if 0
    {
        size_t size;
        size_t blksz;

        if (vic_blockdev_get_size(cd->bd, &size) != VIC_OK)
        {
            ret = -ENOENT;
            goto done;
        }

        if (vic_blockdev_get_block_size(cd->bd, &blksz) != VIC_OK)
        {
            ret = -ENOENT;
            goto done;
        }

        printf("BLKDEV.SIZE=%zu\n", size);
        printf("BLKDEV.BLKSZ=%zu\n", blksz);
    }
#endif

    cd->readonly = true;
    cd->magic = MAGIC;
    *cd_out = cd;
    cd = NULL;

done:
    if (cd)
        crypt_free(cd);

    LEAVE;
    return ret;
}

static int _force_open_for_write(struct crypt_device* cd)
{
    int ret = 0;

    if (!cd)
        ERAISE(EINVAL);

    if (cd->readonly)
    {
        if (vic_blockdev_close(cd->bd) != VIC_OK)
            ERAISE(EIO);

        if (vic_blockdev_open(cd->path, VIC_RDWR, 0, &cd->bd) != VIC_OK)
            ERAISE(EIO);

        cd->readonly = false;
    }

done:
    return ret;
}

void __crypt_free(struct crypt_device* cd)
{
    ENTER;

    if (cd)
    {
        if (cd->bd)
            vic_blockdev_close(cd->bd);

        if (cd->hbd)
            vic_blockdev_close(cd->hbd);

        memset(cd, 0, sizeof(struct crypt_device));
        vic_free(cd);
    }

    LEAVE;
}

int __crypt_deactivate_by_name(
    struct crypt_device* cd,
    const char* name,
    uint32_t flags)
{
    int ret = 0;
    ENTER;

    if (!name)
        ERAISE(EINVAL);

    /* Flags not supported */
    if (flags)
        ERAISE(ENOTSUP);

    if (cd)
    {
        if (_is_luks1(cd->type))
        {
            if (*cd->dm_name)
            {
                if (vic_luks_close(cd->dm_name) != VIC_OK)
                    ERAISE(ENOSYS);

                *cd->dm_name = '\0';
            }

            if (cd->luks1.hdr)
                vic_free(cd->luks1.hdr);

            memset(&cd->luks1, 0, sizeof(cd->luks1));
        }
        else if (_is_luks2(cd->type))
        {
            if (*cd->dm_name)
            {
                if (vic_luks_close(cd->dm_name) != VIC_OK)
                    ERAISE(ENOSYS);

                *cd->dm_name = '\0';
            }

            if (cd->luks2.hdr)
                vic_free(cd->luks2.hdr);

            memset(&cd->luks2, 0, sizeof(cd->luks2));
        }
        else if (_is_verity(cd->type))
        {
            if (*cd->dm_name)
            {
                vic_verity_close(cd->dm_name);
                *cd->dm_name = '\0';
            }

            memset(&cd->verity, 0, sizeof(cd->verity));
        }
        else
        {
            ERAISE(EINVAL);
        }
    }
    else if (name)
    {
        if (vic_luks_close(name) != VIC_OK)
            ERAISE(ENOSYS);
    }

done:
    LEAVE;
    return ret;
}

int __crypt_format(
    struct crypt_device* cd,
    const char* type,
    const char* cipher_name,
    const char* cipher_mode,
    const char* uuid,
    const char* volume_key,
    size_t volume_key_size,
    void* params)
{
    int ret = 0;

    ENTER;

    if (!type)
        type = CRYPT_LUKS1;

    if (!_valid_cd(cd) || !_valid_type(type) || !cipher_name || !cipher_mode)
        ERAISE(EINVAL);

    if (!volume_key_size || volume_key_size > sizeof(vic_key_t))
        ERAISE(EINVAL);

    /* Cache the key or generated key (for use in subsequent functions) */
    if (volume_key)
    {
        cd->volume_key_size = volume_key_size;
        memcpy(&cd->volume_key, volume_key, volume_key_size);
    }
    else
    {
        /* Save in crypt device for later (used when adding keyslots) */
        vic_random(&cd->volume_key, volume_key_size);
        cd->volume_key_size = volume_key_size;
        volume_key = (const char*)cd->volume_key.buf;
    }

    ECHECK(_force_open_for_write(cd));

    /* Save the type for use in subsequent calls */
    ECHECK(STRLCPY(cd->type, type));

    if (strcmp(type, CRYPT_LUKS1) == 0)
    {
        struct crypt_params_luks1* p = params;
        const char* hash = NULL;
        vic_result_t r;

        if (p)
        {
            if (p->data_alignment || p->data_device)
                ERAISE(ENOTSUP);

            hash = p->hash;
        }

        if ((r = luks1_format(
            cd->bd,
            cipher_name,
            cipher_mode,
            uuid,
            hash,
            0, /* mk_iterations */
            (const vic_key_t*)volume_key,
            volume_key_size)) != VIC_OK)
        {
            ERAISE(EINVAL);
        }
    }
    else if (strcmp(type, CRYPT_LUKS2) == 0)
    {
        char cipher[128];
        const struct crypt_params_luks2* p = params;
        const char* hash = NULL;
        const char* label = NULL;
        const char* subsystem = NULL;
        uint64_t iterations = 0;
        vic_result_t r;
        int n;

        if (p)
        {
            if (p->integrity_params)
                ERAISE(ENOTSUP);

            if (p->data_alignment)
                ERAISE(ENOTSUP);

            if (p->data_device)
                ERAISE(ENOTSUP);

            if (p->sector_size && p->sector_size != VIC_SECTOR_SIZE)
                ERAISE(ENOTSUP);

            label = p->label;
            subsystem = p->subsystem;

            if (p->integrity && !vic_integrity_valid(p->integrity))
                ERAISE(EINVAL);

            if (p->pbkdf)
            {
                hash = p->pbkdf->hash;
                iterations = p->pbkdf->iterations;

                /* Save pbkdf for use in subsequent functions */
                ECHECK(_set_pbkdf_type(cd, p->pbkdf));
            }
        }

        n = snprintf(cipher, sizeof(cipher), "%s-%s", cipher_name, cipher_mode);
        if (n <= 0 || n >= (int)sizeof(cipher))
            ERAISE(EINVAL);

        /* Save the cipher for later (used when adding keyslots) */
        ECHECK(STRLCPY(cd->luks2.cipher, cipher));

        if ((r = luks2_format(
            cd->bd,
            label,
            subsystem,
            cipher,
            uuid,
            hash,
            iterations,
            (const vic_key_t*)volume_key,
            volume_key_size,
            p->integrity)) != VIC_OK)
        {
            ERAISE(EINVAL);
        }
    }
    else
    {
        ERAISE(EINVAL);
    }

done:
    LEAVE;
    return ret;
}

int __crypt_keyslot_add_by_key(
    struct crypt_device* cd,
    int keyslot,
    const char* volume_key,
    size_t volume_key_size,
    const char* passphrase,
    size_t passphrase_size,
    uint32_t flags)
{
    int ret = 0;

    ENTER;

    /* Check parameters */
    {
        if (!_valid_cd(cd))
            ERAISE(EINVAL);

        /* ATTN: keyslot selection not supported */
        if (keyslot != CRYPT_ANY_SLOT)
            ERAISE(ENOTSUP);

        /* If volume_key is null, use the one stored by crypt_format() */
        if (!volume_key)
        {
            if (volume_key_size != 0)
                ERAISE(EINVAL);

            volume_key = (const char*)cd->volume_key.buf;
            volume_key_size = cd->volume_key_size;
        }

        if (volume_key_size && !volume_key_size)
            ERAISE(EINVAL);

        if (!passphrase || !passphrase_size)
            ERAISE(EINVAL);

        /* ATTN: limited flag support */
        if (flags & ~CRYPT_PBKDF_NO_BENCHMARK)
            ERAISE(EINVAL);

        if (!_valid_type(cd->type))
            ERAISE(EINVAL);
    }

    if (_is_luks1(cd->type))
    {
        vic_result_t r;

        if ((r = luks1_add_key_by_master_key(
            cd->bd,
            0,
            (const vic_key_t*)volume_key,
            volume_key_size,
            passphrase,
            passphrase_size)) != VIC_OK)
        {
            ERAISE(EINVAL);
        }
    }
    else if (_is_luks2(cd->type))
    {
        vic_result_t r;
        vic_kdf_t kdf =
        {
            .hash = cd->luks2.pbkdf.hash,
            .iterations = cd->luks2.pbkdf.iterations,
            .time = cd->luks2.pbkdf.time_ms,
            .memory = cd->luks2.pbkdf.max_memory_kb,
            .cpus = cd->luks2.pbkdf.parallel_threads,
        };

        if ((r = luks2_add_key_by_master_key(
            cd->bd,
            cd->luks2.cipher,
            cd->luks2.pbkdf.type,
            &kdf,
            (const vic_key_t*)volume_key,
            volume_key_size,
            passphrase,
            passphrase_size)) != VIC_OK)
        {
            ERAISE(EINVAL);
        }
    }
    else
    {
        ERAISE(EINVAL);
    }

done:
    LEAVE;
    return ret;
}

static int _crypt_load_verity(
    struct crypt_device* cd,
    struct crypt_params_verity* p)
{
    int ret = 0;
    /* ATTN: block size hardcoded for 4096 for now */
    const size_t BLOCK_SIZE = 4096;
    vic_blockdev_t* hbd = NULL;
    vic_verity_sb_t sb;

    ENTER;

    if (!p || !p->data_device || !p->hash_device)
        ERAISE(EINVAL);

    if (p->fec_device)
        ERAISE(ENOTSUP);

    if (p->data_block_size && p->data_block_size != BLOCK_SIZE)
        ERAISE(EINVAL);

    if (p->hash_block_size && p->hash_block_size != BLOCK_SIZE)
        ERAISE(EINVAL);

    /* Handle the data device */
    {
        if (strcmp(p->data_device, cd->path) != 0)
            ERAISE(EINVAL);

        if (vic_blockdev_set_block_size(cd->bd, BLOCK_SIZE) != VIC_OK)
            ERAISE(EINVAL);

        if (p->data_size)
        {
            const size_t size = p->data_size * BLOCK_SIZE;

            if (vic_blockdev_set_size(cd->bd, size) != VIC_OK)
                ERAISE(EIO);
        }
    }

    /* Handle the hash device */
    {
        if (vic_blockdev_open(p->hash_device, VIC_RDONLY, 0, &hbd) != VIC_OK)
            ERAISE(ENOENT);

        if (vic_blockdev_set_block_size(hbd, BLOCK_SIZE) != VIC_OK)
            ERAISE(EINVAL);

        if (p->hash_area_offset)
        {
            if (vic_blockdev_set_offset(hbd, p->hash_area_offset) != VIC_OK)
                ERAISE(EINVAL);
        }

        if (vic_verity_read_superblock(hbd, &sb) != VIC_OK)
            ERAISE(EIO);

        if (sb.data_block_size != BLOCK_SIZE)
            ERAISE(ENOTSUP);

        if (sb.hash_block_size != BLOCK_SIZE)
            ERAISE(ENOTSUP);

        if (p->hash_block_size && p->hash_block_size != sb.hash_block_size)
            ERAISE(EINVAL);

        cd->verity.sb = sb;
    }

    cd->hbd = hbd;
    hbd = NULL;

done:

    if (hbd)
        vic_blockdev_close(hbd);

    LEAVE;
    return ret;
}

int __crypt_load(
    struct crypt_device* cd,
    const char* requested_type,
    void* params)
{
    int ret = 0;

    (void)params;

    ENTER;

    if (!_valid_cd(cd))
        ERAISE(EINVAL);

    if (!cd->bd)
        ERAISE(EINVAL);

    if (*cd->type != '\0')
        ERAISE(EBUSY);

    if (!requested_type)
        requested_type = CRYPT_LUKS1;

    if (strcmp(requested_type, CRYPT_LUKS1) == 0)
    {
        ECHECK(STRLCPY(cd->type, requested_type));

        if (luks1_read_hdr(cd->bd, &cd->luks1.hdr) != VIC_OK)
            ERAISE(EIO);
    }
    else if (strcmp(requested_type, CRYPT_LUKS2) == 0)
    {
        ECHECK(STRLCPY(cd->type, requested_type));

        if (luks2_read_hdr(cd->bd, &cd->luks2.hdr) != VIC_OK)
        {
            ERAISE(EIO);
        }
    }
    else if (strcmp(requested_type, CRYPT_VERITY) == 0)
    {
        ECHECK(STRLCPY(cd->type, requested_type));
        ECHECK(_crypt_load_verity(cd, params));
    }
    else
    {
        ERAISE(ENOTSUP);
    }

done:
    LEAVE;
    return ret;
}

int __crypt_activate_by_passphrase(
    struct crypt_device* cd,
    const char* name,
    int keyslot,
    const char* passphrase,
    size_t passphrase_size,
    uint32_t flags)
{
    int ret = 0;

    ENTER;

    if (!_valid_cd(cd) || !cd->bd || !name || !passphrase || !passphrase_size)
        ERAISE(EINVAL);

    if (*cd->type == '\0')
        ERAISE(EINVAL);

    /* If already open within /dev/mapper */
    if (*cd->dm_name != '\0')
        ERAISE(EINVAL);

    if (keyslot != CRYPT_ANY_SLOT)
        ERAISE(ENOTSUP);

    if (_is_luks1(cd->type))
    {
        vic_key_t key;
        size_t key_size;

        /* ATTN: only support read-only flag for now */
        if (flags & ~CRYPT_ACTIVATE_READONLY)
            ERAISE(EINVAL);

        if (!(flags & CRYPT_ACTIVATE_READONLY))
            ECHECK(_force_open_for_write(cd));

        /* Use the passphrase to recover the master key */
        if (luks1_recover_master_key(cd->bd, passphrase, passphrase_size,
            &key, &key_size) != VIC_OK)
        {
            ERAISE(EIO);
        }

        /* Open the LUKS1 device */
        if (luks1_open(cd->bd, cd->path, name, &key, key_size) != VIC_OK)
            ERAISE(EIO);

        ECHECK(STRLCPY(cd->dm_name, name));
    }
    else if (_is_luks2(cd->type))
    {
        /* Open the LUKS1 device */

        /* ATTN: only support read-only flag for now */
        if (flags & ~CRYPT_ACTIVATE_READONLY)
            ERAISE(EINVAL);

        if (!(flags & CRYPT_ACTIVATE_READONLY))
            ECHECK(_force_open_for_write(cd));

        if (luks2_open_by_passphrase(
            cd->bd,
            cd->luks2.hdr,
            cd->path,
            name,
            passphrase,
            passphrase_size) != VIC_OK)
        {
            ERAISE(EIO);
        }

        ECHECK(STRLCPY(cd->dm_name, name));
    }
    else if (_is_verity(cd->type))
    {
        ERAISE(ENOTSUP);
    }
    else
    {
        ERAISE(ENOTSUP);
    }

done:
    LEAVE;
    return ret;
}

int __crypt_activate_by_volume_key(
    struct crypt_device* cd,
    const char* name,
    const char* volume_key,
    size_t volume_key_size,
    uint32_t flags)
{
    int ret = 0;

    ENTER;

    if (!_valid_cd(cd) || !cd->bd || !name || !volume_key || !volume_key_size)
        ERAISE(EINVAL);

    if (volume_key_size > sizeof(vic_key_t))
        ERAISE(EINVAL);

    if (*cd->type == '\0')
        ERAISE(EINVAL);

    /* If already open within /dev/mapper */
    if (*cd->dm_name != '\0')
        ERAISE(EINVAL);

    if (_is_luks1(cd->type))
    {
        vic_key_t key;
        size_t key_size;

        memcpy(&key, volume_key, volume_key_size);
        key_size = volume_key_size;

        /* ATTN: only support read-only flag for now */
        if (flags & ~CRYPT_ACTIVATE_READONLY)
            ERAISE(EINVAL);

        if (!(flags & CRYPT_ACTIVATE_READONLY))
            ECHECK(_force_open_for_write(cd));

        /* Open the LUKS1 device */
        if (luks1_open(cd->bd, cd->path, name, &key, key_size) != VIC_OK)
            ERAISE(EIO);

        ECHECK(STRLCPY(cd->dm_name, name));

        ERAISE(ENOTSUP);
    }
    else if (_is_luks2(cd->type))
    {
        vic_key_t key;
        size_t key_size;

        memcpy(&key, volume_key, volume_key_size);
        key_size = volume_key_size;

        /* ATTN: only support read-only flag for now */
        if (flags & ~CRYPT_ACTIVATE_READONLY)
            ERAISE(EINVAL);

        if (!(flags & CRYPT_ACTIVATE_READONLY))
            ECHECK(_force_open_for_write(cd));

        /* Open the LUKS1 device */
        if (luks2_open(cd->bd, cd->path, name, &key, key_size) != VIC_OK)
            ERAISE(EIO);

        ECHECK(STRLCPY(cd->dm_name, name));

        ERAISE(ENOTSUP);
    }
    else if (_is_verity(cd->type))
    {
        if (!cd->hbd)
            ERAISE(EINVAL);

        if (vic_verity_open(
            name,
            cd->bd,
            cd->hbd,
            volume_key, /* root hash */
            volume_key_size) != VIC_OK)
        {
            ERAISE(EIO);
        }
    }
    else
    {
        ERAISE(ENOTSUP);
    }

done:
    LEAVE;
    return ret;
}

int __crypt_get_volume_key_size(struct crypt_device *cd)
{
    int ret = 0;

    ENTER;

    if (!_valid_cd(cd))
        goto done;

    if (_is_luks1(cd->type))
    {
        if (cd->luks1.hdr)
        {
            ret = cd->luks1.hdr->key_bytes;
            goto done;
        }
    }
    else if (_is_luks2(cd->type))
    {
        const luks2_ext_hdr_t* ext = (luks2_ext_hdr_t*)cd->luks2.hdr;

        if (ext)
        {
            ret = ext->keyslots[0].key_size;
            goto done;
        }
    }
    else if (_is_verity(cd->type))
    {
        size_t size;

        if ((size = vic_hash_size(cd->verity.sb.algorithm)) != (size_t)-1)
        {
            ret = (int)size;
            goto done;
        }
    }

done:
    LEAVE;
    return ret;
}

void __crypt_set_debug_level(int level)
{
    ENTER;

    switch (level)
    {
        case CRYPT_DEBUG_ALL:
            vic_trace_set_level(VIC_TRACE_DEBUG);
            break;
        case CRYPT_DEBUG_JSON:
            vic_trace_set_level(VIC_TRACE_DEBUG);
            break;
        default:
            vic_trace_set_level(VIC_TRACE_NONE);
            break;
    }

    LEAVE;
}
