#include <mbedtls/pkcs5.h>
#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/base64.h>
#include <stdio.h>
#include <sys/uio.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <ctype.h>

#include "luks1.h"
#include "vic.h"
#include "byteorder.h"
#include "strings.h"
#include "hash.h"
#include "lukscommon.h"
#include "hexdump.h"
#include "raise.h"
#include "crypto.h"
#include "uuid.h"
#include "dm.h"
#include "round.h"
#include "goto.h"
#include "malloc.h"

/*
**==============================================================================
**
** Local definitions:
**
**==============================================================================
*/

/* The number of keys in the key material */
#define LUKS_STRIPES 4000

#define LUKS_ALIGN_KEYSLOTS 4096

/* values for vic_luks_keyslot_t.active */
#define LUKS_KEY_DISABLED 0x0000dead
#define LUKS_KEY_ENABLED 0x00ac71f3

#define LUKS_DISK_ALIGNMENT (1024 * 1024)

#define LUKS_IV_SIZE 16

#define DEFAULT_HASH "sha256"

static uint8_t _magic_1st[LUKS_MAGIC_SIZE] = LUKS_MAGIC_1ST;

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

static bool _is_valid_luks1_hdr(const luks1_hdr_t* hdr, bool swap)
{
    if (!hdr)
        return false;

    if (memcmp(hdr->magic, _magic_1st, sizeof(_magic_1st)) != 0)
        return false;

    if (swap)
    {
        if (vic_swap_u16(hdr->version) != LUKS_VERSION_1)
            return false;
    }
    else
    {
        if (hdr->version != LUKS_VERSION_1)
            return false;
    }

    return true;
}

static void _fix_luks1_hdr_byte_order(luks1_hdr_t* hdr)
{
    int i;

    if (!vic_is_big_endian())
    {
        hdr->version = vic_swap_u16(hdr->version);
        hdr->payload_offset = vic_swap_u32(hdr->payload_offset);
        hdr->key_bytes = vic_swap_u32(hdr->key_bytes);
        hdr->mk_digest_iter = vic_swap_u32(hdr->mk_digest_iter);

        for (i = 0; i < LUKS_NUM_KEYS; i++)
        {
            vic_luks_keyslot_t* p = &hdr->keyslots[i];
            p->active = vic_swap_u32(p->active);
            p->iterations = vic_swap_u32(p->iterations);
            p->key_material_offset = vic_swap_u32(p->key_material_offset);
            p->stripes = vic_swap_u32(p->stripes);
        }
    }
}

static bool _valid_cipher_name(const char* cipher_name)
{
    static const char* _cipher_names[] =
    {
        LUKS_CIPHER_NAME_AES,
        LUKS_CIPHER_NAME_TWOFISH,
        LUKS_CIPHER_NAME_SERPENT,
        LUKS_CIPHER_NAME_CAST5,
        LUKS_CIPHER_NAME_CAST6,
    };

    if (!cipher_name || strlen(cipher_name) >= LUKS_CIPHER_NAME_SIZE)
        return false;

    for (size_t i = 0; i < VIC_COUNTOF(_cipher_names); i++)
    {
        if (strcmp(_cipher_names[i], cipher_name) == 0)
            return true;
    }

    return false;
}

static bool _valid_cipher_mode(const char* cipher_mode)
{
    static const char* _cipher_modes[] =
    {
        LUKS_CIPHER_MODE_ECB,
        LUKS_CIPHER_MODE_CBC_PLAIN,
        LUKS_CIPHER_MODE_CBC_ESSIV,
        LUKS_CIPHER_MODE_CBC_ESSIV_SHA256,
        LUKS_CIPHER_MODE_CBC_ESSIV_SHA512,
        LUKS_CIPHER_MODE_CBC_ESSIV_RIPEMD160,
        LUKS_CIPHER_MODE_XTS_PLAIN64,
    };

    if (!cipher_mode || strlen(cipher_mode) >= LUKS_CIPHER_NAME_SIZE)
        return false;

    for (size_t i = 0; i < VIC_COUNTOF(_cipher_modes); i++)
    {
        if (strcmp(_cipher_modes[i], cipher_mode) == 0)
            return true;
    }

    return false;
}

static bool _valid_hash_spec(const char* hash_spec)
{
    static const char* _hash_specs[] =
    {
        VIC_HASH_SPEC_SHA1,
        VIC_HASH_SPEC_SHA256,
        VIC_HASH_SPEC_SHA512,
        VIC_HASH_SPEC_RIPEMD160,
    };

    if (!hash_spec || strlen(hash_spec) >= LUKS_CIPHER_NAME_SIZE)
        return false;

    for (size_t i = 0; i < VIC_COUNTOF(_hash_specs); i++)
    {
        if (strcmp(_hash_specs[i], hash_spec) == 0)
            return true;
    }

    return false;
}

static void _dump_keyslot(const vic_luks_keyslot_t* slot)
{
    if (slot->active == LUKS_KEY_DISABLED)
    {
        printf("DISABLED\n");
    }
    else if (slot->active == LUKS_KEY_ENABLED)
    {
        printf("ENABLED\n");
    }
    else
    {
        /* Ignore error */
        return;
    }

    if (slot->active == LUKS_KEY_DISABLED)
        return;

    printf("\tIterations:\t\t%d\n", slot->iterations);

    printf("\tSalt:\t\t\t");

    const size_t n = LUKS_SALT_SIZE / 2;
    vic_hexdump_formatted(slot->salt, n);
    printf("\t\t\t\t");
    vic_hexdump_formatted(slot->salt + n, n);

    printf("\tKey material offset:\t%d\n", slot->key_material_offset);
    printf("\tAF stripes:\t\t%d\n", slot->stripes);
}

int luks1_dump_hdr(const luks1_hdr_t* hdr)
{
    int ret = -1;
    int i;

    /* Reject null parameters */
    if (!hdr || !_is_valid_luks1_hdr(hdr, false))
        GOTO(done);

    printf("LUKS header information\n");

    printf("Version:\t%d\n", hdr->version);

    printf("Cipher name:\t%s\n", hdr->cipher_name);
    printf("Cipher mode:\t%s\n", hdr->cipher_mode);
    printf("Hash spec:\t%s\n", hdr->hash_spec);

    printf("Payload offset:\t%d\n", hdr->payload_offset);

    printf("MK bits:\t%d\n", hdr->key_bytes * 8);

    printf("MK digest\t");
    vic_hexdump_formatted(hdr->mk_digest, LUKS_DIGEST_SIZE);

    printf("MK salt\t\t");
    const size_t n = LUKS_SALT_SIZE / 2;
    vic_hexdump_formatted(hdr->mk_digest_salt, n);
    printf("\t\t");
    vic_hexdump_formatted(hdr->mk_digest_salt + n, n);

    printf("MK iterations:\t%d\n", hdr->mk_digest_iter);

    printf("UUID:\t\t%s\n", hdr->uuid);

    printf("\n");

    for (i = 0; i < LUKS_NUM_KEYS; i++)
    {
        printf("Key Slot %d: ", i);
        _dump_keyslot(&hdr->keyslots[i]);
    }

    ret = 0;

done:
    return ret;
}

static const mbedtls_cipher_info_t* _get_cipher_info(const luks1_hdr_t* hdr)
{
    const mbedtls_cipher_info_t* ret = NULL;
    mbedtls_cipher_type_t cipher_type;
    uint32_t key_bits;

    if (!hdr)
        GOTO(done);

    /* ATTN-C: Only AES is supported */
    if (strcmp(hdr->cipher_name, LUKS_CIPHER_NAME_AES) != 0)
        return NULL;

    key_bits = hdr->key_bytes * 8;

    if (strcmp(hdr->cipher_mode, LUKS_CIPHER_MODE_ECB) == 0)
    {
        switch (key_bits)
        {
            case 128:
                cipher_type = MBEDTLS_CIPHER_AES_128_ECB;
                break;
            case 256:
                cipher_type = MBEDTLS_CIPHER_AES_256_ECB;
                break;
            default:
                GOTO(done);
        }
    }
    else if (strcmp(hdr->cipher_mode, LUKS_CIPHER_MODE_CBC_PLAIN) == 0)
    {
        switch (key_bits)
        {
            case 128:
                cipher_type = MBEDTLS_CIPHER_AES_128_CBC;
                break;
            case 256:
                cipher_type = MBEDTLS_CIPHER_AES_256_CBC;
                break;
            default:
                GOTO(done);
        }
    }
    else if (strcmp(hdr->cipher_mode, LUKS_CIPHER_MODE_XTS_PLAIN64) == 0)
    {
        /* XTS splits the key in half */
        switch (key_bits / 2)
        {
            case 128:
                cipher_type = MBEDTLS_CIPHER_AES_128_XTS;
                break;
            case 256:
                cipher_type = MBEDTLS_CIPHER_AES_256_XTS;
                break;
            default:
                GOTO(done);
        }
    }
    else
    {
        return NULL;
    }

    ret = mbedtls_cipher_info_from_type(cipher_type);

done:
    return ret;
}

/* Generate the initialization vector */
static int _gen_iv(
    const luks1_hdr_t* hdr,
    uint64_t sector,
    uint8_t* iv,
    const uint8_t* key)
{
    int ret = -1;
    vic_hash_t hash;
    mbedtls_aes_context aes_ctx;

    mbedtls_aes_init(&aes_ctx);

    if (iv)
        memset(iv, 0, LUKS_IV_SIZE);

    if (!hdr || !iv || !key)
        GOTO(done);

    if (strcmp(LUKS_CIPHER_MODE_ECB,  hdr->cipher_mode) == 0)
    {
        memset(iv, 0, LUKS_IV_SIZE);
        ret = 0;
        goto done;
    }

    if (strcmp(LUKS_CIPHER_MODE_CBC_PLAIN, hdr->cipher_mode) == 0)
    {
        /* Assume little endian where the sector number is captured */
        memcpy(iv, &sector, sizeof(uint32_t));
        ret = 0;
        goto done;
    }

    if (strcmp(LUKS_CIPHER_MODE_XTS_PLAIN64, hdr->cipher_mode) == 0)
    {
        memcpy(iv, &sector, sizeof(uint64_t));
        ret = 0;
        goto done;
    }

    /* Compute the hash of the key */
    if (vic_hash1(VIC_HASH_SHA256, key, hdr->key_bytes, &hash) != 0)
        GOTO(done);

    /* Use the SHA256-generated hash as the key */
    if (mbedtls_aes_setkey_enc(
        &aes_ctx, hash.u.sha256, sizeof(hash.u.sha256) * 8) != 0)
    {
        GOTO(done);
    }

    /* Encrypt the sector number with the generated key hash to get the IV */
    {
        uint8_t buf[LUKS_IV_SIZE];

        memset(buf, 0, sizeof(buf));
        memcpy(buf, &sector, sizeof(uint64_t));

        /* Encrypt the buffer with the hash of the key, yielding the IV. */
        if (mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, buf, iv) != 0)
            GOTO(done);
    }

    ret = 0;

done:

    mbedtls_aes_free(&aes_ctx);

    return ret;
}

static int _crypt(
    const luks1_hdr_t* hdr,
    mbedtls_operation_t op, /* MBEDTLS_ENCRYPT or MBEDTLS_DECRYPT */
    const vic_key_t* key,
    const uint8_t* data_in,
    uint8_t* data_out,
    size_t data_size,
    uint64_t sector)
{
    int ret = -1;
    const mbedtls_cipher_info_t* ci;
    mbedtls_cipher_context_t ctx;
    uint8_t iv[LUKS_IV_SIZE];
    uint64_t i;
    uint64_t iters;
    uint64_t block_size;

    mbedtls_cipher_init(&ctx);

    if (!(ci = _get_cipher_info(hdr)))
    {
        /* ATTN-C: unsupported cipher */
        GOTO(done);
    }

    if (mbedtls_cipher_setup(&ctx, ci) != 0)
        GOTO(done);

    const size_t key_bits = hdr->key_bytes * 8;

    if (mbedtls_cipher_setkey(&ctx, key->buf, key_bits, op) != 0)
        GOTO(done);

    if (strcmp(hdr->cipher_mode, LUKS_CIPHER_MODE_CBC_PLAIN) == 0 &&
        mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_NONE) != 0)
    {
        GOTO(done);
    }

    /* Determine the block size */
    if (strcmp(hdr->cipher_mode, LUKS_CIPHER_MODE_ECB) == 0)
    {
        iters = 1;
        block_size = mbedtls_cipher_get_block_size(&ctx);
    }
    else
    {
        block_size = VIC_SECTOR_SIZE;
    }

    iters = data_size / block_size;

    for (i = 0; i < iters; i++)
    {
        uint64_t pos;
        size_t olen;
        int r;

        if (_gen_iv(hdr, sector + i, iv, key->buf) == -1)
            GOTO(done);

        pos = i * block_size;

        if ((r = mbedtls_cipher_crypt(
            &ctx,
            iv, /* iv */
            LUKS_IV_SIZE, /* iv_size */
            data_in + pos, /* input */
            block_size, /* ilen */
            data_out + pos, /* output */
            &olen)) != 0) /* olen */
        {
            printf("r=%d\n", r);
            printf("%d\n", MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED);
            GOTO(done);
        }

        if (olen != block_size)
            GOTO(done);
    }

    ret = 0;

done:
    mbedtls_cipher_free(&ctx);

    return ret;
}

static int _encrypt(
    const luks1_hdr_t* hdr,
    const vic_key_t* key,
    const uint8_t* data_in,
    uint8_t *data_out,
    size_t data_size,
    uint64_t sector)
{
    const mbedtls_operation_t op = MBEDTLS_ENCRYPT;
    return _crypt(hdr, op, key, data_in, data_out, data_size, sector);
}

static int _decrypt(
    const luks1_hdr_t* hdr,
    const vic_key_t* key,
    const uint8_t* data_in,
    uint8_t *data_out,
    size_t data_size,
    uint64_t sector)
{
    const mbedtls_operation_t op = MBEDTLS_DECRYPT;
    return _crypt(hdr, op, key, data_in, data_out, data_size, sector);
}

int luks1_read_hdr(vic_blockdev_t* device, luks1_hdr_t** hdr_out)
{
    int ret = -1;
    uint8_t blocks[VIC_SECTOR_SIZE * 2];
    const size_t nblocks = 2;
    luks1_hdr_t hdr;

    if (hdr_out)
        *hdr_out = NULL;

    /* Reject null parameters */
    if (!_is_valid_device(device) || !hdr_out)
        GOTO(done);

    /* Read two blocks to obtain enough bytes for the header */
    if (vic_blockdev_get(device, 0, blocks, nblocks) != VIC_OK)
        GOTO(done);

    VIC_STATIC_ASSERT(sizeof(luks1_hdr_t) <= sizeof(blocks));
    memcpy(&hdr, blocks, sizeof(luks1_hdr_t));

    /* Check the magic number */
    if (!_is_valid_luks1_hdr(&hdr, true))
        GOTO(done);

    /* Adjust byte order from big-endian to native */
    _fix_luks1_hdr_byte_order(&hdr);

    if (!(*hdr_out = vic_calloc(1, sizeof(luks1_hdr_t))))
        GOTO(done);

    memcpy(*hdr_out, &hdr, sizeof(luks1_hdr_t));

    ret = 0;

done:
    return ret;
}

static int _write_luks1_hdr(vic_blockdev_t* device, const luks1_hdr_t* hdr)
{
    int ret = -1;
    uint8_t blocks[VIC_SECTOR_SIZE * 2];
    size_t nblocks = 2;
    luks1_hdr_t buf;

    if (!device || !hdr)
        GOTO(done);

    buf = *hdr;
    _fix_luks1_hdr_byte_order(&buf);
    memset(blocks, 0, sizeof(blocks));
    memcpy(blocks, &buf, sizeof(luks1_hdr_t));

    if (vic_blockdev_put(device, 0, blocks, nblocks) != 0)
        GOTO(done);

    ret = 0;

done:
    return ret;
}

static int _write_key_material(
    vic_blockdev_t* device,
    const luks1_hdr_t* hdr,
    const vic_luks_keyslot_t* ks,
    const void* buf)
{
    int ret = -1;
    void* zeros = NULL;

    if (!device || !hdr || !ks)
        GOTO(done);

    /* Write the key material (or clear it if buf is null) */
    {
        uint64_t blkno = ks->key_material_offset;
        size_t nblocks = (ks->stripes * hdr->key_bytes) / VIC_SECTOR_SIZE;

        if (buf)
        {
            if (vic_blockdev_put(device, blkno, buf, nblocks) != VIC_OK)
                GOTO(done);
        }
        else
        {
            if (!(zeros = vic_calloc(ks->stripes * hdr->key_bytes, 1)))
                GOTO(done);

            if (vic_blockdev_put(device, blkno, zeros, nblocks) != 0)
                GOTO(done);
        }
    }

    ret = 0;

done:

    if (zeros)
        vic_free(zeros);

    return ret;
}

static int _read_key_material(
    vic_blockdev_t* device,
    const luks1_hdr_t* hdr,
    const vic_luks_keyslot_t* ks,
    void* buf)
{
    int ret = -1;

    if (!device || !hdr || !ks || !buf)
        GOTO(done);

    /* Read the stripes */
    {
        uint64_t blkno = ks->key_material_offset;
        size_t nblocks = (ks->stripes * hdr->key_bytes) / VIC_SECTOR_SIZE;

        if (vic_blockdev_get(device, blkno, buf, nblocks) != VIC_OK)
            GOTO(done);
    }

    ret = 0;

done:
    return ret;
}

static int _initialize_hdr(
    luks1_hdr_t* hdr,
    uint16_t version,
    const char* cipher_name,
    const char* cipher_mode,
    const vic_key_t* master_key,
    size_t master_key_bytes,
    const char* hash_spec,
    const char* uuid,
    uint64_t mk_iterations)
{
    int ret = -1;
    size_t stripes;
    size_t base_offset;
    size_t key_material_sectors;

    if (hdr)
        memset(hdr, 0, sizeof(luks1_hdr_t));

    /* Check parameters */
    {
        if (!hdr || version != LUKS_VERSION_1)
            GOTO(done);

        if (!_valid_cipher_name(cipher_name))
            GOTO(done);

        if (!_valid_cipher_mode(cipher_mode))
            GOTO(done);

        if (!master_key || !master_key_bytes)
            GOTO(done);

        if (!_valid_hash_spec(hash_spec))
            GOTO(done);
    }

    memcpy(hdr->magic, _magic_1st, sizeof(hdr->magic));
    hdr->version = LUKS_VERSION_1;
    strcpy(hdr->cipher_name, cipher_name);
    strcpy(hdr->cipher_mode, cipher_mode);
    strcpy(hdr->hash_spec, hash_spec);
    hdr->key_bytes = master_key_bytes;

    /* Randomly generate the digest salt */
    vic_random(hdr->mk_digest_salt, sizeof(hdr->mk_digest_salt));

    hdr->mk_digest_iter = mk_iterations;

    /* Derive the digest from the master key and the salt */
    if (vic_pbkdf2(
        master_key->buf,
        master_key_bytes,
        hdr->mk_digest_salt,
        sizeof(hdr->mk_digest_salt),
        hdr->mk_digest_iter,
        hdr->hash_spec,
        hdr->mk_digest,
        sizeof(hdr->mk_digest)) != 0)
    {
        GOTO(done);
    }

    /* The number of stripes per slot */
    stripes = LUKS_STRIPES;

    /* Base offset expressed in number of sectors */
    base_offset = sizeof(luks1_hdr_t) / VIC_SECTOR_SIZE + 1;

    /* Calculate byte offset to first sector after pheader */
    size_t byte_offset = base_offset * VIC_SECTOR_SIZE;

    /* Key material sectors expressed in number of sectors */
    key_material_sectors = (stripes * master_key_bytes) / VIC_SECTOR_SIZE + 1;

    /* Initialize the key slots */
    for (size_t i = 0; i < LUKS_NUM_KEYS; i++)
    {
        vic_luks_keyslot_t* ks =  &hdr->keyslots[i];

        ks->active = LUKS_KEY_DISABLED;
        ks->stripes = stripes;

        byte_offset = vic_round_up(byte_offset, LUKS_ALIGN_KEYSLOTS);
        ks->key_material_offset = byte_offset / VIC_SECTOR_SIZE;
        byte_offset += key_material_sectors * VIC_SECTOR_SIZE;
    }

    hdr->payload_offset =
        vic_round_up(byte_offset, LUKS_DISK_ALIGNMENT) / VIC_SECTOR_SIZE;

    if (uuid)
    {
        if (!vic_uuid_valid(uuid))
            GOTO(done);

        strcpy(hdr->uuid, uuid);
    }
    else
    {
        vic_uuid_generate(hdr->uuid);
    }

    ret = 0;

done:
    return ret;
}

static int _add_key(
    luks1_hdr_t* hdr,
    const vic_key_t* master_key,
    const char* pwd,
    size_t pwd_size,
    uint64_t slot_iterations,
    void** data_out,
    size_t* size_out,
    size_t* index_out)
{
    int ret = -1;
    vic_luks_keyslot_t* ks =  NULL;
    uint8_t* plain = NULL;
    uint8_t* cipher = NULL;
    vic_key_t pbkdf2_key;
    size_t size;
    size_t index = -1;

    if (data_out)
        *data_out = NULL;

    if (size_out)
        *size_out = 0;

    if (index_out)
        *index_out = (size_t)-1;

    if (!hdr || !master_key || !pwd)
        GOTO(done);

    if (hdr->key_bytes > sizeof(pbkdf2_key))
        GOTO(done);

    /* Find an empty key slot */
    for (size_t i = 0; i < LUKS_NUM_KEYS; i++)
    {
        if (hdr->keyslots[i].active == LUKS_KEY_DISABLED)
        {
            index = i;
            break;
        }
    }

    /* If no vic_free key slot found */
    if (index == (size_t)-1)
        GOTO(done);

    ks = &hdr->keyslots[index];
    ks->active = LUKS_KEY_ENABLED;
    ks->iterations = slot_iterations;
    vic_random(ks->salt, LUKS_SALT_SIZE);

    if ((size = hdr->key_bytes * ks->stripes) == 0)
        GOTO(done);

    if (!(plain = vic_calloc(1, size)))
        GOTO(done);

    if (!(cipher = vic_calloc(1, size)))
        GOTO(done);

    if (vic_pbkdf2(
        (const uint8_t*)pwd,
        pwd_size,
        ks->salt,
        sizeof(ks->salt),
        ks->iterations,
        hdr->hash_spec,
        &pbkdf2_key,
        hdr->key_bytes) != 0)
    {
        GOTO(done);
    }

    if (vic_afsplit(
        hdr->hash_spec,
        master_key,
        hdr->key_bytes,
        ks->stripes,
        plain) != 0)
    {
        GOTO(done);
    }

    /* Encrypt the stripes */
    if (_encrypt(hdr, &pbkdf2_key, plain, cipher, size, 0) != 0)
        GOTO(done);

    if (data_out)
    {
        *data_out = cipher;
        cipher = NULL;
    }

    if (size_out)
        *size_out = size;

    if (index_out)
        *index_out = index;

    ret = 0;

done:

    if (plain)
        vic_free(plain);

    if (cipher)
        vic_free(cipher);

    return ret;
}

static vic_result_t _find_key_by_pwd(
    vic_blockdev_t* device,
    luks1_hdr_t* hdr,
    const char* pwd,
    size_t pwd_size,
    vic_key_t* master_key,
    vic_luks_keyslot_t** ks_out)
{
    vic_result_t result = VIC_OK;
    bool found = false;
    void* cipher = NULL;
    void* plain = NULL;

    if (ks_out)
        *ks_out = NULL;

    if (master_key)
        memset(master_key, 0, sizeof(vic_key_t));

    for (size_t i = 0; i < LUKS_NUM_KEYS; i++)
    {
        if (hdr->keyslots[i].active == LUKS_KEY_ENABLED)
        {
            size_t size;
            vic_key_t pbkdf2_key;
            vic_key_t mk;
            uint8_t mk_digest[LUKS_DIGEST_SIZE];

            vic_luks_keyslot_t* ks = &hdr->keyslots[i];

            if (vic_pbkdf2(
                (const uint8_t*)pwd,
                pwd_size,
                ks->salt,
                sizeof(ks->salt),
                ks->iterations,
                hdr->hash_spec,
                &pbkdf2_key,
                hdr->key_bytes) != 0)
            {
                RAISE(VIC_PBKDF2_FAILED);
            }

            size = ks->stripes * hdr->key_bytes;

            if (!(cipher = vic_calloc(size, 1)))
                RAISE(VIC_OUT_OF_MEMORY);

            if (_read_key_material(device, hdr, ks, cipher) != 0)
                RAISE(VIC_KEY_MATERIAL_READ_FAILED);

            if (!(plain = vic_calloc(size, 1)))
                RAISE(VIC_OUT_OF_MEMORY);

            if (_decrypt(hdr, &pbkdf2_key, cipher, plain, size, 0) != 0)
                RAISE(VIC_DECRYPT_FAILED);

            if (vic_afmerge(
                hdr->key_bytes,
                ks->stripes,
                hdr->hash_spec,
                plain,
                &mk) != 0)
            {
                RAISE(VIC_AFMERGE_FAILED);
            }

            if (vic_pbkdf2(
                &mk,
                hdr->key_bytes,
                hdr->mk_digest_salt,
                sizeof(hdr->mk_digest_salt),
                hdr->mk_digest_iter,
                hdr->hash_spec,
                mk_digest,
                sizeof(mk_digest)) != 0)
            {
                RAISE(VIC_PBKDF2_FAILED);
            }

            if (memcmp(hdr->mk_digest, mk_digest, sizeof(mk_digest)) == 0)
            {
                found = true;

                if (master_key)
                    memcpy(master_key, &mk, hdr->key_bytes);

                if (ks_out)
                    *ks_out = ks;

                break;
            }

            vic_free(cipher);
            cipher = NULL;

            vic_free(plain);
            plain = NULL;
        }
    }

    if (!found)
        RAISE(VIC_NOT_FOUND);

done:

    if (cipher)
        vic_free(cipher);

    if (plain)
        vic_free(plain);

    return result;
}

/*
**==============================================================================
**
** Public interface:
**
**==============================================================================
*/

vic_result_t luks1_format(
    vic_blockdev_t* device,
    const char* cipher_name,
    const char* cipher_mode,
    const char* uuid,
    const char* hash,
    uint64_t mk_iterations,
    const vic_key_t* master_key,
    size_t master_key_bytes)
{
    vic_result_t result = VIC_OK;
    luks1_hdr_t hdr;
    vic_key_t master_key_buf;
    void* data = NULL;

    if (!_is_valid_device(device) || !cipher_name || !cipher_mode)
        RAISE(VIC_BAD_PARAMETER);

    if (master_key)
    {
        if (master_key_bytes == 0)
            RAISE(VIC_BAD_PARAMETER);

        if (master_key_bytes > sizeof(vic_key_t))
            RAISE(VIC_KEY_TOO_BIG);
    }

    if (!hash)
        hash = DEFAULT_HASH;

    if (!master_key)
    {
        /* Randomly generate a master key */
        vic_random(&master_key_buf, sizeof(master_key_buf));
        master_key = &master_key_buf;
        master_key_bytes = sizeof(master_key_buf);
    }

    if (mk_iterations < LUKS_MIN_MK_ITERATIONS)
        mk_iterations = LUKS_MIN_MK_ITERATIONS;

    /* Initialize the hdr struct */
    if (_initialize_hdr(
        &hdr,
        LUKS_VERSION_1,
        cipher_name,
        cipher_mode,
        master_key,
        master_key_bytes,
        hash,
        uuid,
        mk_iterations) != 0)
    {
        RAISE(VIC_FAILED);
    }

    /* Verify that there is enough room for at least 1 payload block */
    {
        size_t num_blocks;

        CHECK(vic_blockdev_get_num_blocks(device, &num_blocks));

        if (hdr.payload_offset >= num_blocks)
            RAISE(VIC_DEVICE_TOO_SMALL);
    }

    /* Write the hdr structure to the device */
    if (_write_luks1_hdr(device, &hdr) != 0)
        RAISE(VIC_HEADER_WRITE_FAILED);

done:

    if (data)
        vic_free(data);

    return result;
}

vic_result_t luks1_recover_master_key(
    vic_blockdev_t* device,
    const char* pwd,
    size_t pwd_size,
    vic_key_t* master_key,
    size_t* master_key_bytes)
{
    vic_result_t result = VIC_OK;
    luks1_hdr_t* hdr = NULL;

    if (!_is_valid_device(device))
        RAISE(VIC_BAD_DEVICE);

    if (!pwd)
        RAISE(VIC_BAD_PARAMETER);

    if (master_key)
        memset(master_key, 0, sizeof(vic_key_t));

    if (luks1_read_hdr(device, &hdr) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    CHECK(_find_key_by_pwd(device, hdr, pwd, pwd_size, master_key, NULL));

    if (master_key_bytes)
        *master_key_bytes = hdr->key_bytes;

done:

    if (hdr)
        vic_free(hdr);

    return result;
}

vic_result_t luks1_add_key(
    vic_blockdev_t* device,
    uint64_t slot_iterations,
    const char* pwd,
    size_t pwd_size,
    const char* new_pwd,
    size_t new_pwd_size)
{
    vic_result_t result = VIC_OK;
    luks1_hdr_t* hdr = NULL;
    vic_key_t mk;
    void* data = NULL;
    size_t size;
    size_t index;

    if (!_is_valid_device(device))
        RAISE(VIC_BAD_DEVICE);

    if (!pwd || !new_pwd)
        RAISE(VIC_BAD_PARAMETER);

    if (luks1_read_hdr(device, &hdr) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    if (slot_iterations < LUKS_MIN_SLOT_ITERATIONS)
        slot_iterations = LUKS_MIN_SLOT_ITERATIONS;

    if (vic_luks_recover_master_key(device, pwd, pwd_size, &mk, NULL) != 0)
    {
        RAISE(VIC_FAILED);
    }

    if (_add_key(hdr, &mk, new_pwd, new_pwd_size, slot_iterations, &data,
        &size, &index) != 0)
    {
        RAISE(VIC_FAILED);
    }

    if (index >= LUKS_NUM_KEYS)
        RAISE(VIC_OUT_OF_BOUNDS);

    /* Write the hdr structure to the device */
    if (_write_luks1_hdr(device, hdr) != 0)
        RAISE(VIC_HEADER_WRITE_FAILED);

    /* Write out the stripes */
    if (_write_key_material(device, hdr, &hdr->keyslots[index], data) != 0)
        RAISE(VIC_KEY_MATERIAL_WRITE_FAILED);

done:

    if (hdr)
        vic_free(hdr);

    if (data)
        vic_free(data);

    return result;
}

vic_result_t luks1_add_key_by_master_key(
    vic_blockdev_t* device,
    uint64_t slot_iterations,
    const vic_key_t* master_key,
    size_t master_key_bytes,
    const char* pwd,
    size_t pwd_size)
{
    vic_result_t result = VIC_OK;
    luks1_hdr_t* hdr = NULL;
    void* data = NULL;
    size_t size;
    size_t index;

    if (!_is_valid_device(device))
        RAISE(VIC_BAD_DEVICE);

    if (!master_key || !pwd)
        RAISE(VIC_BAD_PARAMETER);

    if (luks1_read_hdr(device, &hdr) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    if (master_key_bytes != hdr->key_bytes)
        RAISE(VIC_BAD_PARAMETER);

    if (slot_iterations < LUKS_MIN_SLOT_ITERATIONS)
        slot_iterations = LUKS_MIN_SLOT_ITERATIONS;

    if (_add_key(
        hdr,
        master_key,
        pwd,
        pwd_size,
        slot_iterations,
        &data,
        &size,
        &index) != 0)
    {
        RAISE(VIC_FAILED);
    }

    if (index >= LUKS_NUM_KEYS)
        RAISE(VIC_OUT_OF_BOUNDS);

    /* Write the hdr structure to the device */
    if (_write_luks1_hdr(device, hdr) != 0)
        RAISE(VIC_HEADER_WRITE_FAILED);

    /* Write out the stripes */
    if (_write_key_material(device, hdr, &hdr->keyslots[index], data) != 0)
        RAISE(VIC_KEY_MATERIAL_WRITE_FAILED);

done:

    if (hdr)
        vic_free(hdr);

    if (data)
        vic_free(data);

    return result;
}

vic_result_t luks1_remove_key(
    vic_blockdev_t* device,
    const char* pwd,
    size_t pwd_size)
{
    vic_result_t result = VIC_OK;
    luks1_hdr_t* hdr = NULL;
    vic_luks_keyslot_t* ks;

    if (!_is_valid_device(device))
        RAISE(VIC_BAD_DEVICE);

    if (!pwd)
        RAISE(VIC_BAD_PARAMETER);

    if (luks1_read_hdr(device, &hdr) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    CHECK(_find_key_by_pwd(device, hdr, pwd, pwd_size, NULL, &ks));

    /* Disable the key slot */
    memset(ks->salt, 0, sizeof(ks->salt));
    ks->active = LUKS_KEY_DISABLED;

    /* Rewrite the header */
    if (_write_luks1_hdr(device, hdr) != 0)
        RAISE(VIC_HEADER_WRITE_FAILED);

    /* Rewrite the stripes */
    if (_write_key_material(device, hdr, ks, NULL) != 0)
        RAISE(VIC_KEY_MATERIAL_WRITE_FAILED);

done:

    if (hdr)
        vic_free(hdr);

    return result;
}

vic_result_t luks1_kill_slot(vic_blockdev_t* device, size_t index)
{
    vic_result_t result = VIC_OK;
    luks1_hdr_t* hdr;
    vic_luks_keyslot_t* ks;

    if (!_is_valid_device(device))
        RAISE(VIC_BAD_DEVICE);

    if (index >= LUKS_NUM_KEYS)
        RAISE(VIC_OUT_OF_BOUNDS);

    if (luks1_read_hdr(device, &hdr) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    /* Use this slot */
    ks = &hdr->keyslots[index];

    /* Kill the slot if active */
    if (ks->active == LUKS_KEY_ENABLED)
    {
        /* Disable the key slot */
        memset(ks->salt, 0, sizeof(ks->salt));
        ks->active = LUKS_KEY_DISABLED;

        /* Rewrite the header */
        if (_write_luks1_hdr(device, hdr) != 0)
            RAISE(VIC_HEADER_WRITE_FAILED);

        /* Rewrite the stripes */
        if (_write_key_material(device, hdr, ks, NULL) != 0)
            RAISE(VIC_KEY_MATERIAL_WRITE_FAILED);
    }

done:

    if (hdr)
        vic_free(hdr);

    return result;
}

vic_result_t luks1_change_key(
    vic_blockdev_t* device,
    const char* old_pwd,
    size_t old_pwd_size,
    const char* new_pwd,
    size_t new_pwd_size)
{
    vic_result_t result = VIC_OK;
    luks1_hdr_t* hdr = NULL;
    vic_key_t mk;
    vic_luks_keyslot_t* ks;
    void* plain = NULL;
    void* cipher = NULL;
    size_t size;
    vic_key_t pbkdf2_key;

    if (!_is_valid_device(device))
        RAISE(VIC_BAD_DEVICE);

    if (!old_pwd || !new_pwd)
        RAISE(VIC_BAD_PARAMETER);

    if (luks1_read_hdr(device, &hdr) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    CHECK(_find_key_by_pwd(device, hdr, old_pwd, old_pwd_size, &mk, &ks));

    /* Generate a new salt for this key slot */
    vic_random(ks->salt, sizeof(ks->salt));

    if ((size = hdr->key_bytes * ks->stripes) == 0)
        GOTO(done);

    if (!(plain = vic_calloc(1, size)))
        GOTO(done);

    if (!(cipher = vic_calloc(1, size)))
        GOTO(done);

    if (vic_pbkdf2(
        (const uint8_t*)new_pwd,
        new_pwd_size,
        ks->salt,
        sizeof(ks->salt),
        ks->iterations,
        hdr->hash_spec,
        &pbkdf2_key,
        hdr->key_bytes) != 0)
    {
        GOTO(done);
    }

    if (vic_afsplit(
        hdr->hash_spec,
        &mk,
        hdr->key_bytes,
        ks->stripes,
        plain) != 0)
    {
        GOTO(done);
    }

    /* Encrypt the stripes */
    if (_encrypt(hdr, &pbkdf2_key, plain, cipher, size, 0) != 0)
        GOTO(done);

    /* Rewrite the header */
    if (_write_luks1_hdr(device, hdr) != 0)
        RAISE(VIC_HEADER_WRITE_FAILED);

    /* Rewrite the stripes */
    if (_write_key_material(device, hdr, ks, cipher) != 0)
        RAISE(VIC_KEY_MATERIAL_WRITE_FAILED);

done:

    if (hdr)
        vic_free(hdr);

    if (plain)
        vic_free(plain);

    if (cipher)
        vic_free(cipher);

    return result;
}

vic_result_t luks1_stat(vic_blockdev_t* device, vic_luks_stat_t* buf)
{
    vic_result_t result = VIC_OK;
    luks1_hdr_t* hdr = NULL;
    size_t nblocks;
    size_t nbytes;
    size_t offset;

    if (!_is_valid_device(device) || !buf)
        RAISE(VIC_BAD_PARAMETER);

    if (luks1_read_hdr(device, &hdr) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    CHECK(vic_blockdev_get_num_blocks(device, &nblocks));

    nbytes = nblocks * VIC_SECTOR_SIZE;
    offset = hdr->payload_offset * VIC_SECTOR_SIZE;
    buf->version = LUKS_VERSION_1;
    buf->payload_offset = offset;
    buf->payload_size = nbytes - offset;

done:

    if (hdr)
        vic_free(hdr);

    return result;
}

vic_result_t luks1_open(
    vic_blockdev_t* device,
    const char* path,
    const char* name,
    const vic_key_t* master_key,
    size_t master_key_bytes)
{
    vic_result_t result = VIC_OK;
    luks1_hdr_t* hdr = NULL;
    uint64_t size;
    uint64_t offset;
    uint64_t iv_offset = 0;
    char cipher[32];

    if (!_is_valid_device(device) || !path || !name || !master_key ||
        !master_key_bytes)
    {
        RAISE(VIC_BAD_PARAMETER);
    }

    if (luks1_read_hdr(device, &hdr) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    /* Determine the size of the payload in sectors */
    {
        size_t num_blocks;
        offset = hdr->payload_offset;

        CHECK(vic_blockdev_get_num_blocks(device, &num_blocks));

        if (offset >= num_blocks)
            RAISE(VIC_DEVICE_TOO_SMALL);

        size = num_blocks - offset;
    }

    /* Format cipher and cipher mode as single string */
    {
        if (strcmp(hdr->cipher_name, LUKS_CIPHER_NAME_AES) == 0 &&
            strcmp(hdr->cipher_mode, LUKS_CIPHER_MODE_CBC_ESSIV_SHA256) == 0)
        {
            vic_strlcpy(cipher, "aes-cbc-essiv:sha256", sizeof(cipher));
        }
        else if (strcmp(hdr->cipher_name, LUKS_CIPHER_NAME_AES) == 0 &&
            strcmp(hdr->cipher_mode, LUKS_CIPHER_MODE_XTS_PLAIN64) == 0)
        {
            vic_strlcpy(cipher, "aes-xts-plain64", sizeof(cipher));
        }
        else if (strcmp(hdr->cipher_name, LUKS_CIPHER_NAME_TWOFISH) == 0 &&
            strcmp(hdr->cipher_mode, LUKS_CIPHER_MODE_ECB) == 0)
        {
            vic_strlcpy(cipher, "twofish-ecb", sizeof(cipher));
        }
        else if (strcmp(hdr->cipher_name, LUKS_CIPHER_NAME_SERPENT) == 0 &&
            strcmp(hdr->cipher_mode, LUKS_CIPHER_MODE_CBC_PLAIN) == 0)
        {
            vic_strlcpy(cipher, "serpent-cbc-plain", sizeof(cipher));
        }
        else if (strcmp(hdr->cipher_name, LUKS_CIPHER_NAME_AES) == 0 &&
            strcmp(hdr->cipher_mode, LUKS_CIPHER_MODE_CBC_PLAIN) == 0)
        {
            vic_strlcpy(cipher, "aes-cbc-plain", sizeof(cipher));
        }
        else if (strcmp(hdr->cipher_name, LUKS_CIPHER_NAME_AES) == 0 &&
            strcmp(hdr->cipher_mode, LUKS_CIPHER_MODE_ECB) == 0)
        {
            vic_strlcpy(cipher, "aes-ecb", sizeof(cipher));
        }
        else
        {
            /* ATTN-C: "aes:64-cbc-lmk" not supported */
            RAISE(VIC_UNSUPPORTED_CIPHER);
        }
    }

    CHECK(vic_dm_create_crypt(
        "CRYPT-LUKS1",
        name,
        path,
        hdr->uuid,
        0, /* start */
        size,
        "", /* integrity */
        cipher,
        master_key->buf,
        master_key_bytes,
        iv_offset,
        offset));

done:

    if (hdr)
        vic_free(hdr);

    return result;
}
