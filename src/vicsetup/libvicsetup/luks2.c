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
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <json.h>

#include "luks2.h"
#include "vic.h"
#include "byteorder.h"
#include "strings.h"
#include "lukscommon.h"
#include "hexdump.h"
#include "raise.h"
#include "hash.h"
#include "crypto.h"
#include "trace.h"
#include "dm.h"
#include "integrity.h"
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

static uint8_t _magic_1st[LUKS_MAGIC_SIZE] = LUKS_MAGIC_1ST;

static uint8_t _magic_2nd[LUKS_MAGIC_SIZE] = LUKS_MAGIC_2ND;

#define VIC_HASH_SPEC_SHA1 "sha1"
#define VIC_HASH_SPEC_SHA256 "sha256"
#define VIC_HASH_SPEC_SHA512 "sha512"
#define VIC_HASH_SPEC_RIPEMD160 "ripemd160"

#define DEFAULT_HDR_SIZE 16384

/* The number of keys in the key material */
#define DEFAULT_AF_STRIPES 4000

#define DEFAULT_HASH "sha256"

#define DEFAULT_KDF_TYPE "argon2i"
#define DEFAULT_KDF_HASH "sha256"
#define DEFAULT_KDF_ITERATIONS 1000
#define DEFAULT_KDF_TIME 4
#define DEFAULT_KDF_MEMORY 744976
#define DEFAULT_KDF_CPUS 1

#define DEFAULT_SEGMENT_OFFSET 4194304 /* power of two */

/* Default size of the two headers plus the key material (16 megabytes) */
#define OVERHEAD_BYTES 16777216

/* The device must be at least 17 megabytes */
#define MIN_DEVICE_BYTES 17825792

#define LUKS_ALIGN_KEYSLOTS 4096

/* values for vic_luks_keyslot_t.active */
#define LUKS_KEY_DISABLED 0x0000dead
#define LUKS_KEY_ENABLED 0x00ac71f3

#define LUKS_DISK_ALIGNMENT (1024 * 1024)

#define VIC_SHA1_SIZE 20
#define VIC_SHA256_SIZE 32
#define VIC_SHA512_SIZE 64
#define VIC_RIPE160_SIZE 20
#define VIC_MAX_HASH_SIZE 64

#define LUKS_IV_SIZE 16

uint32_t vic_luks_checksum(const void* data, size_t size)
{
    uint32_t n = 0;
    const uint8_t* p = (const uint8_t*)data;

    while (size--)
        n += *p++;

    return n;
}

static bool _is_valid_luks2_hdr(const luks2_hdr_t* hdr, bool swap)
{
    if (!hdr)
        return false;

    if (memcmp(hdr->magic, _magic_1st, sizeof(_magic_1st)) != 0 &&
        memcmp(hdr->magic, _magic_2nd, sizeof(_magic_2nd)) != 0)
    {
        return false;
    }

    if (swap)
    {
        if (vic_swap_u16(hdr->version) != LUKS_VERSION_2)
            return false;
    }
    else
    {
        if (hdr->version != LUKS_VERSION_2)
            return false;
    }

    return true;
}

static void _fix_luks2_hdr_byte_order(luks2_hdr_t* hdr)
{
    if (!vic_is_big_endian())
    {
        hdr->version = vic_swap_u16(hdr->version);
        hdr->hdr_size = vic_swap_u64(hdr->hdr_size);
        hdr->seqid = vic_swap_u64(hdr->seqid);
        hdr->hdr_offset = vic_swap_u64(hdr->hdr_offset);
    }
}

#define MAX_JSON_PATH 64

typedef struct json_callback_data
{
    luks2_ext_hdr_t* hdr;
    size_t depth;
    const char* path[MAX_JSON_PATH];
}
json_callback_data_t;

static int _strtou64(uint64_t* x, const char* str)
{
    char* end;

    *x = strtoull(str, &end, 10);

    if (!end || *end != '\0')
        return -1;

    return 0;
}

static const char* _get_integrity_type(luks2_ext_hdr_t* ext)
{
    return ext->segments[0].integrity.type;
}

static const char* _get_encryption(luks2_ext_hdr_t* ext)
{
    return ext->segments[0].encryption;
}

static vic_kdf_t* _get_default_kdf(const char* kdf_type)
{
    if (strcmp(kdf_type, "pbkdf2") == 0)
    {
        static vic_kdf_t _pbkdf2 =
        {
            .hash = "sha256",
            .iterations = DEFAULT_KDF_ITERATIONS,
        };

        return &_pbkdf2;
    }
    else if (strncmp(kdf_type, "argon2i", 7) == 0)
    {
        static vic_kdf_t _argon2i =
        {
            .time = DEFAULT_KDF_TIME,
            .memory = DEFAULT_KDF_MEMORY,
            .cpus = DEFAULT_KDF_CPUS,
        };

        return &_argon2i;
    }

    return NULL;
}

static bool _valid_pbkdf_type(const char* type)
{
    if (strcmp(type, "pbkdf2") == 0 ||
        strcmp(type, "argon2i") == 0 ||
        strcmp(type, "argon2id") == 0)
    {
        return true;
    }

    return false;
}

static void _write(void* stream, const void* buf, size_t count)
{
    fwrite(buf, 1, count, (FILE*)stream);
}

static json_result_t _json_read_callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* callback_data)
{
    json_result_t result = JSON_UNEXPECTED;
    json_callback_data_t* data = (json_callback_data_t*)callback_data;
    const size_t MAX_DEPTH = VIC_COUNTOF(data->path);

    (void)parser;

    switch (reason)
    {
        case JSON_REASON_NONE:
        {
            /* Unreachable */
            assert(false);
            break;
        }
        case JSON_REASON_NAME:
        {
            assert(data->depth > 0);

            data->path[data->depth - 1] = un->string;
            break;
        }
        case JSON_REASON_BEGIN_OBJECT:
        {
            if (data->depth == MAX_DEPTH)
            {
                result = JSON_NESTING_OVERFLOW;
                GOTO(done);
            }

            data->depth++;
            break;
        }
        case JSON_REASON_END_OBJECT:
        {
            if (data->depth == 0)
            {
                result = JSON_NESTING_UNDERFLOW;
                GOTO(done);
            }

            data->depth--;
            break;
        }
        case JSON_REASON_BEGIN_ARRAY:
        {
            break;
        }
        case JSON_REASON_END_ARRAY:
        {
            break;
        }
        case JSON_REASON_VALUE:
        {
            if (json_match(parser, "keyslots.#.type") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                const size_t n = sizeof(ks->type);

                if (vic_strlcpy(ks->type, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "keyslots.#.key_size") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                ks->key_size = un->integer;
            }
            else if (json_match(parser, "keyslots.#.kdf.type") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                const size_t n = sizeof(ks->kdf.type);

                if (vic_strlcpy(ks->kdf.type, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    GOTO(done);
                }

                if (!_valid_pbkdf_type(ks->kdf.type))
                {
                    result = JSON_UNSUPPORTED;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "keyslots.#.kdf.time") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                ks->kdf.time = un->integer;
            }
            else if (json_match(parser, "keyslots.#.kdf.memory") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                ks->kdf.memory = un->integer;
            }
            else if (json_match(parser, "keyslots.#.kdf.hash") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                const size_t n = sizeof(ks->kdf.hash);

                if (vic_strlcpy(ks->kdf.hash, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    GOTO(done);
                }
            }
            else if (json_match(
                parser, "keyslots.#.kdf.iterations") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                ks->kdf.iterations = un->integer;
            }
            else if (json_match(parser, "keyslots.#.kdf.cpus") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                ks->kdf.cpus = un->integer;
            }
            else if (json_match(parser, "keyslots.#.kdf.salt") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                size_t olen;

                if (mbedtls_base64_decode(
                    ks->kdf.salt,
                    sizeof(ks->kdf.salt),
                    &olen,
                    (const unsigned char*)un->string,
                    strlen(un->string)) != 0)
                {
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }
                }

                if (olen != LUKS_SALT_SIZE)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "keyslots.#.af.type") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                const size_t n = sizeof(ks->af.type);

                if (vic_strlcpy(ks->af.type, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "keyslots.#.af.hash") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                const size_t n = sizeof(ks->af.hash);

                if (vic_strlcpy(ks->af.hash, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "keyslots.#.af.stripes") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                ks->af.stripes = un->integer;
            }
            else if (json_match(parser, "keyslots.#.area.type") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                const size_t n = sizeof(ks->area.type);

                if (vic_strlcpy(ks->area.type, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    GOTO(done);
                }
            }
            else if (json_match(
                parser, "keyslots.#.area.encryption") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                const size_t n = sizeof(ks->area.encryption);

                if (vic_strlcpy(ks->area.encryption, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    GOTO(done);
                }
            }
            else if (json_match(
                parser, "keyslots.#.area.key_size") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];
                ks->area.key_size = un->integer;
            }
            else if (json_match(
                parser, "keyslots.#.area.offset") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];

                if (_strtou64(&ks->area.offset, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "keyslots.#.area.size") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_KEYSLOTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_keyslot_t* ks = &data->hdr->keyslots[i];

                if (_strtou64(&ks->area.size, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "segments.#.type") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_segment_t* seg = &data->hdr->segments[i];
                const size_t n = sizeof(seg->type);

                if (vic_strlcpy(seg->type, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "segments.#.offset") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_segment_t* seg = &data->hdr->segments[i];

                if (_strtou64(&seg->offset, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "segments.#.iv_tweak") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_segment_t* seg = &data->hdr->segments[i];

                if (_strtou64(&seg->iv_tweak, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "segments.#.size") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_segment_t* seg = &data->hdr->segments[i];

                if (strcmp(un->string , "dynamic") == 0)
                    seg->size = (uint64_t)-1;
                else if (_strtou64(&seg->size, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "segments.#.encryption") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_segment_t* seg = &data->hdr->segments[i];
                const size_t n = sizeof(seg->encryption);

                if (vic_strlcpy(seg->encryption, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    GOTO(done);
                }
            }
            else if (json_match(
                parser, "segments.#.sector_size") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= LUKS2_NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_segment_t* seg = &data->hdr->segments[i];
                seg->sector_size = un->integer;
            }
            else if (json_match(
                parser, "segments.#.integrity.type") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_segment_t* seg = &data->hdr->segments[i];
                const size_t n = sizeof(seg->integrity.type);

                if (vic_strlcpy(seg->integrity.type, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    GOTO(done);
                }
            }
            else if (json_match(parser,
                "segments.#.integrity.journal_encryption") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_segment_t* seg = &data->hdr->segments[i];
                const size_t n = sizeof(seg->integrity.journal_encryption);
                char* p = seg->integrity.journal_encryption;

                if (strcmp(un->string, "none") != 0)
                {
                    result = JSON_UNSUPPORTED;
                    GOTO(done);
                }

                if (vic_strlcpy(p, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    GOTO(done);
                }
            }
            else if (json_match(parser,
                "segments.#.integrity.journal_integrity") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_SEGMENTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_segment_t* seg = &data->hdr->segments[i];
                const size_t n = sizeof(seg->integrity.journal_integrity);
                char* p = seg->integrity.journal_integrity;

                if (strcmp(un->string, "none") != 0)
                {
                    result = JSON_UNSUPPORTED;
                    GOTO(done);
                }

                if (vic_strlcpy(p, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "digests.#.type") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_DIGESTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_digest_t* digest = &data->hdr->digests[i];
                const size_t n = sizeof(digest->type);

                if (strcmp(un->string, "pbkdf2") != 0)
                {
                    result = JSON_UNSUPPORTED;
                    GOTO(done);
                }

                if (vic_strlcpy(digest->type, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "digests.#.keyslots") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                uint64_t n;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_DIGESTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_digest_t* digest = &data->hdr->digests[i];

                if (_strtou64(&n, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                if (n >= VIC_COUNTOF(digest->keyslots))
                {
                    result = JSON_OUT_OF_BOUNDS;
                    GOTO(done);
                }

                digest->keyslots[n] = 1;
            }
            else if (json_match(parser, "digests.#.segments") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;
                uint64_t n;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_DIGESTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_digest_t* digest = &data->hdr->digests[i];

                if (_strtou64(&n, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                if (n >= VIC_COUNTOF(digest->segments))
                {
                    result = JSON_OUT_OF_BOUNDS;
                    GOTO(done);
                }

                digest->segments[n] = 1;
            }
            else if (json_match(parser, "digests.#.hash") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_DIGESTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_digest_t* digest = &data->hdr->digests[i];
                const size_t n = sizeof(digest->hash);

                if (vic_strlcpy(digest->hash, un->string, n) >= n)
                {
                    result = JSON_BUFFER_OVERFLOW;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "digests.#.iterations") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_INTEGER || i >= LUKS2_NUM_DIGESTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_digest_t* digest = &data->hdr->digests[i];
                digest->iterations = un->integer;
            }
            else if (json_match(parser, "digests.#.salt") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_DIGESTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_digest_t* digest = &data->hdr->digests[i];
                size_t olen;

                if (mbedtls_base64_decode(
                    digest->salt,
                    sizeof(digest->salt),
                    &olen,
                    (const unsigned char*)un->string,
                    strlen(un->string)) != 0)
                {
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }
                }

                if (olen != LUKS_SALT_SIZE)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "digests.#.digest") == JSON_OK)
            {
                uint64_t i = parser->path[1].number;

                if (type != JSON_TYPE_STRING || i >= LUKS2_NUM_DIGESTS)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                luks2_digest_t* digest = &data->hdr->digests[i];
                size_t olen;

                if (mbedtls_base64_decode(
                    digest->digest,
                    sizeof(digest->digest),
                    &olen,
                    (const unsigned char*)un->string,
                    strlen(un->string)) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }

                if (olen != vic_hash_size(digest->hash))
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "config.json_size") == JSON_OK)
            {
                luks2_config_t* config = &data->hdr->config;

                if (_strtou64(&config->json_size, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }
            }
            else if (json_match(parser, "config.keyslots_size") == JSON_OK)
            {
                luks2_config_t* config = &data->hdr->config;

                if (_strtou64(&config->keyslots_size, un->string) != 0)
                {
                    result = JSON_TYPE_MISMATCH;
                    GOTO(done);
                }
            }
            else
            {
                json_dump_path(_write, stdout, parser);
                result = JSON_UNKNOWN_VALUE;
                GOTO(done);
            }

            break;
        }
    }

    result = JSON_OK;

done:
    return result;
}

typedef struct _traits
{
    const char* sp;
    const char* nl;
}
traits_t;

static void _indent(FILE* os, size_t indent, traits_t t)
{
    for (size_t i = 0; i < indent; i++)
        fprintf(os, "%s%s", t.sp, t.sp);
}

static void _put_str_field(
    FILE* os,
    const char* name,
    const char* value,
    const char* comma,
    traits_t t)
{
    json_union_t un;

    fprintf(os, "\"%s\":%s", name, t.sp);

    un.string = (char*)value;
    json_print_value(_write, os, JSON_TYPE_STRING, &un);

    fprintf(os, "%s%s", comma, t.nl);
}

static void _put_base64_field(
    FILE* os,
    const char* name,
    const uint8_t* data,
    size_t size,
    const char* comma,
    traits_t t)
{
    json_union_t un;
    unsigned char buf[128];
    size_t olen;

    fprintf(os, "\"%s\":%s", name, t.sp);

    memset(buf, 0, sizeof(buf));

    if (mbedtls_base64_encode(
        buf,
        sizeof(buf),
        &olen,
        data,
        size) != 0)
    {
        assert(false);
    }

    un.string = (char*)buf;
    json_print_value(_write, os, JSON_TYPE_STRING, &un);

    fprintf(os, "%s%s", comma, t.nl);
}

static void _dump_keyslot(
    FILE* os,
    const luks2_keyslot_t* p,
    size_t index,
    size_t indent,
    const char* comma,
    traits_t t)
{
    _indent(os, indent++, t);
    fprintf(os, "\"%zu\":%s{%s", index, t.sp, t.nl);

    _indent(os, indent, t);
    _put_str_field(os, "type", p->type, ",", t);

    _indent(os, indent, t);
    fprintf(os, "\"key_size\":%s%lu,%s", t.sp, p->key_size, t.nl);

    /* kdf */
    {
        _indent(os, indent++, t);
        fprintf(os, "\"kdf\":%s{%s", t.sp, t.nl);

        _indent(os, indent, t);
        _put_str_field(os, "type", p->kdf.type, ",", t);

        if (strcmp(p->kdf.type, "pbkdf2") == 0)
        {
            _indent(os, indent, t);
            fprintf(os, "\"iterations\":%s%lu,%s",
                t.sp, p->kdf.iterations, t.nl);

            _indent(os, indent, t);
            _put_str_field(os, "hash", p->kdf.hash, ",", t);
        }
        else if (
            strcmp(p->kdf.type, "argon2i") == 0 ||
            strcmp(p->kdf.type, "argon2id") == 0)
        {
            _indent(os, indent, t);
            fprintf(os, "\"time\":%s%lu,%s", t.sp, p->kdf.time, t.nl);

            _indent(os, indent, t);
            fprintf(os, "\"memory\":%s%lu,%s", t.sp, p->kdf.memory, t.nl);

            _indent(os, indent, t);
            fprintf(os, "\"cpus\":%s%lu,%s", t.sp, p->kdf.cpus, t.nl);
        }

        _indent(os, indent, t);
        _put_base64_field(os, "salt", p->kdf.salt, sizeof(p->kdf.salt), "", t);

        _indent(os, --indent, t);
        fprintf(os, "},%s", t.nl);
    }

    /* af */
    {
        _indent(os, indent++, t);
        fprintf(os, "\"af\":%s{%s", t.sp, t.nl);

        _indent(os, indent, t);
        _put_str_field(os, "type", p->af.type, ",", t);

        _indent(os, indent, t);
        _put_str_field(os, "hash", p->af.hash, ",", t);

        _indent(os, indent, t);
        fprintf(os, "\"stripes\":%s%lu%s", t.sp, p->af.stripes, t.nl);

        _indent(os, --indent, t);
        fprintf(os, "},%s", t.nl);
    }

    /* area */
    {
        _indent(os, indent++, t);
        fprintf(os, "\"area\":%s{%s", t.sp, t.nl);

        _indent(os, indent, t);
        _put_str_field(os, "type", p->area.type, ",", t);

        _indent(os, indent, t);
        _put_str_field(os, "encryption", p->area.encryption, ",", t);

        _indent(os, indent, t);
        fprintf(os, "\"key_size\":%s%lu,%s", t.sp, p->area.key_size, t.nl);

        _indent(os, indent, t);
        fprintf(os, "\"offset\":%s\"%lu\",%s", t.sp, p->area.offset, t.nl);

        _indent(os, indent, t);
        fprintf(os, "\"size\":%s\"%lu\"%s", t.sp, p->area.size, t.nl);

        _indent(os, --indent, t);
        fprintf(os, "}%s", t.nl);
    }

    _indent(os, --indent, t);

    fprintf(os, "}");

    fprintf(os, "%s%s", comma, t.nl);
}

static void _dump_segment(
    FILE* os,
    const luks2_segment_t* p,
    size_t index,
    size_t indent,
    const char* comma,
    traits_t t)
{
    _indent(os, indent++, t);
    fprintf(os, "\"%zu\":%s{%s", index, t.sp, t.nl);

    _indent(os, indent, t);
    _put_str_field(os, "type", p->type, ",", t);

    _indent(os, indent, t);
    fprintf(os, "\"offset\":%s\"%lu\",%s", t.sp, p->offset, t.nl);

    _indent(os, indent, t);
    fprintf(os, "\"iv_tweak\":%s\"%lu\",%s", t.sp, p->iv_tweak, t.nl);

    if (p->size == (uint64_t)-1)
    {
        _indent(os, indent, t);
        fprintf(os, "\"size\":%s\"dynamic\",%s", t.sp, t.nl);
    }
    else
    {
        _indent(os, indent, t);
        fprintf(os, "\"size\":%s\"%lu\",%s", t.sp, p->size, t.nl);
    }

    _indent(os, indent, t);
    _put_str_field(os, "encryption", p->encryption, ",", t);

    {
        const char* comma = p->integrity.type[0] ? "," : "";
        _indent(os, indent, t);
        fprintf(os, "\"sector_size\":%s%lu%s%s",
            t.sp, p->sector_size, comma, t.nl);
    }

    /* dump integrity object if any */
    if (strcmp(p->integrity.type, "") != 0)
    {
        _indent(os, indent++, t);
        fprintf(os, "\"integrity\":%s{%s", t.sp, t.nl);

        _indent(os, indent, t);
        _put_str_field(os, "type", p->integrity.type, ",", t);

        _indent(os, indent, t);
        _put_str_field(
            os, "journal_encryption", p->integrity.journal_encryption, ",", t);

        _indent(os, indent, t);
        _put_str_field(
            os, "journal_integrity", p->integrity.journal_integrity, "", t);

        _indent(os, --indent, t);
        fprintf(os, "}%s", t.nl);
    }

    _indent(os, --indent, t);
    fprintf(os, "}");

    fprintf(os, "%s%s", comma, t.nl);
}

static void _dump_digest(
    FILE* os,
    const luks2_digest_t* p,
    size_t index,
    size_t indent,
    const char* comma,
    traits_t t)
{
    size_t digest_size;

    _indent(os, indent++, t);
    fprintf(os, "\"%zu\":%s{%s", index, t.sp, t.nl);

    _indent(os, indent, t);
    _put_str_field(os, "type", p->type, ",", t);

    /* keyslots */
    {
        size_t more = 0;

        _indent(os, indent++, t);
        fprintf(os, "\"keyslots\":%s[%s", t.sp, t.nl);

        for (size_t i = 0; i < VIC_COUNTOF(p->keyslots); i++)
        {
            if (p->keyslots[i])
                more++;
        }

        for (size_t i = 0; i < VIC_COUNTOF(p->keyslots); i++)
        {
            if (p->keyslots[i])
            {
                _indent(os, indent, t);
                fprintf(os, "\"%zu\"", i);

                if (--more)
                    fprintf(os, ",");

                fprintf(os, "%s", t.nl);
            }
        }

        _indent(os, --indent, t);
        fprintf(os, "],%s", t.nl);
    }

    /* segments */
    {
        size_t more = 0;

        _indent(os, indent++, t);
        fprintf(os, "\"segments\":%s[%s", t.sp, t.nl);

        for (size_t i = 0; i < VIC_COUNTOF(p->segments); i++)
        {
            if (p->segments[i])
                more++;
        }

        for (size_t i = 0; i < VIC_COUNTOF(p->segments); i++)
        {
            if (p->segments[i])
            {
                _indent(os, indent, t);
                fprintf(os, "\"%zu\"", i);

                if (--more)
                    fprintf(os, ",");

                fprintf(os, "%s", t.nl);
            }
        }

        _indent(os, --indent, t);
        fprintf(os, "],%s", t.nl);
    }

    _indent(os, indent, t);
    _put_str_field(os, "hash", p->hash, ",", t);

    _indent(os, indent, t);
    fprintf(os, "\"iterations\":%s%lu,%s", t.sp, p->iterations, t.nl);

    _indent(os, indent, t);
    _put_base64_field(os, "salt", p->salt, sizeof(p->salt), ",", t);

    if ((digest_size = vic_hash_size(p->hash)) == (size_t)-1)
        assert(false);

    _indent(os, indent, t);
    _put_base64_field(os, "digest", p->digest, digest_size, "", t);

    _indent(os, --indent, t);

    fprintf(os, "}");

    fprintf(os, "%s%s", comma, t.nl);
}

static int _dump_json_objects(
    FILE* os,
    luks2_ext_hdr_t* ext,
    size_t indent,
    traits_t t)
{
    int ret = -1;

    /* Print the JSON opening brace */
    _indent(os, indent++, t);
    fprintf(os, "{%s", t.nl);

    /* "keyslots" */
    {
        size_t more = 0;

        _indent(os, indent++, t);
        fprintf(os, "\"keyslots\":%s{%s", t.sp, t.nl);

        for (size_t i = 0; i < VIC_COUNTOF(ext->keyslots); i++)
        {
            luks2_keyslot_t* ks = &ext->keyslots[i];

            if (*ks->type)
                more++;
        }

        for (size_t i = 0; i < VIC_COUNTOF(ext->keyslots); i++)
        {
            luks2_keyslot_t* ks = &ext->keyslots[i];

            if (*ks->type)
            {
                const char* comma = --more ? "," : "";
                _dump_keyslot(os, ks, i, indent, comma, t);
            }
        }

        _indent(os, --indent, t);
        fprintf(os, "},%s", t.nl);
    }

    /* "tokens" */
    {
        _indent(os, indent++, t);
        fprintf(os, "\"tokens\":%s{%s", t.sp, t.nl);

        _indent(os, --indent, t);
        fprintf(os, "},%s", t.nl);
    }

    /* "segments" */
    {
        size_t more = 0;

        _indent(os, indent++, t);
        fprintf(os, "\"segments\":%s{%s", t.sp, t.nl);

        for (size_t i = 0; i < VIC_COUNTOF(ext->segments); i++)
        {
            luks2_segment_t* seg = &ext->segments[i];

            if (*seg->type)
                more++;
        }

        for (size_t i = 0; i < VIC_COUNTOF(ext->segments); i++)
        {
            luks2_segment_t* seg = &ext->segments[i];

            if (*seg->type)
            {
                const char* comma = --more ? "," : "";
                _dump_segment(os, seg, i, indent, comma, t);
            }
        }

        _indent(os, --indent, t);
        fprintf(os, "},%s", t.nl);
    }

    /* "digests" */
    {
        size_t more = 0;

        _indent(os, indent++, t);
        fprintf(os, "\"digests\":%s{%s", t.sp, t.nl);

        for (size_t i = 0; i < VIC_COUNTOF(ext->digests); i++)
        {
            luks2_digest_t* digest = &ext->digests[i];

            if (*digest->type)
                more++;
        }

        for (size_t i = 0; i < VIC_COUNTOF(ext->digests); i++)
        {
            luks2_digest_t* digest = &ext->digests[i];

            if (*digest->type)
            {
                const char* comma = --more ? "," : "";
                _dump_digest(os, digest, i, indent, comma, t);
            }
        }

        _indent(os, --indent, t);
        fprintf(os, "},%s", t.nl);
    }

    /* "config" */
    {
        _indent(os, indent++, t);
        fprintf(os, "\"config\":%s{%s", t.sp, t.nl);

        _indent(os, indent, t);
        fprintf(os, "\"json_size\":%s\"%lu\",%s",
            t.sp, ext->config.json_size, t.nl);

        _indent(os, indent, t);
        fprintf(os, "\"keyslots_size\":%s\"%lu\"%s",
            t.sp, ext->config.keyslots_size, t.nl);

        _indent(os, --indent, t);
        fprintf(os, "}%s", t.nl);
    }

    /* Print the JSON closing brace */
    _indent(os, --indent, t);
    fprintf(os, "}%s", t.nl);

    ret = 0;

    return ret;
}

static char* _to_json(luks2_ext_hdr_t* hdr)
{
    char* ret = NULL;
    traits_t t = { "", "" };
    FILE* os;
    char* data = NULL;
    size_t size;

    if (!(os = open_memstream(&data, &size)))
        GOTO(done);

    if (_dump_json_objects(os, hdr, 0, t) != 0)
        GOTO(done);

    fclose(os);
    os = NULL;

    ret = data;
    data = NULL;

done:

    if (os)
        fclose(os);

    if (data)
        vic_free(data);

    return ret;
}

static void _dump_binary_hdr(
    FILE* os,
    const luks2_hdr_t* hdr,
    size_t indent);

static int _calculate_csum(
    const luks2_hdr_t* hdr,
    const char* json_data,
    size_t json_size,
    vic_hash_t* hash_out,
    size_t* hash_size_out)
{
    int ret = -1;
    vic_hash_ctx_t ctx;
    vic_hash_type_t hash_type;
    size_t hash_size;
    vic_hash_t hash;
    luks2_hdr_t tmp;
    bool free_hash = false;

    if (!hdr || !hash_out || !hash_size_out)
        goto done;

    if (!json_data || !json_size)
        goto done;

    if ((hash_size = vic_hash_size(hdr->csum_alg)) == (size_t)-1)
        goto done;

    if ((hash_type = vic_hash_type(hdr->csum_alg)) == VIC_HASH_NONE)
        goto done;

    tmp = *hdr;

    /* Zero out the checksum so it is not included in the hash */
    memset(tmp.csum, 0, sizeof(tmp.csum));
    _fix_luks2_hdr_byte_order(&tmp);

    if (vic_hash_init(&ctx, hash_type) != 0)
        goto done;

    free_hash = true;

    if (vic_hash_start(&ctx) != 0)
        goto done;

    if (vic_hash_update(&ctx, &tmp, sizeof(tmp)) != 0)
        goto done;

    if (vic_hash_update(&ctx, json_data, json_size) != 0)
        goto done;

    if (vic_hash_finish(&ctx, &hash) != 0)
        goto done;

    *hash_out = hash;
    *hash_size_out = hash_size;

    ret = 0;

done:

    if (free_hash)
        vic_hash_free(&ctx);

    return ret;
}

static void _dump_binary_hdr(
    FILE* os,
    const luks2_hdr_t* hdr,
    size_t indent)
{
    traits_t t = { " ", "\n" };

    _indent(os, indent++, t);
    printf("{\n");

    if (memcmp(hdr->magic, _magic_1st, sizeof(hdr->magic)) == 0)
    {
        _indent(os, indent, t);
        printf("magic: LUKS[0xba][0xbe]\n");
    }
    else if (memcmp(hdr->magic, _magic_2nd, sizeof(hdr->magic)) == 0)
    {
        _indent(os, indent, t);
        printf("magic: SKUL[0xba][0xbe]\n");
    }

    _indent(os, indent, t);
    printf("version: %u\n", hdr->version);

    _indent(os, indent, t);
    printf("hdr_size: %lu\n", hdr->hdr_size);

    _indent(os, indent, t);
    printf("seqid: %lu\n", hdr->seqid);

    _indent(os, indent, t);
    printf("label: \"%s\"\n", hdr->label);

    _indent(os, indent, t);
    printf("csum_alg: \"%s\"\n", hdr->csum_alg);

    _indent(os, indent, t);
    printf("salt:\n");
    vic_hexdump_special(hdr->salt, sizeof(hdr->salt), true, true, indent + 1);

    _indent(os, indent, t);
    printf("uuid: \"%s\"\n", hdr->uuid);

    _indent(os, indent, t);
    printf("subsystem: \"%s\"\n", hdr->subsystem);

    _indent(os, indent, t);
    printf("hdr_offset: %lu\n", hdr->hdr_offset);

    _indent(os, indent, t);
    printf("csum:\n");
    vic_hexdump_special(hdr->csum, vic_hash_size(hdr->csum_alg),
        true, true, indent + 1);

    _indent(os, --indent, t);
    printf("}\n");
}

int luks2_dump_hdr(const luks2_hdr_t* hdr)
{
    int ret = -1;
    luks2_ext_hdr_t* ext = (luks2_ext_hdr_t*)hdr;

    /* Reject null parameters */
    if (!hdr || !_is_valid_luks2_hdr(hdr, false))
        GOTO(done);

    printf("{\n");
    {
        _dump_binary_hdr(stdout, &ext->phdr, 1);

        _dump_binary_hdr(stdout, &ext->shdr, 1);

        /* Verify the check sum */
        {
            vic_hash_t hash;
            size_t hash_size;

            if (_calculate_csum(
                &ext->phdr,
                ext->json_data,
                ext->json_size,
                &hash,
                &hash_size) != 0)
            {
                GOTO(done);
            }

            if (memcmp(hash.u.sha256, ext->phdr.csum, hash_size) != 0)
                GOTO(done);
        }

#if 0
        printf("%.*s\n", (int)ext->json_size, ext->json_data);
        json_print(stdout, ext->json_data, ext->json_size);
#endif

        /* Dump the JSON objects */
        {
            traits_t t = { " ", "\n" };

            if (_dump_json_objects(stdout, ext, 1, t) != 0)
                GOTO(done);
        }

    }
    printf("}\n");

    /* ATTN: remove or normalize JSON object ordering */
#if 0
    /* Compare with original JSON */
    {
        char* json;

        if (!(json = _to_json(ext)))
            GOTO(done);

        if (strlen(json) != strlen(ext->json_data))
        {
            fprintf(stderr, "*** WARNING: JSON size mismatch\n");
            GOTO(done);
        }

        if (strcmp(json, ext->json_data) != 0)
        {
            fprintf(stderr, "*** WARNING: JSON data mismatch\n");
            json_print(stderr, json, strlen(json) + 1);
            json_print(stderr, ext->json_data, strlen(ext->json_data) + 1);
            GOTO(done);
        }

        vic_free(json);
    }
#endif

    ret = 0;

done:
    return ret;
}

typedef struct
{
    /* The offset to the LUKS2 secondary header */
    uint64_t offset;

    /* The size of the JSON area in kilobytes */
    uint64_t json_kbytes;
}
sec_hdr_offset_t;

static sec_hdr_offset_t _sec_hdr_offsets[] =
{
    { 16384,  12 }, /* default header size */
    { 32768,  28 },
    { 65536,  60 },
    { 131072,  124 },
    { 262144,  252 },
    { 524288,  508 },
    { 1048576,  1020 },
    { 2097152,  2044 },
    { 4194304,  4092 },
};

static int _read_binary_hdr(
    vic_blockdev_t* dev,
    luks2_hdr_t* hdr,
    bool primary)
{
    int ret = -1;
    size_t blkno =  primary ? 0 : (DEFAULT_HDR_SIZE / VIC_SECTOR_SIZE);
    uint8_t blocks[sizeof(luks2_hdr_t)];
    const size_t nblocks = sizeof(blocks) / VIC_SECTOR_SIZE;

    if (vic_blockdev_get(dev, blkno, blocks, nblocks) != VIC_OK)
        GOTO(done);

    VIC_STATIC_ASSERT(sizeof(luks2_hdr_t) <= sizeof(blocks));
    memcpy(hdr, blocks, sizeof(luks2_hdr_t));

    /* Check the magic number */
    if (!_is_valid_luks2_hdr(hdr, true))
        GOTO(done);

    _fix_luks2_hdr_byte_order(hdr);

    ret = 0;

done:
    return ret;
}

static int _write_binary_hdr(
    vic_blockdev_t* dev,
    const luks2_hdr_t* hdr,
    bool primary)
{
    int ret = -1;
    uint8_t blocks[sizeof(luks2_hdr_t)];
    size_t nblocks = sizeof(blocks) / VIC_SECTOR_SIZE;
    luks2_hdr_t buf;
    size_t blkno = primary ? 0 : hdr->hdr_size / VIC_SECTOR_SIZE;

    assert(sizeof(blocks) == sizeof(luks2_hdr_t));

    buf = *hdr;
    _fix_luks2_hdr_byte_order(&buf);
    memset(blocks, 0, sizeof(blocks));
    memcpy(blocks, &buf, sizeof(luks2_hdr_t));

    if (vic_blockdev_put(dev, blkno, blocks, nblocks) != VIC_OK)
        GOTO(done);

    ret = 0;

done:
    return ret;
}

static int _read_json_area(
    vic_blockdev_t* dev,
    const luks2_hdr_t* hdr,
    char* json_data,
    size_t json_size)
{
    int ret = -1;
    size_t blkno = (sizeof(luks2_hdr_t) + hdr->hdr_offset) / VIC_SECTOR_SIZE;
    void* blocks = json_data;
    const size_t nblocks = json_size / VIC_SECTOR_SIZE;

    if (vic_blockdev_get(dev, blkno, blocks, nblocks) != 0)
        GOTO(done);

    ret = 0;

done:
    return ret;
}

static int _write_json_area(
    vic_blockdev_t* dev,
    const luks2_hdr_t* hdr,
    const char* json_data,
    size_t json_size)
{
    int ret = -1;
    size_t blkno = (sizeof(luks2_hdr_t) + hdr->hdr_offset) / VIC_SECTOR_SIZE;
    const void* blocks = json_data;
    const size_t nblocks = json_size / VIC_SECTOR_SIZE;

    if (vic_blockdev_put(dev, blkno, blocks, nblocks) != 0)
        GOTO(done);

    ret = 0;

done:
    return ret;
}

static int _read_key_material(
    vic_blockdev_t* dev,
    uint64_t offset,
    uint64_t size,
    void* buf)
{
    int ret = -1;

    if (!dev || !buf)
        GOTO(done);

    /* Read the key material */
    {
        uint64_t blkno = offset / VIC_SECTOR_SIZE;
        size_t nblocks = size / VIC_SECTOR_SIZE;

        if (vic_blockdev_get(dev, blkno, buf, nblocks) != 0)
            GOTO(done);
    }

    ret = 0;

done:
    return ret;
}

static int _write_key_material(
    vic_blockdev_t* dev,
    const luks2_keyslot_t* ks,
    const void* buf)
{
    int ret = -1;
    void* zeros = NULL;

    if (!dev || !ks)
        GOTO(done);

    /* Write the key material (or clear it if buf is null) */
    {
        uint64_t blkno = ks->area.offset / VIC_SECTOR_SIZE;
        size_t nblocks = ks->area.size / VIC_SECTOR_SIZE;

        if (buf)
        {
            if (vic_blockdev_put(dev, blkno, buf, nblocks) != 0)
                GOTO(done);
        }
        else
        {
            if (!(zeros = vic_calloc(ks->area.size, 1)))
                GOTO(done);

            if (vic_blockdev_put(dev, blkno, zeros, nblocks) != 0)
                GOTO(done);
        }
    }

    ret = 0;

done:

    if (zeros)
        vic_free(zeros);

    return ret;
}

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

int luks2_read_hdr(vic_blockdev_t* dev, luks2_hdr_t** hdr_out)
{
    int ret = -1;
    luks2_hdr_t hdr;
    luks2_ext_hdr_t* ext = NULL;
    size_t min_hdr_size;
    char* data = NULL;
    char* json_data = NULL;

    if (hdr_out)
        *hdr_out = NULL;

    /* Reject null parameters */
    if (!_is_valid_device(dev) || !hdr_out)
        GOTO(done);

    /* Read the primary header */
    if (_read_binary_hdr(dev, &hdr, true) != 0)
        GOTO(done);

    /* Check the version (must be 2) */
    if (hdr.version != LUKS_VERSION_2)
        GOTO(done);

    /* There must be at least room for the minimally-sized JSON area */
    if (hdr.hdr_size < _sec_hdr_offsets[0].offset)
        GOTO(done);

    /* Calculate the smallest total header size (including JSON area) */
    min_hdr_size = sizeof(hdr) + _sec_hdr_offsets[0].json_kbytes * 1024;

    /* Fail if total header is too small */
    if (hdr.hdr_size < min_hdr_size)
        GOTO(done);

    /* Allocate space for the extended header */
    {
        const size_t json_size = hdr.hdr_size - sizeof(luks2_hdr_t);

        /* Allocate space for the header struct and the JSON area */
        if (!(ext = vic_calloc(1, sizeof(luks2_ext_hdr_t) + json_size)))
            GOTO(done);

        memcpy(ext, &hdr, sizeof(luks2_hdr_t));
        ext->json_size = json_size;
    }

    /* Validate the offset of the secondary header */
    {
        size_t index = (size_t)-1;
        const size_t KILOBYTE = 1024;

        for (size_t i = 0; i < VIC_COUNTOF(_sec_hdr_offsets); i++)
        {
            if (_sec_hdr_offsets[i].offset == hdr.hdr_size)
            {
                index = i;
                break;
            }
        }

        if (index == (size_t)-1)
            GOTO(done);

        if (_sec_hdr_offsets[index].json_kbytes != ext->json_size / KILOBYTE)
            GOTO(done);
    }

    /* Read the JSON area */
    if (_read_json_area(dev, &hdr, ext->json_data, ext->json_size) != 0)
        GOTO(done);

    /* Verify the csum_alg */
    if (vic_hash_type(hdr.csum_alg) == VIC_HASH_NONE)
        GOTO(done);

    /* Verify the check sum */
    {
        vic_hash_t hash;
        size_t hash_size;

        if (_calculate_csum(
            &ext->phdr,
            ext->json_data,
            ext->json_size,
            &hash,
            &hash_size) != 0)
        {
            GOTO(done);
        }

        if (memcmp(hash.u.buf, hdr.csum, hash_size) != 0)
            GOTO(done);
    }

    /* Parse and read the JSON elements */
    {
        json_parser_t parser;
        static json_allocator_t allocator =
        {
            vic_malloc,
            vic_free,
        };

        json_callback_data_t callback_data = { ext, 0, { 0 } };

        /* Copy the JSON data since the parser destroys its input */
        {
            if (!(data = vic_malloc(ext->json_size)))
                GOTO(done);

            memcpy(data, ext->json_data, ext->json_size);
        }

        /* Initialize the JSON parser */
        if (json_parser_init(
            &parser,
            data,
            ext->json_size,
            _json_read_callback,
            &callback_data,
            &allocator) != JSON_OK)
        {
            GOTO(done);
        }

        /* Perform the parsing */
        if (json_parser_parse(&parser) != JSON_OK)
            GOTO(done);

        /* Verify that there are no open JSON elements */
        if (callback_data.depth != 0)
            GOTO(done);
    }

    /* Read and verify the secondary header */
    {
        luks2_hdr_t* shdr = &ext->shdr;

        /* Read the secondary header */
        if (_read_binary_hdr(dev, shdr, false) != 0)
            GOTO(done);

        /* Verify the checksum */
        {
            vic_hash_t hash;
            size_t hash_size;

            if (_calculate_csum(
                shdr,
                ext->json_data,
                ext->json_size,
                &hash,
                &hash_size) != 0)
            {
                GOTO(done);
            }

            if (memcmp(shdr->csum, hash.u.buf, hash_size) != 0)
                GOTO(done);
        }

        /* Validate the checksum and the consistency of the binary header */
        {
            if (memcmp(shdr->magic, _magic_2nd, sizeof(shdr->magic)) != 0)
                GOTO(done);

            if (shdr->version != hdr.version)
                GOTO(done);

            if (shdr->hdr_size != hdr.hdr_size)
                GOTO(done);

            if (shdr->seqid != hdr.seqid)
                GOTO(done);

            if (strcmp(shdr->label, hdr.label) != 0)
                GOTO(done);

            if (strcmp(shdr->csum_alg, hdr.csum_alg) != 0)
                GOTO(done);

            if (strcmp(shdr->uuid, hdr.uuid) != 0)
                GOTO(done);

            if (strcmp(shdr->subsystem, hdr.subsystem) != 0)
                GOTO(done);

            if (shdr->hdr_offset != hdr.hdr_size)
                GOTO(done);

            /* Note: the header and secondary header have different salts */

            if (shdr->hdr_offset != ext->phdr.hdr_size)
                GOTO(done);
        }

        /* Validate the consistency of the JSON */
        {
            const size_t json_size = shdr->hdr_size - sizeof(luks2_hdr_t);

            if (ext->json_size != json_size)
                GOTO(done);

            if (!(json_data = vic_calloc(json_size, 1)))
                GOTO(done);

            if (_read_json_area(dev, shdr, json_data, json_size) != 0)
                GOTO(done);

            if (memcmp(ext->json_data, json_data, json_size) != 0)
                GOTO(done);
        }
    }
    *hdr_out = &ext->phdr;
    ext = NULL;

    ret = 0;

done:

    if (ext)
        vic_free(ext);

    if (data)
        vic_free(data);

    if (json_data)
        vic_free(json_data);

    return ret;
}

static const mbedtls_cipher_info_t* _get_cipher_info(
    const char* encryption,
    uint64_t key_bytes)
{
    const mbedtls_cipher_info_t* ret = NULL;
    mbedtls_cipher_type_t cipher_type;

    if (strcmp(encryption, "aes-xts-plain64") == 0)
    {
        const uint64_t key_bits = key_bytes * 8;

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
        /* ATTN: support other cipher types */
        GOTO(done);
    }

    ret = mbedtls_cipher_info_from_type(cipher_type);

done:
    return ret;
}

/* Generate the initialization vector */
static int _gen_iv(
    const char* encryption,
    size_t key_bytes,
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

    if (!iv || !key)
        GOTO(done);

    if (strcmp(encryption, "aes-xts-plain64") == 0)
    {
        memcpy(iv, &sector, sizeof(uint64_t));
        ret = 0;
        goto done;
    }

    /* Compute the hash of the key */
    if (vic_hash1(VIC_HASH_SHA256, key, key_bytes, &hash) != 0)
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
    mbedtls_operation_t op, /* MBEDTLS_ENCRYPT or MBEDTLS_DECRYPT */
    const char* encryption,
    size_t key_bytes,
    const vic_key_t* key,
    const uint8_t* data_in,
    uint8_t *data_out,
    size_t data_size,
    uint64_t sector)
{
    int ret = -1;
    const mbedtls_cipher_info_t* ci;
    mbedtls_cipher_context_t cipher_ctx;
    const size_t key_bits = key_bytes * 8;
    uint8_t iv[LUKS_IV_SIZE];
    uint64_t i;
    uint64_t iters;
    uint64_t block_len;

    mbedtls_cipher_init(&cipher_ctx);

    if (!(ci = _get_cipher_info(encryption, key_bytes)))
        GOTO(done);

    if (mbedtls_cipher_setup(&cipher_ctx, ci) != 0)
        GOTO(done);

    if (mbedtls_cipher_setkey(&cipher_ctx, key->buf, key_bits, op) != 0)
        GOTO(done);

    iters = data_size / VIC_SECTOR_SIZE;
    block_len = VIC_SECTOR_SIZE;

    for (i = 0; i < iters; i++)
    {
        uint64_t pos;
        size_t olen;

        if (_gen_iv(encryption, key_bytes, sector + i, iv, key->buf) == -1)
            GOTO(done);

        pos = i * block_len;

        if (mbedtls_cipher_crypt(
            &cipher_ctx,
            iv, /* iv */
            LUKS_IV_SIZE, /* iv_size */
            data_in + pos, /* input */
            block_len, /* ilen */
            data_out + pos, /* output */
            &olen) != 0) /* olen */
        {
            GOTO(done);
        }
    }

    ret = 0;

done:
    mbedtls_cipher_free(&cipher_ctx);

    return ret;
}

static int _encrypt(
    const char* encryption,
    uint64_t key_bytes,
    const vic_key_t* key,
    const uint8_t* data_in,
    uint8_t *data_out,
    size_t data_size,
    uint64_t sector)
{
    const mbedtls_operation_t op = MBEDTLS_ENCRYPT;
    return _crypt(
        op,
        encryption,
        key_bytes,
        key,
        data_in,
        data_out,
        data_size,
        sector);
}

static int _decrypt(
    const char* encryption,
    uint64_t key_bytes,
    const vic_key_t* key,
    const uint8_t* data_in,
    uint8_t *data_out,
    size_t data_size,
    uint64_t sector)
{
    const mbedtls_operation_t op = MBEDTLS_DECRYPT;
    return _crypt(
        op,
        encryption,
        key_bytes,
        key,
        data_in,
        data_out,
        data_size,
        sector);
}

static const luks2_digest_t* _find_digest(
    luks2_ext_hdr_t* ext,
    size_t keyslot_index)
{
    for (size_t i = 0; i < VIC_COUNTOF(ext->digests); i++)
    {
        const luks2_digest_t* digest = &ext->digests[i];

        for (size_t j = 0; j < VIC_COUNTOF(digest->keyslots); j++)
        {
            if (digest->keyslots[j] && j == keyslot_index)
                return digest;
        }
    }

    return NULL;
}

static vic_result_t _find_key_by_pwd(
    vic_blockdev_t* dev,
    luks2_ext_hdr_t* ext,
    const char* pwd,
    size_t pwd_size,
    vic_key_t* key,
    size_t* key_size,
    size_t* index)
{
    vic_result_t result = VIC_OK;
    bool found = false;
    void* cipher = NULL;
    void* plain = NULL;

    if (index)
        *index = (size_t)-1;

    if (key)
        memset(key, 0, sizeof(vic_key_t));

    for (size_t i = 0; i < VIC_COUNTOF(ext->keyslots); i++)
    {
        luks2_keyslot_t* ks = &ext->keyslots[i];
        vic_key_t pbkdf2_key;
        size_t size;
        vic_key_t mk;
        uint8_t mk_digest[LUKS2_DIGEST_SIZE];
        size_t digest_size;
        const luks2_digest_t* digest;

        if (*ks->type == '\0')
            continue;

        if (strcmp(ks->type, "luks2") != 0)
            RAISE(VIC_UNKNOWN_KEYSLOT_TYPE);

        if (strcmp(ks->kdf.type, "pbkdf2") == 0)
        {
            if (vic_pbkdf2(
                pwd,
                pwd_size,
                ks->kdf.salt,
                sizeof(ks->kdf.salt),
                ks->kdf.iterations,
                ks->kdf.hash,
                &pbkdf2_key,
                ks->area.key_size) != 0)
            {
                RAISE(VIC_PBKDF2_FAILED);
            }
        }
        else if (strcmp(ks->kdf.type, "argon2i") == 0)
        {
            if (vic_argon2i(
                pwd,
                pwd_size,
                ks->kdf.salt,
                sizeof(ks->kdf.salt),
                ks->kdf.time,
                ks->kdf.memory,
                ks->kdf.cpus,
                &pbkdf2_key,
                ks->area.key_size) != 0)
            {
                RAISE(VIC_ARGON2I_FAILED);
            }
        }
        else if (strcmp(ks->kdf.type, "argon2id") == 0)
        {
            if (vic_argon2id(
                pwd,
                pwd_size,
                ks->kdf.salt,
                sizeof(ks->kdf.salt),
                ks->kdf.time,
                ks->kdf.memory,
                ks->kdf.cpus,
                &pbkdf2_key,
                ks->area.key_size) != 0)
            {
                RAISE(VIC_ARGON2I_FAILED);
            }
        }

        size = ks->area.size;

        if (!(cipher = vic_calloc(size, 1)))
            RAISE(VIC_OUT_OF_MEMORY);

        if (_read_key_material(
            dev,
            ks->area.offset,
            ks->area.size,
            cipher) != 0)
        {
            RAISE(VIC_KEY_MATERIAL_READ_FAILED);
        }

        if (!(plain = vic_calloc(size, 1)))
            RAISE(VIC_OUT_OF_MEMORY);

        if (_decrypt(
            ks->area.encryption,
            ks->area.key_size,
            &pbkdf2_key,
            cipher,
            plain,
            size,
            0) != 0)
        {
            RAISE(VIC_DECRYPT_FAILED);
        }

        if (vic_afmerge(
            ks->key_size,
            ks->af.stripes,
            ks->af.hash,
            plain,
            &mk) != 0)
        {
            RAISE(VIC_AFMERGE_FAILED);
        }

        if (!(digest = _find_digest(ext, i)))
            RAISE(VIC_DIGEST_NOT_FOUND);

        if ((digest_size = vic_hash_size(digest->hash)) == (size_t)-1)
            RAISE(VIC_UNEXPECTED);

        if (strcmp(digest->type, "pbkdf2") == 0)
        {
            if (vic_pbkdf2(
                &mk,
                ks->key_size,
                digest->salt,
                sizeof(digest->salt),
                digest->iterations,
                digest->hash,
                mk_digest,
                digest_size) != 0)
            {
                RAISE(VIC_PBKDF2_FAILED);
            }
        }
        else
        {
            RAISE(VIC_UNSUPPORTED);
        }

        if (memcmp(digest->digest, mk_digest, digest_size) == 0)
        {
            found = true;

            if (key)
                memcpy(key, &mk, ks->key_size);

            if (key_size)
                *key_size = ks->key_size;

            if (index)
                *index = i;

            break;
        }

        vic_free(cipher);
        cipher = NULL;

        vic_free(plain);
        plain = NULL;
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

vic_result_t luks2_recover_master_key(
    vic_blockdev_t* dev,
    const char* pwd,
    size_t pwd_size,
    vic_key_t* master_key,
    size_t* master_key_bytes)
{
    vic_result_t result = VIC_OK;
    luks2_hdr_t* hdr = NULL;
    luks2_ext_hdr_t* ext;

    if (!_is_valid_device(dev))
        RAISE(VIC_BAD_DEVICE);

    if (!pwd)
        RAISE(VIC_BAD_PARAMETER);

    if (master_key)
        memset(master_key, 0, sizeof(vic_key_t));

    if (luks2_read_hdr(dev, &hdr) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    ext = (luks2_ext_hdr_t*)hdr;

    CHECK(_find_key_by_pwd(
        dev, ext, pwd, pwd_size, master_key, master_key_bytes, NULL));

done:

    if (hdr)
        vic_free(hdr);

    return result;
}

static int _init_keyslot(
    luks2_keyslot_t* ks_out,
    const char* keyslot_cipher,
    uint64_t key_size,
    uint64_t area_key_size,
    const char* pbkdf_type,
    const char* pbkdf2_hash,
    uint64_t pbkdf2_iterations,
    uint64_t argon2_time,
    uint64_t argon2_memory,
    uint64_t argon2_cpus,
    size_t index)
{
    int ret = -1;
    size_t area_size = vic_round_up(DEFAULT_AF_STRIPES * key_size, 4096);
    size_t area_offset = (DEFAULT_HDR_SIZE * 2) + (area_size * index);
    size_t hash_size;

    if (!ks_out || !keyslot_cipher || !key_size)
        goto done;

    if (!_valid_pbkdf_type(pbkdf_type))
        goto done;

    if (!pbkdf2_hash)
        pbkdf2_hash = DEFAULT_KDF_HASH;

    if ((hash_size = vic_hash_size(pbkdf2_hash)) == (size_t)-1)
        goto done;

    luks2_keyslot_t ks =
    {
        .type = "luks2",
        .key_size = key_size,
        .kdf =
        {
            .type = "",
            .salt = { 0 },
            /* pbkdf2 */
            .hash = "",
            .iterations = 0,
            /* argon2 */
            .time = 0,
            .memory = 0,
            .cpus = 0,
        },
        .af =
        {
            .type = "luks1",
            .hash = DEFAULT_HASH,
            .stripes = DEFAULT_AF_STRIPES,
        },
        .area =
        {
            .type = "raw",
            .key_size = area_key_size,
            .offset = area_offset,
            .size = area_size,
        },
    };

    if (STRLCPY(ks.kdf.type, pbkdf_type) != 0)
        goto done;

    if (strcmp(pbkdf_type, "pbkdf2") == 0)
    {
        if (STRLCPY(ks.kdf.hash, pbkdf2_hash) != 0)
            goto done;

        ks.kdf.iterations =
            pbkdf2_iterations ? pbkdf2_iterations : DEFAULT_KDF_ITERATIONS;
    }
    else if (strncmp(pbkdf_type, "argon2i", 7) == 0)
    {
        ks.kdf.time = argon2_time ? argon2_time : DEFAULT_KDF_TIME;
        ks.kdf.memory = argon2_memory ? argon2_memory : DEFAULT_KDF_MEMORY;
        ks.kdf.cpus = argon2_cpus ? argon2_cpus : DEFAULT_KDF_CPUS;
    }

    vic_strlcpy(ks.af.hash, pbkdf2_hash, sizeof(ks.af.hash));
    vic_strlcpy(ks.area.encryption, keyslot_cipher, sizeof(ks.area.encryption));

    vic_random(ks.kdf.salt, sizeof(ks.kdf.salt));

#if 0
    if ((ks.kdf.cpus = vic_num_cpus()) == (uint64_t)-1)
        GOTO(done);
#endif

    *ks_out = ks;

    ret = 0;

done:
    return ret;
}

static vic_result_t _initialize_hdr(
    luks2_ext_hdr_t** ext_out,
    const char* label,
    const char* subsystem,
    const vic_key_t* key,
    size_t key_size,
    const char* cipher,
    const char* uuid,
    const char* hash,
    uint64_t iterations,
    const char* integrity)
{
    vic_result_t result = VIC_OK;
    luks2_ext_hdr_t* p = NULL;
    const size_t hdr_size = DEFAULT_HDR_SIZE;
    size_t keyslots_size;
    size_t json_size = DEFAULT_HDR_SIZE - sizeof(vic_luks_hdr_t);

    if (!ext_out)
        RAISE(VIC_BAD_PARAMETER);

    /* hdr */
    {
        luks2_hdr_t hdr =
        {
            .magic = LUKS_MAGIC_1ST,
            .version = LUKS_VERSION_2,
            .hdr_size = hdr_size,
            .seqid = 1,
            .label = "",
            .csum_alg = DEFAULT_HASH,
            .salt = { 0 },
            .uuid = "",
            .subsystem = "",
            .hdr_offset = 0,
            ._padding = { 0 },
            .csum = { 0 },
            ._padding4096 = { 0 },
        };

        /* hdr.label */
        if (label)
            vic_strlcpy(hdr.label, label, sizeof(hdr.label));

        /* hdr.subsystem */
        if (subsystem)
            vic_strlcpy(hdr.subsystem, subsystem, sizeof(hdr.subsystem));

        if (!(p = vic_calloc(1, sizeof(luks2_ext_hdr_t) + json_size)))
            RAISE(VIC_OUT_OF_MEMORY);

        p->phdr = hdr;

        /* hdr.hdr_size */
        p->phdr.hdr_size = hdr_size;

        /* hdr.salt */
        vic_random(p->phdr.salt, sizeof(p->phdr.salt));

        /* hdr.uuid */
        strcpy(p->phdr.uuid, uuid);
    }

    /* hdr.keyslots[] */
    {
        const size_t hdr_sizes = 2 * p->phdr.hdr_size;
#if 0
        size_t area_size = vic_round_up(DEFAULT_AF_STRIPES * key_size, 4096);
#endif

        /* Calcualte the keyslots size */
        keyslots_size = OVERHEAD_BYTES - hdr_sizes;

#if 0
        /* ATTN: figure out why this fails */
        /* Verify that keyslots_size is big enough */
        if (keyslots_size < LUKS2_NUM_KEYSLOTS * area_size)
            RAISE(VIC_UNEXPECTED);
#endif
    }

    /* hdr.segments[] */
    {
        luks2_segment_t s =
        {
            .type = "crypt",
            .iv_tweak = 0,
            .size = (uint64_t)-1, /* dynamic */
            .sector_size = VIC_SECTOR_SIZE,
        };

        vic_strlcpy(s.encryption, cipher, sizeof(s.encryption));

        s.offset = (2 * hdr_size) + keyslots_size;

        /* Handle integrity parameter */
        if (integrity)
        {
            if (!vic_integrity_valid(integrity))
                RAISE(VIC_BAD_INTEGRITY_TYPE);

            if (STRLCPY(s.integrity.type, integrity) != 0)
                RAISE(VIC_BUFFER_TOO_SMALL);

            strcpy(s.integrity.journal_encryption, "none");
            strcpy(s.integrity.journal_integrity, "none");
        }

        p->segments[0] = s;
    }

    /* hdr.digests */
    {
        size_t digest_size;

        luks2_digest_t d =
        {
            .type = "pbkdf2",
            .segments = { 1 },
            .iterations = iterations,
        };

        if ((digest_size = vic_hash_size(hash)) == (size_t)-1)
            RAISE(VIC_UNEXPECTED);

        vic_strlcpy(d.hash, hash, sizeof(d.hash));

        vic_random(d.salt, sizeof(d.salt));

        if (vic_pbkdf2(
            key->buf,
            key_size,
            d.salt,
            sizeof(d.salt),
            d.iterations,
            d.hash,
            d.digest,
            digest_size) != 0)
        {
            RAISE(VIC_PBKDF2_FAILED);
        }

        p->digests[0] = d;
    }

    /* hdr.config */
    {
        p->config.json_size = hdr_size - sizeof(luks2_hdr_t);
        p->config.keyslots_size = keyslots_size;
    }

    /* Allocate the JSON area */
    {
        p->json_size = p->config.json_size;
        memset(p->json_data, 0, p->json_size);
    }

    /* Fill the JSON area */
    {
        char* json;
        size_t json_len;

        if (!(json = _to_json(p)))
            RAISE(VIC_FAILED);

        if ((json_len = strlen(json)) >= p->json_size)
        {
            vic_free(json);
            RAISE(VIC_FAILED);
        }

        memset(p->json_data, 0, p->json_size);
        memcpy(p->json_data, json, json_len);
        vic_free(json);
    }

    /* Calculate hdr.csum */
    {
        vic_hash_t hash;
        size_t hash_size;

        if (_calculate_csum(
            &p->phdr,
            p->json_data,
            p->json_size,
            &hash,
            &hash_size) != 0)
        {
            GOTO(done);
        }

        memset(p->phdr.csum, 0, sizeof(p->phdr.csum));
        memcpy(p->phdr.csum, hash.u.buf, hash_size);
    }

    *ext_out = p;
    p = NULL;

done:

    if (p)
        vic_free(p);

    return result;
}

static vic_result_t _generate_key_material(
    luks2_ext_hdr_t* ext,
    const luks2_keyslot_t* ks,
    const vic_key_t* key,
    const char* pwd,
    size_t pwd_size,
    void** data_out)
{
    vic_result_t result = VIC_OK;
    uint8_t* plain = NULL;
    uint8_t* cipher = NULL;
    vic_key_t pbkdf2_key;

    if (data_out)
        *data_out = NULL;

    if (!ext || !ks || !key|| !pwd)
        RAISE(VIC_BAD_PARAMETER);

    if (!(plain = vic_calloc(1, ks->area.size)))
        RAISE(VIC_OUT_OF_MEMORY);

    if (!(cipher = vic_calloc(1, ks->area.size)))
        RAISE(VIC_OUT_OF_MEMORY);

    if (strcmp(ks->kdf.type, "pbkdf2") == 0)
    {
        if (vic_pbkdf2(
            pwd,
            pwd_size,
            ks->kdf.salt,
            sizeof(ks->kdf.salt),
            ks->kdf.iterations,
            ks->kdf.hash,
            &pbkdf2_key,
            ks->area.key_size) != 0)
        {
            RAISE(VIC_PBKDF2_FAILED);
        }
    }
    else if (strcmp(ks->kdf.type, "argon2i") == 0)
    {
        if (vic_argon2i(
            pwd,
            pwd_size,
            ks->kdf.salt,
            sizeof(ks->kdf.salt),
            ks->kdf.time,
            ks->kdf.memory,
            ks->kdf.cpus,
            &pbkdf2_key,
            ks->area.key_size) != 0)
        {
            RAISE(VIC_ARGON2I_FAILED);
        }
    }
    else if (strcmp(ks->kdf.type, "argon2id") == 0)
    {
        if (vic_argon2id(
            pwd,
            pwd_size,
            ks->kdf.salt,
            sizeof(ks->kdf.salt),
            ks->kdf.time,
            ks->kdf.memory,
            ks->kdf.cpus,
            &pbkdf2_key,
            ks->area.key_size) != 0)
        {
            RAISE(VIC_ARGON2I_FAILED);
        }
    }

    if (vic_afsplit(
        ks->af.hash,
        key,
        ks->key_size,
        ks->af.stripes,
        plain) != 0)
    {
        RAISE(VIC_AFSPLIT_FAILED);
    }

    /* Encrypt the stripes */
    if (_encrypt(
        ks->area.encryption,
        ks->area.key_size,
        &pbkdf2_key,
        plain,
        cipher,
        ks->area.size,
        0) != 0)
    {
        RAISE(VIC_ENCRYPT_FAILED);
    }

    if (data_out)
    {
        *data_out = cipher;
        cipher = NULL;
    }

done:

    if (plain)
        vic_free(plain);

    if (cipher)
        vic_free(cipher);

    return result;
}

static vic_result_t _get_payload_size_in_sectors(
    vic_blockdev_t* dev,
    uint64_t payload_offset,
    uint64_t* payload_size)
{
    vic_result_t result = VIC_OK;
    size_t num_sectors;

    CHECK(vic_blockdev_get_num_blocks(dev, &num_sectors));

    if (payload_offset >= num_sectors)
        RAISE(VIC_DEVICE_TOO_SMALL);

    *payload_size = num_sectors - payload_offset;

done:
    return result;
}

static int _clear_integrity_superblock(
    vic_blockdev_t* dev,
    luks2_ext_hdr_t* ext)
{
    int ret = -1;
    uint64_t blkno;
    uint8_t blk[VIC_SECTOR_SIZE];

    if (!dev || !ext)
        goto done;

    /* Get the payload offset in sectors */
    blkno = ext->segments[0].offset / VIC_SECTOR_SIZE;

    /* Write the block */
    memset(&blk, 0, sizeof(blk));

    if (vic_blockdev_put(dev, blkno, blk, 1) != VIC_OK)
        goto done;

    ret = 0;

done:
    return ret;
}

static int _gen_dev_name(
    char* name,
    size_t size,
    const char* prefix,
    const char* suffix)
{
    char uuid[VIC_UUID_STRING_SIZE];
    int n;

    vic_uuid_generate(uuid);

    n = snprintf(name, size, "%s%s%s", prefix, uuid, suffix);

    if (n <= 0 || (size_t)n >= size)
        return -1;

    return 0;
}

static vic_result_t _format_integrity_device(
    vic_blockdev_t* dev,
    luks2_ext_hdr_t* ext)
{
    vic_result_t result = VIC_OK;
    char name[PATH_MAX];
    char path[PATH_MAX];
    const size_t start = 0;
    const size_t size = 8; /* let dm-integrity determine the size */
    size_t offset;
    const char mode = 'J';

    /* Clear the superblock (dm-integrity initializes it) */
    if (_clear_integrity_superblock(dev, ext) != 0)
        RAISE(VIC_FAILED);

    /* Randomly generate a name (hex characters) */
    if (_gen_dev_name(name, sizeof(name), "temporary-luks-", "") != 0)
        RAISE(VIC_BUFFER_TOO_SMALL);

    /* Get the path from the device */
    CHECK(vic_blockdev_get_path(dev, path));

    /* Get the payload offset in sectors */
    offset = ext->segments[0].offset / VIC_SECTOR_SIZE;

    /* Let dm-integrity format the integrity device */
    CHECK(vic_dm_create_integrity(
        name, path, start, size, offset, mode, _get_integrity_type(ext)));

    /* Remove the integrity device from the device mapper */
    CHECK(vic_dm_remove(name));

done:
    return result;
}

static vic_result_t _open_integrity_device(
    vic_blockdev_t* dev,
    luks2_ext_hdr_t* ext,
    const char* name,
    char mode)
{
    vic_result_t result = VIC_OK;
    char path[PATH_MAX];
    size_t size;
    size_t offset;
    vic_integrity_sb_t sb;

    /* Read the super block */
    CHECK(vic_integrity_read_sb(dev, ext->segments[0].offset, &sb));

#if 0
    vic_integrity_dump_sb(&sb);
#endif

    /* Set the device size */
    size = sb.provided_data_sectors;

    CHECK(vic_blockdev_get_path(dev, path));

    /* Get the payload offset in sectors */
    offset = ext->segments[0].offset / VIC_SECTOR_SIZE;

    /* Create the integrity device */
    {
        const size_t start = 0;

        CHECK(vic_dm_create_integrity(
            name, path, start, size, offset, mode, _get_integrity_type(ext)));
    }

done:
    return result;
}

static vic_result_t _open_integrity_luks2_device(
    vic_blockdev_t* dev,
    luks2_ext_hdr_t* ext,
    const char* name,
    const char* path,
    const vic_key_t* key,
    size_t key_size)
{
    vic_result_t result = VIC_OK;
    uint64_t size;
    vic_integrity_sb_t sb;

    /* Get the size of the block device */
    if ((size = vic_blockdev_get_size_from_path(path)) == (size_t)-1)
        RAISE(VIC_FAILED);

    /* Read the super block */
    CHECK(vic_integrity_read_sb(dev, ext->segments[0].offset, &sb));

    size /= VIC_SECTOR_SIZE;

    CHECK(vic_dm_create_crypt(
        "CRYPT-LUKS2",
        name,
        path,
        ext->phdr.uuid,
        0, /* start */
        size,
        _get_integrity_type(ext),
        _get_encryption(ext),
        key->buf,
        key_size,
        0, /* iv_offset */
        0 /* offset */));

done:
    return result;
}

static vic_result_t _wipe_device(const char* path)
{
    vic_result_t result = VIC_OK;
    size_t size;
    int fd = -1;
    void* blk = NULL;
    const size_t blksz = 4096;
    size_t nblks;

    if (!path)
        RAISE(VIC_BAD_PARAMETER);

    /* Open the device to wiped */
    if ((fd = open(path, O_RDWR)) < 0)
        RAISE(VIC_FAILED);

    /* Allocate a zero-filled aligned block */
    {
        if (posix_memalign(&blk, blksz, blksz) != 0)
            goto done;

        memset(blk, 0, blksz);
    }

    /* Get the device size in bytes */
    if ((size = vic_blockdev_get_size_from_path(path)) == (size_t)-1)
        RAISE(VIC_FAILED);

    /* Determine the number of blocks */
    nblks = size / blksz;

    /* Zero out all the blocks */
    for (size_t i = 0; i < nblks; i++)
    {
        ssize_t n;
        size_t offset = i * blksz;

        if (lseek(fd, offset, SEEK_SET) != (ssize_t)offset)
            RAISE(VIC_FAILED);

        if ((n = write(fd, blk, blksz)) != (ssize_t)blksz)
            RAISE(VIC_WRITE_FAILED);
    }

    /* Fail if any bytes remain */
    if (size % blksz)
        RAISE(VIC_UNEXPECTED);

    /* Sync this device, else dm-remove will fail with device busy */
    fsync(fd);

done:

    if (fd >= 0)
        close(fd);

    if (blk)
        vic_free(blk);

    return result;
}

vic_result_t luks2_format(
    vic_blockdev_t* dev,
    const char* label,
    const char* subsystem,
    const char* cipher,
    const char* uuid,
    const char* hash,
    uint64_t iterations,
    const vic_key_t* master_key,
    size_t master_key_bytes,
    const char* integrity)
{
    vic_result_t result = VIC_OK;
    luks2_ext_hdr_t* ext = NULL;
    vic_key_t master_key_buf;
    char uuid_buf[VIC_UUID_STRING_SIZE];
    void* data = NULL;
    size_t num_device_blocks;

    if (!_is_valid_device(dev))
        RAISE(VIC_BAD_PARAMETER);

    if (uuid)
    {
        if (!vic_uuid_valid(uuid))
            RAISE(VIC_BAD_UUID);
    }
    else
    {
        vic_uuid_generate(uuid_buf);
        uuid = uuid_buf;
    }

    if (!hash)
        hash = DEFAULT_HASH;

    if (master_key)
    {
        if (master_key_bytes == 0)
            RAISE(VIC_BAD_PARAMETER);

        if (master_key_bytes > sizeof(vic_key_t))
            RAISE(VIC_KEY_TOO_BIG);
    }

    if (!master_key)
    {
        /* Randomly generate a master key */
        vic_random(&master_key_buf, sizeof(master_key_buf));
        master_key = &master_key_buf;
        master_key_bytes = sizeof(master_key_buf);
    }

    if (!cipher)
        cipher = LUKS_DEFAULT_CIPHER;

    if (iterations < LUKS_MIN_MK_ITERATIONS)
        iterations = LUKS_MIN_MK_ITERATIONS;

    /* Get the number of sectors in the device */
    CHECK(vic_blockdev_get_num_blocks(dev, &num_device_blocks));

    /* Verify that the device is big enough */
    if (num_device_blocks * VIC_SECTOR_SIZE < MIN_DEVICE_BYTES)
        RAISE(VIC_DEVICE_TOO_SMALL);

    /* Determine the device size in bytes */
    CHECK(_initialize_hdr(
        &ext,
        label,
        subsystem,
        master_key,
        master_key_bytes,
        cipher,
        uuid,
        hash,
        iterations,
        integrity));

    /* Verify that there is enough room for at least 1 payload block */
    {
        const size_t nblocks = ext->segments[0].offset / VIC_SECTOR_SIZE;

        if (nblocks >= num_device_blocks)
            RAISE(VIC_DEVICE_TOO_SMALL);
    }

    /* Write the primary binary header */
    if (_write_binary_hdr(dev, &ext->phdr, true) != 0)
        RAISE(VIC_FAILED);

    /* Write the primary JSON area */
    if (_write_json_area(
        dev,
        &ext->phdr,
        ext->json_data,
        ext->json_size) != 0)
    {
        RAISE(VIC_FAILED);
    }

    /* Initialize and write the secondary binary header */
    {
        /* Copy the primary header onto the secondary header */
        memcpy(&ext->shdr, &ext->phdr, sizeof(ext->shdr));

        /* Set shdr.magic */
        memcpy(&ext->shdr.magic, &_magic_2nd, sizeof(ext->shdr.magic));

        /* Set shdr.hdr_offset */
        ext->shdr.hdr_offset = ext->phdr.hdr_size;

        /* Calculate shdr.csum */
        {
            vic_hash_t hash;
            size_t hash_size;

            if (_calculate_csum(
                &ext->shdr,
                ext->json_data,
                ext->json_size,
                &hash,
                &hash_size) != 0)
            {
                GOTO(done);
            }

            memset(ext->shdr.csum, 0, sizeof(ext->shdr.csum));
            memcpy(ext->shdr.csum, hash.u.buf, hash_size);
        }

        /* Write the secondary binary header */
        if (_write_binary_hdr(dev, &ext->shdr, false) != 0)
            RAISE(VIC_FAILED);
    }

    /* Write the secondary JSON area (identical to the first) */
    if (_write_json_area(
        dev,
        &ext->shdr,
        ext->json_data,
        ext->json_size) != 0)
    {
        RAISE(VIC_FAILED);
    }

    /* Format the integrity header and journals if any */
    if (integrity)
    {
        char name[PATH_MAX];
        char name_dif[PATH_MAX];
        const char prefix[] = "temporary-luks-";
        char dmpath[PATH_MAX];
        char mode = 'D';

        CHECK(_format_integrity_device(dev, ext));

        /* Generate the name of the LUKS2 device */
        if (_gen_dev_name(name, sizeof(name), prefix, "") != 0)
            RAISE(VIC_BUFFER_TOO_SMALL);

        /* Format the name of the integrity device */
        if (snprintf(name_dif, sizeof(name_dif), "%s_dif", name) >= PATH_MAX)
            RAISE(VIC_BUFFER_TOO_SMALL);

        CHECK(_open_integrity_device(dev, ext, name_dif, mode));

        /* Format the name of the integrity device (under /dev/mapper) */
        snprintf(dmpath, sizeof(dmpath), "/dev/mapper/%s", name_dif);

        CHECK(_open_integrity_luks2_device(
            dev,
            ext,
            name,
            dmpath,
            master_key,
            master_key_bytes));

        snprintf(dmpath, sizeof(dmpath), "/dev/mapper/%s", name);

        CHECK(_wipe_device(dmpath));
        (void)_wipe_device;

        CHECK(vic_dm_remove(name));
        CHECK(vic_dm_remove(name_dif));
    }

done:

    if (ext)
        vic_free(ext);

    if (data)
        vic_free(data);

    return result;
}

static size_t _find_free_keyslot(luks2_ext_hdr_t* ext)
{
    for (size_t i = 0; i < VIC_COUNTOF(ext->keyslots); i++)
    {
        /* implement ks.enabled */
        if (ext->keyslots[i].type[0] == '\0')
            return i;
    }

    return (size_t)-1;
}

static vic_result_t _write_hdr(vic_blockdev_t* dev, luks2_ext_hdr_t* ext)
{
    vic_result_t result = VIC_OK;
    char* json = NULL;

    /* Regenerate the JSON area */
    {
        size_t json_len;

        if (!(json = _to_json(ext)))
            RAISE(VIC_FAILED);

        if ((json_len = strlen(json)) >= ext->json_size)
            RAISE(VIC_FAILED);

        memset(ext->json_data, 0, ext->json_size);
        memcpy(ext->json_data, json, json_len);
    }

    /* Rewrite the primary header */
    {
        /* Bump the sequence number */
        ext->phdr.seqid++;

        /* Calculate phdr.csum */
        {
            vic_hash_t hash;
            size_t hash_size;

            if (_calculate_csum(
                &ext->phdr,
                ext->json_data,
                ext->json_size,
                &hash,
                &hash_size) != 0)
            {
                GOTO(done);
            }

            memset(ext->phdr.csum, 0, sizeof(ext->phdr.csum));
            memcpy(ext->phdr.csum, hash.u.buf, hash_size);
        }

        /* Write the primary binary header */
        if (_write_binary_hdr(dev, &ext->phdr, true) != 0)
            RAISE(VIC_FAILED);
    }

    /* Write the primary JSON area */
    if (_write_json_area(
        dev,
        &ext->phdr,
        ext->json_data,
        ext->json_size) != 0)
    {
        RAISE(VIC_FAILED);
    }

    /* Rewrite the secondary header */
    {
        /* Bump the sequence number */
        ext->shdr.seqid++;

        /* Calculate shdr.csum */
        {
            vic_hash_t hash;
            size_t hash_size;

            if (_calculate_csum(
                &ext->shdr,
                ext->json_data,
                ext->json_size,
                &hash,
                &hash_size) != 0)
            {
                GOTO(done);
            }

            memset(ext->shdr.csum, 0, sizeof(ext->shdr.csum));
            memcpy(ext->shdr.csum, hash.u.buf, hash_size);
        }

        /* Write the secondary binary header */
        if (_write_binary_hdr(dev, &ext->shdr, false) != 0)
            RAISE(VIC_FAILED);
    }

    /* Write the secondary JSON area (identical to the first) */
    if (_write_json_area(
        dev,
        &ext->shdr,
        ext->json_data,
        ext->json_size) != 0)
    {
        RAISE(VIC_FAILED);
    }

done:

    if (json)
        vic_free(json);

    return result;
}

vic_result_t luks2_add_key(
    vic_blockdev_t* dev,
    const char* keyslot_cipher,
    const char* kdf_type,
    vic_kdf_t* kdf,
    const char* pwd,
    size_t pwd_size,
    const char* new_pwd,
    size_t new_pwd_size)
{
    vic_result_t result = VIC_OK;
    luks2_ext_hdr_t* ext = NULL;
    vic_key_t key;
    size_t key_size;
    size_t index;
    void* data = NULL;
    size_t area_key_size;

    /* Check parameters */
    if (!_is_valid_device(dev) || !pwd || !new_pwd)
        RAISE(VIC_BAD_PARAMETER);

    /* Handle kdf */
    {
        if (!kdf_type)
            kdf_type = DEFAULT_KDF_TYPE;

        if (!_valid_pbkdf_type(kdf_type))
            RAISE(VIC_BAD_PARAMETER);

        if (!kdf)
            kdf = _get_default_kdf(kdf_type);
    }

    /* Read the LUKS2 header */
    if (luks2_read_hdr(dev, (luks2_hdr_t**)&ext) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    /* Use password to find the master key */
    CHECK(_find_key_by_pwd(dev, ext, pwd, pwd_size, &key, &key_size,
        &index));

    /* The area key excludes the integrity key suffix (if any) */
    area_key_size = key_size - vic_integrity_key_size(
        ext->segments[0].integrity.type);

    if (!keyslot_cipher)
        keyslot_cipher = ext->keyslots[index].area.encryption;

    /* Add a new key slot */
    {
        if ((index = _find_free_keyslot(ext)) == (size_t)-1)
            RAISE(VIC_OUT_OF_KEYSLOTS);

        if (_init_keyslot(
            &ext->keyslots[index],
            keyslot_cipher,
            key_size,
            area_key_size,
            kdf_type,
            kdf->hash,
            kdf->iterations,
            kdf->time,
            kdf->memory,
            kdf->cpus,
            index) != 0)
        {
            RAISE(VIC_FAILED);
        }

        /* Add this keyslot to the digest[0] */
        ext->digests[0].keyslots[index] = 1;
    }

    /* Rewrite the header */
    CHECK(_write_hdr(dev, ext));

    /* Generate and write the key material for the new keyslot */
    {
        const luks2_keyslot_t* ks = &ext->keyslots[index];

        CHECK(_generate_key_material(ext, ks, &key, new_pwd, new_pwd_size,
            &data));

        if (_write_key_material(dev, ks, data) != 0)
            RAISE(VIC_KEY_MATERIAL_WRITE_FAILED);
    }

done:

    if (ext)
        vic_free(ext);

    if (data)
        vic_free(data);

    return result;
}

vic_result_t luks2_add_key_by_master_key(
    vic_blockdev_t* dev,
    const char* keyslot_cipher,
    const char* kdf_type,
    vic_kdf_t* kdf,
    const vic_key_t* master_key,
    size_t master_key_bytes,
    const char* pwd,
    size_t pwd_size)
{
    vic_result_t result = VIC_OK;
    luks2_ext_hdr_t* ext = NULL;
    size_t index;
    void* data = NULL;
    size_t area_key_size;

    /* Check parameters */
    if (!_is_valid_device(dev) || !keyslot_cipher || !master_key || !pwd)
        RAISE(VIC_BAD_PARAMETER);

    /* Handle kdf */
    {
        if (!kdf_type)
            kdf_type = DEFAULT_KDF_TYPE;

        if (!_valid_pbkdf_type(kdf_type))
            RAISE(VIC_BAD_PARAMETER);

        if (!kdf)
            kdf = _get_default_kdf(kdf_type);
    }

    /* Read the LUKS2 header */
    if (luks2_read_hdr(dev, (luks2_hdr_t**)&ext) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    /* The area key excludes the integrity key suffix (if any) */
    area_key_size = master_key_bytes - vic_integrity_key_size(
        ext->segments[0].integrity.type);

    /* Add a new key slot */
    {
        if ((index = _find_free_keyslot(ext)) == (size_t)-1)
            RAISE(VIC_OUT_OF_KEYSLOTS);

        if (_init_keyslot(
            &ext->keyslots[index],
            keyslot_cipher,
            master_key_bytes,
            area_key_size,
            kdf_type,
            kdf->hash,
            kdf->iterations,
            kdf->time,
            kdf->memory,
            kdf->cpus,
            index) != 0)
        {
            RAISE(VIC_FAILED);
        }

        /* Add this keyslot to the digest[0] */
        ext->digests[0].keyslots[index] = 1;
    }

    /* Rewrite the header */
    CHECK(_write_hdr(dev, ext));

    /* Generate and write the key material for the new keyslot */
    {
        const luks2_keyslot_t* ks = &ext->keyslots[index];

        CHECK(_generate_key_material(
            ext, ks, master_key, pwd, pwd_size, &data));

        if (_write_key_material(dev, ks, data) != 0)
            RAISE(VIC_KEY_MATERIAL_WRITE_FAILED);
    }

done:

    if (ext)
        vic_free(ext);

    if (data)
        vic_free(data);

    return result;
}

vic_result_t luks2_change_key(
    vic_blockdev_t* dev,
    const char* old_pwd,
    size_t old_pwd_size,
    const char* new_pwd,
    size_t new_pwd_size)
{
    vic_result_t result = VIC_OK;
    luks2_ext_hdr_t* ext = NULL;
    vic_key_t key;
    size_t key_size;
    size_t index;
    void* data = NULL;

    /* Check parameters */
    if (!_is_valid_device(dev) || !old_pwd || !new_pwd)
        RAISE(VIC_BAD_PARAMETER);

    /* Read the LUKS2 header */
    if (luks2_read_hdr(dev, (luks2_hdr_t**)&ext) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    /* Use password to find the master key */
    CHECK(_find_key_by_pwd(
        dev, ext, old_pwd, old_pwd_size, &key, &key_size, &index));

    /* Rewrite the header */
    CHECK(_write_hdr(dev, ext));

    /* Generate and write the key material for the new keyslot */
    {
        const luks2_keyslot_t* ks = &ext->keyslots[index];

        CHECK(_generate_key_material(
            ext, ks, &key, new_pwd, new_pwd_size, &data));

        if (_write_key_material(dev, ks, data) != 0)
            RAISE(VIC_KEY_MATERIAL_WRITE_FAILED);
    }

done:

    if (ext)
        vic_free(ext);

    if (data)
        vic_free(data);

    return result;
}

vic_result_t luks2_remove_key(
    vic_blockdev_t* dev,
    const char* pwd,
    size_t pwd_size)
{
    vic_result_t result = VIC_OK;
    luks2_ext_hdr_t* ext = NULL;
    vic_key_t key;
    size_t key_size;
    luks2_keyslot_t* ks;
    size_t index;
    void* data = NULL;

    /* Check parameters */
    if (!_is_valid_device(dev) || !pwd)
        RAISE(VIC_BAD_PARAMETER);

    /* Read the LUKS2 header */
    if (luks2_read_hdr(dev, (luks2_hdr_t**)&ext) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    /* Use password to find the master key */
    CHECK(_find_key_by_pwd(dev, ext, pwd, pwd_size, &key, &key_size, &index));

    /* Disallow if this is the last key */
    {
        size_t n = 0;

        for (size_t i = 0; i < VIC_COUNTOF(ext->keyslots); i++)
        {
            if (*ext->keyslots[i].type)
                n++;
        }

        if (n == 1)
            return VIC_LAST_KEYSLOT;
    }

    /* Remove this keyslot */
    {
        ks = &ext->keyslots[index];
        memset(ks, 0, sizeof(luks2_keyslot_t));
        ext->digests[0].keyslots[index] = 0;
    }

    /* Rewrite the header */
    CHECK(_write_hdr(dev, ext));

    /* Clear the key material for this keyslot */
    {
        if (_write_key_material(dev, ks, NULL) != 0)
            RAISE(VIC_KEY_MATERIAL_WRITE_FAILED);
    }

done:

    if (ext)
        vic_free(ext);

    if (data)
        vic_free(data);

    return result;
}

vic_result_t luks2_stat(vic_blockdev_t* dev, vic_luks_stat_t* buf)
{
    vic_result_t result = VIC_OK;
    luks2_ext_hdr_t* ext = NULL;
    size_t nblocks;
    size_t nbytes;
    size_t offset;

    if (!_is_valid_device(dev) || !buf)
        RAISE(VIC_BAD_PARAMETER);

    if (luks2_read_hdr(dev, (luks2_hdr_t**)&ext) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    CHECK(vic_blockdev_get_num_blocks(dev, &nblocks));

    nbytes = nblocks * VIC_SECTOR_SIZE;
    offset = ext->segments[0].offset;
    buf->version = LUKS_VERSION_1;
    buf->payload_offset = offset;
    buf->payload_size = nbytes - offset;

done:

    if (ext)
        vic_free(ext);

    return result;
}

vic_result_t luks2_open(
    vic_blockdev_t* dev,
    const char* path,
    const char* name,
    const vic_key_t* master_key,
    size_t master_key_bytes)
{
    vic_result_t result = VIC_OK;
    luks2_ext_hdr_t* ext = NULL;
    const uint64_t start = 0;
    uint64_t size;
    uint64_t offset;
    uint64_t iv_offset = 0;
    const char* integrity;

    if (!_is_valid_device(dev) || !path || !name || !master_key ||
        !master_key_bytes)
    {
        RAISE(VIC_BAD_PARAMETER);
    }

    if (luks2_read_hdr(dev, (luks2_hdr_t**)&ext) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    /* Get the payload offset in sectors */
    offset = ext->segments[0].offset / VIC_SECTOR_SIZE;

    /* Get the payload size */
    CHECK(_get_payload_size_in_sectors(dev, offset, &size));

    /* Get the integrity type */
    integrity = _get_integrity_type(ext);

    /* Create the crypt device */
    if (*integrity)
    {
        char name_dif[PATH_MAX];
        char dmpath[PATH_MAX];
        const char mode = 'J';

        /* Format the name of the integrity device */
        if (snprintf(name_dif, sizeof(name_dif), "%s_dif", name) >= PATH_MAX)
            RAISE(VIC_BUFFER_TOO_SMALL);

        CHECK(_open_integrity_device(dev, ext, name_dif, mode));

        /* Format the name of the integrity device (under /dev/mapper) */
        snprintf(dmpath, sizeof(dmpath), "/dev/mapper/%s", name_dif);

        CHECK(_open_integrity_luks2_device(
            dev, ext, name, dmpath, master_key, master_key_bytes));
    }
    else
    {
        CHECK(vic_dm_create_crypt(
            "CRYPT-LUKS2",
            name,
            path,
            ext->phdr.uuid,
            start,
            size,
            _get_integrity_type(ext),
            _get_encryption(ext),
            master_key->buf,
            master_key_bytes,
            iv_offset,
            offset));
    }

done:

    if (ext)
        vic_free(ext);

    return result;
}

vic_result_t luks2_open_by_passphrase(
    vic_blockdev_t* dev,
    luks2_hdr_t* hdr,
    const char* path,
    const char* name,
    const char* pwd,
    size_t pwd_size)
{
    vic_result_t result = VIC_OK;
    luks2_ext_hdr_t* ext = (luks2_ext_hdr_t*)hdr;
    const uint64_t start = 0;
    uint64_t size;
    uint64_t offset;
    uint64_t iv_offset = 0;
    const char* integrity;
    vic_key_t master_key;
    size_t master_key_bytes;

    if (!_is_valid_device(dev) || !name || !pwd || !pwd_size)
        RAISE(VIC_BAD_PARAMETER);

    if (!hdr && luks2_read_hdr(dev, (luks2_hdr_t**)&ext) != 0)
        RAISE(VIC_HEADER_READ_FAILED);

    CHECK(_find_key_by_pwd(
        dev, ext, pwd, pwd_size, &master_key, &master_key_bytes, NULL));

    /* Get the payload offset in sectors */
    offset = ext->segments[0].offset / VIC_SECTOR_SIZE;

    /* Get the payload size */
    CHECK(_get_payload_size_in_sectors(dev, offset, &size));

    /* Get the integrity type */
    integrity = _get_integrity_type(ext);

    /* Create the crypt device */
    if (*integrity)
    {
        char name_dif[PATH_MAX];
        char dmpath[PATH_MAX];
        const char mode = 'J';

        /* Format the name of the integrity device */
        if (snprintf(name_dif, sizeof(name_dif), "%s_dif", name) >= PATH_MAX)
            RAISE(VIC_BUFFER_TOO_SMALL);

        CHECK(_open_integrity_device(dev, ext, name_dif, mode));

        /* Format the name of the integrity device (under /dev/mapper) */
        snprintf(dmpath, sizeof(dmpath), "/dev/mapper/%s", name_dif);

        CHECK(_open_integrity_luks2_device(
            dev, ext, name, dmpath, &master_key, master_key_bytes));
    }
    else
    {
        CHECK(vic_dm_create_crypt(
            "CRYPT-LUKS2",
            name,
            path,
            ext->phdr.uuid,
            start,
            size,
            _get_integrity_type(ext),
            _get_encryption(ext),
            master_key.buf,
            master_key_bytes,
            iv_offset,
            offset));
    }

done:

    if (ext)
        vic_free(ext);

    return result;
}
