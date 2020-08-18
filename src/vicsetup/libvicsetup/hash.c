#include <mbedtls/ripemd160.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <stdbool.h>
#include <string.h>

#include "defs.h"
#include "hash.h"

/* The OE version of mbedtls does not include ripemd160 */
// #define HAVE_RIPEMD160

VIC_STATIC_ASSERT(
    sizeof(mbedtls_sha1_context) <= sizeof(((vic_hash_ctx_t*)0)->impl));

VIC_STATIC_ASSERT(
    sizeof(mbedtls_sha256_context) <= sizeof(((vic_hash_ctx_t*)0)->impl));

VIC_STATIC_ASSERT(
    sizeof(mbedtls_sha512_context) <= sizeof(((vic_hash_ctx_t*)0)->impl));

#ifdef HAVE_RIPEMD160
VIC_STATIC_ASSERT(
    sizeof(mbedtls_ripemd160_context) <= sizeof(((vic_hash_ctx_t*)0)->impl));
#endif

int vic_hash_init(vic_hash_ctx_t* ctx, vic_hash_type_t type)
{
    int ret = -1;

    if (!ctx)
        goto done;

    switch (type)
    {
        case VIC_HASH_NONE:
        {
            goto done;
        }
        case VIC_HASH_SHA1:
        {
            mbedtls_sha1_init((mbedtls_sha1_context*)ctx->impl);
            break;
        }
        case VIC_HASH_SHA256:
        {
            mbedtls_sha256_init((mbedtls_sha256_context*)ctx->impl);
            break;
        }
        case VIC_HASH_SHA512:
        {
            mbedtls_sha512_init((mbedtls_sha512_context*)ctx->impl);
            break;
        }
        case VIC_HASH_RIPEMD160:
        {
#ifdef HAVE_RIPEMD160
            mbedtls_ripemd160_init((mbedtls_ripemd160_context*)ctx->impl);
            break;
#else
            goto done;
#endif
        }
    }

    ctx->type = type;

    ret = 0;

done:
    return ret;
}

int vic_hash_start(vic_hash_ctx_t* ctx)
{
    int ret = -1;

    if (!ctx)
        goto done;

    switch (ctx->type)
    {
        case VIC_HASH_NONE:
        {
            goto done;
        }
        case VIC_HASH_SHA1:
        {
            mbedtls_sha1_context* p = (mbedtls_sha1_context*)ctx->impl;

            if (mbedtls_sha1_starts_ret(p) != 0)
                goto done;

            break;
        }
        case VIC_HASH_SHA256:
        {
            mbedtls_sha256_context* p = (mbedtls_sha256_context*)ctx->impl;

            if (mbedtls_sha256_starts_ret(p, 0) != 0)
                goto done;

            break;
        }
        case VIC_HASH_SHA512:
        {
            mbedtls_sha512_context* p = (mbedtls_sha512_context*)ctx->impl;

            if (mbedtls_sha512_starts_ret(p, 0) != 0)
                goto done;

            break;
        }
        case VIC_HASH_RIPEMD160:
        {
#ifdef HAVE_RIPEMD160
            mbedtls_ripemd160_context* p =
                (mbedtls_ripemd160_context*)ctx->impl;

            if (mbedtls_ripemd160_starts_ret(p) != 0)
                goto done;
#else
            goto done;
#endif

            break;
        }
    }

    ret = 0;

done:
    return ret;
}

int vic_hash_update(vic_hash_ctx_t* ctx, const void* data, size_t size)
{
    int ret = -1;

    if (!ctx)
        goto done;

    switch (ctx->type)
    {
        case VIC_HASH_NONE:
        {
            goto done;
        }
        case VIC_HASH_SHA1:
        {
            mbedtls_sha1_context* p = (mbedtls_sha1_context*)ctx->impl;

            if (mbedtls_sha1_update_ret(p, data, size) != 0)
                goto done;

            break;
        }
        case VIC_HASH_SHA256:
        {
            mbedtls_sha256_context* p = (mbedtls_sha256_context*)ctx->impl;

            if (mbedtls_sha256_update_ret(p, data, size) != 0)
                goto done;

            break;
        }
        case VIC_HASH_SHA512:
        {
            mbedtls_sha512_context* p = (mbedtls_sha512_context*)ctx->impl;

            if (mbedtls_sha512_update_ret(p, data, size) != 0)
                goto done;

            break;
        }
        case VIC_HASH_RIPEMD160:
        {
#ifdef HAVE_RIPEMD160
            mbedtls_ripemd160_context* p =
                (mbedtls_ripemd160_context*)ctx->impl;

            if (mbedtls_ripemd160_update_ret(p, data, size) != 0)
                goto done;
#else
            goto done;
#endif

            break;
        }
    }

    ret = 0;

done:
    return ret;
}

int vic_hash_finish(vic_hash_ctx_t* ctx, vic_hash_t* hash)
{
    int ret = -1;

    if (!ctx || !hash)
        goto done;

    switch (ctx->type)
    {
        case VIC_HASH_NONE:
        {
            goto done;
        }
        case VIC_HASH_SHA1:
        {
            mbedtls_sha1_context* p = (mbedtls_sha1_context*)ctx->impl;

            if (mbedtls_sha1_finish_ret(p, hash->u.sha1) != 0)
                goto done;

            break;
        }
        case VIC_HASH_SHA256:
        {
            mbedtls_sha256_context* p = (mbedtls_sha256_context*)ctx->impl;

            if (mbedtls_sha256_finish_ret(p, hash->u.sha256) != 0)
                goto done;

            break;
        }
        case VIC_HASH_SHA512:
        {
            mbedtls_sha512_context* p = (mbedtls_sha512_context*)ctx->impl;

            if (mbedtls_sha512_finish_ret(p, hash->u.sha512) != 0)
                goto done;

            break;
        }
        case VIC_HASH_RIPEMD160:
        {
#ifdef HAVE_RIPEMD160
            mbedtls_ripemd160_context* p =
                (mbedtls_ripemd160_context*)ctx->impl;

            if (mbedtls_ripemd160_finish_ret(p, hash->u.ripemd160) != 0)
                goto done;

            break;
#else
            goto done;
#endif
        }
    }

    ret = 0;

done:
    return ret;
}

void vic_hash_free(vic_hash_ctx_t* ctx)
{
    if (ctx)
    {
        switch (ctx->type)
        {
            case VIC_HASH_NONE:
            {
                break;
            }
            case VIC_HASH_SHA1:
            {
                mbedtls_sha1_free((mbedtls_sha1_context*)ctx->impl);
                break;
            }
            case VIC_HASH_SHA256:
            {
                mbedtls_sha256_free((mbedtls_sha256_context*)ctx->impl);
                break;
            }
            case VIC_HASH_SHA512:
            {
                mbedtls_sha512_free((mbedtls_sha512_context*)ctx->impl);
                break;
            }
            case VIC_HASH_RIPEMD160:
            {
#ifdef HAVE_RIPEMD160
                mbedtls_ripemd160_free((mbedtls_ripemd160_context*)ctx->impl);
#endif
                break;
            }
        }
    }
}

int vic_hashv(
    vic_hash_type_t type,
    const vic_vec_t* vec,
    size_t count,
    vic_hash_t* hash)
{
    int ret = -1;
    vic_hash_ctx_t ctx;

    if (vic_hash_init(&ctx, type) != 0)
        goto done;

    if (!vec || !hash)
        goto done;

    if (vic_hash_start(&ctx) != 0)
        goto done;

    for (size_t i = 0; i < count; i++)
    {
        if (vec[i].size)
        {
            if (!vec[i].data)
                goto done;

            if (vic_hash_update(&ctx, vec[i].data, vec[i].size) != 0)
                goto done;
        }
    }

    if (vic_hash_finish(&ctx, hash) != 0)
        goto done;

    ret = 0;

done:

    vic_hash_free(&ctx);

    return ret;
}

size_t vic_hash_size(const char* hash_spec)
{
    if (strcmp(hash_spec, VIC_HASH_SPEC_SHA1) == 0)
        return VIC_SHA1_SIZE;
    else if (strcmp(hash_spec, VIC_HASH_SPEC_SHA256) == 0)
        return VIC_SHA256_SIZE;
    else if (strcmp(hash_spec, VIC_HASH_SPEC_SHA512) == 0)
        return VIC_SHA512_SIZE;
    else if (strcmp(hash_spec, VIC_HASH_SPEC_RIPEMD160) == 0)
        return VIC_RIPE160_SIZE;

    return (size_t)-1;
}

vic_hash_type_t vic_hash_type(const char* hash_spec)
{
    if (strcmp(hash_spec, VIC_HASH_SPEC_SHA1) == 0)
        return VIC_HASH_SHA1;
    else if (strcmp(hash_spec, VIC_HASH_SPEC_SHA256) == 0)
        return VIC_HASH_SHA256;
    else if (strcmp(hash_spec, VIC_HASH_SPEC_SHA512) == 0)
        return VIC_HASH_SHA512;
    else if (strcmp(hash_spec, VIC_HASH_SPEC_RIPEMD160) == 0)
        return VIC_HASH_RIPEMD160;

    return VIC_HASH_NONE;
}

const char* vic_hash_name(vic_hash_type_t type)
{
    switch (type)
    {
        case VIC_HASH_NONE:
            return "";
        case VIC_HASH_SHA1:
            return VIC_HASH_SPEC_SHA1;
        case VIC_HASH_SHA256:
            return VIC_HASH_SPEC_SHA256;
        case VIC_HASH_SHA512:
            return VIC_HASH_SPEC_SHA512;
        case VIC_HASH_RIPEMD160:
            return VIC_HASH_SPEC_RIPEMD160;
    }

    return "";
}
