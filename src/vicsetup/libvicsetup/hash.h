#ifndef _VIC_HASH_H
#define _VIC_HASH_H

#include <stddef.h>
#include <stdint.h>
#include <vic.h>
#include "defs.h"
#include "vec.h"

#define VIC_HASH_SPEC_SHA1 "sha1"
#define VIC_HASH_SPEC_SHA256 "sha256"
#define VIC_HASH_SPEC_SHA512 "sha512"
#define VIC_HASH_SPEC_RIPEMD160 "ripemd160"

#define VIC_SHA1_SIZE 20
#define VIC_SHA256_SIZE 32
#define VIC_SHA512_SIZE 64
#define VIC_RIPE160_SIZE 20
#define VIC_MAX_HASH_SIZE 64

typedef enum vic_hash_type
{
    VIC_HASH_NONE,
    VIC_HASH_SHA1,
    VIC_HASH_SHA256,
    VIC_HASH_SHA512,
    VIC_HASH_RIPEMD160,
} vic_hash_type_t;

typedef struct vic_hash_ctx
{
    vic_hash_type_t type;
    uint64_t impl[32];
} vic_hash_ctx_t;

typedef struct _vic_hash
{
    union {
        uint8_t sha1[VIC_SHA1_SIZE];
        uint8_t sha256[VIC_SHA256_SIZE];
        uint8_t sha512[VIC_SHA512_SIZE];
        uint8_t ripemd160[VIC_RIPE160_SIZE];
        uint8_t buf[VIC_MAX_HASH_SIZE];
    } u;
} vic_hash_t;

int vic_hash_init(vic_hash_ctx_t* ctx, vic_hash_type_t type);

int vic_hash_start(vic_hash_ctx_t* ctx);

int vic_hash_update(vic_hash_ctx_t* ctx, const void* data, size_t size);

int vic_hash_finish(vic_hash_ctx_t* ctx, vic_hash_t* hash);

void vic_hash_free(vic_hash_ctx_t* ctx);

int vic_hashv(
    vic_hash_type_t type,
    const vic_vec_t* vec,
    size_t count,
    vic_hash_t* hash);

VIC_INLINE int vic_hash1(
    vic_hash_type_t type,
    const void* s,
    size_t n,
    vic_hash_t* hash)
{
    vic_vec_t vec[] = {{(void*)s, n}};
    return vic_hashv(type, vec, VIC_COUNTOF(vec), hash);
}

VIC_INLINE int vic_hash2(
    vic_hash_type_t type,
    const void* s1,
    size_t n1,
    const void* s2,
    size_t n2,
    vic_hash_t* hash)
{
    vic_vec_t vec[] = {{(void*)s1, n1}, {(void*)s2, n2}};
    return vic_hashv(type, vec, VIC_COUNTOF(vec), hash);
}

size_t vic_hash_size(const char* hash_spec);

vic_hash_type_t vic_hash_type(const char* hash_spec);

const char* vic_hash_name(vic_hash_type_t type);

#endif /* _VIC_HASH_H */
