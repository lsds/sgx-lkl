#ifndef _VIC_CRYPTO_H
#define _VIC_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#include "vic.h"

void vic_random(void* data, size_t size);

int vic_pbkdf2(
    const void* password,
    size_t password_size,
    const uint8_t* salt,
    size_t salt_size,
    uint32_t iterations,
    const char* hash_spec,
    void* key,
    size_t key_size);

int vic_argon2i(
    const void* password,
    size_t password_size,
    const uint8_t* salt,
    size_t salt_size,
    uint32_t time,
    uint32_t memory,
    uint32_t cpus,
    void* key,
    size_t key_size);

int vic_argon2id(
    const void* password,
    size_t password_size,
    const uint8_t* salt,
    size_t salt_size,
    uint32_t time,
    uint32_t memory,
    uint32_t cpus,
    void* key,
    size_t key_size);

int vic_afmerge(
    uint64_t key_bytes,
    uint64_t stripes,
    const char* hash_spec,
    const uint8_t* split_key,
    vic_key_t* key);

int vic_afsplit(
    const char* hash_spec,
    const vic_key_t* key,
    size_t key_size,
    uint32_t stripes,
    uint8_t* split_key);

#endif /* _VIC_CRYPTO_H */
