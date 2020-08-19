#ifndef _SHARED_UTIL_H
#define _SHARED_UTIL_H

#include <stddef.h>
#include <stdint.h>

uint64_t hex_to_int(const char* digits, size_t num_digits);

uint64_t next_pow2(uint64_t x);

ssize_t hex_to_bytes(const char* hex, uint8_t** result);

char* bytes_to_hex(
    char* str,
    size_t str_size,
    const void* data,
    size_t data_size);

#endif