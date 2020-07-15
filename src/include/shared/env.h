#ifndef _ENV_H
#define _ENV_H

#include "shared/oe_compat.h"

uint64_t hex_to_int(const char* digits, size_t num_digits);

uint64_t size_str_to_uint64(const char* str, uint64_t def, uint64_t max);

void size_uint64_to_str(uint64_t size, char* buf, uint64_t len);

uint64_t getenv_uint64(const char* var, uint64_t def, uint64_t max);

char* getenv_str(const char* var, const char* def);

int getenv_bool(const char* var, int def);

uint64_t next_pow2(uint64_t x);

ssize_t hex_to_bytes(const char* hex, uint8_t** result);

char* bytes_to_hex(
    char* str,
    size_t str_size,
    const void* data,
    size_t data_size);

#endif /* _ENV_H */