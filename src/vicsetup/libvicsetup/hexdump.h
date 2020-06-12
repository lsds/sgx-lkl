#ifndef _VIC_HEXDUMP_H
#define _VIC_HEXDUMP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "vic.h"

void vic_hexdump_special(
    const void* data,
    size_t size,
    bool spaces,
    bool newlines,
    size_t indent);

void vic_hexdump(const void* data, size_t size);

void vic_hexdump_flat(const void* data, size_t size);

vic_result_t vic_bin_to_ascii(const void* data, size_t size, char** ascii);

vic_result_t vic_ascii_to_bin(const char* ascii, uint8_t** data, size_t* size);

#endif /* _VIC_HEXDUMP_H */
