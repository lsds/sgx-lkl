#ifndef _VIC_HEXDUMP_H
#define _VIC_HEXDUMP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vic.h"

/* Perform a hex dump of the given data to standard output. */
void vic_hexdump(
    const void* data, /* data to be hex-dumped */
    size_t size,      /* number of bytes to be hex-dumped */
    bool spaces,      /* whether to put spaces between hex bytes */
    bool newlines,    /* whether to put newlines after every 16 hex bytes */
    size_t indent);   /* whether to indent each line */

// Perform hex dump where hex bytes are separated by spaces and newlines are
// added after every 16 hex bytes.
void vic_hexdump_formatted(const void* data, size_t size);

// Perform hex dump where all hex bytes are displayed on a single line with
// no spaces between them.
void vic_hexdump_flat(const void* data, size_t size);

/* Convert binary data to hex-ascii */
vic_result_t vic_bin_to_ascii(const void* data, size_t size, char** ascii);

/* Convert hex-ascii to binary data */
vic_result_t vic_ascii_to_bin(const char* ascii, uint8_t** data, size_t* size);

#endif /* _VIC_HEXDUMP_H */
