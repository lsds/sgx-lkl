#ifndef _VIC_UUID_H
#define _VIC_UUID_H

#include <stdbool.h>
#include <stdint.h>

#define VIC_UUID_STRING_SIZE 40
#define VIC_UUID_BINARY_SIZE 16

bool vic_uuid_valid(const char* uuid);

void vic_uuid_generate(char uuid[VIC_UUID_STRING_SIZE]);

int vic_uuid_str2bin(
    const char str[VIC_UUID_STRING_SIZE],
    uint8_t binary[VIC_UUID_BINARY_SIZE]);

void vic_uuid_bin2str(
    const uint8_t binary[VIC_UUID_BINARY_SIZE],
    char str[VIC_UUID_STRING_SIZE]);

#endif /* _VIC_UUID_H */
