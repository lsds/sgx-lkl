#include "uuid.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "defs.h"
#include "crypto.h"

void vic_uuid_generate(char uuid[VIC_UUID_STRING_SIZE])
{
    /* example: 6ec8247b-ba97-49bc-b9d2-2b35c6d17d5f */
    uint8_t bytes[16];
    const uint8_t* src = bytes;
    char* dest = uuid;

    vic_random(bytes, sizeof(bytes));

    memset(uuid, 0, VIC_UUID_STRING_SIZE);

    for (size_t i = 0; i < VIC_COUNTOF(bytes); i++)
    {
        if (i == 4 || i == 6 || i == 8 || i == 10)
        {
            *dest++ = '-';
        }

        snprintf(dest, 3, "%02x", *src);
        src++;
        dest += 2;
    }
}

bool vic_uuid_valid(const char* uuid)
{
    /* example: 979fe290-ffd0-41d0-b18a-50569b55acb3 */
    uint32_t x1;
    uint32_t x2;
    uint32_t x3;
    uint32_t x4;
    uint64_t x5;
    int n;

    if (!uuid)
        return false;

    if (strlen(uuid) != 36)
        return false;

    n = sscanf(uuid, "%08x-%04x-%04x-%04x-%012lx", &x1, &x2, &x3, &x4, &x5);

    if (n != 5)
        return false;

    return true;
}

int vic_uuid_str2bin(
    const char str[VIC_UUID_STRING_SIZE],
    uint8_t binary[VIC_UUID_BINARY_SIZE])
{
    int ret = -1;
    uint8_t* dest;
    const char* src;

    if (!str || !vic_uuid_valid(str) || !binary)
        goto done;

    dest = binary;
    src = str;

    while (*src)
    {
        uint32_t x;

        if (*src == '-')
            src++;

        if (sscanf(src, "%02x", &x) != 1)
            goto done;

        *dest++ = (uint8_t)x;
        src += 2;
    }

    ret = 0;

done:
    return ret;
}

void vic_uuid_bin2str(
    const uint8_t binary[VIC_UUID_BINARY_SIZE],
    char str[VIC_UUID_STRING_SIZE])
{
    if (binary && str)
    {
        /* example: 6ef272c7-663b-4655-b80b-8dd369021a3a */
        snprintf(str, VIC_UUID_STRING_SIZE,
            "%02x%02x%02x%02x-"
            "%02x%02x-"
            "%02x%02x-"
            "%02x%02x-"
            "%02x%02x%02x%02x%02x%02x",
            binary[0],
            binary[1],
            binary[2],
            binary[3],
            binary[4],
            binary[5],
            binary[6],
            binary[7],
            binary[8],
            binary[9],
            binary[10],
            binary[11],
            binary[12],
            binary[13],
            binary[14],
            binary[15]);
    }
}
