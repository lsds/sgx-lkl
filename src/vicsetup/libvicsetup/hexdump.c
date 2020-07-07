#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "hexdump.h"
#include "raise.h"

static void _indent(size_t indent)
{
    for (size_t i = 0; i < indent; i++)
        printf("  ");
}

void vic_hexdump(
    const void* data,
    size_t size,
    bool spaces,
    bool newlines,
    size_t indent)
{
    const uint8_t* p = (const uint8_t*)data;
    static const uint8_t _zeros[16];

    for (size_t i = 0; i < size; )
    {
        /* If starting a new row */
        if ((i % 16) == 0)
        {
            size_t r = size - i;

            _indent(indent);

            /* If complete row contains all zeros */
            if (r >= 16 && memcmp(&p[i], _zeros, sizeof(_zeros)) == 0)
            {
                printf("*");

                /* ignore consecutive zero rows */
                do
                {
                    i += 16;
                    r = size - i;
                }
                while (r >= 16 && memcmp(&p[i], _zeros, sizeof(_zeros)) == 0);

                if (r != 0)
                {
                    if (newlines)
                        printf("\n");
                }

                continue;
            }
        }

        printf("%02x", p[i]);

        if (i + 1 != size)
        {
            if (((i + 1) % 16) == 0)
            {
                if (newlines)
                    printf("\n");
            }
            else
            {
                if (spaces)
                    printf(" ");
            }
        }

        i++;
    }

    if (newlines)
        printf("\n");

    fflush(stdout);
}

void vic_hexdump_formatted(const void* data, size_t size)
{
    vic_hexdump(data, size, true, true, 0);
}

void vic_hexdump_flat(const void* data, size_t size)
{
    vic_hexdump(data, size, false, false, 0);
}

vic_result_t vic_bin_to_ascii(const void* data_, size_t size, char** ascii_out)
{
    const uint8_t* data = (const uint8_t*)data_;
    vic_result_t result = VIC_OK;
    char* ascii;

    if (!data || !size)
        RAISE(VIC_BAD_PARAMETER);

    if (!(ascii = malloc(2 * size + 1)))
        RAISE(VIC_OUT_OF_MEMORY);

    for (size_t i = 0; i < size; i++)
        snprintf(&ascii[2 * i], 3, "%02x", data[i]);

    *ascii_out = ascii;

done:

    return result;
}

vic_result_t vic_ascii_to_bin(
    const char* ascii,
    uint8_t** data_out,
    size_t* size_out)
{
    vic_result_t result = VIC_OK;
    size_t len;
    uint8_t* data = NULL;
    size_t size;

    if (data_out)
        *data_out = NULL;

    if (size_out)
        *size_out = 0;

    if (!ascii || !data_out || !size_out)
        RAISE(VIC_BAD_PARAMETER);

    if ((len = strlen(ascii)) == 0)
        RAISE(VIC_FAILED);

    size = len / 2;

    if (!(data = malloc(size)))
        RAISE(VIC_OUT_OF_MEMORY);

    for (size_t i = 0; i < size; i++)
    {
        uint32_t x;

        if (sscanf(&ascii[2 * i], "%02x", &x) != 1)
            RAISE(VIC_UNEXPECTED);

        data[i] = (uint8_t)x;
    }

    *data_out = data;
    data = NULL;
    *size_out = size;

done:

    if (data)
        free(data);

    return result;
}
