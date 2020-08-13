#include <stdint.h>
#include <stdio.h>

void log_hex_data(const char* msg, const uint8_t* data, size_t size)
{
    printf("%s: ", msg);

    for (size_t i = 0; i < size; i++)
    {
        printf("0x%02x,", data[i]);

        if (i + 1 != size)
            printf(" ");
    }

    printf("\n");
}
