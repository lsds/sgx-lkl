#ifndef SGXLKL_ENCLAVE
#include <errno.h>
#endif

#include <shared/oe_compat.h>
#include <shared/util.h>

uint64_t hex_to_int(const char* digits, size_t num_digits)
{
    uint64_t r = 0;
    for (size_t i = 0; i < num_digits; i++)
    {
        char c = digits[i];
        r <<= 4;
        if (c >= '0' && c <= '9')
            r |= (c - '0') & 0xFF;
        else if (c >= 'a' && c <= 'f')
            r |= (0xA + (c - 'a')) & 0xFF;
        else if (c >= 'A' && c <= 'F')
            r |= (0xA + (c - 'A')) & 0xFF;
    }
    return r;
}

uint64_t next_pow2(uint64_t x)
{
    uint64_t n = 1;
    while (n < x)
        n = n << 1;
    return n;
}

ssize_t hex_to_bytes(const char* hex, uint8_t** result)
{
    char buf[3] = "xx\0", *endp;
    uint8_t* bytes;
    size_t i, len;
    int odd = 0;

    len = strlen(hex);
    if (len % 2)
    {
        odd = 1;
        len += 1;
    }
    len /= 2;

    bytes = malloc(2 * len);
    if (!bytes)
    {
#ifndef SGXLKL_ENCLAVE
        errno = ENOMEM;
#endif
        return -1;
    }

    if (odd)
    {
        buf[0] = 0;
        buf[1] = hex[0];
        bytes[0] = strtoul(buf, &endp, 16);
        if (endp != &buf[2])
        {
            free(bytes);
#ifndef SGXLKL_ENCLAVE
            errno = EINVAL;
#endif
            return -1;
        }
        hex++;
        bytes++;
        len--;
    }

    for (i = 0; i < len; i++)
    {
        memcpy(buf, &hex[i * 2], 2);
        bytes[i] = strtoul(buf, &endp, 16);
        if (endp != &buf[2])
        {
            free(bytes);
#ifndef SGXLKL_ENCLAVE
            errno = EINVAL;
#endif
            return -1;
        }
    }
    *result = bytes;
    return i;
}

char* bytes_to_hex(
    char* str,
    size_t str_size,
    const void* data,
    size_t data_size)
{
    char* s = str;
    const uint8_t* p = (const uint8_t*)data;
    size_t n = data_size;

    if (!str || !data)
        return NULL;

    if (str_size < (2 * data_size + 1))
        return NULL;

    while (n--)
    {
        snprintf(s, 3, "%02x", *p);
        p++;
        s += 2;
    }

    *s = '\0';

    return str;
}