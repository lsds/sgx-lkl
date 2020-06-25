#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint64_t size_str_to_uint64(const char* str, uint64_t def, uint64_t max)
{
    uint64_t r;
    char* endptr;
    errno = 0;
    r = (uint64_t)strtoull(str, &endptr, 10);
    if (r == ULONG_MAX && errno == ERANGE)
    {
        r = def;
    }
    int m = 1;
    switch (*endptr)
    {
        case 'G':
        case 'g':
            m *= 1024;
        case 'M':
        case 'm':
            m *= 1024;
        case 'K':
        case 'k':
            m *= 1024;
        default:
            break;
    }

    // Check for potential overflow
    if (r > (ULONG_MAX / m))
        return max;
    r *= m;

    return (r > max) ? max : r;
}

void size_uint64_to_str(uint64_t size, char* buf, uint64_t len)
{
    int i = 0;
    double bytes = size;
    const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    while (bytes > 1024.0)
    {
        bytes /= 1024.0;
        i++;
    }
    snprintf(buf, len, "%.*f %s", i, bytes, units[i]);
}

uint64_t getenv_uint64(const char* var, uint64_t def, uint64_t max)
{
    char *val;
    if (!(val = getenv(var)))
        return def;

    return size_str_to_uint64(val, def, max);
}

char* getenv_str(const char* var, const char* def)
{
    char* val = getenv(var);
    // Duplicate default value as it might not be allocated on the heap and to
    // make API consistent, i.e. the memory pointed to by the return value
    // should be freeable.
    return (val != NULL) ? strdup(val) : ((def != NULL) ? strdup(def) : NULL);
}

int getenv_bool(const char* var, int def)
{
    char* val = getenv(var);
    if (val == NULL)
        return def;
    if (def)
        return (strncmp(val, "0", 1) != 0);
    else
        return (strncmp(val, "1", 1) == 0);
}

uint64_t next_pow2(uint64_t x)
{
    uint64_t n = 1;
    while (n < x)
        n = n << 1;
    return n;
}

ssize_t hex_to_bytes(const char* hex, char** result)
{
    char buf[3] = "xx\0", *endp, *bytes;
    size_t i, len;
    int odd = 0;

    len = strlen(hex);
    if (len % 2)
    {
        odd = 1;
        len += 1;
    }
    len /= 2;

    bytes = malloc(len);
    if (!bytes)
    {
        errno = ENOMEM;
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
            errno = EINVAL;
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
            errno = EINVAL;
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
