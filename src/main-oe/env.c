#include "host/env.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shared/util.h"

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
    char* val;
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
