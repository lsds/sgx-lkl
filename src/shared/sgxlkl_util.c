/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint64_t getenv_uint64(const char *var, uint64_t def, uint64_t max) {
    uint64_t r;
    char *val, *endptr;
    if (!(val = getenv(var))) return def;

    errno = 0;
    r = (uint64_t) strtoull(val, &endptr, 10);
    if (r == ULONG_MAX && errno == ERANGE) {
        r = def;
    }
    int m = 1;
    switch (*endptr) {
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
    if (r > (ULONG_MAX / m)) return max;
    r *= m;

    return (r > max) ? max : r;
}

char *getenv_str(const char *var, const char *def) {
    char *val = getenv(var);
    //Duplicate default value as it might not be allocated on the heap and to
    //make API consistent, i.e. the memory pointed to by the return value
    //should be freeable.
    return (val != NULL) ? strdup(val) : ((def != NULL) ? strdup(def) : NULL);
}

int getenv_bool(const char *var, int def)
{
    char *val = getenv(var);
    if (val == NULL)
        return def;
    if (def)
        return (strncmp(val, "0", 1) != 0);
    else
        return (strncmp(val, "1", 1) == 0);
}

uint64_t next_pow2(uint64_t x) {
    uint64_t n = 1;
    while (n < x)
        n = n << 1;
    return n;
}
