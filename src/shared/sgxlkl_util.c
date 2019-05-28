/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void sgxlkl_fail(char *msg, ...) {
    va_list(args);
    fprintf(stderr, "[    SGX-LKL   ] Error: ");
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    exit(EXIT_FAILURE);
}

void sgxlkl_err(char *msg, ...) {
    va_list(args);
    fprintf(stderr, "[    SGX-LKL   ] Errror: ");
    va_start(args, msg);
    vfprintf(stderr, msg, args);
}

void sgxlkl_warn(char *msg, ...) {
    va_list(args);
    fprintf(stderr, "[    SGX-LKL   ] Warning: ");
    va_start(args, msg);
    vfprintf(stderr, msg, args);
}

void sgxlkl_info(char *msg, ...) {
    va_list(args);
    fprintf(stderr, "[    SGX-LKL   ] ");
    va_start(args, msg);
    vfprintf(stderr, msg, args);
}

uint64_t size_str_to_uint64(const char *str, uint64_t def, uint64_t max) {
    uint64_t r;
    char *endptr;
    errno = 0;
    r = (uint64_t) strtoull(str, &endptr, 10);
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

uint64_t getenv_uint64(const char *var, uint64_t def, uint64_t max) {
    uint64_t r;
    char *val, *endptr;
    if (!(val = getenv(var))) return def;

    return size_str_to_uint64(val, def, max);
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

ssize_t hex_to_bytes(const char *hex, char **result) {
    char buf[3] = "xx\0", *endp, *bytes;
    size_t i, len;
    int odd = 0;

    len = strlen(hex);
    if (len % 2) {
        odd = 1;
        len += 1;
    }
    len /= 2;

    bytes = malloc(len);
    if (!bytes) {
        errno = ENOMEM;
        return -1;
    }

    if (odd) {
        buf[0] = 0;
        buf[1] = hex[0];
        bytes[0] = strtoul(buf, &endp, 16);
        if (endp != &buf[2]) {
            free(bytes);
            errno = EINVAL;
            return -1;
        }
        hex++;
        bytes++;
        len--;
    }

    for (i = 0; i < len; i++) {
        memcpy(buf, &hex[i * 2], 2);
        bytes[i] = strtoul(buf, &endp, 16);
        if (endp != &buf[2]) {
            free(bytes);
            errno = EINVAL;
            return -1;
        }
    }
    *result = bytes;
    return i;
}

