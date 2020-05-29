#ifndef OE_COMPAT_H
#define OE_COMPAT_H

#ifdef SGXLKL_ENCLAVE

#include <openenclave/corelibc/bits/types.h>
#include <openenclave/corelibc/oemalloc.h>
#include <openenclave/corelibc/oestring.h>
#include <openenclave/internal/safecrt.h>

// extern long long int strtoll(const char* nptr, char** endptr, int base);
// extern double strtod(const char* nptr, char** endptr);
// extern unsigned long long int strtoull(
//     const char* nptr,
//     char** endptr,
//     int base);

#define malloc oe_malloc
#define realloc oe_realloc
#define calloc oe_calloc
#define free oe_free
#define strlen oe_strlen
#define strcmp oe_strcmp
#define strtok_r oe_strtok_r
#define snprintf oe_snprintf
// #define strcpy oe_strcpy
// #define strtoll oe_strtoll
// #define strcpy oe_strcpy
// #define strtod oe_strtod
// #define strtoull oe_strtoull

#endif // SGXLKL_ENCLAVE

#endif /* OE_COMPAT_H */