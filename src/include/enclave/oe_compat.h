#ifndef OE_COMPAT_H
#define OE_COMPAT_H

#ifdef SGXLKL_ENCLAVE

#include <stddef.h>

extern void* memmove(void* dest, const void* src, size_t n);
extern int memcmp(const void* s1, const void* s2, size_t n);
extern void* memset(void* s, int c, size_t n);

extern void* oe_malloc(size_t s);
extern void* oe_realloc(void*, size_t s);
extern void* oe_calloc(size_t n, size_t s);
extern void oe_free(void*);
extern size_t oe_strlen(const char* s);
extern int oe_strcmp(const char* s1, const char* s2);
extern char* oe_strtok_r(char* str, const char* delim, char** saveptr);

extern char* strcpy(char* dest, const char* src);
extern long long int strtoll(const char* nptr, char** endptr, int base);
extern double strtod(const char* nptr, char** endptr);
extern unsigned long long int strtoull(
    const char* nptr,
    char** endptr,
    int base);

#define malloc oe_malloc
#define realloc oe_realloc
#define calloc oe_calloc
#define free oe_free
#define strlen oe_strlen
#define strcmp oe_strcmp
#define strtok_r oe_strtok_r
// #define strtoll oe_strtoll
// #define strcpy oe_strcpy
// #define strtod oe_strtod
// #define strtoull oe_strtoull

#endif // SGXLKL_ENCLAVE

#endif /* OE_COMPAT_H */