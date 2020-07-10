#ifndef __OE_STRING_INCLUDED__
#define __OE_STRING_INCLUDED__

/* The mem methods are always defined by their stdc names in oecore */
extern void* memmove(void* dest, const void* src, size_t n);
extern int memcmp(const void* s1, const void* s2, size_t n);
extern void* memset(void* s, int c, size_t n);
extern void* memcpy(void* dest, const void* src, size_t n);

int oe_snprintf(char* str, size_t size, const char* format, ...);
int oe_strcmp(const char* s1, const char* s2);
char* oe_strdup(const char* s);
size_t oe_strlen(const char* s);

#endif
