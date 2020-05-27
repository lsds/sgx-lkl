#ifndef __OE_STRING_INCLUDED__
#define __OE_STRING_INCLUDED__

char* oe_strdup(const char* s);
size_t oe_strlen(const char* s);
int oe_snprintf(char* str, size_t size, const char* format, ...);

#endif
