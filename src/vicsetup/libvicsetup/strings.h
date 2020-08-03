#ifndef _VIC_STRINGS_H
#define _VIC_STRINGS_H

#include "vic.h"
#include "defs.h"
#include <stddef.h>
#include <errno.h>

size_t vic_strlcpy(char* dest, const char* src, size_t size);

size_t vic_strlcat(char* dest, const char* src, size_t size);

VIC_INLINE int __vic_strlcpy(char* dest, const char* src, size_t size)
{
    return (vic_strlcpy(dest, src, size) >= size) ? EOVERFLOW : 0;
}

VIC_INLINE int __vic_strlcat(char* dest, const char* src, size_t size)
{
    return (vic_strlcat(dest, src, size) >= size) ? EOVERFLOW : 0;
}

#define STRLCPY(DEST, SRC) __vic_strlcpy(DEST, SRC, sizeof(DEST))

#define STRLCAT(DEST, SRC) __vic_strlcat(DEST, SRC, sizeof(DEST))

#endif /* _VIC_STRINGS_H */
