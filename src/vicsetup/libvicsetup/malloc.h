#ifndef _VIC_MALLOC_H
#define _VIC_MALLOC_H

#include <stddef.h>

void* vic_malloc(size_t size);

void vic_free(void* ptr);

void* vic_calloc(size_t nmemb, size_t size);

#endif /* _VIC_MALLOC_H */
