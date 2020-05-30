#include <stdlib.h>
#include <string.h>
#include "malloc.h"

#define USE_OE_MALLOC

void* oe_malloc(size_t size);
void oe_free(void* ptr);
void* oe_calloc(size_t nmemb, size_t size);

static void* (*_custom_malloc)(size_t size);
static void (*_custom_free)(void* ptr);

void vic_set_custom_allocator(
    void* (*custom_malloc)(size_t size),
    void (*custom_free)(void* ptr))
{
    _custom_malloc = custom_malloc;
    _custom_free = custom_free;
}

void* vic_malloc(size_t size)
{
    if (_custom_malloc)
        return (*_custom_malloc)(size);

    return oe_malloc(size);
}

void vic_free(void* ptr)
{
    if (ptr)
    {
        if (_custom_free)
            return (*_custom_free)(ptr);

        return oe_free(ptr);
    }
}

void* vic_calloc(size_t nmemb, size_t size)
{
    void* ptr;
    size_t n = nmemb * size;

    if (!(ptr = oe_malloc(n)))
        return NULL;

    return memset(ptr, 0, n);
}
