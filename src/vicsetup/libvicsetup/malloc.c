#include <stdlib.h>
#include "malloc.h"

// These functions may be overriden with strong versions but beware that
// vic_free() must handle blocks allocated by libc with functions such as
// opem_memstream().

__attribute__((__weak__))
void* vic_malloc(size_t size)
{
    return malloc(size);
}

__attribute__((__weak__))
void vic_free(void* ptr)
{
    free(ptr);
}

__attribute__((__weak__))
void* vic_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}
