#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "defs.h"

__attribute__((__weak__))
void* oe_malloc(size_t size)
{
    return malloc(size);
}

__attribute__((__weak__))
void oe_free(void* ptr)
{
    return free(ptr);
}

__attribute__((__weak__))
void* oe_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}
