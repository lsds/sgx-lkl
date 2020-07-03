#ifndef __OE_MALLOC_INCLUDED__
#define __OE_MALLOC_INCLUDED__

void *oe_malloc(size_t size);
void oe_free(void *ptr);
void *oe_calloc(size_t nmemb, size_t size);
void *oe_realloc(void *ptr, size_t size);

#endif
