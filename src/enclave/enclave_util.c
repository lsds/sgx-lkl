#include "enclave/enclave_util.h"

#include <stdarg.h>

#include "openenclave/internal/print.h"
#include "openenclave/corelibc/oemalloc.h"

#define OE_STDERR_FILENO 1

void sgxlkl_fail(const char* msg, ...)
{
    va_list(args);
    oe_host_fprintf(OE_STDERR_FILENO, "[[  SGX-LKL ]] FAIL: ");
    va_start(args, msg);
    oe_host_vfprintf(OE_STDERR_FILENO, msg, args);
    oe_abort();
}

void sgxlkl_error(const char* msg, ...)
{
    va_list(args);
    oe_host_fprintf(OE_STDERR_FILENO, "[[  SGX-LKL ]] ERROR: ");
    va_start(args, msg);
    oe_host_vfprintf(OE_STDERR_FILENO, msg, args);
}

void sgxlkl_warn(const char* msg, ...)
{
    va_list(args);
    oe_host_fprintf(OE_STDERR_FILENO, "[[  SGX-LKL ]] WARN: ");
    va_start(args, msg);
    oe_host_vfprintf(OE_STDERR_FILENO, msg, args);
}

void sgxlkl_info(const char* msg, ...)
{
    va_list(args);
    oe_host_fprintf(OE_STDERR_FILENO, "[[  SGX-LKL ]] ");
    va_start(args, msg);
    oe_host_vfprintf(OE_STDERR_FILENO, msg, args);
}

void* oe_malloc_or_die(size_t size, const char* fail_msg, ...)
{
    va_list(args);
    va_start(args, fail_msg);

    void* ptr = oe_malloc(size);
    if (ptr == NULL)
    {
        sgxlkl_fail(fail_msg, args);
    }
    return ptr;
}

void* oe_calloc_or_die(size_t nmemb, size_t size, const char* fail_msg, ...)
{
    va_list(args);
    va_start(args, fail_msg);

    void* ptr = oe_calloc(nmemb, size);
    if (ptr == NULL)
    {
        sgxlkl_fail(fail_msg, args);
    }
    return ptr;
}

uint64_t next_power_of_2(uint64_t n)
{
    uint64_t power_of_2 = 1;
    while (power_of_2 < n)
        power_of_2 = power_of_2 << 1;
    return power_of_2;
}