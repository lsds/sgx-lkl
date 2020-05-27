#include "enclave/enclave_util.h"

#include <stdarg.h>

#include "openenclave/internal/print.h"

#define OE_STDERR_FILENO 1

void sgxlkl_fail(char* msg, ...)
{
    va_list(args);
    oe_host_fprintf(OE_STDERR_FILENO, "[[  SGX-LKL ]] FAIL: ");
    va_start(args, msg);
    oe_host_vfprintf(OE_STDERR_FILENO, msg, args);
    oe_abort();
}

void sgxlkl_error(char* msg, ...)
{
    va_list(args);
    oe_host_fprintf(OE_STDERR_FILENO, "[[  SGX-LKL ]] ERROR: ");
    va_start(args, msg);
    oe_host_vfprintf(OE_STDERR_FILENO, msg, args);
}

void sgxlkl_warn(char* msg, ...)
{
    va_list(args);
    oe_host_fprintf(OE_STDERR_FILENO, "[[  SGX-LKL ]] WARN: ");
    va_start(args, msg);
    oe_host_vfprintf(OE_STDERR_FILENO, msg, args);
}

void sgxlkl_info(char* msg, ...)
{
    va_list(args);
    oe_host_fprintf(OE_STDERR_FILENO, "[[  SGX-LKL ]] ");
    va_start(args, msg);
    oe_host_vfprintf(OE_STDERR_FILENO, msg, args);
}
