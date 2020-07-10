#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "host/host_state.h"

void sgxlkl_host_fail(char* msg, ...)
{
    va_list(args);
    fprintf(stderr, "[   SGX-LKL  ] FAIL: ");
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    exit(EXIT_FAILURE);
}

void sgxlkl_host_err(char* msg, ...)
{
    va_list(args);
    fprintf(stderr, "[   SGX-LKL  ] ERROR: ");
    va_start(args, msg);
    vfprintf(stderr, msg, args);
}

void sgxlkl_host_warn(char* msg, ...)
{
    va_list(args);
    fprintf(stderr, "[   SGX-LKL  ] WARN: ");
    va_start(args, msg);
    vfprintf(stderr, msg, args);
}

void sgxlkl_host_info(char* msg, ...)
{
    va_list(args);
    fprintf(stderr, "[   SGX-LKL  ] ");
    va_start(args, msg);
    vfprintf(stderr, msg, args);
}

void sgxlkl_host_verbose(char* msg, ...)
{
    if (sgxlkl_host_state.config.verbose)
    {
        va_list(args);
        fprintf(stderr, "[   SGX-LKL  ] ");
        va_start(args, msg);
        vfprintf(stderr, msg, args);
    }
}

void sgxlkl_host_verbose_raw(char* msg, ...)
{
    if (sgxlkl_host_state.config.verbose)
    {
        va_list(args);
        va_start(args, msg);
        vfprintf(stderr, msg, args);
    }
}
