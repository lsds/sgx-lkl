#ifndef _ENCLAVE_UTIL_H
#define _ENCLAVE_UTIL_H

#include <openenclave/enclave.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

__attribute__((noreturn)) void sgxlkl_fail(char* msg, ...);

void sgxlkl_error(char* msg, ...);

void sgxlkl_warn(char* msg, ...);

void sgxlkl_info(char* msg, ...);

int int_log2(unsigned long long arg);

#ifdef DEBUG

#include "openenclave/internal/print.h"

extern int sgxlkl_verbose;
extern int sgxlkl_trace_thread;
extern int sgxlkl_trace_mmap;
extern int sgxlkl_trace_signal;
extern int sgxlkl_trace_disk;
extern int sgxlkl_trace_lkl_syscall;
extern int sgxlkl_trace_internal_syscall;
extern int sgxlkl_trace_ignored_syscall;
extern int sgxlkl_trace_unsupported_syscall;
extern int sgxlkl_trace_redirect_syscall;

#define SGXLKL_ASSERT(EXPR)                                   \
    do                                                        \
    {                                                         \
        if (!(EXPR))                                          \
        {                                                     \
            oe_host_printf(                                   \
                "SGXLKL ASSERTION FAILED: %s (%s: %d: %s)\n", \
                #EXPR,                                        \
                __FILE__,                                     \
                __LINE__,                                     \
                __FUNCTION__);                                \
            oe_abort();                                       \
        }                                                     \
    } while (0)

#define SGXLKL_VERBOSE(x, ...)                                              \
    if (sgxlkl_verbose)                                                     \
    {                                                                       \
        oe_host_printf("[[  SGX-LKL ]] %s(): " x, __func__, ##__VA_ARGS__); \
    }
#define SGXLKL_VERBOSE_RAW(x, ...)        \
    if (sgxlkl_verbose)                   \
    {                                     \
        oe_host_printf(x, ##__VA_ARGS__); \
    }
#define SGXLKL_TRACE_THREAD(x, ...)                         \
    if (sgxlkl_trace_thread)                                \
    {                                                       \
        oe_host_printf("[[  THREAD  ]] " x, ##__VA_ARGS__); \
    }
#define SGXLKL_TRACE_MMAP(x, ...)                           \
    if (sgxlkl_trace_mmap)                                  \
    {                                                       \
        oe_host_printf("[[   MMAP   ]] " x, ##__VA_ARGS__); \
    }
#define SGXLKL_TRACE_SYSCALL(type, x, ...)                           \
    if ((sgxlkl_trace_lkl_syscall && type == SGXLKL_LKL_SYSCALL))    \
    {                                                                \
        oe_host_printf("[[ LKL SYSC ]] " x, ##__VA_ARGS__);          \
    }                                                                \
    else if ((sgxlkl_trace_internal_syscall &&                       \
              type == SGXLKL_INTERNAL_SYSCALL))                      \
    {                                                                \
        oe_host_printf("[[ INT SYSC ]] " x, ##__VA_ARGS__);          \
    }                                                                \
    else if ((sgxlkl_verbose && type == SGXLKL_IGNORED_SYSCALL))     \
    {                                                                \
        oe_host_printf("[[ IGN SYSC ]] " x, ##__VA_ARGS__);          \
    }                                                                \
    else if ((sgxlkl_verbose && type == SGXLKL_UNSUPPORTED_SYSCALL)) \
    {                                                                \
        oe_host_printf("[[NO SYSC  !]] " x, ##__VA_ARGS__);          \
    }                                                                \
    else if ((sgxlkl_verbose && type == SGXLKL_REDIRECT_SYSCALL))    \
    {                                                                \
        oe_host_printf("[[REDIR SYSC]] " x, ##__VA_ARGS__);          \
    }

#define SGXLKL_TRACE_SIGNAL(x, ...)                         \
    if (sgxlkl_trace_signal)                                \
    {                                                       \
        oe_host_printf("[[  SIGNAL  ]] " x, ##__VA_ARGS__); \
    }

#define SGXLKL_TRACE_DISK(x, ...)                         \
    if (sgxlkl_trace_disk)                                \
    {                                                       \
        oe_host_printf("[[   DISK   ]] " x, ##__VA_ARGS__); \
    }

#else
#define SGXLKL_ASSERT(EXPR)
#define SGXLKL_VERBOSE(x, ...)
#define SGXLKL_VERBOSE_RAW(x, ...)
#define SGXLKL_TRACE_THREAD(x, ...)
#define SGXLKL_TRACE_MMAP(x, ...)
#define SGXLKL_TRACE_SIGNAL(x, ...)
#define SGXLKL_TRACE_DISK(x, ...)
#define SGXLKL_TRACE_SYSCALL(x, ...)
#endif

#endif /* _ENCLAVE_UTIL_H */
