#ifndef _LKL_UTIL_H
#define _LKL_UTIL_H

#include <openenclave/enclave.h>

// Eventually we will want to turn system call tracing on and off independently
// of the debug configuration, but for now they are the same.
#define SGXLKL_ENABLE_SYSCALL_TRACING DEBUG

/**
 * The mechanism used to implement a specified system call.
 */
typedef enum
{
    /**
     * System calls that are implemented by LKL as a normal Linux system call.
     */
    SGXLKL_LKL_SYSCALL = 1,
    /**
     * System calls that are implemented using SGX-LKL custom code paths that
     * bypass the Linux kernel.  Eventually, these will all be replaced.
     */
    SGXLKL_INTERNAL_SYSCALL = 3,
    /**
     * System calls that are not possible to implement in an SGX environment but
     * software that expects it to work can act as if it does.  For example,
     * `mlock` is ignored because memory is all locked by the SGX environment.
     */
    SGXLKL_IGNORED_SYSCALL = 4,
    /**
     * System calls that are not supported in the SGX
     * environment at all and which callers may handle.
     */
    SGXLKL_UNSUPPORTED_SYSCALL = 5,
    /**
     * System calls that were invoked using the normal
     * architecture's system call numbers and
     * redirected.
     */
    SGXLKL_REDIRECT_SYSCALL = 6,
} sgxlkl_syscall_kind;

/**
 * Logs a trace message for the specified syscall.  The type argument
 * identifies how the system call is implemented, `n` gives the number of
 * parameters, `res` the result value. There are `params_len` variadic
 * parameters (0 to 6) that give the arguments for the system call.
 *
 * This function returns `res`, so that it can be tail called on the return
 * path.
 */
#if SGXLKL_ENABLE_SYSCALL_TRACING
long __sgxlkl_log_syscall(
    sgxlkl_syscall_kind type,
    long n,
    long res,
    int params_len,
    ...);
#else
static inline long __sgxlkl_log_syscall(
    sgxlkl_syscall_kind type,
    long n,
    long res,
    int params_len,
    ...)
{
	return res;
}
#endif

int int_log2(unsigned long long arg);

#ifdef DEBUG

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

#define SGXLKL_TRACE_DISK(x, ...)                           \
    if (sgxlkl_trace_disk)                                  \
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
