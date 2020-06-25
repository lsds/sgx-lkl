#ifndef _ENCLAVE_UTIL_H
#define _ENCLAVE_UTIL_H

#include <enclave/enclave_state.h>
#include <openenclave/enclave.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

__attribute__((noreturn)) void sgxlkl_fail(const char* msg, ...);

void sgxlkl_error(const char* msg, ...);

void sgxlkl_warn(const char* msg, ...);

void sgxlkl_info(const char* msg, ...);

/**
 * Performs a memory allocation with oe_malloc(size) and fails
 * execution with fail_msg if it is not successful.
 */
void* oe_malloc_or_die(size_t size, const char* fail_msg, ...);

/**
 * Performs a memory allocation with oe_calloc(nmemb, size) and
 * fails execution with fail_msg if it is not successful.
 */
void* oe_calloc_or_die(size_t nmemb, size_t size, const char* fail_msg, ...);

/**
 *
 * Note that generating a stack trace by unwinding stack frames could be exploited
 * by an attacker and therefore should only be possible in a DEBUG build.
 */
#ifdef DEBUG
/**
 * Prints a stacktrace using oe_backtrace() from start_frame. If start_frame
 * is NULL, it uses the current stack frame.
 */
void sgxlkl_print_backtrace(void** start_frame);
#endif

int int_log2(unsigned long long arg);

/**
 * Rounds a number to the next power of 2.
 */
uint64_t next_power_of_2(uint64_t n);

#ifdef DEBUG

#include "openenclave/internal/print.h"

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
    if (sgxlkl_enclave_state.verbose)                                       \
    {                                                                       \
        oe_host_printf("[[  SGX-LKL ]] %s(): " x, __func__, ##__VA_ARGS__); \
    }
#define SGXLKL_VERBOSE_RAW(x, ...)        \
    if (sgxlkl_enclave_state.verbose)     \
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
#define SGXLKL_TRACE_SYSCALL(type, x, ...)                                     \
    if ((sgxlkl_trace_lkl_syscall && type == SGXLKL_LKL_SYSCALL))              \
    {                                                                          \
        oe_host_printf("[[ LKL SYSC ]] " x, ##__VA_ARGS__);                    \
    }                                                                          \
    else if ((sgxlkl_trace_internal_syscall &&                                 \
              type == SGXLKL_INTERNAL_SYSCALL))                                \
    {                                                                          \
        oe_host_printf("[[ INT SYSC ]] " x, ##__VA_ARGS__);                    \
    }                                                                          \
    else if ((sgxlkl_enclave_state.verbose && type == SGXLKL_IGNORED_SYSCALL)) \
    {                                                                          \
        oe_host_printf("[[ IGN SYSC ]] " x, ##__VA_ARGS__);                    \
    }                                                                          \
    else if ((sgxlkl_enclave_state.verbose &&                                  \
              type == SGXLKL_UNSUPPORTED_SYSCALL))                             \
    {                                                                          \
        oe_host_printf("[[NO SYSC  !]] " x, ##__VA_ARGS__);                    \
    }                                                                          \
    else if ((sgxlkl_enclave_state.verbose &&                                  \
              type == SGXLKL_REDIRECT_SYSCALL))                                \
    {                                                                          \
        oe_host_printf("[[REDIR SYSC]] " x, ##__VA_ARGS__);                    \
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
