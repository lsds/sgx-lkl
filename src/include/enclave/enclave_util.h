#ifndef _ENCLAVE_UTIL_H
#define _ENCLAVE_UTIL_H

#include <enclave/enclave_state.h>
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
 * Note that generating a stack trace by unwinding stack frames could be
 * exploited by an attacker and therefore should only be possible in a DEBUG
 * build.
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

#include "openenclave/internal/print.h"

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

#define SGXLKL_VERBOSE(x, ...)                                               \
    if (sgxlkl_enclave_state.config->verbose &&                              \
        sgxlkl_enclave_state.trace_enabled.verbose)                          \
    {                                                                        \
        struct schedctx* _sgxlkl_verbose_self;                               \
        __asm__ __volatile__("mov %%gs:48,%0" : "=r"(_sgxlkl_verbose_self)); \
        struct lthread_sched* _sgxlkl_verbose_sched =                        \
            _sgxlkl_verbose_self ? &_sgxlkl_verbose_self->sched : NULL;      \
        struct lthread* _sgxlkl_verbose_lt =                                 \
            _sgxlkl_verbose_sched ? _sgxlkl_verbose_sched->current_lthread   \
                                  : NULL;                                    \
        oe_host_printf(                                                      \
            "[[  SGX-LKL ]] [%p] [%4d] %s(): " x,                            \
            _sgxlkl_verbose_self,                                            \
            _sgxlkl_verbose_lt ? _sgxlkl_verbose_lt->tid : -1,               \
            __func__,                                                        \
            ##__VA_ARGS__);                                                  \
    }
#define SGXLKL_VERBOSE_RAW(x, ...)                  \
    if (sgxlkl_enclave_state.config->verbose &&     \
        sgxlkl_enclave_state.trace_enabled.verbose) \
    {                                               \
        oe_host_printf(x, ##__VA_ARGS__);           \
    }
#define SGXLKL_TRACE_THREAD(x, ...)                         \
    if (sgxlkl_enclave_state.config->trace.thread)          \
    {                                                       \
        oe_host_printf("[[  THREAD  ]] " x, ##__VA_ARGS__); \
    }
#define SGXLKL_TRACE_MMAP(x, ...)                           \
    if (sgxlkl_enclave_state.config->trace.mmap)            \
    {                                                       \
        oe_host_printf("[[   MMAP   ]] " x, ##__VA_ARGS__); \
    }
#define SGXLKL_TRACE_SYSCALL(type, x, ...)                           \
    if ((sgxlkl_enclave_state.config->trace.lkl_syscall &&           \
         sgxlkl_enclave_state.trace_enabled.lkl_syscall &&           \
         type == SGXLKL_LKL_SYSCALL))                                \
    {                                                                \
        oe_host_printf("[[ LKL SYSC ]] " x, ##__VA_ARGS__);          \
    }                                                                \
    else if ((sgxlkl_enclave_state.config->trace.internal_syscall && \
              sgxlkl_enclave_state.trace_enabled.internal_syscall && \
              type == SGXLKL_INTERNAL_SYSCALL))                      \
    {                                                                \
        oe_host_printf("[[ INT SYSC ]] " x, ##__VA_ARGS__);          \
    }                                                                \
    else if ((sgxlkl_enclave_state.config->verbose &&                \
              sgxlkl_enclave_state.trace_enabled.verbose &&          \
              type == SGXLKL_IGNORED_SYSCALL))                       \
    {                                                                \
        oe_host_printf("[[ IGN SYSC ]] " x, ##__VA_ARGS__);          \
    }                                                                \
    else if ((sgxlkl_enclave_state.config->verbose &&                \
              sgxlkl_enclave_state.trace_enabled.verbose &&          \
              type == SGXLKL_UNSUPPORTED_SYSCALL))                   \
    {                                                                \
        oe_host_printf("[[NO SYSC  !]] " x, ##__VA_ARGS__);          \
    }                                                                \
    else if ((sgxlkl_enclave_state.config->verbose &&                \
              sgxlkl_enclave_state.trace_enabled.verbose &&          \
              type == SGXLKL_REDIRECT_SYSCALL))                      \
    {                                                                \
        oe_host_printf("[[REDIR SYSC]] " x, ##__VA_ARGS__);          \
    }

#define SGXLKL_TRACE_SIGNAL(x, ...)                         \
    if (sgxlkl_enclave_state.config->trace.signal)          \
    {                                                       \
        oe_host_printf("[[  SIGNAL  ]] " x, ##__VA_ARGS__); \
    }

#define SGXLKL_TRACE_DISK(x, ...)                           \
    if (sgxlkl_enclave_state.config->trace.disk)            \
    {                                                       \
        oe_host_printf("[[   DISK   ]] " x, ##__VA_ARGS__); \
    }

#endif /* _ENCLAVE_UTIL_H */
