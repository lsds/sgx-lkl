#include <asm-generic/errno.h>
#include <sys/syscall.h>
#include "enclave/enclave_util.h"
#include "lkl/posix-host.h"
#include "lkl/syscall-overrides-fstat.h"
#include "lkl/syscall-overrides-mem.h"
#include "lkl/syscall-overrides-sysinfo.h"

/**
 * Macros for generating functions for implementing ignored system calls and
 * for their log variants.
 */
#if SGXLKL_ENABLE_SYSCALL_TRACING
#define IGNORED_SYSCALL(name, args)                           \
    static long ignore##name(                                 \
        long a1, long a2, long a3, long a4, long a5, long a6) \
    {                                                         \
        return 0;                                             \
    }                                                         \
    static long log_and_ignore##name(                         \
        long a1, long a2, long a3, long a4, long a5, long a6) \
    {                                                         \
        return __sgxlkl_log_syscall(                          \
            SGXLKL_IGNORED_SYSCALL,                           \
            __lkl__NR##name,                                  \
            0,                                                \
            args,                                             \
            a1,                                               \
            a2,                                               \
            a3,                                               \
            a4,                                               \
            a5,                                               \
            a6);                                              \
    }
#else
#define IGNORED_SYSCALL(name, args)                           \
    static long ignore##name(                                 \
        long a1, long a2, long a3, long a4, long a5, long a6) \
    {                                                         \
        return 0;                                             \
    }
#endif
/**
 * Function used to implement unsupported system calls.  Ignores all arguments
 * and returns a not-implemented error.  The log variant logs that the system
 * call was unsupported.
 */
#if SGXLKL_ENABLE_SYSCALL_TRACING
#define UNSUPPORTED_SYSCALL(name, args)                       \
    static long unsupported##name()                           \
    {                                                         \
        return -ENOSYS;                                       \
    }                                                         \
                                                              \
    static long log_unsupported##name(                        \
        long a1, long a2, long a3, long a4, long a5, long a6) \
    {                                                         \
        return __sgxlkl_log_syscall(                          \
            SGXLKL_UNSUPPORTED_SYSCALL,                       \
            __lkl__NR##name,                                  \
            -ENOSYS,                                          \
            args,                                             \
            a1,                                               \
            a2,                                               \
            a3,                                               \
            a4,                                               \
            a5,                                               \
            a6);                                              \
    }
#else
#define UNSUPPORTED_SYSCALL(name, args) \
    static long unsupported##name()     \
    {                                   \
        return -ENOSYS;                 \
    }
#endif

#include "unsupported-syscalls.h"

#if SGXLKL_ENABLE_SYSCALL_TRACING
static lkl_syscall_handler_t real_syscalls[__lkl__NR_syscalls];

#undef LKL_SYSCALL_DEFINE0
#undef LKL_SYSCALL_DEFINE1
#undef LKL_SYSCALL_DEFINE2
#undef LKL_SYSCALL_DEFINE3
#undef LKL_SYSCALL_DEFINE4
#undef LKL_SYSCALL_DEFINE5
#undef LKL_SYSCALL_DEFINE6
#define LKL_SYSCALL_DEFINE0(name, ...)                                     \
    static long log##name()                                                \
    {                                                                      \
        int ret = ((long (*)(void))real_syscalls[__lkl__NR##name])();       \
        __sgxlkl_log_syscall(SGXLKL_LKL_SYSCALL, __lkl__NR##name, ret, 0); \
        return ret;                                                        \
    }

#define LKL_SYSCALL_DEFINE1(name, t1, a1)                                      \
    static long log##name(t1 a1)                                               \
    {                                                                          \
        int ret = ((long (*)(t1))real_syscalls[__lkl__NR##name])(a1);           \
        __sgxlkl_log_syscall(SGXLKL_LKL_SYSCALL, __lkl__NR##name, ret, 1, a1); \
        return ret;                                                            \
    }

#define LKL_SYSCALL_DEFINE2(name, t1, a1, t2, a2)                            \
    static long log##name(t1 a1, t2 a2)                                      \
    {                                                                        \
        int ret = ((long (*)(t1, t2))real_syscalls[__lkl__NR##name])(a1, a2); \
        __sgxlkl_log_syscall(                                                \
            SGXLKL_LKL_SYSCALL, __lkl__NR##name, ret, 2, a1, a2);            \
        return ret;                                                          \
    }

#define LKL_SYSCALL_DEFINE3(name, t1, a1, t2, a2, t3, a3)                      \
    static long log##name(t1 a1, t2 a2, t3 a3)                                 \
    {                                                                          \
        long ret =                                                              \
            ((long (*)(t1, t2, t3))real_syscalls[__lkl__NR##name])(a1, a2, a3); \
        __sgxlkl_log_syscall(                                                  \
            SGXLKL_LKL_SYSCALL, __lkl__NR##name, ret, 3, a1, a2, a3);          \
        return ret;                                                            \
    }

#define LKL_SYSCALL_DEFINE4(name, t1, a1, t2, a2, t3, a3, t4, a4)            \
    static long log##name(t1 a1, t2 a2, t3 a3, t4 a4)                        \
    {                                                                        \
        long ret = ((long (*)(t1, t2, t3, t4))real_syscalls[__lkl__NR##name])( \
            a1, a2, a3, a4);                                                 \
        __sgxlkl_log_syscall(                                                \
            SGXLKL_LKL_SYSCALL, __lkl__NR##name, ret, 4, a1, a2, a3, a4);    \
        return ret;                                                          \
    }

#define LKL_SYSCALL_DEFINE5(name, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)     \
    static long log##name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5)                  \
    {                                                                         \
        long ret =                                                             \
            ((long (*)(t1, t2, t3, t4, t5))real_syscalls[__lkl__NR##name])(    \
                a1, a2, a3, a4, a5);                                          \
        __sgxlkl_log_syscall(                                                 \
            SGXLKL_LKL_SYSCALL, __lkl__NR##name, ret, 5, a1, a2, a3, a4, a5); \
        return ret;                                                           \
    }

#define LKL_SYSCALL_DEFINE6(                                                   \
    name, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)                      \
    static long log##name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6)            \
    {                                                                          \
        long ret =                                                              \
            ((long (*)(t1, t2, t3, t4, t5, t6))real_syscalls[__lkl__NR##name])( \
                a1, a2, a3, a4, a5, a6);                                       \
        __sgxlkl_log_syscall(                                                  \
            SGXLKL_LKL_SYSCALL,                                                \
            __lkl__NR##name,                                                   \
            ret,                                                               \
            6,                                                                 \
            a1,                                                                \
            a2,                                                                \
            a3,                                                                \
            a4,                                                                \
            a5,                                                                \
            a6);                                                               \
        return ret;                                                            \
    }

#include <lkl/asm/syscall_defs.h>
#endif

void register_lkl_syscall_overrides()
{
    // Register fstat overrides early.  These are ABI compat wrappers, so we
    // count them as LKL syscalls for the purpose of tracing.
    syscall_register_fstat_overrides();

#if SGXLKL_ENABLE_SYSCALL_TRACING
    // If tracing is enabled, register syscall overrides that call the tracing
    // functions.
#undef LKL_SYSCALL_DEFINE0
#undef LKL_SYSCALL_DEFINE1
#undef LKL_SYSCALL_DEFINE2
#undef LKL_SYSCALL_DEFINE3
#undef LKL_SYSCALL_DEFINE4
#undef LKL_SYSCALL_DEFINE5
#undef LKL_SYSCALL_DEFINE6
#define LKL_SYSCALL_DEFINE0(name, ...)                    \
    real_syscalls[__lkl__NR##name] = lkl_replace_syscall( \
        __lkl__NR##name, (lkl_syscall_handler_t)log##name);
#define LKL_SYSCALL_DEFINE1(name, ...)                    \
    real_syscalls[__lkl__NR##name] = lkl_replace_syscall( \
        __lkl__NR##name, (lkl_syscall_handler_t)log##name);
#define LKL_SYSCALL_DEFINE2(name, ...)                    \
    real_syscalls[__lkl__NR##name] = lkl_replace_syscall( \
        __lkl__NR##name, (lkl_syscall_handler_t)log##name);
#define LKL_SYSCALL_DEFINE3(name, ...)                    \
    real_syscalls[__lkl__NR##name] = lkl_replace_syscall( \
        __lkl__NR##name, (lkl_syscall_handler_t)log##name);
#define LKL_SYSCALL_DEFINE4(name, ...)                    \
    real_syscalls[__lkl__NR##name] = lkl_replace_syscall( \
        __lkl__NR##name, (lkl_syscall_handler_t)log##name);
#define LKL_SYSCALL_DEFINE5(name, ...)                    \
    real_syscalls[__lkl__NR##name] = lkl_replace_syscall( \
        __lkl__NR##name, (lkl_syscall_handler_t)log##name);
#define LKL_SYSCALL_DEFINE6(name, ...)                    \
    real_syscalls[__lkl__NR##name] = lkl_replace_syscall( \
        __lkl__NR##name, (lkl_syscall_handler_t)log##name);
    if (sgxlkl_trace_lkl_syscall)
    {
#include <lkl/asm/syscall_defs.h>
    }
#endif

    // We currently provide our own sysinfo override, because LKL is not aware
    // of the total amount of RAM (or of the number of cores)
    lkl_replace_syscall(
        __lkl__NR_sysinfo, (lkl_syscall_handler_t)syscall_sysinfo_override);

    // If tracing ignored syscalls is enabled, replace the ignored set with a
    // version that does the tracing and exits, otherwise replace them with a
    // version that silently returns success.
#if SGXLKL_ENABLE_SYSCALL_TRACING
    if (sgxlkl_trace_ignored_syscall)
    {
#define IGNORED_SYSCALL(name, args) \
    lkl_replace_syscall(            \
        __lkl__NR##name, (lkl_syscall_handler_t)log_and_ignore##name);
#include "unsupported-syscalls.h"
    }
    else
#endif
    {
#define IGNORED_SYSCALL(name, args) \
    lkl_replace_syscall(__lkl__NR##name, (lkl_syscall_handler_t)ignore##name);
#include "unsupported-syscalls.h"
    }
    // If tracing unsupported syscalls is enabled, replace the ignored set with
    // a version that does the tracing and exits, otherwise replace them with a
    // version that silently returns failure.
#if SGXLKL_ENABLE_SYSCALL_TRACING
    if (sgxlkl_trace_unsupported_syscall)
    {
#define UNSUPPORTED_SYSCALL(name, args) \
    lkl_replace_syscall(                \
        __lkl__NR##name, (lkl_syscall_handler_t)log_unsupported##name);
#include "unsupported-syscalls.h"
    }
    else
#endif
    {
#define UNSUPPORTED_SYSCALL(name, args) \
    lkl_replace_syscall(                \
        __lkl__NR##name, (lkl_syscall_handler_t)unsupported##name);
#include "unsupported-syscalls.h"
    }
		/*
    // Register overrides for the memory management functions.
    // These are internal - use the trace versions if we are doing internal
    // syscall tracing.
#if SGXLKL_ENABLE_SYSCALL_TRACING
    syscall_register_mem_overrides(sgxlkl_trace_internal_syscall);
#else
    syscall_register_mem_overrides(false);
#endif
    */
}
