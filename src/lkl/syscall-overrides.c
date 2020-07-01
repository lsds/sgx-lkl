#include <asm-generic/errno.h>
#include <sys/syscall.h>
#include "lkl/posix-host.h"
#include "lkl/syscall-overrides-fstat.h"
#include "lkl/syscall-overrides-sysinfo.h"

/**
 * List of system calls that we treat as no-ops that silently succeed.  The
 * mlock family may be removed from this list if we transition to using the
 * Linux built-in nommu mode for mmap, because then Linux should silently ignore
 * them.
 *
 * We ignore sched_setaffinity because the Linux scheduler is not responsible
 * for scheduling userspace threads in the LKL model and so cannot support this
 * call.  The lthread scheduler could be extended to provide ethread affinity
 * but does not currently.  We silently report success because it keeps OpenMP
 * runtimes and similar code quiet.
 */
static const long ignored_syscalls[] = {__lkl__NR_mlock,
                                        __lkl__NR_mlockall,
                                        __lkl__NR_munlock,
                                        __lkl__NR_munlockall,
                                        __lkl__NR_sched_setaffinity};

/**
 * List of system calls that can't work properly in this environment that we
 * report failure to the program.  Currently, this is only brk, which would
 * work if we used the nommu code from Linux for our memory management.
 */
static const long unsupported_syscalls[] = {
    // FIXME: Should sbrk be on this list?
    __lkl__NR_brk};

/**
 * Function used to implement silently ignored system calls.  Ignores all
 * arguments and returns success.
 */
static long ignored_syscall()
{
    return 0;
}

/**
 * Function used to implement unsupported system calls.  Ignores all arguments
 * and returns a not-implemented error.
 */
static long unsupported_syscall()
{
    return -ENOSYS;
}

void register_lkl_syscall_overrides()
{
    syscall_register_fstat_overrides();
    lkl_replace_syscall(
        __lkl__NR_sysinfo, (lkl_syscall_handler_t)syscall_sysinfo_override);
    // Register all of the ignored system calls.
    for (int i = 0; i < (sizeof(ignored_syscalls) / sizeof(*ignored_syscalls));
         i++)
    {
        lkl_replace_syscall(
            ignored_syscalls[i], (lkl_syscall_handler_t)ignored_syscall);
    }
    // Register all of the unsupported system calls.
    for (int i = 0;
         i < (sizeof(unsupported_syscalls) / sizeof(*unsupported_syscalls));
         i++)
    {
        lkl_replace_syscall(
            unsupported_syscalls[i],
            (lkl_syscall_handler_t)unsupported_syscall);
    }
}
