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
#ifdef IGNORED_SYSCALL
IGNORED_SYSCALL(_munlockall, 0)
IGNORED_SYSCALL(_mlockall, 1)
IGNORED_SYSCALL(_mlock, 2)
IGNORED_SYSCALL(_munlock, 2)
IGNORED_SYSCALL(_mlock2, 3)
IGNORED_SYSCALL(_sched_setaffinity, 3)
#undef IGNORED_SYSCALL
#endif
/**
 * List of system calls that can't work properly in this environment that we
 * report failure to the program.  Currently, this is only brk, which would
 * work if we used the nommu code from Linux for our memory management.
 */
// FIXME: Should sbrk be on this list?
#ifdef UNSUPPORTED_SYSCALL
UNSUPPORTED_SYSCALL(_brk, 1);
#undef UNSUPPORTED_SYSCALL
#endif
