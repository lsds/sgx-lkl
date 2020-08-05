#ifndef _LKL_SYSCALL_OVERRIDES_MEM_H
#define _LKL_SYSCALL_OVERRIDES_MEM_H

/**
 * Register override functions for the memory management functions.
 * The `log` argument indicates whether these functions will log the system
 * calls.  This is ignored in builds that do not support system call tracing.
 */
void syscall_register_mem_overrides(bool log);

#endif
