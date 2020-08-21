#ifndef _LKL_SYSCALL_OVERRIDES_FSTAT_H
#define _LKL_SYSCALL_OVERRIDES_FSTAT_H

typedef long (*syscall_fstat_handler)(int, void*);
typedef long (*syscall_newfstatat_handler)(int, const char*, void*, int);

/**
 * Register override functions that maintain compatibility
 * between LKL's handling of syscall fstat and newfstatat
 * and MUSL's expectation.
 */
void syscall_register_fstat_overrides();

#endif