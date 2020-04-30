#ifndef _LKL_SYSCALL_OVERRIDES_FUTEX_H
#define _LKL_SYSCALL_OVERRIDES_FUTEX_H

#include <time.h>

int syscall_SYS_futex_override(
    int* uaddr,
    int op,
    int val,
    const struct timespec* timeout,
    int* uaddr2,
    int val3);

#endif
