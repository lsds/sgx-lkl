#ifndef _SCHED_FUTEX_H
#define _SCHED_FUTEX_H

#include <time.h>

int syscall_SYS_enclave_futex(
    int* uaddr,
    int op,
    int val,
    const struct timespec* timeout,
    int* uaddr2,
    int val3);

#endif
