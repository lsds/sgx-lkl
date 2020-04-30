#include <futex.h>
#include <sys/time.h>
#include <time.h>
//#include "enclave/enclave_util.h"
#include "sched/futex.h"
#include "lkl/posix-host.h"

/*
 * Get the difference between starttime and endtime.
 * If endtime < starttime, difference will be considered to be "0".
 */
static void timespec_diff(
    const struct timespec* starttime,
    const struct timespec* endtime,
    struct timespec* diff)
{
    if (starttime->tv_sec > endtime->tv_sec ||
        (starttime->tv_sec == endtime->tv_sec &&
         starttime->tv_nsec >= endtime->tv_nsec))
    {
        diff->tv_sec = 0;
        diff->tv_nsec = 0;
    }
    else
    {
        diff->tv_sec = endtime->tv_sec - starttime->tv_sec;
        if (starttime->tv_nsec > endtime->tv_nsec)
        {
            diff->tv_sec--;
        }

        diff->tv_nsec =
            (1000000000 + endtime->tv_nsec - starttime->tv_nsec) % 1000000000;
    }
}

/*
* SEAN-TODO: document what is happening here
*/
int syscall_SYS_futex_override(
    int* uaddr,
    int op,
    int val,
    const struct timespec* timeout,
    int* uaddr2,
    int val3)
{
    if ((op & FUTEX_WAIT_BITSET) && timeout != NULL)
    {
        // adjust absolute timeout to a relative one
        clock_t clock =
            op & FUTEX_CLOCK_REALTIME ? CLOCK_REALTIME : CLOCK_MONOTONIC;

        struct lkl_timespec now;
        if (lkl_sys_clock_gettime(clock, &now) != 0)
        {
            // SEAN-TODO: fail here
        }

        struct timespec diff;
        timespec_diff(&now, timeout, &diff);

        return syscall_SYS_enclave_futex(uaddr, op, val, &diff, uaddr2, val3);
    }

    return syscall_SYS_enclave_futex(uaddr, op, val, timeout, uaddr2, val3);
}
