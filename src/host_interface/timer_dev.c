#include <errno.h>
#include <host/sgxlkl_util.h>
#include <shared/sgxlkl_config.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#define NSEC_PER_SEC 1000000000

uint64_t counter_start_offset;

static uint64_t host_nanos()
{
    struct timespec m;
    clock_gettime(CLOCK_MONOTONIC, &m);

    return (uint64_t)((m.tv_sec * NSEC_PER_SEC) + m.tv_nsec);
}

/*
 * Initializes our monotonic time generator's shared memory data structure
 */
int timerdev_init(sgxlkl_config_t* config)
{
    struct timer_dev* timer_dev_mem =
        (struct timer_dev*)malloc(sizeof(struct timer_dev));

    if (timer_dev_mem == NULL)
    {
        sgxlkl_host_fail("Timer device shared memory alloc failed\n");
        return -1;
    }

    /* initialize to current monotonic time */
    counter_start_offset = host_nanos();

    /* Set up shared structure */
    timer_dev_mem->version = 0;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    timer_dev_mem->nanos = 0;
    timer_dev_mem->init_walltime_sec = ts.tv_sec;
    timer_dev_mem->init_walltime_nsec = ts.tv_nsec;

    config->shared_memory.timer_dev_mem = timer_dev_mem;

    return 0;
}

/*
 * Task run by an indepedent pthread to update a shared data structure with
 * a monontonically increasing counter of time advancing outside of the enclave.
 * The shared data structure is used in enclave_timer.c to provide a time source
 * for a monotonic timer.
 */
void* timerdev_task(struct timer_dev* timer_dev_mem)
{
    struct timespec ts;
    ts.tv_sec = 0;

    // TODO: make configurable
    ts.tv_nsec = 500000;

    for (;;)
    {
        clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, NULL);

        timer_dev_mem->nanos = host_nanos() - counter_start_offset;
    }
}
