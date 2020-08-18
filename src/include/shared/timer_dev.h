/*
 * timer_dev is a shared data structure used to communicate information about
 * time and its passage from the host environment to the enclave. An instance
 * of timer_dev is created in the host environment when we are bringing up the
 * enclave and is then shared with the enclave environment.
 *
 */
struct timer_dev
{
    /*
     * The version of this structure and the value should be
     * incremented any time the shape of timer_dev changes. Version
     * is initialized in timer_dev.c in timerdev_init.
     */
    uint64_t version;

    /*
     * The number of monotonic nanos that have passed outside of the
     * enclave since it was started up. nanos is used in enclave_timer.c to
     * update the internal clock for the passage of time.
     */
    _Atomic(uint64_t) nanos;

    /*
     * init_walltime_* are used once on enclave startup to set the wallclock
     * time in the enclave one that closely matches the host's walltime. Neither
     * field is used after enclave wallclock is initialized on startup in
     * startup.c.
     */
    uint64_t init_walltime_sec;
    uint64_t init_walltime_nsec;
};
