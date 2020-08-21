#ifndef TICKETLOCK_H
#define TICKETLOCK_H

#include <stdatomic.h>

#if DEBUG
#include "lthread.h"
#endif /* DEBUG */

/**
 * A ticket lock.  This provides a simple spinlock that guarantees that the
 * lock will be acquired in the order that callers attempt to acquire it.
 *
 * This is similar to the mechanism used in some shops, where customers take a
 * numbered ticket and wait until that number is called.  Threads that attempt
 * to acquire the lock 'take a ticket' by atomically incrementing one counter
 * and then wait until that ticket is the current one.  Threads releasing the
 * lock increment a second counter representing the current ticket.
 */
struct ticketlock
{
    /**
     * Anonymous union of the two words used to represent the ticket lock.
     * It's not clear whether doing different-sized atomic accesses to the same
     * address is defined behaviour in C.  It is definitely broken on some
     * PowerPC implementations but is fine on x86.
     */
    union {
        /**
         * A single view of the ticket and users fields.  This is needed for
         * `ticket_trylock`, which attempts to atomically test `ticket` and set
         * `users`.
         */
        _Atomic(uint64_t) u;
        struct
        {
            /**
             * The current ticket value.  Each thread that attempts to acquire
             * a ticket lock waits until this field matches its ticket.
             */
            _Atomic(uint32_t) ticket;
            /**
             * The value that the next thread attempting to acquire the lock
             * should take.  A thread 'takes a ticket' by atomically
             * incrementing this field.  The value before the increment is the
             * value of that thread's ticket.
             */
            _Atomic(uint32_t) users;
        } s;
    };
#if DEBUG
    struct lthread* lt; // Thread that is holding the lock.
#endif                  /* DEBUG */
};

/**
 * Acquire a ticket lock.  This spins until the lock is acquired, it does *not*
 * yield to other cooperatively scheduled threads.
 */
static inline void ticket_lock(struct ticketlock* t)
{
    // Acquire a ticket
    uint32_t me = atomic_fetch_add(&t->s.users, 1);
    // Wait until our ticket is called.
    while (t->s.ticket != me)
    {
#ifdef __x86__
        __builtin_ia32_pause()
#endif
            ;
    }

#if DEBUG
    t->lt = NULL;
    // t->lt = lthread_self();
#endif /* DEBUG */
}

/**
 * Release the ticket lock.
 */
static inline void ticket_unlock(struct ticketlock* t)
{
    t->s.ticket++;
#if DEBUG
    t->lt = NULL;
#endif /* DEBUG */
}

/**
 * Try to acquire a ticket lock.  Returns zero on success, non-zero on failure.
 */
static inline int ticket_trylock(struct ticketlock* t)
{
    // Get the expected next ticket value
    uint32_t me = t->s.users;
    // Set our expected next-ticket value.
    uint32_t menew = me + 1;
    // If the ticket lock is not held, t->s.users will equal t->s.ticket.
    // Expect that to be the case.
    uint64_t expected = ((uint64_t)me << 32) + me;
    // If we successfully acquire the lock, the ticket value is our ticket and
    // the next-ticket value is that value plus one.
    uint64_t desired = ((uint64_t)menew << 32) + me;

    // Try the CAS once.  If it succeeds, we acquired the lock. If it fails
    // then we did not but we did not modify the state so we can just return.
    if (atomic_compare_exchange_strong(&t->u, &expected, desired))
    {
#if DEBUG
        t->lt = NULL;
        // t->lt = lthread_self();
#endif /* DEBUG */
        return 0;
    }

    return -1;
}

#endif /* TICKETLOCK_H */
