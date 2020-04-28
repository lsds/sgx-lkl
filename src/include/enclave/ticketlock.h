#ifndef TICKETLOCK_H
#define TICKETLOCK_H

#include "atomic.h"

#if DEBUG
#include "lthread.h"
#endif /* DEBUG */

struct ticketlock
{
    union {
        uint64_t u;
        struct
        {
            uint32_t ticket;
            uint32_t users;
        } s;
    };
#if DEBUG
    struct lthread* lt; // Thread that is holding the lock.
#endif                  /* DEBUG */
};

static void ticket_lock(struct ticketlock* t)
{
    uint32_t me = a_fetch_add_uint(&t->s.users, 1);
    while (t->s.ticket != me)
        a_spin();
#if DEBUG
    t->lt = NULL;
    // t->lt = lthread_self();
#endif /* DEBUG */
}

static void ticket_unlock(struct ticketlock* t)
{
    a_barrier();
    t->s.ticket++;
#if DEBUG
    t->lt = NULL;
#endif /* DEBUG */
}

static int ticket_trylock(struct ticketlock* t)
{
    uint32_t me = t->s.users;
    uint32_t menew = me + 1;
    uint64_t cmp = ((uint64_t)me << 32) + me;
    uint64_t cmpnew = ((uint64_t)menew << 32) + me;

    if (a_cas_64(&t->u, cmp, cmpnew) == cmp)
    {
#if DEBUG
        t->lt = NULL;
        // t->lt = lthread_self();
#endif /* DEBUG */
        return 0;
    }

    return EBUSY;
}

#endif /* TICKETLOCK_H */
