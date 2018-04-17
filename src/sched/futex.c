/*
 * Copyright 2016, 2017, 2018 Imperial College London
 * 
 * This file is part of SGX-LKL.
 * 
 * SGX-LKL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * SGX-LKL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with SGX-LKL.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <hostqueues.h>
#include <time.h>
#include <lthread.h>
#include <atomic.h>
#include <ticketlock.h>
#include <sgxlkl_debug.h>

#include <futex.h>

/* stores all the futex_q's */
SLIST_HEAD(__futex_q_head, futex_q) futex_queues =
     SLIST_HEAD_INITIALIZER(futex_queues);

/* for the total ordering of futex operations as mandated by POSIX */
static struct ticketlock futex_q_lock;

/* number of threads sleeping on a futex, protected by futex_q_lock */
static volatile int futex_sleepers;

/* wake-up reasons */
#define FUTEX_NONE    0 /* no extraordinary happened */
#define FUTEX_EXPIRED 1 /* timeout expired */

//#define SGXLKL_DEBUG_FUTEX
#ifdef SGXLKL_DEBUG_FUTEX
# define FUTEX_SGXLKL_VERBOSE(...) SGXLKL_VERBOSE(__VA_ARGS__)
#else
# define FUTEX_SGXLKL_VERBOSE(...) do {} while (0)
#endif

static uint32_t
to_futex_key(int *uaddr) {
    /* XXX (lkurusa): for now, this will suffice, but we need a better
     * futex_key at one point to use with a hashtable
     */
    return (uint32_t) uaddr;
}

/* called on a scheduler tick to check for timed out, sleeping futexes */
void
futex_tick() {
    struct futex_q *fq, *tmp;
    uint64_t curr_usec;
    struct timespec ts;
    int local_futex_sleepers;

    /* if there are no sleepers, we can bail quickly */
    local_futex_sleepers = a_fetch_add(&futex_sleepers, 0);
    if (!local_futex_sleepers)
        return;

    clock_gettime(CLOCK_LTHREAD, &ts);
    curr_usec = _lthread_timespec_to_usec(&ts);

    a_barrier();

    if (ticket_trylock(&futex_q_lock) == EBUSY)
        return;

    SLIST_FOREACH_SAFE(fq, &futex_queues, entries, tmp) {
        if (fq->futex_deadline && fq->futex_deadline <= curr_usec) {
            struct lthread *lt = fq->futex_lt;
            fq->futex_lt = NULL;
            a_fetch_add(&futex_sleepers, -1);
            SLIST_REMOVE(&futex_queues, fq, futex_q, entries);
            lt->err = FUTEX_EXPIRED;
            __scheduler_enqueue(lt);
        }
    }

    ticket_unlock(&futex_q_lock);
}

/* constructs a new futex_q */
static struct futex_q *
__futex_wait_new(uint32_t futex_key) {
    int rc;
    struct futex_q *fq;

    /*
     * It is not safe to use malloc and/or free while holding the futex
     * ticketlock as both malloc and free perform a futex system call themselves
     * under certain circumstances which will result in a deadlock.
     *
     * There should only ever be at most one fq per lthread. We therefore use an
     * fq field in the lthread struct instead of dynamically allocating a new
     * futex_q struct here.
     */
    fq = &lthread_self()->fq;
    fq->futex_key = futex_key;
    fq->futex_deadline = 0;
    fq->futex_lt = lthread_self();

    FUTEX_SGXLKL_VERBOSE("%s: created new futex_q in tid %d\n",
            __func__, lthread_current()->tid);

    /* add the fq to the futex_queues list */
    SLIST_INSERT_HEAD(&futex_queues, fq, entries);

    return fq;
}

static uint64_t
_lthread_timespec_to_usec_safe(struct timespec *ts) {
    if (!ts)
        return 0;

    return _lthread_timespec_to_usec(ts);
}

static void
__do_futex_unlock(void *lock) {
    ticket_unlock((struct ticketlock *) lock);
}

static int
__do_futex_sleep(struct futex_q *fq, const struct timespec *ts, const struct timespec *now) {
    FUTEX_SGXLKL_VERBOSE("%s: about to sleep in tid %d on key 0x%x\n",
            __func__, lthread_self()->tid, fq->futex_key);

    /* increase the global count of sleepers, this is safe, since
     * futex_sleepers is protected by futex_q_lock */
    a_fetch_add(&futex_sleepers, 1);

    /* set the deadline for wake up */
    if (ts) {
        fq->futex_deadline = _lthread_timespec_to_usec(now)
                + _lthread_timespec_to_usec(ts);
    }

    /* give up the CPU, unlocking the lock in one atomic step */
    _lthread_yield_cb(lthread_self(), __do_futex_unlock, &futex_q_lock);

    /* we woke up, check lt->err for the reason */
    return lthread_self()->err == FUTEX_EXPIRED ? -ETIMEDOUT : 0;
}

/* a FUTEX_WAIT operation */
static int
futex_wait(int *uaddr, int val, const struct timespec *ts, const struct timespec *now) {
    /* XXX (lkurusa): this should be an atomic read */
    int r, rc;
    uint32_t futex_key;

    futex_key = to_futex_key(uaddr);

    FUTEX_SGXLKL_VERBOSE("%s: FUTEX_WAIT in tid %d with key: 0x%x, timeout: %lld usec\n",
            __func__, lthread_self()->tid, futex_key, _lthread_timespec_to_usec_safe(ts));

    r = a_fetch_add(uaddr, 0);

    /*
     * if the real value still matches the expected value, we need to sleep
     */
    if (r == val) {
        struct futex_q *fq;
        /* it doesn't, so create it */
        fq = __futex_wait_new(futex_key);
        if (!fq)
            return -1;

        /* sleep on the FQ */
        rc = __do_futex_sleep(fq, ts, now);

        FUTEX_SGXLKL_VERBOSE("%s: FUTEX_WAITING woke up, this is tid %d\n",
                __func__, lthread_self()->tid);

        /* we were woken up */
        return rc;
    } else {
        return -EAGAIN;
    }
}

/* a FUTEX_WAKE operation */
static int
futex_wake(int *uaddr, unsigned int num) {
    uint32_t futex_key;
    struct futex_q *fq, *tmp;
    unsigned int w = 0;

    futex_key = to_futex_key(uaddr);

    FUTEX_SGXLKL_VERBOSE("%s: FUTEX_WAKE in tid %d with key: 0x%x, num %d\n",
            __func__, lthread_current()->tid, futex_key, num);

    SLIST_FOREACH_SAFE(fq, &futex_queues, entries, tmp) {
        if (fq->futex_key == futex_key && w < num) {
            struct lthread *lt = fq->futex_lt;
            fq->futex_lt = NULL;
            w++;
            a_fetch_add(&futex_sleepers, -1);
            SLIST_REMOVE(&futex_queues, fq, futex_q, entries);
            lt->err = FUTEX_NONE;
            __scheduler_enqueue(lt);
        }
    }

    FUTEX_SGXLKL_VERBOSE("%s: FUTEX_WAKE in tid %d with key: 0x%x, woke %d\n",
            __func__, lthread_current()->tid, futex_key, w);

    return w;
}

int
syscall_SYS_futex(int *uaddr, int op, int val, const struct timespec *timeout,
                    int *uaddr2, int val3) {
    int rc;
    static int init = 1;

    if (init) {
        memset((void*) &futex_q_lock, 0, sizeof(struct ticketlock));
        init = 0;
    }

    /* XXX (lkurusa): we remove FUTEX_PRIVATE, does it even make sense for us
     * to have FUTEX_PRIVATE? */
    op &= ~(FUTEX_PRIVATE);

    /* Get current time before acquiring the lock since clock_gettime performs
     * a host system call which will make the lthread yield and potentially
     * cause a deadlock. */
    struct timespec now;
    if(op == FUTEX_WAIT) {
        clock_gettime(CLOCK_LTHREAD, &now);
    }

    ticket_lock(&futex_q_lock);
    switch(op) {
        case FUTEX_WAIT:
            assert(lthread_self());

            rc = futex_wait(uaddr, val, timeout, &now);
            if (rc == 0 || rc == -ETIMEDOUT)
                goto ret_nounlock;
            break;
        case FUTEX_WAKE:
            rc = futex_wake(uaddr, val);
            break;
        default:
            FUTEX_SGXLKL_VERBOSE("%s: futex invalid op: %d\n", __func__, op);
            rc = -ENOSYS;
    }

    ticket_unlock(&futex_q_lock);

ret_nounlock:
    return rc;
}
