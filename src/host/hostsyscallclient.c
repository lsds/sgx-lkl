/*
 * Copyright 2016, 2017, 2018 Imperial College London
 * Copyright 2016, 2017 TU Dresden (under SCONE open source license)
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

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sched.h>

#include "lthread.h"
#include "hostqueues.h"
#include "pthread_impl.h"
#include "ticketlock.h"

#include "hostsyscallclient.h"

static syscall_t* S;

static size_t maxsyscalls;
static size_t nthreads = 0;

static uint8_t *freeslots;
/* maps index into array of syscall slots S to lthread */
static struct lthread **slotlthreads;
static union ticketlock slotslock;

syscall_t *getsyscallslot(Arena **a) {
    struct lthread_sched *sch = lthread_get_sched();
    size_t r = sch->current_syscallslot;
    Arena *ar = sch->current_arena;
    if (a != NULL) {
        *a = ar;
    }
    return &S[r];
}

int hostsyscallclient_init(enclave_config_t *encl) {
    S = encl->syscallpage;
    maxsyscalls = encl->maxsyscalls;
    slotlthreads = calloc(maxsyscalls, sizeof(*slotlthreads));
    freeslots = calloc(maxsyscalls, sizeof(*freeslots));
    return 1;
}

struct lthread *slottolthread(size_t s) {
    /* crash if trying to wake wrong lthread */
    if (s < maxsyscalls) {
        return slotlthreads[s];
    }
    a_crash();
    return 0;
}

static inline void submitsc(void *slot) {
    for(;!mpmc_enqueue(__syscall_queue, slot);){}
}

void threadswitch(syscall_t *sc) {
    /* can this be the same as current lthread? */
    /* post size_t inside void* field */
    struct lthread_sched *sch = lthread_get_sched();
    union {size_t s; void *a;} slot;
    slot.s = sch->current_syscallslot;
    struct lthread *lt = sch->current_lthread;
    if (lt != NULL && !(lt->attr.state & BIT(LT_ST_PINNED)) ) {
        /* avoid race condition -- another worker can pick up this thread while it's running on 
           current worker */
        _lthread_yield_cb(lt, submitsc, slot.a);
    } else {
        a_barrier();
        S[slot.s].status = 1;
        /* syscall thread won't push anything into return queue if S[slot].status is 1, so there
           is no risc of race condition in this branch */
        submitsc(slot.a);
        /* busy wait to get return value from the syscall threads
           this can happen only in two cases: initialization of the library
           and waking sleeping threads. */
        while (__atomic_load_n(&sc->status, __ATOMIC_ACQUIRE) != 2) {
            /* This either causes bugs or unmasks them.
               Concurrency is hard. */
            a_spin();
        }
    }
}

size_t allocslot(struct lthread *lt) {
    size_t i;
    ticket_lock(&slotslock);
    while (nthreads >= maxsyscalls) {
        a_crash();
        /* sched_yield */
    }
    nthreads++;
    for (i = 0; i < maxsyscalls; i++) {
        if (freeslots[i] == 0) {
            freeslots[i] = 1;
            slotlthreads[i] = lt;
            break;
        }
    }
    ticket_unlock(&slotslock);
    return i;
}

void freeslot(size_t slotno) {
    if (slotno > maxsyscalls) {
        return;
    }
    ticket_lock(&slotslock);
    slotlthreads[slotno] = 0;
    nthreads--;
    freeslots[slotno] = 0;
    ticket_unlock(&slotslock);
}
