/*
 * Copyright 2016, 2017, 2018 Imperial College London (under GNU General Public License v3)
 * Copyright 2016, 2017 TU Dresden (under SCONE source code license)
 */

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sched.h>

#define _GNU_SOURCE
#include <sys/mman.h>

#include "lthread.h"
#include "pthread_impl.h"
#include "ticketlock.h"

#include "hostcall_interface.h"

static syscall_t* S;

static size_t maxsyscalls;
static size_t nthreads = 0;

static uint8_t *freeslots;
/* maps index into array of syscall slots S to lthread */
static struct lthread **slotlthreads;
static struct ticketlock slotslock;

struct mpmcq *__syscall_queue;
struct mpmcq *__return_queue;

void arena_new(Arena *a, size_t sz) {
    a->mem = host_syscall_SYS_mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    if (a->mem < 0)
        a_crash();
    a->size = sz;
}

syscall_t *arena_ensure(Arena *a, size_t sz, syscall_t *sc) {
    if (a->size < sz) {
        void *newmem;
        newmem = host_syscall_SYS_mremap(a->mem, a->size, sz, MREMAP_MAYMOVE, 0);
        if (newmem >= 0) {
            a->mem = newmem;
            a->size = sz;
        } else {
            a_crash();
        }
        return getsyscallslot(NULL);
    }
    return sc;
}

void *arena_alloc(Arena *a, size_t sz) {
    if (sz == 0) {
        return NULL;
    }
    void *ret = (void*)(a->mem + a->allocated);
    a->allocated += sz;
    return ret;
}

void arena_free(Arena *a) {
    a->allocated = 0;
}

void arena_destroy(Arena *a) {
    if (a->mem != 0) {
        host_syscall_SYS_munmap(a->mem, a->size);
        a->mem = 0;
        a->size = 0;
    }
}

size_t deepsizeiovec(const struct iovec *dst) {
    return sizeof(*dst) + dst->iov_len;
}

int deepinitiovec(Arena *a, struct iovec *dst, const struct iovec *src) {
    dst->iov_len = src->iov_len;
    dst->iov_base = arena_alloc(a, src->iov_len);
    return 1;
}

void deepcopyiovec(struct iovec *dst, const struct iovec *src) {
    if (dst->iov_len != src->iov_len) {*(int *)NULL = 0;}
    memcpy(dst->iov_base, src->iov_base, src->iov_len);
    dst->iov_len = src->iov_len;
}


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
