/*
 * Lthread
 * Copyright (C) 2012, Hasan Alayli <halayli@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * lthread.h
 */

#ifndef LTHREAD_H
#define LTHREAD_H

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#include "atomic.h"
#include "locale_impl.h"

#include "enclave/mpmc_queue.h"
#include "shared/queue.h"

#define CLOCK_LTHREAD CLOCK_REALTIME

// Configures after how many scheduler cycles futexes are woken up
#define DEFAULT_FUTEX_WAKE_SPINS 1

struct mpmcq __scheduler_queue;

typedef void* (*lthread_func)(void*);

struct cpu_ctx
{
    void* esp;
    void* ebp;
    void* eip;
    void* edi;
    void* esi;
    void* ebx;
    void* r1;
    void* r2;
    void* r3;
    void* r4;
    void* r5;
};

enum lthread_st
{
    LT_ST_NEW,             /* lthread spawned but needs initialization */
    LT_ST_READY,           /* lthread is ready to run */
    LT_ST_EXITED,          /* lthread has exited and needs cleanup */
    LT_ST_BUSY,            /* lthread is waiting on join/cond/compute/io */
    LT_ST_SLEEPING,        /* lthread is sleeping */
    LT_ST_EXPIRED,         /* lthread has expired and needs to run */
    LT_ST_DETACH,          /* lthread frees when done, else it waits to join */
    LT_ST_PINNED,          /* lthread pinned to ethread */
};

enum lthread_type
{
    USERSPACE_THREAD,
    LKL_KERNEL_THREAD
};

struct lthread_tls
{
    pthread_key_t key;
    void* data;
    LIST_ENTRY(lthread_tls) tls_next;
};
LIST_HEAD(lthread_tls_l, lthread_tls);

struct lthread_tls_destructors
{
    pthread_key_t key;
    void (*destructor)(void*);
    LIST_ENTRY(lthread_tls_destructors) tlsdestr_next;
};
LIST_HEAD(lthread_tlsdestr_l, lthread_tls_destructors);

struct lthread_attr
{
    size_t stack_size;  /* current stack_size */
    _Atomic(int) state; /* current lthread state */
    void* stack;        /* ptr to lthread_stack */
    int thread_type;    /* type of thread: usermode or lkl kernel */
};

typedef void (*sig_handler)(int sig, siginfo_t* si, void* unused);

/*
 * a simple struct describing an existing futex. It is not safe to use malloc
 * and/or free while holding the futex ticketlock as both malloc and free
 * perform a futex system call themselves under certain circumstances which will
 * result in a deadlock.
 *
 * We therefore have an fq field in the lthread struct.
 */
struct futex_q
{
    uint32_t futex_key;
    uint64_t futex_deadline;
    struct lthread* futex_lt;

    SLIST_ENTRY(futex_q) entries;
};

struct lthread
{
    struct cpu_ctx ctx;           /* cpu ctx info */
    lthread_func fun;             /* func lthread is running */
    void* arg;                    /* func args passed to func */
    struct lthread_attr attr;     /* various attributes */
    int tid;                      /* lthread id */
    char funcname[64];            /* optional func name */
    struct lthread* lt_join;      /* lthread we want to join on */
    void** lt_exit_ptr;           /* exit ptr for lthread_join */
    uint32_t ops;                 /* num of ops since yield */
    uint64_t sleep_usecs;         /* how long lthread is sleeping */
    struct lthread_tls_l tls;     /* pointer to TLS */
    uint8_t* itls;                /* image TLS */
    size_t itlssz;                /* size of TLS image */
    uintptr_t* tp;                 /* thread pointer */
    int err;                      /* errno value */
    /* yield_cb_* are a callback to call after yield finished and it's arg */
    /* they are required to release futex lock on FUTEX_WAIT operation */
    /* and in sched_yield (see comment there) to avoid race among schedulers */
    void (*yield_cb)(void*);
    void* yield_cbarg;
    struct futex_q fq;
};

struct lthread_queue
{
    struct lthread* lt;
    struct lthread_queue* next;
};

LIST_HEAD(lthread_l, lthread);
TAILQ_HEAD(lthread_q, lthread);

struct lthread_sched
{
    struct cpu_ctx ctx;
    void* stack;
    size_t stack_size;
    uint64_t default_timeout;
    /* convenience data maintained by lthread_resume */
    struct lthread* current_lthread;
};
/**
 * lthread scheduler context. Pointer to this structure can be fetched by
 * calling __scheduler_self(). 
 * The structure is located towards the end of the page pointed by %gs.
 */
struct schedctx {
	struct schedctx *self;
	int tid;
	struct lthread_sched sched;
};

/* Thread Control Block (TCB) for lthreads and lthread scheduler */
struct lthread_tcb_base {
    void *self;
    char _pad_0[32];
    // SGX-LKL does not have full stack smashing protection (SSP) support right
    // now. In particular, we do not generate a random stack guard for every
    // new thread. However, when aplications are compiled with stack protection
    // enabled, GCC makes certain assumptions about the Thread Control Block
    // (TCB) layout. Among other things, it expects a read-only stack
    // guard/canary value at an offset 0x28 (40 bytes) from the FS segment
    // base/start of the TCB (see schedctx struct above).
    uint64_t stack_guard_dummy;
    struct schedctx *schedctx;
};

typedef struct lthread* lthread_t;
#ifdef __cplusplus
extern "C"
{
#endif
    /**
     * Initialisation of ethread/lthread scheduler thread pointer (schedctx).
     */
    void init_ethread_tp();

    void lthread_sched_global_init(
        size_t sleepspins,
        size_t sleeptime_ns);

    /**
     * Create a new thread where the caller manages the initial thread state.
     * The newly created thread is returned via `new_lt`.  The newly created
     * thread will begin executing from `pc`, with its stack pointer set to
     * `sp` and its TLS area set to `tls`.  It is the caller's responsibility
     * to ensure that the stack and TLS area allocated by this thread are
     * cleaned up.
     *
     * The thread is not scheduled by this call and must be explicitly
     * scheduled by the caller.
     */
    int lthread_create_primitive(
        struct lthread** new_lt,
        void* pc,
        void* sp,
        void* tls);

    int lthread_create(
        struct lthread** new_lt,
        struct lthread_attr* attrp,
        void* lthread_func,
        void* arg);

    void lthread_notify_completion(void);

    bool lthread_should_stop(void);

    void lthread_run(void);

    int lthread_join(struct lthread* lt, void** ptr, uint64_t timeout);

    void lthread_detach(void);

    void lthread_detach2(struct lthread* lt);

    void lthread_exit(void* ptr) __attribute__((noreturn));

    /**
     * Yields to the scheduler and puts the current lthread to sleep by
     * marking it as sleeping. The lthread can be added back to the scheduler
     * queue by calling lthread_wakeup afterwards.
     */
    void lthread_yield_and_sleep(void);

    void lthread_wakeup(struct lthread* lt);

    int lthread_init(size_t size);

    struct lthread* lthread_current();

    void lthread_set_funcname(struct lthread* lt, const char* f);

    uint64_t lthread_id();

    struct lthread* lthread_self(void);

    void lthread_set_expired(struct lthread* lt);

    int lthread_key_create(long* k, void (*destructor)(void*));

    int lthread_key_delete(long key);

    /**
     * Access a thread-local variable corresponding to the key given by `key`,
     * in the thread specified by `lt`.  This function is not safe to call
     * while `lt` is running or concurrently with a call to
     * `lthread_setspecific_remote` on the same lthread.  It is the caller's
     * responsibility to ensure that this does not happen, for example after
     * the thread has been removed from the scheduler during tear-down or by
     * explicitly descheduling it.
     */
    void* lthread_getspecific_remote(struct lthread* lt, long key);

    /**
     * Sets a thread-local variable corresponding to the key given by `key` to
     * `value`, in the thread specified by `lt`.  This function is not safe to
     * call while `lt` is running or concurrently with a call to
     * `lthread_setspecific_remote` on the same lthread.  It is the caller's
     * responsibility to ensure that this does not happen.  The most common use
     * for this is between a call to `lthread_create_primitive` and
     * `__scheduler_enqueue`, to initialise a thread-local variable before a
     * thread starts.
     */
    int lthread_setspecific_remote(
        struct lthread* lt,
        long key,
        const void* value);

    static inline void* lthread_getspecific(long key)
    {
        return lthread_getspecific_remote(lthread_current(), key);
    }

    static inline int lthread_setspecific(long key, const void* value)
    {
        return lthread_setspecific_remote(lthread_current(), key, value);
    }

    static inline void __scheduler_enqueue(struct lthread* lt)
    {
#ifndef NDEBUG
        // Abort if we try to schedule an exited lthread.  We cannot rely on
        // our normal assert machinery working if this invariant is violated.
        if (lt->attr.state & (1 << (LT_ST_EXITED)))
            __builtin_trap();
#endif
        if (!lt)
        {
            a_crash();
        }
        for (; !mpmc_enqueue(&__scheduler_queue, lt);)
            a_spin();
    }

    /**
     * Remove a thread from the list blocking on a futex.
     */
    void futex_dequeue(struct lthread* lt);

#ifdef DEBUG
    /**
     * Print stack traces for all lthreads that currently exist.
     *
     * This outputs the stack frames of all lthreads based on the frame
     * pointers saved by the lthread scheduler. It shows the stack traces
     * at the time of the last context switch.
     *
     * The argument is_lthread should be set to true if the function is
     * called from an lthread (and not a regular pthread, e.g. after an
     * ecall).
     *
     * For the current lthread (marked with a '*'), it prints the active
     * stack frames (if called from an lthread).
     */
    void lthread_dump_all_threads(bool is_lthread);
#endif

#ifdef __cplusplus
}
#endif

#endif
