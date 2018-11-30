/*
 * Lthread
 * Copyright (C) 2012, Hasan Alayli <halayli@gmail.com>
 * Copyright (C) 2016, 2017, 2018 Imperial College London
 * Copyright (C) 2016, 2017 TU Dresden
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
 */

#define WANT_REAL_ARCH_SYSCALLS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <limits.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <stddef.h>

#include <lthread.h>
#include "libc.h"
#include "lthread_int.h"
#include "pthread_impl.h"
#include "sgxlkl_debug.h"
#include "stdio_impl.h"
#include "hostcall_interface.h"
#include "ticketlock.h"
#include "tree.h"
#include "enclave_config.h"

extern int errno;

int __copy_utls(struct lthread *, uint8_t *, size_t);
static void _exec(void *lt);
static inline void _lthread_madvise(struct lthread *lt);
static void _lthread_init(struct lthread *lt);
static void _lthread_resume_expired(struct timespec *ts);
static void _lthread_lock(struct lthread *lt);
static void lthread_rundestructors(struct lthread *lt);

static void dummy_0(){}
weak_alias(dummy_0, __do_orphaned_stdio_locks);

static inline int _lthread_sleep_cmp(struct lthread *l1, struct lthread *l2);

static inline int
_lthread_sleep_cmp(struct lthread *l1, struct lthread *l2) {
    if (l1->sleep_usecs < l2->sleep_usecs)
        return (-1);
    if (l1->sleep_usecs == l2->sleep_usecs)
        return (0);
    return (1);
}

RB_GENERATE(lthread_rb_sleep, lthread, sleep_node, _lthread_sleep_cmp);

static int spawned_lthreads = 1;

static struct ticketlock sleeplock;
int _lthread_sleeprb_inited = 0;
struct lthread_rb_sleep _lthread_sleeping;

static size_t nsleepers = 0;

static size_t sleepspins = 500000000;
static size_t sleeptime_ns = 1600;
static size_t futex_wake_spins = 500;
static volatile int schedqueuelen = 0;

#if DEBUG
int thread_count = 1;
struct lthread_queue *__active_lthreads = NULL;
struct lthread_queue *__active_lthreads_tail = NULL;
#endif

int _switch(struct cpu_ctx *new_ctx, struct cpu_ctx *cur_ctx);
#ifdef __i386__
__asm__ (
"    .text                                  \n"
"    .p2align 2,,3                          \n"
".globl _switch                             \n"
"_switch:                                   \n"
"__switch:                                  \n"
"movl 8(%esp), %edx      # fs->%edx         \n"
"movl %esp, 0(%edx)      # save esp         \n"
"movl %ebp, 4(%edx)      # save ebp         \n"
"movl (%esp), %eax       # save eip         \n"
"movl %eax, 8(%edx)                         \n"
"movl %ebx, 12(%edx)     # save ebx,esi,edi \n"
"movl %esi, 16(%edx)                        \n"
"movl %edi, 20(%edx)                        \n"
"movl 4(%esp), %edx      # ts->%edx         \n"
"movl 20(%edx), %edi     # restore ebx,esi,edi      \n"
"movl 16(%edx), %esi                                \n"
"movl 12(%edx), %ebx                                \n"
"movl 0(%edx), %esp      # restore esp              \n"
"movl 4(%edx), %ebp      # restore ebp              \n"
"movl 8(%edx), %eax      # restore eip              \n"
"movl %eax, (%esp)                                  \n"
"ret                                                \n"
);
#elif defined(__x86_64__)

__asm__ (
"    .text                                  \n"
"       .p2align 4,,15                                   \n"
".globl _switch                                          \n"
".globl __switch                                         \n"
"_switch:                                                \n"
"__switch:                                               \n"
"       movq %rsp, 0(%rsi)      # save stack_pointer     \n"
"       movq %rbp, 8(%rsi)      # save frame_pointer     \n"
"       movq (%rsp), %rax       # save insn_pointer      \n"
"       movq %rax, 16(%rsi)                              \n"
"       movq %rbx, 24(%rsi)     # save rbx,r12-r15       \n"
"       movq %r12, 32(%rsi)                              \n"
"       movq %r13, 40(%rsi)                              \n"
"       movq %r14, 48(%rsi)                              \n"
"       movq %r15, 56(%rsi)                              \n"
"       movq 56(%rdi), %r15                              \n"
"       movq 48(%rdi), %r14                              \n"
"       movq 40(%rdi), %r13     # restore rbx,r12-r15    \n"
"       movq 32(%rdi), %r12                              \n"
"       movq 24(%rdi), %rbx                              \n"
"       movq 8(%rdi), %rbp      # restore frame_pointer  \n"
"       movq 0(%rdi), %rsp      # restore stack_pointer  \n"
"       movq 16(%rdi), %rax     # restore insn_pointer   \n"
"       movq %rax, (%rsp)                                \n"
"       ret                                              \n"
);
#endif

static void _exec(void *lt_) {

#if defined(__llvm__) && defined(__x86_64__)
    __asm__ ("movq 16(%%rbp), %[lt_]" : [lt_] "=r" (lt_));
#endif
    void *ret;
    struct lthread *lt = lt_;
    ret = lt->fun(lt->arg);
    _lthread_lock(lt);
    lt->yield_cbarg = ret;
    lt->attr.state |= BIT(LT_ST_EXITED);
    _lthread_yield(lt);
}

static long lthread_scall(long n, long a1, long a2, long a3) {
    unsigned long ret;
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = 0;
    register long r9 __asm__("r9") = 0;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(0), "r"(r10), "r"(r8), "r"(r9)
                          : "rcx", "r11", "memory");
    return ret;
}

void __schedqueue_inc() {
    a_inc(&schedqueuelen);
}

void lthread_sched_global_init(size_t sleepspins_, size_t sleeptime_ns_, size_t futex_wake_spins_) {
        sleepspins = sleepspins_;
        sleeptime_ns = sleeptime_ns_;
        futex_wake_spins = futex_wake_spins_;
        RB_INIT(&_lthread_sleeping);
}

void lthread_run(void) {
    const struct lthread_sched *const sched = lthread_get_sched();
    struct lthread *lt = NULL;
    size_t s, pauses = sleepspins;
    struct timespec sleeptime = {0, sleeptime_ns};
    int spins = futex_wake_spins;
    int dequeued;
    size_t i;
    struct mpmcq *retq = __return_queue;
    /* scheduler not initiliazed, and no lthreads where created */
    if (sched == NULL) {
        return;
    }
    for (;;) {
        /* start by checking if a sleeping thread needs to wakeup */
        do {
            dequeued = 0;
            if (mpmc_dequeue(retq, (void *)&s)) {
                dequeued++;
                lt = slottolthread(s);
                pauses = sleepspins;
                SGXLKL_TRACE_THREAD("[tid=%-3d] lthread_run() lthread_resume (wakeup sleeping thread) \n", lt->tid);
                _lthread_resume(lt);
            }
            if (mpmc_dequeue(&__scheduler_queue, (void **)&lt)) {
                dequeued++;
                pauses = sleepspins;
                a_dec(&schedqueuelen);
                SGXLKL_TRACE_THREAD("[tid=%-3d] lthread_run() lthread_resume (dequeue sched queue) \n", lt->tid);
                _lthread_resume(lt);
            }
        } while (dequeued);

        spins--;
        if (spins <= 0) {
            futex_tick();
            spins = futex_wake_spins;
        }

        pauses--;
        if (pauses == 0) {
            pauses = sleepspins;
            spins = 0;
#ifndef SGXLKL_HW
            lthread_scall(SYS_nanosleep, (long)&sleeptime, (long)NULL, 0L);
#else
            leave_enclave(SGXLKL_EXIT_SLEEP, sleeptime_ns);
#endif
        }
    }
}

/*
 * Removes lthread from sleeping rbtree.
 * This can be called multiple times on the same lthread regardless if it was
 * sleeping or not.
 */
void _lthread_desched_sleep(struct lthread *lt) {
    ticket_lock(&sleeplock);
    SGXLKL_TRACE_THREAD("[tid=%-3d] _lthread_desched_sleep() TICKET_LOCK lock=SLEEPLOCK tid=%d \n", (lthread_self() ? lthread_self()->tid : 0), lt->tid);
    if (lt->attr.state & BIT(LT_ST_SLEEPING)) {
        RB_REMOVE(lthread_rb_sleep, &_lthread_sleeping, lt);
        lt->attr.state &= CLEARBIT(LT_ST_SLEEPING);
        lt->attr.state |= BIT(LT_ST_READY);
        lt->attr.state &= CLEARBIT(LT_ST_EXPIRED);
        nsleepers--;
    }

   ticket_unlock(&sleeplock);

   SGXLKL_TRACE_THREAD("[tid=%-3d] _lthread_desched_sleep() TICKET_UNLOCK lock=SLEEPLOCK tid=%d\n", (lthread_self() ? lthread_self()->tid : 0), lt->tid);
}

/*
 * Resumes expired lthread and cancels its events whether it was waiting
 * on one or not, and deschedules it from sleeping rbtree in case it was
 * sleeping.
 */
static void _lthread_resume_expired(struct timespec *now) {
    struct lthread *lt = NULL;
    uint64_t curr_usec = 0;

    if (nsleepers == 0) {
        return;
    }

    ticket_lock(&sleeplock);

    SGXLKL_TRACE_THREAD("[tid=%-3d] _lthread_resume_expired() TICKET_LOCK lock=SLEEPLOCK tid=NULL\n", (lthread_self() ? lthread_self()->tid : 0));

    curr_usec = _lthread_timespec_to_usec(now);
    while ((lt = RB_MIN(lthread_rb_sleep, &_lthread_sleeping)) != NULL) {

        if (lt->sleep_usecs <= curr_usec) {
            _lthread_desched_sleep(lt);
            lthread_set_expired(lt);

            /* don't clear expired if lthread exited/cancelled */
            if (_lthread_resume(lt) != -1)
                lt->attr.state &= CLEARBIT(LT_ST_EXPIRED);

            continue;
        }
        break;
    }
    ticket_unlock(&sleeplock);

    SGXLKL_TRACE_THREAD("[tid=%-3d] _lthread_resume_expired() TICKET_UNLOCK lock=SLEEPLOCK tid=NULL\n", (lthread_self() ? lthread_self()->tid : 0));
}

static void _lthread_lock(struct lthread *lt) {
    int state, newstate;
    for (;;) {
        state = __atomic_load_n(&lt->attr.state, __ATOMIC_SEQ_CST);
        if (state & BIT(LT_ST_BUSY)) continue;
        newstate = state|BIT(LT_ST_BUSY);
        if (a_cas(&lt->attr.state, state, newstate) != state) continue;
        break;
    }
}

static void _lthread_unlock(struct lthread *lt) {
    a_barrier();
    lt->attr.state &= CLEARBIT(LT_ST_BUSY);
}

void _lthread_yield_cb(struct lthread *lt, void (*f)(void*), void *arg) {
    struct lthread_sched *sched = lthread_get_sched();
    lt->yield_cb = f;
    lt->yield_cbarg = arg;
    _switch(&sched->ctx, &lt->ctx);
}

void _lthread_yield(struct lthread *lt) {
    struct lthread_sched *sched = lthread_get_sched();
    _switch(&sched->ctx, &lt->ctx);
}

void _lthread_free(struct lthread *lt) {
    volatile void *volatile *rp;
    while (lt->cancelbuf) {
        void (*f)(void *) = lt->cancelbuf->__f;
        void *x = lt->cancelbuf->__x;
        lt->cancelbuf = lt->cancelbuf->__next;
        f(x);
    }
    if(lthread_self() != NULL)
        lthread_rundestructors(lt);
    if (lt->itls != 0) {
        munmap(lt->itls, lt->itlssz);
    }
    while ((rp=lt->robust_list.head) && rp != &lt->robust_list.head) {
        pthread_mutex_t *m = (void *)((char *)rp
                       - offsetof(pthread_mutex_t, _m_next));
        int waiters = m->_m_waiters;
        int priv = (m->_m_type & 128) ^ 128;
        lt->robust_list.pending = rp;
        lt->robust_list.head = *rp;
        int cont = a_swap(&m->_m_lock, lt->tid|0x40000000);
        lt->robust_list.pending = 0;
        if (cont < 0 || waiters)
            __wake(&m->_m_lock, 1, priv);
    }
    __do_orphaned_stdio_locks(lt);
    if (lt->attr.stack) {
        munmap(lt->attr.stack, lt->attr.stack_size);
        lt->attr.stack = NULL;
    }
    freeslot(lt->syscall);
    memset(lt, 0, sizeof(*lt));
    if (a_fetch_add(&libc.threads_minus_1, -1) == 0) {
        libc.threads_minus_1 = 0;
    }

#if DEBUG
    if (__active_lthreads != NULL && __active_lthreads->lt == lt) {
        if (__active_lthreads_tail == __active_lthreads) {
            __active_lthreads_tail == NULL;
        }
        struct lthread_queue *new_head = __active_lthreads->next;
        free (__active_lthreads);
        __active_lthreads = new_head;
    } else {
        struct lthread_queue *ltq = __active_lthreads;
        while (ltq != NULL) {
            if (ltq->next != NULL && ltq->next->lt == lt) {
                if (ltq->next == __active_lthreads_tail) {
                    __active_lthreads_tail = ltq;
                }
                struct lthread_queue *next_ltq = ltq->next->next;
                free(ltq->next);
                ltq->next = next_ltq;
                break;
            }
            ltq = ltq->next;
        }
    }
#endif /* DEBUG */

    free(lt);
    lt = 0;
}

void set_tls_tp(struct lthread *lt) {
    if (!libc.user_tls_enabled || !lt->itls)
        return;

    struct schedctx **sp = (struct schedctx **) (lt->itls + lt->itlssz - sizeof(struct lthread_tcb_base));
    *sp = __scheduler_self();
#ifdef SGXLKL_HW
    __asm__ volatile ( "wrfsbase %0" :: "r" (sp) );
#else
    int r = __set_thread_area(TP_ADJ(sp));
    if(r < 0) {
        fprintf(stderr, "[SGX-LKL] Error: Could not set thread area %p: %s\n", sp, strerror(errno));
    }
#endif
}

void reset_tls_tp(struct lthread *lt) {
    if (!libc.user_tls_enabled)
        return;

    struct schedctx *sp = __scheduler_self();
#ifdef SGXLKL_HW
    char *tp = (char *)__scheduler_self() - sizeof(enclave_parms_t) - sizeof(struct sched_tcb_base);
    __asm__ volatile ( "wrfsbase %0" :: "r" (tp) );
#else
    int r = __set_thread_area(TP_ADJ(sp));
    if(r < 0) {
        fprintf(stderr, "[SGX-LKL] Error: Could not set thread area %p: %s\n", sp, strerror(errno));
    }
#endif
}

int _lthread_resume(struct lthread *lt) {
    struct lthread_sched *sched = lthread_get_sched();
    if (lt->attr.state & BIT(LT_ST_CANCELLED)) {
        /* if an lthread was joining on it, schedule it to run */
        if (lt->lt_join) {
            __scheduler_enqueue(lt->lt_join);
            lt->lt_join = NULL;
        }
        /* if lthread is detached, then we can free it up */
        if (lt->attr.state & BIT(LT_ST_DETACH)) {
            _lthread_free(lt);
        }
        return (-1);
    }

    if (lt->attr.state & BIT(LT_ST_NEW))
        _lthread_init(lt);

    /* clear yield callback */
    lt->yield_cb = 0;
    lt->yield_cbarg = 0;

    sched->current_lthread = lt;
    sched->current_syscallslot = lt->syscall;
    sched->current_arena = &lt->syscallarena;

    set_tls_tp(lt);
    _switch(&lt->ctx, &sched->ctx);
    sched->current_arena = &sched->arena;
    sched->current_syscallslot = sched->syscall;
    sched->current_lthread = NULL;
    reset_tls_tp(lt);
    _lthread_madvise(lt);
    if (lt->attr.state & BIT(LT_ST_EXITED)) {
        /* lt is always locked before LT_ST_EXITED is set */
        arena_destroy(&lt->syscallarena);
        if (lt->lt_join) {
            __scheduler_enqueue(lt->lt_join);
            lt->lt_join = NULL;
        }
        _lthread_unlock(lt);
        /* code below is only for detached threads, so it's safe to unlock here */
        /* if lthread is detached, free it, otherwise lthread_join() will */
        if (lt->attr.state & BIT(LT_ST_DETACH)) {
            _lthread_free(lt);
        }
        sched->current_lthread = NULL;
        return (-1);
    }
    if (lt->yield_cb) {
        lt->yield_cb(lt->yield_cbarg);
    }

    return (0);
}

static inline void _lthread_madvise(struct lthread *lt) {
    size_t current_stack = ((uintptr_t)lt->attr.stack + lt->attr.stack_size) - (uintptr_t)lt->ctx.esp;
    /* make sure function did not overflow stack, we can't recover from that */
    assert(current_stack <= lt->attr.stack_size);
    lt->attr.last_stack_size = current_stack;
}

int lthread_init(size_t size) {
    return (_lthread_sched_init(size));
}

static void _lthread_init(struct lthread *lt) {
    void **stack = NULL;
    _lthread_lock(lt);
    stack = (void **)((uintptr_t)lt->attr.stack + (lt->attr.stack_size));

    stack[-3] = NULL;
    stack[-2] = (void *)lt;
    lt->ctx.esp = (void *)((uintptr_t)stack - (4 * sizeof(void *)));
    lt->ctx.ebp = (void *)((uintptr_t)stack - (3 * sizeof(void *)));
    lt->ctx.eip = (void *)_exec;
    /* this is equivalent to unlock */
    a_barrier();
    if (lt->attr.state & BIT(LT_ST_DETACH)) {
            lt->attr.state = BIT(LT_ST_READY)|BIT(LT_ST_DETACH);
    } else {
            lt->attr.state = BIT(LT_ST_READY);
    }
}

int _lthread_sched_init(size_t stack_size) {
    size_t sched_stack_size = 0;

    sched_stack_size = stack_size ? stack_size : MAX_STACK_SIZE;

    struct schedctx *c = __scheduler_self();

    c->sched.syscall = allocslot(NULL);
    c->sched.current_syscallslot = c->sched.syscall;

    arena_new(&c->sched.arena, 4096);
    c->sched.current_arena = &c->sched.arena;

    c->sched.stack_size = sched_stack_size;
    c->sched.page_size = sysconf(_SC_PAGESIZE);

    c->sched.default_timeout = 3000000u;

    memset(&c->sched.ctx, 0, sizeof(struct cpu_ctx));

    return (0);
}

static FILE *volatile dummy_file = 0;
weak_alias(dummy_file, __stdin_used);
weak_alias(dummy_file, __stdout_used);
weak_alias(dummy_file, __stderr_used);
static void init_file_lock(FILE *f) {
    if (f && f->lock<0) f->lock = 0;
}

int lthread_create(struct lthread **new_lt, struct lthread_attr *attrp, void *fun, void *arg) {
    struct lthread *lt = NULL;
    size_t stack_size;
    struct lthread_sched *sched = lthread_get_sched();

    if (!libc.threaded && libc.threads_minus_1 >= 0) {
        for (FILE *f=*__ofl_lock(); f; f=f->next)
            init_file_lock(f);
        __ofl_unlock();
        init_file_lock(__stdin_used);
        init_file_lock(__stdout_used);
        init_file_lock(__stderr_used);
        libc.threaded = 1;
    }

    stack_size = attrp && attrp->stack_size ? attrp->stack_size : sched->stack_size;
    if ((lt = calloc(1, sizeof(struct lthread))) == NULL) {
        return (errno);
    }
    lt->attr.stack = attrp ? attrp->stack : 0;
    if ((!lt->attr.stack)&&((lt->attr.stack = mmap(0, stack_size, PROT_READ|PROT_WRITE,
                                                  MAP_ANONYMOUS|MAP_PRIVATE,
                                                   -1, 0)) == MAP_FAILED)) {
        free(lt);
        return (errno);
    }
    lt->attr.stack_size = stack_size;

    /* mmap tls image */
    lt->itlssz = libc.tls_size;
    if (libc.tls_size) {
        if ((lt->itls = (uint8_t *) mmap(0, lt->itlssz, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
            free(lt);
            return errno;
        }
        if (!__copy_utls(lt, lt->itls, lt->itlssz)) {
            munmap(lt->attr.stack, stack_size);
            free(lt);
            return errno;
        }
    }

    lt->attr.state = BIT(LT_ST_NEW) | (attrp ? attrp->state : 0);
    lt->tid = a_fetch_add(&spawned_lthreads, 1);
    lt->fun = fun;
    lt->arg = arg;
    arena_new(&lt->syscallarena, 4096);
    lt->locale = &libc.global_locale;
    LIST_INIT(&lt->tls);
    lt->syscall = allocslot(lt);
    lt->robust_list.head = &lt->robust_list.head;

    // Inherit name from parent
    if (lthread_self() && lthread_self()->funcname) {
        lthread_set_funcname(lt, lthread_self()->funcname);
    }

    if (new_lt) {
        *new_lt = lt;
    }

    a_inc(&libc.threads_minus_1);

    SGXLKL_TRACE_THREAD("[tid=%-3d] create: thread_count=%d\n", lt->tid, thread_count);

#if DEBUG
    struct lthread_queue *new_ltq = (struct lthread_queue*) malloc(sizeof(struct lthread_queue));
    new_ltq->lt = lt;
    new_ltq->next = NULL;
    if (__active_lthreads_tail) {
        __active_lthreads_tail->next = new_ltq;
    } else {
        __active_lthreads = new_ltq;
    }
    __active_lthreads_tail = new_ltq;
#endif /* DEBUG */

    __scheduler_enqueue(lt);
    return 0;
}

struct lthread* lthread_current(void) {
    return (lthread_get_sched()->current_lthread);
}

void lthread_cancel(struct lthread *lt) {
    if (lt == NULL)
        return;

    if (lt->attr.state & BIT(LT_ST_CANCELSTATE)) {
        return;
    }
    lt->attr.state |= BIT(LT_ST_CANCELLED);
    _lthread_desched_sleep(lt);
    __scheduler_enqueue(lt);
}

void lthread_wakeup(struct lthread *lt) {
    if (lt->attr.state & BIT(LT_ST_SLEEPING)) {
        _lthread_desched_sleep(lt);
        __scheduler_enqueue(lt);
    }
}

void lthread_exit(void *ptr) {

    struct lthread *lt = lthread_get_sched()->current_lthread;
    /* switch thread to exiting state */
    _lthread_lock(lt);

    SGXLKL_TRACE_THREAD("[tid=%-3d] thread_exit: thread_count=%d\n", lt->tid, thread_count);

    lt->yield_cbarg = ptr;
    lt->attr.state |= BIT(LT_ST_EXITED);
    _lthread_yield(lt);
}

/* lthread_join may proceed only when:
   1. the thread is still running and not exiting;
   2. the thread has exited and is no longer seen by scheduler.
   The period between 1. and 2. is protected by taking a lock. */
int lthread_join(struct lthread *lt, void **ptr, uint64_t timeout) {

    int ret = 0;
    struct lthread *current = lthread_get_sched()->current_lthread;
    if (lt->attr.state & BIT(LT_ST_DETACH)) {
        return EINVAL;
    }
    _lthread_lock(lt);
    if (lt->attr.state & BIT(LT_ST_EXITED)) {
        SGXLKL_TRACE_THREAD("[tid=%-3d] join:  tid=%d count=%d\n", (lthread_self() ? lthread_self()->tid : 0), lt->tid, thread_count);

        /* we can test for exited flag only with lock acquired */
        _lthread_unlock(lt);
    } else {

        SGXLKL_TRACE_THREAD("[tid=%-3d] join:  tid=%d count=%d\n", (lthread_self() ? lthread_self()->tid : 0), lt->tid, thread_count);

        /* thread is still running, set current lthread as joiner */
        if (a_cas_p(&lt->lt_join, 0, current) != 0) {
            /* there already is a joiner */
            _lthread_unlock(lt);
            return EINVAL;
        }
        _lthread_yield_cb(current, (void *)_lthread_unlock, lt);
    }
    if (ptr) {
        *ptr = lt->yield_cbarg;
    }
    _lthread_free(lt);
    return ret;
}

void lthread_detach(void) {
    struct lthread *current = lthread_get_sched()->current_lthread;
    current->attr.state |= BIT(LT_ST_DETACH);
}

void lthread_detach2(struct lthread *lt) {
    lt->attr.state |= BIT(LT_ST_DETACH);
}

void lthread_set_funcname(struct lthread *lt, const char *f) {
    strncpy(lt->funcname, f, 64);
    lt->funcname[64-1] = 0;
}

uint64_t lthread_id(void) {
    struct lthread_sched *sched = lthread_get_sched();
    if (sched->current_lthread) {
        return sched->current_lthread->tid;
    }
    return ~0UL;
}

struct lthread* lthread_self(void) {
    struct lthread_sched *sched = lthread_get_sched();
    if (sched) {
        return sched->current_lthread;
    } else {
        return NULL;
    }
}

/*
 * convenience function for performance measurement.
 */
void lthread_print_timestamp(char *msg) {
    struct timeval t1 = {0, 0};
    gettimeofday(&t1, NULL);
    printf("lt timestamp: sec: %ld usec: %ld (%s)\n", t1.tv_sec, (long) t1.tv_usec, msg);
}

int lthread_setcancelstate(int new, int *old) {
    if (new > 2U) return EINVAL;
    struct lthread *curr = lthread_get_sched()->current_lthread;
    if (old) {
        *old = (curr->attr.state & BIT(LT_ST_CANCELSTATE)) > 0;
    }
    if (new) {
        curr->attr.state |= BIT(LT_ST_CANCELSTATE);
    } else {
        curr->attr.state &= ~BIT(LT_ST_CANCELSTATE);
    }
    return 0;
}

static struct lthread_tls *lthread_findtlsslot(pthread_key_t key) {
    struct lthread_tls *d, *d_tmp;
    struct lthread *lt = lthread_current();
    LIST_FOREACH_SAFE (d, &lt->tls, tls_next, d_tmp) {
        if (d->key == key) {
            return d;
        }
    }
    return NULL;
}

static int lthread_addtlsslot(pthread_key_t key, void *data) {
    struct lthread_tls *d;
    struct lthread *lt = lthread_current();
    d = calloc(1, sizeof(struct lthread_tls));
    if (d == NULL) {
        return ENOMEM;
    }
    d->key = key;
    d->data = data;
    LIST_INSERT_HEAD(&lt->tls, d, tls_next);
    return 0;
}

void *lthread_getspecific(pthread_key_t key) {
    struct lthread_tls *d;
    if ((d = lthread_findtlsslot(key)) == NULL) {
        return NULL;
    }
    return d->data;
}

int lthread_setspecific(pthread_key_t key, const void *value) {
    struct lthread_tls *d;
    if ((d = lthread_findtlsslot(key)) != NULL) {
        d->data = (void *)value;
        return 0;
    } else {
        return lthread_addtlsslot(key, (void *)value);
    }
}

static struct lthread_tlsdestr_l lthread_destructors;
typedef void (*lthread_destructor_func)(void*);

static unsigned global_count = 0;

int lthread_key_create(pthread_key_t *k, void (*destructor)(void*)) {
    struct lthread_tls_destructors *d;
    d = calloc(1, sizeof(struct lthread_tls_destructors));
    if (d == NULL) {
        return ENOMEM;
    }
    d->key = a_fetch_add((void *)&global_count, 1);
    d->destructor = destructor;
    LIST_INSERT_HEAD(&lthread_destructors, d, tlsdestr_next);
    *k = d->key;
    return 0;
}

int lthread_key_delete(pthread_key_t key) {
    struct lthread_tls_destructors *d, *d_tmp;
    LIST_FOREACH_SAFE (d, &lthread_destructors, tlsdestr_next, d_tmp) {
        if (d->key == key) {
            LIST_REMOVE(d, tlsdestr_next);
            free(d);
            return 0;
        }
    }
    return -1;
}

static lthread_destructor_func lthread_finddestr(pthread_key_t key) {
    struct lthread_tls_destructors *d, *d_tmp;
    LIST_FOREACH_SAFE (d, &lthread_destructors, tlsdestr_next, d_tmp) {
        if (d->key == key) {
            return d->destructor;
        }
    }
    return NULL;
}

static void lthread_rundestructors(struct lthread *lt) {
    struct lthread_tls *d, *d_tmp;
    lthread_destructor_func destr;
    LIST_FOREACH_SAFE (d, &lt->tls, tls_next, d_tmp) {
        if (d->data) {
                destr = lthread_finddestr(d->key);
                if (destr) {
                    destr(d->data);
                }
        }
        LIST_REMOVE(d, tls_next);
        free(d);
    }
}

void lthread_set_expired(struct lthread *lt) {
    lt->attr.state |= BIT(LT_ST_EXPIRED);
}

