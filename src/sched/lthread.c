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

#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "pthread_impl.h"
#include "stdio_impl.h"

#include <enclave/enclave_mem.h>
#include <enclave/enclave_oe.h>
#include <enclave/enclave_util.h>
#include <enclave/lthread.h>
#include "enclave/lthread_int.h"
#include "enclave/sgxlkl_t.h"
#include "enclave/ticketlock.h"
#include "openenclave/corelibc/oemalloc.h"

#include "openenclave/corelibc/oemalloc.h"
#include "openenclave/corelibc/oestring.h"
#include "openenclave/internal/safecrt.h"

extern int vio_enclave_wakeup_event_channel(void);

int __init_utp(void*, int);
void* __copy_utls(struct lthread*, uint8_t*, size_t);
static void _exec(void* lt);
static void _lthread_init(struct lthread* lt);
static void _lthread_lock(struct lthread* lt);
static void lthread_rundestructors(struct lthread* lt);

#define TLS_ALIGN 16

static int spawned_ethreads = 1;

void init_ethread_tp()
{
	struct schedctx *td = __scheduler_self();
	td->self = td;
	// Prevent collisions with lthread TIDs which are assigned to newly spawned
	// lthreads incrementally, starting from one.
	td->tid = INT_MAX - a_fetch_add(&spawned_ethreads, 1);
}

static inline int _lthread_sleep_cmp(struct lthread* l1, struct lthread* l2);

static inline int _lthread_sleep_cmp(struct lthread* l1, struct lthread* l2)
{
    if (l1->sleep_usecs < l2->sleep_usecs)
        return (-1);
    if (l1->sleep_usecs == l2->sleep_usecs)
        return (0);
    return (1);
}

static int spawned_lthreads = 1;
static _Atomic(bool) _lthread_should_stop = false;

static size_t sleepspins = 500000000;
static size_t sleeptime_ns = 1600;
static size_t futex_wake_spins = 500;
static volatile int schedqueuelen = 0;

int thread_count = 1;

#if DEBUG
struct lthread_queue* __active_lthreads = NULL;
struct lthread_queue* __active_lthreads_tail = NULL;
#endif

int _switch(struct cpu_ctx* new_ctx, struct cpu_ctx* cur_ctx);
#ifdef __i386__
__asm__("    .text                                  \n"
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
        "ret                                                \n");
#elif defined(__x86_64__)

__asm__("    .text                                  \n"
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
        "       movq 16(%rdi), %rdx     # restore insn_pointer   \n"
        "       xor  %rax, %rax         # Clear return register 1\n"
        "       movq %rdx, (%rsp)                                \n"
        "       ret                                              \n");
#endif

static inline struct lthread* lthread_alloc()
{
#ifdef LTHREAD_UAF_CHECKS
    return paranoid_alloc(sizeof(struct lthread));
#else
    return oe_calloc(sizeof(struct lthread), 1);
#endif
}

static inline void lthread_dealloc(struct lthread* lt)
{
#ifdef LTHREAD_UAF_CHECKS
    return paranoid_dealloc(lt, sizeof(struct lthread));
#else
    return oe_free(lt);
#endif
}

static void _exec(void* lt_)
{
#if defined(__llvm__) && defined(__x86_64__)
    __asm__("movq 16(%%rbp), %[lt_]" : [lt_] "=r"(lt_));
#endif
    void* ret;
    struct lthread* lt = lt_;
    ret = lt->fun(lt->arg);
    _lthread_lock(lt);
    lt->yield_cbarg = ret;
    lt->attr.state |= BIT(LT_ST_EXITED);
    _lthread_yield(lt);
}

void __schedqueue_inc()
{
    a_inc(&schedqueuelen);
}

void lthread_sched_global_init(size_t sleepspins_, size_t sleeptime_ns_)
{
    sleepspins = sleepspins_;
    sleeptime_ns = sleeptime_ns_;
    futex_wake_spins = DEFAULT_FUTEX_WAKE_SPINS;
}

void lthread_notify_completion(void)
{
    SGXLKL_TRACE_THREAD(
        "[%4d] lthread_notify_completion\n", lthread_self()->tid);
    _lthread_should_stop = true;
}

/*
 * Returns whether thread should stop. This function is called by enclave task
 * to check whether a shutdown has been triggered to do a graceful exit.
 */
bool lthread_should_stop(void)
{
    return _lthread_should_stop;
}

void lthread_run(void)
{
    const struct lthread_sched* const sched = lthread_get_sched();
    struct lthread* lt = NULL;
    size_t pauses = sleepspins;
    int spins = futex_wake_spins;
    int dequeued;

    /* scheduler not initiliazed, and no lthreads where created */
    if (sched == NULL)
    {
        return;
    }

    for (;;)
    {
        /* start by checking if a sleeping thread needs to wakeup */
        do
        {
            dequeued = 0;
            if (mpmc_dequeue(&__scheduler_queue, (void**)&lt))
            {
                dequeued++;
                pauses = sleepspins;
                a_dec(&schedqueuelen);
                SGXLKL_TRACE_THREAD(
                    "[%4d] lthread_run(): lthread_resume (dequeue)\n",
                    lt ? lt->tid : -1);
                _lthread_resume(lt);
            }

            if (vio_enclave_wakeup_event_channel())
            {
                dequeued++;
                pauses = sleepspins;
            }

            spins--;
            if (spins <= 0)
            {
                /* Do not handle futexes when enclave is terminating */
                if (_lthread_should_stop)
                {
                    break;
                }

                futex_tick();
                spins = futex_wake_spins;
            }
        } while (dequeued);

        pauses--;
        if (pauses == 0)
        {
            pauses = sleepspins;
            spins = 0;
            /* sleep outside the enclave */
            sgxlkl_host_idle_ethread(sleeptime_ns);
        }

        /* Break out of scheduler loop when enclave is terminating */
        if (_lthread_should_stop)
        {
            SGXLKL_TRACE_THREAD(
                "[%4d] lthread_run(): quitting\n", lt ? lt->tid : -1);
            break;
        }
    }
}

/*
 * Changes lthread state from sleeping to ready.
 * This can be called multiple times on the same lthread regardless if it was
 * sleeping or not.
 */
void _lthread_desched_sleep(struct lthread* lt)
{
    SGXLKL_TRACE_THREAD(
        "[%4d] _lthread_desched_sleep() TICKET_LOCK lock=SLEEPLOCK tid=%d "
        "\n",
        (lthread_self() ? lthread_self()->tid : 0),
        lt->tid);
    if (lt->attr.state & BIT(LT_ST_SLEEPING))
    {
        lt->attr.state &= CLEARBIT(LT_ST_SLEEPING);
        lt->attr.state &= CLEARBIT(LT_ST_EXPIRED);
        lt->attr.state |= BIT(LT_ST_READY);
    }

    SGXLKL_TRACE_THREAD(
        "[%4d] _lthread_desched_sleep() TICKET_UNLOCK lock=SLEEPLOCK "
        "tid=%d\n",
        (lthread_self() ? lthread_self()->tid : 0),
        lt->tid);
}

static void _lthread_lock(struct lthread* lt)
{
    int state, newstate;
    for (;;)
    {
        state = lt->attr.state;
        if (state & BIT(LT_ST_BUSY))
            continue;
        newstate = state | BIT(LT_ST_BUSY);
        if (!atomic_compare_exchange_strong(&lt->attr.state, &state, newstate))
            continue;
        break;
    }
}

static void _lthread_unlock(struct lthread* lt)
{
    a_barrier();

    // We should never unlock an lthread that is not locked.
    SGXLKL_ASSERT(lt->attr.state & BIT(LT_ST_BUSY));

    lt->attr.state &= CLEARBIT(LT_ST_BUSY);
}

void _lthread_yield_cb(struct lthread* lt, void (*f)(void*), void* arg)
{
    struct lthread_sched* sched = lthread_get_sched();
    lt->yield_cb = f;
    lt->yield_cbarg = arg;
    _switch(&sched->ctx, &lt->ctx);
}

void _lthread_yield(struct lthread* lt)
{
    struct lthread_sched* sched = lthread_get_sched();
    _switch(&sched->ctx, &lt->ctx);
}

void _lthread_free(struct lthread* lt)
{
    volatile void* volatile* rp;
    if (lthread_self() != NULL)
        lthread_rundestructors(lt);
    /**
     * lthreads doesn't know about either the tls region or stacks of threads
     * created by lthread_create_primitive, and therefore we should not attempt
     * to unmap them.
     */
    if (lt->attr.stack_size > 0) {
        if (lt->itls != 0)
        {
            enclave_munmap(lt->itls, lt->itlssz);
        }

        if (lt->attr.stack)
        {
            enclave_munmap(lt->attr.stack, lt->attr.stack_size);
            lt->attr.stack = NULL;
        }
    }
    oe_memset_s(lt, sizeof(*lt), 0, sizeof(*lt));

#if DEBUG
    if (__active_lthreads != NULL && __active_lthreads->lt == lt)
    {
        if (__active_lthreads_tail == __active_lthreads)
        {
            __active_lthreads_tail = NULL;
        }
        struct lthread_queue* new_head = __active_lthreads->next;
        oe_free(__active_lthreads);
        __active_lthreads = new_head;
    }
    else
    {
        struct lthread_queue* ltq = __active_lthreads;
        while (ltq != NULL)
        {
            if (ltq->next != NULL && ltq->next->lt == lt)
            {
                if (ltq->next == __active_lthreads_tail)
                {
                    __active_lthreads_tail = ltq;
                }
                struct lthread_queue* next_ltq = ltq->next->next;
                oe_free(ltq->next);
                ltq->next = next_ltq;
                break;
            }
            ltq = ltq->next;
        }
    }
#endif /* DEBUG */

    lthread_dealloc(lt);
}

int __init_utp(void *p, int set_tp)
{
	struct lthread_tcb_base *tcb = (struct lthread_tcb_base *)p;
	tcb->self = p;
	tcb->schedctx = __scheduler_self();
	if (set_tp)
	{
		if (sgxlkl_enclave->mode == SW_DEBUG_MODE)
		{
			int r = __set_thread_area(TP_ADJ(p));
			if (r < 0)
			{
				sgxlkl_fail("Could not set thread area %p: %s\n", p, strerror(errno));
			}
		}
		else
		{
			__asm__ volatile("wrfsbase %0" ::"r"(p));
		}
	}
	return 0;
}

void *__copy_utls(struct lthread *lt, unsigned char *mem, size_t sz)
{
	mem += sz - sizeof(struct lthread_tcb_base);
	mem -= (uintptr_t)mem & (TLS_ALIGN - 1);
	return (void *)mem;
}

void set_tls_tp(struct lthread* lt)
{
    uintptr_t tp_unaligned, tp;
    if (!lt->itls)
        return;
    // pthread_create passes thread pointer for lt->itls
    // no need to calculate offset of tp in tls region
    if (lt->attr.stack_size == 0)
    {
        tp = lt->itls;
    }
    else
    {
        tp_unaligned =
        (uintptr_t)(lt->itls + lt->itlssz - sizeof(struct lthread_tcb_base));
        tp =
            (struct
            lthread_tcb_base*)(tp_unaligned - (tp_unaligned & (TLS_ALIGN - 1)));
    }
    if (!sgxlkl_in_sw_debug_mode())
    {
        __asm__ volatile("wrfsbase %0" ::"r"(tp));
    }
    else
    {
        int r = __set_thread_area(TP_ADJ(tp));
        if (r < 0)
        {
            sgxlkl_fail("Could not set thread area %p\n", tp);
        }
    }
}

void reset_tls_tp(struct lthread* lt)
{
    if (!lt->itls)
        return;

    struct schedctx* sp = __scheduler_self();

    // The scheduler context is at a fixed offset from its ethread's fsbase.
    char* tp = (char*)sp - SCHEDCTX_OFFSET;

    if (!sgxlkl_in_sw_debug_mode())
    {
        __asm__ volatile("wrfsbase %0" ::"r"(tp));
    }
    else
    {
        int r = __set_thread_area(TP_ADJ(tp));
        if (r < 0)
        {
            sgxlkl_fail("Could not set thread area %p: %s\n", tp);
        }
    }
}

int _lthread_resume(struct lthread* lt)
{
    struct lthread_sched* sched = lthread_get_sched();
    if (lt->attr.state & BIT(LT_ST_CANCELLED))
    {
        /* if an lthread was joining on it, schedule it to run */
        if (lt->lt_join)
        {
            __scheduler_enqueue(lt->lt_join);
            lt->lt_join = NULL;
        }
        /* if lthread is detached, then we can free it up */
        if (lt->attr.state & BIT(LT_ST_DETACH))
        {
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

    set_tls_tp(lt);
    _switch(&lt->ctx, &sched->ctx);
    sched->current_lthread = NULL;
    reset_tls_tp(lt);

    if (lt->attr.state & BIT(LT_ST_EXITED))
    {
        /* lt is always locked before LT_ST_EXITED is set */
        if (lt->lt_join)
        {
            __scheduler_enqueue(lt->lt_join);
            lt->lt_join = NULL;
        }
        _lthread_unlock(lt);
        /* code below is only for detached threads, so it's safe to unlock here
         */
        /* if lthread is detached, free it, otherwise lthread_join() will */
        if (lt->attr.state & BIT(LT_ST_DETACH))
        {
            _lthread_free(lt);
        }
        sched->current_lthread = NULL;
        return (-1);
    }
    if (lt->yield_cb)
    {
        lt->yield_cb(lt->yield_cbarg);
    }

    return (0);
}

int lthread_init(size_t size)
{
    return (_lthread_sched_init(size));
}

static void _lthread_init(struct lthread* lt)
{
    void** stack = NULL;
    _lthread_lock(lt);
    stack = (void**)((uintptr_t)lt->attr.stack + (lt->attr.stack_size));

    stack[-3] = NULL;
    stack[-2] = (void*)lt;
    lt->ctx.esp = (void*)((uintptr_t)stack - (4 * sizeof(void*)));
    lt->ctx.ebp = (void*)((uintptr_t)stack - (3 * sizeof(void*)));
    lt->ctx.eip = (void*)_exec;
    /* this is equivalent to unlock */
    a_barrier();
    if (lt->attr.state & BIT(LT_ST_DETACH))
    {
        lt->attr.state = BIT(LT_ST_READY) | BIT(LT_ST_DETACH);
    }
    else
    {
        lt->attr.state = BIT(LT_ST_READY);
    }
}

int _lthread_sched_init(size_t stack_size)
{
    size_t sched_stack_size = 0;

    sched_stack_size = stack_size ? stack_size : MAX_STACK_SIZE;

    struct schedctx* c = __scheduler_self();

    c->sched.stack_size = sched_stack_size;

    c->sched.default_timeout = 3000000u;

    oe_memset_s(
        &c->sched.ctx, sizeof(struct cpu_ctx), 0, sizeof(struct cpu_ctx));

    return (0);
}

static FILE* volatile dummy_file = 0;

weak_alias(dummy_file, __stdin_used);
weak_alias(dummy_file, __stdout_used);
weak_alias(dummy_file, __stderr_used);

//TODO: can this be removed
static void init_file_lock(FILE* f)
{
    if (f && f->lock < 0)
        f->lock = 0;
}

int lthread_create_primitive(
    struct lthread** new_lt,
    void* pc,
    void* sp,
    void* tls)
{
    struct lthread* lt;

    if ((lt = oe_calloc(1, sizeof(struct lthread))) == NULL)
    {
        return -1;
    }

    lt->itls = tls;
    lt->itlssz = libc.tls_size; // not setting this causes problems in set_tls_tp
    LIST_INIT(&lt->tls);
    lt->attr.state = BIT(LT_ST_READY);
    lt->attr.stack_size = 0; // lthread doesn't manage userspace thread stacks
    lt->tid = a_fetch_add(&spawned_lthreads, 1);

    static unsigned long long n = 0;
    oe_snprintf(
        lt->funcname,
        64,
        "cloned host task %llu",
        __atomic_fetch_add(&n, 1, __ATOMIC_SEQ_CST));

    if (new_lt)
    {
        *new_lt = lt;
    }

    SGXLKL_TRACE_THREAD("[%4d] create: count=%d\n", lt->tid, thread_count);

#if DEBUG
    struct lthread_queue* new_ltq =
        (struct lthread_queue*)oe_malloc(sizeof(struct lthread_queue));
    new_ltq->lt = lt;
    new_ltq->next = NULL;
    if (__active_lthreads_tail)
    {
        __active_lthreads_tail->next = new_ltq;
    }
    else
    {
        __active_lthreads = new_ltq;
    }
    __active_lthreads_tail = new_ltq;
#endif /* DEBUG */

    // Set up the lthread initial PC and stack pointer.
    lt->ctx.eip = pc;
    // Reserve space on the stack for the return address.  `_switch` will pop
    // this off.
    lt->ctx.esp = ((char*)sp) - sizeof(void*);
    (void)tls;

    return 0;
}

int lthread_create(
    struct lthread** new_lt,
    struct lthread_attr* attrp,
    void* fun,
    void* arg)
{
    struct lthread* lt = NULL;
    size_t stack_size;
    struct lthread_sched* sched = lthread_get_sched();

    stack_size =
        attrp && attrp->stack_size ? attrp->stack_size : sched->stack_size;
    if ((lt = lthread_alloc(1, sizeof(struct lthread))) == NULL)
    {
        return -1;
    }
    lt->attr.stack = attrp ? attrp->stack : 0;
    if ((!lt->attr.stack) && ((intptr_t)(
                                  lt->attr.stack = enclave_mmap(
                                      0,
                                      stack_size,
                                      0, /* map_fixed */
                                      PROT_READ | PROT_WRITE,
                                      1 /* zero_pages */)) < 0))
    {
        lthread_dealloc(lt);
        return -1;
    }
    lt->attr.stack_size = stack_size;

    /* mmap tls image */
    lt->itlssz = (sizeof(lthread_tcb_base) + TLS_ALIGN - 1) & -TLS_ALIGN;
    if (lt->itlssz)
    {
        if ((intptr_t)(
                lt->itls = (uint8_t*)enclave_mmap(
                    0,
                    lt->itlssz,
                    0, /* map_fixed */
                    PROT_READ | PROT_WRITE,
                    1 /* zero_pages */)) < 0)
        {
            lthread_dealloc(lt);
            return -1;
        }
        if (__init_utp(__copy_utls(lt, lt->itls, lt->itlssz), 0))
        {
            enclave_munmap(lt->attr.stack, stack_size);
            lthread_dealloc(lt);
            return -1;
        }
    }

    lt->attr.state = BIT(LT_ST_NEW) | (attrp ? attrp->state : 0);
    lt->tid = a_fetch_add(&spawned_lthreads, 1);
    lt->fun = fun;
    lt->arg = arg;

    LIST_INIT(&lt->tls);

    // Inherit name from parent
    if (lthread_self() && lthread_self()->funcname)
    {
        lthread_set_funcname(lt, lthread_self()->funcname);
    }

    if (new_lt)
    {
        *new_lt = lt;
    }

    //a_inc(&libc.threads_minus_1);

    SGXLKL_TRACE_THREAD("[%4d] create: count=%d\n", lt->tid, thread_count);

#if DEBUG
    struct lthread_queue* new_ltq =
        (struct lthread_queue*)oe_malloc(sizeof(struct lthread_queue));
    new_ltq->lt = lt;
    new_ltq->next = NULL;
    if (__active_lthreads_tail)
    {
        __active_lthreads_tail->next = new_ltq;
    }
    else
    {
        __active_lthreads = new_ltq;
    }
    __active_lthreads_tail = new_ltq;
#endif /* DEBUG */

    __scheduler_enqueue(lt);
    return 0;
}

struct lthread* lthread_current(void)
{
    return (lthread_get_sched()->current_lthread);
}

void lthread_cancel(struct lthread* lt)
{
    if (lt == NULL)
        return;

    if (lt->attr.state & BIT(LT_ST_CANCELSTATE))
    {
        return;
    }
    lt->attr.state |= BIT(LT_ST_CANCELLED);
    _lthread_desched_sleep(lt);
    __scheduler_enqueue(lt);
}

static inline void _lthread_desched_ready(void* _lt)
{
    // Update lthread state to sleep.
    struct lthread* lt = _lt;
    lt->attr.state &= CLEARBIT(LT_ST_READY);
    lt->attr.state |= BIT(LT_ST_SLEEPING);
}

void lthread_yield_and_sleep(void)
{
    struct lthread* current_lt = lthread_self();
    _lthread_yield_cb(current_lt, _lthread_desched_ready, current_lt);
}

void lthread_wakeup(struct lthread* lt)
{
    if (lt->attr.state & BIT(LT_ST_SLEEPING))
    {
        _lthread_desched_sleep(lt);
        __scheduler_enqueue(lt);
    }
}

void lthread_exit(void* ptr)
{
    struct lthread* lt = lthread_get_sched()->current_lthread;
    /* switch thread to exiting state */
    _lthread_lock(lt);

    SGXLKL_TRACE_THREAD("[%4d] thread_exit: count=%d\n", lt->tid, thread_count);

    lt->yield_cbarg = ptr;
    lt->attr.state |= BIT(LT_ST_EXITED);
    _lthread_yield(lt);
    __builtin_unreachable();
}

/* lthread_join may proceed only when:
   1. the thread is still running and not exiting;
   2. the thread has exited and is no longer seen by scheduler.
   The period between 1. and 2. is protected by taking a lock. */
int lthread_join(struct lthread* lt, void** ptr, uint64_t timeout)
{
    /* TODO: The code below does not support timeouts */
    SGXLKL_ASSERT(timeout == -1);

    int ret = 0;
    struct lthread* current = lthread_get_sched()->current_lthread;
    if (lt->attr.state & BIT(LT_ST_DETACH))
    {
        SGXLKL_TRACE_THREAD(
            "[%4d] join (detached): tid=%d count=%d\n",
            (lthread_self() ? lthread_self()->tid : 0),
            lt->tid,
            thread_count);
        return EINVAL;
    }
    _lthread_lock(lt);
    if (lt->attr.state & BIT(LT_ST_EXITED))
    {
        SGXLKL_TRACE_THREAD(
            "[%4d] join (exited): tid=%d count=%d\n",
            (lthread_self() ? lthread_self()->tid : 0),
            lt->tid,
            thread_count);
    }
    else
    {
        SGXLKL_TRACE_THREAD(
            "[%4d] join (waiting): tid=%d count=%d\n",
            (lthread_self() ? lthread_self()->tid : 0),
            lt->tid,
            thread_count);

        /* thread is still running, set current lthread as joiner */
        void* null_ptr = NULL;
        if (!atomic_compare_exchange_strong(&lt->lt_join, &null_ptr, current) !=
            0)
        {
            /* there already is a joiner */
            _lthread_unlock(lt);
            return EINVAL;
        }
        _lthread_yield_cb(current, (void*)_lthread_unlock, lt);

        // Reacquire the lthread lock before we start freeing the lthread. It
        // may still be exiting concurrently.
        _lthread_lock(lt);
    }
    if (ptr)
    {
        *ptr = lt->yield_cbarg;
    }
    _lthread_free(lt);
    return ret;
}

void lthread_detach(void)
{
    struct lthread* current = lthread_get_sched()->current_lthread;
    // current->attr.state |= BIT(LT_ST_DETACH);
    lthread_detach2(current);
}

void lthread_detach2(struct lthread* lt)
{
    // lt->attr.state |= BIT(LT_ST_DETACH);
    int state, newstate;
    for (;;)
    {
        state = lt->attr.state;
        if (state & BIT(LT_ST_BUSY))
            continue;
        newstate = state | BIT(LT_ST_DETACH);
        if (!atomic_compare_exchange_strong(&lt->attr.state, &state, newstate))
            continue;
        break;
    }
}

void lthread_set_funcname(struct lthread* lt, const char* f)
{
    oe_strncpy_s(lt->funcname, 64, f, 64);
    lt->funcname[64 - 1] = 0;
}

uint64_t lthread_id(void)
{
    struct lthread_sched* sched = lthread_get_sched();
    if (sched->current_lthread)
    {
        return sched->current_lthread->tid;
    }
    return ~0UL;
}

struct lthread* lthread_self(void)
{
    struct lthread_sched* sched = lthread_get_sched();
    if (sched)
    {
        return sched->current_lthread;
    }
    else
    {
        return NULL;
    }
}

int lthread_setcancelstate(int new, int* old)
{
    if (new > 2U)
        return EINVAL;
    struct lthread* curr = lthread_get_sched()->current_lthread;
    if (old)
    {
        *old = (curr->attr.state & BIT(LT_ST_CANCELSTATE)) > 0;
    }
    if (new)
    {
        curr->attr.state |= BIT(LT_ST_CANCELSTATE);
    }
    else
    {
        curr->attr.state &= ~BIT(LT_ST_CANCELSTATE);
    }
    return 0;
}

/**
 * Find the TLS slot for a specified lthread.  It is the caller's
 * responsibility to ensure that the specified lthread is not concurrently
 * accessed.  `lthread_current()` is always safe to use here as is any lthread
 * that has not yet been scheduled.
 */
static struct lthread_tls* lthread_findtlsslot(struct lthread* lt, long key)
{
    struct lthread_tls *d, *d_tmp;
    LIST_FOREACH_SAFE(d, &lt->tls, tls_next, d_tmp)
    {
        if (d->key == key)
        {
            return d;
        }
    }
    return NULL;
}

/**
 * Add a TLS slot for a specified lthread.  It is the caller's responsibility
 * to ensure that the specified lthread is not concurrently accessed.
 * `lthread_current()` is always safe to use here as is any lthread that has
 * not yet been scheduled.
 */
static int lthread_addtlsslot(struct lthread* lt, long key, void* data)
{
    struct lthread_tls* d;
    d = oe_calloc(1, sizeof(struct lthread_tls));
    if (d == NULL)
    {
        return ENOMEM;
    }
    d->key = key;
    d->data = data;
    LIST_INSERT_HEAD(&lt->tls, d, tls_next);
    return 0;
}

void* lthread_getspecific_remote(struct lthread* lt, long key)
{
    struct lthread_tls* d;
    if ((d = lthread_findtlsslot(lt, key)) == NULL)
    {
        return NULL;
    }
    return d->data;
}

int lthread_setspecific_remote(struct lthread* lt, long key, const void* value)
{
    struct lthread_tls* d;
    if ((d = lthread_findtlsslot(lt, key)) != NULL)
    {
        d->data = (void*)value;
        return 0;
    }
    else
    {
        return lthread_addtlsslot(lt, key, (void*)value);
    }
}

static struct lthread_tlsdestr_l lthread_destructors;
typedef void (*lthread_destructor_func)(void*);

static unsigned global_count = 0;

int lthread_key_create(long* k, void (*destructor)(void*))
{
    struct lthread_tls_destructors* d;
    d = oe_calloc(1, sizeof(struct lthread_tls_destructors));
    if (d == NULL)
    {
        return ENOMEM;
    }
    d->key = a_fetch_add((void*)&global_count, 1);
    d->destructor = destructor;
    LIST_INSERT_HEAD(&lthread_destructors, d, tlsdestr_next);
    *k = d->key;
    return 0;
}

int lthread_key_delete(long key)
{
    struct lthread_tls_destructors *d, *d_tmp;
    LIST_FOREACH_SAFE(d, &lthread_destructors, tlsdestr_next, d_tmp)
    {
        if (d->key == key)
        {
            LIST_REMOVE(d, tlsdestr_next);
            oe_free(d);
            return 0;
        }
    }
    return -1;
}

static lthread_destructor_func lthread_finddestr(long key)
{
    struct lthread_tls_destructors *d, *d_tmp;
    LIST_FOREACH_SAFE(d, &lthread_destructors, tlsdestr_next, d_tmp)
    {
        if (d->key == key)
        {
            return d->destructor;
        }
    }
    return NULL;
}

static void lthread_rundestructors(struct lthread* lt)
{
    struct lthread_tls *d, *d_tmp;
    lthread_destructor_func destr;
    LIST_FOREACH_SAFE(d, &lt->tls, tls_next, d_tmp)
    {
        if (d->data)
        {
            destr = lthread_finddestr(d->key);
            if (destr)
            {
                destr(d->data);
            }
        }
        LIST_REMOVE(d, tls_next);
        oe_free(d);
    }
}

void lthread_set_expired(struct lthread* lt)
{
    lt->attr.state |= BIT(LT_ST_EXPIRED);
}

#ifdef DEBUG
void lthread_dump_all_threads(bool is_lthread)
{
    struct lthread_queue* lt_queue = __active_lthreads;

    sgxlkl_info(
        "=============================================================\n");
    sgxlkl_info("Stack traces for all lthreads:\n");

    struct lthread* this_lthread = NULL;

    // Is this called from an lthread?
    if (is_lthread)
        this_lthread = lthread_self();

    for (int i = 1; lt_queue; i++)
    {
        struct lthread* lt = lt_queue->lt;

        // Do we have a valid lthread?
        if (lt)
        {
            int tid = lt->tid;
            char* funcname = lt->funcname;
            sgxlkl_info("------------------------------------------------------"
                        "-------\n");
            sgxlkl_info(
                "%s%i: tid=%i (%p) [%s]\n",
                lt == this_lthread ? "*" : "",
                i,
                tid,
                lt,
                funcname);
            sgxlkl_print_backtrace(
                lt == this_lthread ? __builtin_frame_address(0) : lt->ctx.ebp);
        }
        else
        {
            sgxlkl_info("lt == NULL\n");
        }

        lt_queue = lt_queue->next;
    }

    sgxlkl_info(
        "=============================================================\n");
}
#endif