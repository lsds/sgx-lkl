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

#include "stdio_impl.h"

#include <enclave/enclave_mem.h>
#include <enclave/enclave_oe.h>
#include <enclave/enclave_util.h>
#include <enclave/lthread.h>
#include "enclave/lthread_int.h"
#include "enclave/sgxlkl_t.h"
#include "enclave/ticketlock.h"
#include "openenclave/corelibc/oemalloc.h"
#include "openenclave/corelibc/oestring.h"
#include "openenclave/internal/safecrt.h"

extern int vio_enclave_wakeup_event_channel(void);

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

// Record the scheduler that runs the lthread responsible for termination
static _Atomic(struct lthread_sched*) _lthread_terminating_scheduler = NULL;

static size_t sleepspins = 500000000;
static size_t sleeptime_ns = 1600;
static size_t futex_wake_spins = 500;

int thread_count = 1;

#if DEBUG
struct ticketlock _lt_active_threads_lock;
LIST_HEAD(_lt_active_threads_head, lthread)
_lt_active_threads = LIST_HEAD_INITIALIZER(_lt_active_threads);
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

void lthread_sched_global_init(size_t sleepspins_, size_t sleeptime_ns_)
{
    sleepspins = sleepspins_;
    sleeptime_ns = sleeptime_ns_;
    futex_wake_spins = DEFAULT_FUTEX_WAKE_SPINS;
    futex_init();
#ifdef DEBUG
    LIST_INIT(&_lt_active_threads);
#endif
}

void lthread_terminate_other_schedulers(void)
{
    SGXLKL_TRACE_THREAD(
        "[%4d] lthread_terminate_other_schedulers\n", lthread_self()->tid);
    _lthread_terminating_scheduler = lthread_get_sched();
}

void lthread_terminate_this_scheduler(void)
{
    struct lthread* lt = lthread_self();
    SGXLKL_ASSERT(lt);
    SGXLKL_TRACE_THREAD("[%4d] lthread_terminate_this_scheduler\n", lt->tid);
    lt->attr.state |= BIT(LT_ST_TERMINATE);
}

int lthread_run(void)
{
    const struct lthread_sched* const sched = lthread_get_sched();
    struct lthread* lt = NULL;
    size_t pauses = sleepspins;
    int spins = futex_wake_spins;
    int dequeued;

    /* Check if the scheduler was initialized. */
    if (sched == NULL)
    {
        sgxlkl_fail("Scheduler not initialised\n");
    }

    for (;;)
    {
        /* start by checking if a sleeping thread needs to wakeup */
        do
        {
            dequeued = 0;
            if (mpmc_dequeue(&__scheduler_queue, (void**)&lt))
            {
                SGXLKL_ASSERT(!(lt->attr.state & BIT(LT_ST_EXITED)));
                SGXLKL_ASSERT(!(lt->attr.state & BIT(LT_ST_TERMINATE)));

                dequeued++;
                pauses = sleepspins;
                SGXLKL_TRACE_THREAD(
                    "[%4d] lthread_run(): lthread_resume (dequeue)\n",
                    lt ? lt->tid : -1);
                _lthread_resume(lt);

                // The lthread indicated termination, and we are likely to be
                // the terminatng scheduler.
                if (lt->attr.state & BIT(LT_ST_TERMINATE))
                {
                    SGXLKL_VERBOSE("Exiting scheduler due to terminating lthread\n");
                    // Report exit status
                    return sgxlkl_enclave_state.exit_status;
                }

                // Bail out if there is a terminating scheduler, and we are not
                // it.
                struct lthread_sched* terminating_sched =
                    _lthread_terminating_scheduler;
                if (terminating_sched && terminating_sched != sched)
                {
                    SGXLKL_VERBOSE("Exiting non-terminating scheduler\n");
                    // Do not report exit status
                    return INT_MAX;
                }
            }

            if (vio_enclave_wakeup_event_channel())
            {
                dequeued++;
                pauses = sleepspins;
            }

            spins--;
            if (spins <= 0)
            {
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
    // Only run the destructors if this is not the main application thread,
    // otherwise it would get deallocated twice
    if (lthread_self() != NULL && !(lt->attr.state & BIT(LT_ST_APP_MAIN)))
    {
        lthread_rundestructors(lt);
    }

    // lthread only manages tls region for lkl kernel threads
    if (lt->attr.thread_type == LKL_KERNEL_THREAD && lt->itls != 0)
    {
        enclave_munmap(lt->itls, lt->itlssz);
    }

    if (lt->attr.stack)
    {
        enclave_munmap(lt->attr.stack, lt->attr.stack_size);
        lt->attr.stack = NULL;
    }

#if DEBUG
    ticket_lock(&_lt_active_threads_lock);
    LIST_REMOVE(lt, entries);
    ticket_unlock(&_lt_active_threads_lock);
#endif

    lthread_dealloc(lt);
}

static void init_tp(struct lthread *lt, unsigned char *mem, size_t sz)
{
	mem += sz - sizeof(struct lthread_tcb_base);
	mem -= (uintptr_t)mem & (TLS_ALIGN - 1);
    lt->tp = (uintptr_t*)mem;
    struct lthread_tcb_base* tcb = (struct lthread_tcb_base*)mem;
    tcb->self = mem;
}

static void set_fsbase(void* tp){

    if (!sgxlkl_in_sw_debug_mode())
    {
        __asm__ volatile("wrfsbase %0" ::"r"(tp));
    }
    else
    {
        int res;
        __asm__ volatile(
            "mov %1, %%rsi\n\t"
            "movl $0x1002, %%edi\n\t"       /* SET_FS register */
            "movl $158, %%eax\n\t"          /* set fs segment to */
            "syscall"                       /* arch_prctl(SET_FS, arg)*/
            : "=a" (res)
            : "r" (tp)
        );
        if (res < 0)
        {
            sgxlkl_fail( "Could not set thread area %p\n", tp);
        }
    }
}
void set_tls_tp(struct lthread* lt)
{
    if (!lt->tp)
        return;
    set_fsbase(lt->tp);
}

void reset_tls_tp(struct lthread* lt)
{
    if (!lt->tp)
        return;

    struct schedctx* sp = __scheduler_self();

    // The scheduler context is at a fixed offset from its ethread's gsbase.
    char* tp = (char*)sp - SCHEDCTX_OFFSET;
    set_fsbase(tp);
}

int _lthread_resume(struct lthread* lt)
{
    struct lthread_sched* sched = lthread_get_sched();

    if (lt->attr.state & BIT(LT_ST_NEW))
        _lthread_init(lt);

    /* clear yield callback */
    lt->yield_cb = 0;
    lt->yield_cbarg = 0;

    sched->current_lthread = lt;

    set_tls_tp(lt);
    _switch(&lt->ctx, &sched->ctx);

    // The "app-main" thread eventually loads the app's ELF image
    // and initializes its TLS area. As an lthread has to properly set the
    // TLS region on context switches, check if FS has changed and
    // update the lthread's thread pointer field accordingly.
    struct lthread* current_lt = sched->current_lthread;
    if ((current_lt->attr.state & BIT(LT_ST_APP_MAIN)) &&
        (current_lt->attr.thread_type == LKL_KERNEL_THREAD))
    {
        void* fs_ptr;
        __asm__ __volatile__("mov %%fs:0,%0" : "=r"(fs_ptr));
        if (fs_ptr != current_lt->tp)
        {
            current_lt->tp = fs_ptr;
        }
    }

    sched->current_lthread = NULL;
    reset_tls_tp(lt);

    if (lt->attr.state & BIT(LT_ST_TERMINATE))
    {
        SGXLKL_VERBOSE("lthread LT_ST_TERMINATE\n");
        return 0;
    }

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

    lt->attr.state &= CLEARBIT(LT_ST_NEW);

    _lthread_unlock(lt);
}

int _lthread_sched_init(size_t stack_size)
{
    size_t sched_stack_size = 0;

    sched_stack_size = stack_size ? stack_size : MAX_STACK_SIZE;

    struct lthread_sched* sched = lthread_get_sched();

    sched->stack_size = sched_stack_size;

    sched->default_timeout = 3000000u;

    oe_memset_s(
        &sched->ctx, sizeof(struct cpu_ctx), 0, sizeof(struct cpu_ctx));

    return (0);
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

    // For USERSPACE_THREADS created via clone(), lthread doesn't manage the
    // tls region(stored in lt->itls, not be confused by lt->tls, which is similar
    // to key based tsd in pthreads)
    // Also for these threads, the tls pointer passed to this function is the
    // pointer to the thread's control block. So we save it here in lt->tp for
    // setting up fsbase on a context switch.
    size_t* tp = tls;
    SGXLKL_ASSERT(tp[0] == (size_t)tls); // check if tls self pointer is set
    lt->tp = tls;

    LIST_INIT(&lt->tls);
    lt->attr.state = BIT(LT_ST_READY);
    lt->attr.thread_type = USERSPACE_THREAD;
    lt->tid = a_fetch_add(&spawned_lthreads, 1);

    static unsigned long long n = 0;
    oe_snprintf(
        lt->attr.funcname,
        64,
        "cloned host task %llu",
        __atomic_fetch_add(&n, 1, __ATOMIC_SEQ_CST));

    if (new_lt)
    {
        *new_lt = lt;
    }

    SGXLKL_TRACE_THREAD("[%4d] create: count=%d\n", lt->tid, thread_count);

#if DEBUG
    ticket_lock(&_lt_active_threads_lock);
    LIST_INSERT_HEAD(&_lt_active_threads, lt, entries);
    ticket_unlock(&_lt_active_threads_lock);
#endif

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

    if ((lt = oe_calloc(1, sizeof(struct lthread))) == NULL)
    {
        return -1;
    }

    stack_size =
        attrp && attrp->stack_size ? attrp->stack_size : sched->stack_size;
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
    // To maintain tls alignment, calculates
    // closest multiple of TLS_ALIGN > sizeof(struct lthread_tcb_base)
    lt->itlssz = (sizeof(struct lthread_tcb_base) + TLS_ALIGN - 1) & -TLS_ALIGN;
    if ((lt->itls = (uint8_t*)enclave_mmap(
                 0,
                 lt->itlssz,
                 0, /* map_fixed */
                 PROT_READ | PROT_WRITE,
                 1 /* zero_pages */)) == MAP_FAILED)
    {
        oe_free(lt);
        return -1;
    }
    init_tp(lt, lt->itls, lt->itlssz);

    lt->attr.state = BIT(LT_ST_NEW) | (attrp ? attrp->state : 0);
    lt->attr.thread_type = LKL_KERNEL_THREAD;
    lt->attr.funcname[0] = '\0';
    lt->tid = a_fetch_add(&spawned_lthreads, 1);
    lt->fun = fun;
    lt->arg = arg;

    LIST_INIT(&lt->tls);

    // Did we get a thread name?
    if (attrp && attrp->funcname)
    {
        lthread_set_funcname(lt, attrp->funcname);
    }
    else
    {
        // Inherit the thread name from the parent
        if (lthread_self() && lthread_self()->attr.funcname)
        {
            lthread_set_funcname(lt, lthread_self()->attr.funcname);
        }
    }

    if (new_lt)
    {
        *new_lt = lt;
    }

    SGXLKL_TRACE_THREAD("[%4d] create: count=%d\n", lt->tid, thread_count);

#if DEBUG
    ticket_lock(&_lt_active_threads_lock);
    LIST_INSERT_HEAD(&_lt_active_threads, lt, entries);
    ticket_unlock(&_lt_active_threads_lock);
#endif

    __scheduler_enqueue(lt);
    return 0;
}

struct lthread* lthread_current(void)
{
    return (lthread_get_sched()->current_lthread);
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
    oe_strncpy_s(
        lt->attr.funcname,
        sizeof(lt->attr.funcname),
        f,
        sizeof(lt->attr.funcname));
    lt->attr.funcname[sizeof(lt->attr.funcname) - 1] = '\0';
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

#define STRINGIFY_LT_STATE(enum_lt_state)     \
    if (state & BIT(LT_ST_##enum_lt_state))   \
    {                                         \
        str_len = sizeof(#enum_lt_state "|"); \
        oe_strncpy_s(                         \
            lt_state_str + offset,            \
            size - offset,                    \
            #enum_lt_state "|",               \
            str_len);                         \
        offset += str_len - 1;                \
    }

static void lthread_state_to_string(
    struct lthread* lt,
    char* lt_state_str,
    const size_t size)
{
    int state = lt->attr.state;
    size_t str_len = 0;
    size_t offset = 0;

    STRINGIFY_LT_STATE(NEW)
    STRINGIFY_LT_STATE(READY)
    STRINGIFY_LT_STATE(EXITED)
    STRINGIFY_LT_STATE(BUSY)
    STRINGIFY_LT_STATE(SLEEPING)
    STRINGIFY_LT_STATE(EXPIRED)
    STRINGIFY_LT_STATE(DETACH)
    STRINGIFY_LT_STATE(PINNED)
    STRINGIFY_LT_STATE(APP_MAIN)
    STRINGIFY_LT_STATE(TERMINATE)

    lt_state_str[offset - 1] = '\0';
}

void lthread_dump_all_threads(bool is_lthread)
{
    sgxlkl_info(
        "=============================================================\n");
    sgxlkl_info("Stack traces for all lthreads:\n");

    struct lthread* this_lthread = NULL;

    // Is this called from an lthread?
    if (is_lthread)
        this_lthread = lthread_self();

    struct lthread *lt, *tmp;
    int i = 1;

    ticket_lock(&_lt_active_threads_lock);
    LIST_FOREACH_SAFE(lt, &_lt_active_threads, entries, tmp)
    {
        // Do we have a valid lthread?
        if (lt)
        {
            int tid = lt->tid;
            char* funcname = lt->attr.funcname;
            char lt_state_str[1024] = "";

            lthread_state_to_string(lt, lt_state_str, 1024);

            sgxlkl_info("------------------------------------------------------"
                        "-------\n");
            sgxlkl_info(
                "%s%i: tid=%i (%p) [%s] (%s) %s\n",
                lt == this_lthread ? "*" : "",
                i,
                tid,
                lt,
                funcname,
                lt_state_str,
                lt->lt_join ? "J" : "");
            sgxlkl_print_backtrace(
                lt == this_lthread ? __builtin_frame_address(0) : lt->ctx.ebp);
        }
        else
        {
            sgxlkl_info("%i: lt=NULL\n", i);
        }
        i++;
    }
    ticket_unlock(&_lt_active_threads_lock);

    sgxlkl_info(
        "=============================================================\n");
}
#endif
