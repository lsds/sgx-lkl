/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* This file is based on posix-host.c from LKL, modified to provide a host
 * interface for enclave environments. */

#include <errno.h>
#include <futex.h>
#include <lkl_host.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include "syscall.h"

#include "lkl/iomem.h"
#include "lkl/jmp_buf.h"
#include "lkl/posix-host.h"
#include "lkl/setup.h"

#include "enclave/enclave_timer.h"
#include "enclave/sgxlkl_config.h"
#include "enclave/sgxlkl_t.h"
#include "lkl/iomem.h"
#include "lkl/jmp_buf.h"
#include "openenclave/internal/print.h"
#include "syscall.h"

#define NSEC_PER_SEC 1000000000L

// The function used to implement the futex system call on top of lthreads
int enclave_futex(
    int* uaddr,
    int op,
    int val,
    const struct timespec* timeout,
    int* uaddr2,
    int val3);

static void panic(void)
{
    sgxlkl_fail(
        "Kernel panic!%s Aborting...\n",
        sgxlkl_enclave->kernel_verbose
            ? ""
            : " Run DEBUG build with SGXLKL_KERNEL_VERBOSE=1 for more "
              "information.");
}

static void terminate(int exit_status, int received_signal)
{
    /* Is the termination due to a received signal? */
    if (received_signal)
    {
        /* TODO: add missing error codes here */
        switch (received_signal)
        {
            case SIGSEGV:
                oe_host_printf("Segmentation fault\n");
                exit_status = 139;
                break;
            case SIGKILL:
                oe_host_printf("Killed\n");
                exit_status = 137;
                break;
            case SIGABRT:
                oe_host_printf("Aborted\n");
                exit_status = 134;
                break;
            case SIGTERM:
                oe_host_printf("Terminated\n");
                exit_status = 143;
                break;
            default:
                sgxlkl_error(
                    "Unhandled signal %i received. Aborting.\n",
                    received_signal);
                if (!exit_status)
                {
                    exit_status = 1;
                }
        }
    }

    LKL_TRACE(
        "Shutting down SGX-LKL (exit_status=%i received_signal=%i)\n",
        exit_status,
        received_signal);
    lkl_terminate(exit_status);
}

static void print(const char* str, int len)
{
    oe_host_printf("%.*s", len, str);
}

/**
 * Mutex state.
 */
enum mutex_state
{
    /** Unlocked, can be acquired without blocking. */
    unlocked = 0,
    /** Locked, but not threads are waiting.  Can unlock without waking
     * anything, the first waiter must change the state. */
    locked_no_waiters = 1,
    /** Locked and has waiters.  When unlocking, must wake other threads.
     */
    locked_waiters = 2
};

struct lkl_mutex
{
    /**
     * The state of this mutex.  Used as the futex value.
     */
    _Atomic(enum mutex_state) flag;
    /**
     * If this is a recursive mutex, which thread owns it?
     */
    _Atomic(struct lthread*) owner;
    /**
     * Is this a recursive mutex? If this is false then the `owner` field
     * is unused.
     */
    bool is_recursive : 1;
    /**
     * The number of times a recursive mutex has been locked beyond the
     * initial lock.  This can be modified only with the mutex locked and
     * so doesn't need to be atomic.
     */
    int recursion_count : 31;
};

struct lkl_sem
{
    /**
     * Semaphore count.  This is a naive implementation that assumes all
     * semaphores have waiters.
     */
    _Atomic(int) count;
};

struct lkl_tls_key
{
    /**
     * The key used by the lthreads library.
     */
    long key;
};

#define WARN_UNLESS(exp)                                        \
    do                                                          \
    {                                                           \
        if (exp < 0)                                            \
            sgxlkl_fail("%s: %s\n", #exp, lkl_strerror(errno)); \
    } while (0)

static int _warn_pthread(int ret, char* str_exp)
{
    if (ret != 0)
        sgxlkl_fail("%s: %s\n", str_exp, lkl_strerror(ret));

    return ret;
}

/* pthread_* functions use the reverse convention */
#define WARN_PTHREAD(exp) _warn_pthread(exp, #exp)

static int futex_timed_wait(
    _Atomic(int) * ftx,
    int val,
    const struct timespec* timeout)
{
    return enclave_futex((int*)ftx, FUTEX_WAIT, val, timeout, 0, 0);
}

static void futex_wait(_Atomic(int) * ftx, int val)
{
    enclave_futex((int*)ftx, FUTEX_WAIT, val, NULL, 0, 0);
}

static void futex_wake(_Atomic(int) * ftx, int val)
{
    enclave_futex((int*)ftx, FUTEX_WAKE, val, NULL, 0, 0);
}

static struct lkl_sem* sem_alloc(int count)
{
    struct lkl_sem* sem;

    sem = calloc(1, sizeof(*sem));
    if (!sem)
        return NULL;

    sem->count = count;

    return sem;
}

static void sem_free(struct lkl_sem* sem)
{
    free(sem);
}

static void sem_up(struct lkl_sem* sem)
{
    // Increment the semaphore count.  If we are moving from 0 to non-zero,
    // there may be waiters.  Wake one up.
    if (atomic_fetch_add(&sem->count, 1) == 0)
    {
        futex_wake(&sem->count, 1);
    }
}

static void sem_down(struct lkl_sem* sem)
{
    int count = sem->count;
    // Loop if the count is 0 or if we try to decrement it but fail.
    while ((count == 0) ||
           !atomic_compare_exchange_weak(&sem->count, &count, count - 1))
    {
        // If the value is non-zero, we lost a race, so try again (this
        // could be avoided by doing an atomic decrement and handling
        // the negative case, but this is the simplest possible
        // implementation).
        // If the value is 0, we need to wait until another thread
        // releases a value, so sleep and then reload the value of
        // count.
        if (count == 0)
        {
            futex_wait(&sem->count, 0);
            count = sem->count;
        }
    }
}

static struct lkl_mutex* mutex_alloc(int recursive)
{
    struct lkl_mutex* mutex = calloc(1, sizeof(struct lkl_mutex));

    if (!mutex)
        return NULL;

    mutex->is_recursive = recursive;

    return mutex;
}

static void mutex_lock(struct lkl_mutex* mutex)
{
    enum mutex_state state = unlocked;
    // Try to transition from from unlocked to locked with no waiters.  If
    // this works, return immediately, we've acquired the lock.  If not,
    // then we need to register ourself as a waiter.  This can spuriously
    // fail.  If it does, we hit the slow path when we don't need to, but
    // we are still correct.
    if (!atomic_compare_exchange_weak(&mutex->flag, &state, locked_no_waiters))
    {
        if (mutex->is_recursive && (mutex->owner == lthread_self()))
        {
            mutex->recursion_count++;
            return;
        }
        // Mark the mutex as having waiters.
        if (state != 2)
        {
            state = atomic_exchange(&mutex->flag, locked_waiters);
        }
        while (state != unlocked)
        {
            futex_wait((_Atomic(int)*)&mutex->flag, locked_waiters);
            state = atomic_exchange(&mutex->flag, locked_waiters);
        }
    }
    // If this is a recursive mutex, update the owner to this thread.
    // Skip for non-recursive mutexes to avoid the lthread_self call.
    if (mutex->is_recursive)
    {
        mutex->owner = lthread_self();
    }
}

static void mutex_unlock(struct lkl_mutex* mutex)
{
    // If this is a recursive mutex, we may not actually unlock it.
    if (mutex->is_recursive)
    {
        // If we are just undoing a recursive lock, decrement the
        // counter.
        if (mutex->recursion_count > 0)
        {
            mutex->recursion_count--;
            return;
        }
        // Clear the owner.
        mutex->owner = 0;
    }
    if (atomic_fetch_sub(&mutex->flag, 1) != locked_no_waiters)
    {
        // Implicitly sequentially-consistent atomic
        mutex->flag = 0;
        // Wake up all waiting threads.  We could improve this to wake
        // only one thread if we kept track of the number of waiters,
        // though doing that in a non-racy way is non-trivial.
        futex_wake((_Atomic(int)*)&mutex->flag, INT_MAX);
    }
}

static void mutex_free(struct lkl_mutex* _mutex)
{
    free(_mutex);
}

static lkl_thread_t thread_create(void (*fn)(void*), void* arg)
{
    struct lthread* thread;
    int ret = lthread_create(&thread, NULL, (void* (*)(void*))fn, arg);
    if (ret)
    {
        sgxlkl_fail("lthread_create failed: %s\n", lkl_strerror(ret));
    }
    LKL_TRACE("created (thread=%p)\n", thread);
    return (lkl_thread_t)thread;
}

/**
 * Create an lthread to back a Linux task, created with a clone-family call
 * into the kernel.
 */
static lkl_thread_t thread_create_host(void* pc, void* sp, void* tls, struct lkl_tls_key* task_key, void* task_value)
{
    struct lthread* thread;
    // Create the thread.  The lthread layer will set up the threading data
    // structures and prepare the lthread to run with the specified instruction
    // and stack addresses.
    int ret = lthread_create_primitive(&thread, pc, sp, tls);
    if (ret)
    {
        sgxlkl_fail("lthread_create failed\n");
    }
    // Store the host task pointer.  LKL normally sets this lazily the first
    // time that a thread calls into the LKL.  Threads created via this
    // mechanism begin life in the kernel and so need to be associated with the
    // kernel task that created them.
    lthread_setspecific_remote(thread, task_key->key, task_value);
    // Mark the thread as runnable.  This must be done *after* the
    // `lthread_setspecific_remote` call, to ensure that the thread does not
    // run while we are modifying its TLS.
    __scheduler_enqueue(thread);
    return (lkl_thread_t)thread;
}

static void host_thread_exit(void)
{
    LKL_TRACE("enter");
    lthread_exit(0);
}

 


/**
 * Destroy the lthread backing a host task created with a clone-family call.
 * This is called after an `exit` system call.  The system call does not return
 * and the lthread backing the LKL thread that issued the task will not be
 * invoked again.
 */
static void thread_destroy_host(lkl_thread_t tid, struct lkl_tls_key* task_key)
{
    static const size_t teardown_stack_size = 8192;
    struct lthread *thr = (struct lthread*)tid;
    // The thread is currently blocking on the LKL scheduler semaphore, remove
    // it from the sleeping list.
    _lthread_desched_sleep(thr);
    // Delete its task reference in TLS.  Without this, the thread's destructor
    // will call back into LKL and deadlock.
    lthread_setspecific_remote(thr, task_key->key, NULL);
    // Give the thread a stack to use during lthread teardown.
    thr->attr.stack_size = teardown_stack_size;
    thr->attr.stack = enclave_mmap(0, teardown_stack_size, 0, PROT_READ | PROT_WRITE, 1);
    // Set up the state so that this will call into the host_thread_exit function and 
    thr->ctx.eip = host_thread_exit;
    thr->ctx.esp = thr->attr.stack + teardown_stack_size;
    // Schedule the thread again.  It will exit when it is next scheduled.
    __scheduler_enqueue(thr);
}


static void thread_detach(void)
{
    LKL_TRACE("enter\n");
    lthread_detach();
}

static void thread_exit(void)
{
    LKL_TRACE("enter\n");
    lthread_exit(0);
}

static int thread_join(lkl_thread_t tid)
{
    LKL_TRACE("enter (tid=%li)\n", tid);
    int ret = lthread_join((struct lthread*)tid, NULL, -1);
    if (ret)
    {
        sgxlkl_fail("lthread_join failed: %s\n", lkl_strerror(ret));
    }
    return 0;
}

static lkl_thread_t thread_self(void)
{
    return (lkl_thread_t)lthread_self();
}

static int thread_equal(lkl_thread_t a, lkl_thread_t b)
{
    return a == b;
}

static struct lkl_tls_key* tls_alloc(void (*destructor)(void*))
{
    LKL_TRACE("enter (destructor=%p)\n", destructor);
    struct lkl_tls_key* ret = malloc(sizeof(struct lkl_tls_key));

    if (WARN_PTHREAD(lthread_key_create(&ret->key, destructor)))
    {
        free(ret);
        return NULL;
    }
    return ret;
}

static void tls_free(struct lkl_tls_key* key)
{
    LKL_TRACE("enter (key=%p)\n", key);
    WARN_PTHREAD(lthread_key_delete(key->key));
    free(key);
}

static int tls_set(struct lkl_tls_key* key, void* data)
{
    LKL_TRACE("enter (key=%p data=%p)\n", key, data);
    if (WARN_PTHREAD(lthread_setspecific(key->key, data)))
        return -1;
    return 0;
}

static void* tls_get(struct lkl_tls_key* key)
{
    return lthread_getspecific(key->key);
}

typedef struct sgxlkl_timer
{
    void (*callback_fn)(void*);
    void* callback_arg;
    unsigned long long delay_ns;
    unsigned long long next_delay_ns;
    struct lthread* thread;
    /**
     * Mutex used to protect access to this structure between threads setting
     * the timer and the thread that handles the callback.
     */
    struct lkl_mutex mtx;
    /**
     * Free-running counter used as a futex for wakeups.  The sleeping thread
     * reads the value with `mtx` held, releases `mtx`, then sleeps with the
     * read value as the expected version.  The waking thread increments this
     * counter with the `mtx` held before sending the futex wake.
     */
    _Atomic(int) wake;
    /** Flag indicating that the timer is armed. */
    _Atomic(bool) armed;
} sgxlkl_timer;

static void* timer_callback(void* _timer)
{
    sgxlkl_timer* timer = (sgxlkl_timer*)_timer;
    struct timespec timeout;
    struct timespec now;

    if (timer == NULL || timer->callback_fn == NULL)
    {
        sgxlkl_fail("timer_callback() called with unitialised timer.\n");
    }

    mutex_lock(&timer->mtx);

    do
    {
        if (timer->delay_ns <= 0)
        {
            SGXLKL_VERBOSE("timer->delay_ns=%llu <= 0\n", timer->delay_ns);
            break;
        }

        int ret = 0;
        timeout.tv_sec = timer->delay_ns / NSEC_PER_SEC;
        timeout.tv_nsec = timer->delay_ns % NSEC_PER_SEC;

        // Record the initial wake flag to before releasing the mutex.  We will
        // only ever be woken by a thread that holds the mutex, so this avoids a
        // race: the waking side will increment the counter and then wake us
        // with the mutex held, so `futex_wait` will return immediately if the
        // other thread increments the counter before waking us.
        int wake = timer->wake;
        mutex_unlock(&timer->mtx);
        bool did_timeout =
            futex_timed_wait(&timer->wake, wake, &timeout) == -ETIMEDOUT;
        mutex_lock(&timer->mtx);

        // Check if the timer should shut down
        if (!timer->armed)
        {
            break;
        }

        // Check if the timer has triggered
        if (did_timeout)
        {
            timer->callback_fn(timer->callback_arg);
            // If the callback function itself resets the timer,
            // timer->next_delay_ns will be non-zero.
            if (timer->next_delay_ns)
            {
                timer->delay_ns = timer->next_delay_ns;
                timer->next_delay_ns = 0;
            }
        }

    } while (timer->armed);
    mutex_unlock(&timer->mtx);

    lthread_exit(NULL);
}

static void* timer_alloc(void (*fn)(void*), void* arg)
{
    sgxlkl_timer* timer = calloc(sizeof(*timer), 1);

    if (timer == NULL)
    {
        sgxlkl_fail("LKL host op: timer_alloc() failed. OOM\n");
    }
    timer->callback_fn = fn;
    timer->callback_arg = arg;
    timer->armed = 0;
    timer->delay_ns = 0;
    timer->next_delay_ns = 0;

    return (void*)timer;
}

static int timer_set_oneshot(void* _timer, unsigned long ns)
{
    sgxlkl_timer* timer = (sgxlkl_timer*)_timer;

    // timer_set_oneshot is executed as part of the current timer's
    // callback. Do not try to acquire the lock we are already holding.
    if (timer->thread == lthread_self())
    {
        // Fail if the timer is being destroyed
        if (!timer->armed)
        {
            SGXLKL_VERBOSE("timer_set_oneshot() called on destroyed timer\n");
            return -1;
        }

        if (timer->next_delay_ns)
        {
            sgxlkl_fail("Bug: next_delay_ns already set for timer\n");
        }
        timer->next_delay_ns = ns;
    }
    else
    {
        mutex_lock(&timer->mtx);

        // Are we updating an armed timer or arming a new timer?
        if (timer->armed)
        {
            timer->delay_ns = ns;
            timer->wake++;
            futex_wake(&timer->wake, 1);
        }
        else
        {
            timer->armed = true;
            timer->delay_ns = ns;
            timer->next_delay_ns = 0;

            int res = lthread_create(
                &(timer->thread), NULL, &timer_callback, (void*)timer);
            if (res != 0)
            {
                sgxlkl_fail("pthread_create(timer_thread) returned %d\n", res);
            }
        }

        mutex_unlock(&timer->mtx);
    }

    return 0;
}

static void timer_free(void* _timer)
{
    sgxlkl_timer* timer = (sgxlkl_timer*)_timer;
    if (timer == NULL)
    {
        sgxlkl_fail("timer_free() called with NULL\n");
    }

    mutex_lock(&timer->mtx);

    bool current_value = true;
    if (atomic_compare_exchange_strong(&timer->armed, &current_value, false))
    {
        timer->wake++;
        futex_wake(&timer->wake, 1);
        mutex_unlock(&timer->mtx);

        void* exit_val = NULL;
        int res = lthread_join(timer->thread, &exit_val, -1);
        if (res != 0)
        {
            sgxlkl_warn("lthread_join(timer_thread) returned %d\n", res);
        }
    }
    else
    {
        SGXLKL_VERBOSE("timer->thread not armed\n");
        mutex_unlock(&timer->mtx);
    }

    free(_timer);
}

static long _gettid(void)
{
    return (long)lthread_self();
}

struct lkl_host_operations sgxlkl_host_ops = {
    .panic = panic,
    .terminate = terminate,
    .thread_create = thread_create,
    .thread_create_host = thread_create_host,
    .thread_destroy_host = thread_destroy_host,
    .thread_detach = thread_detach,
    .thread_exit = thread_exit,
    .thread_join = thread_join,
    .thread_self = thread_self,
    .thread_equal = thread_equal,
    .sem_alloc = sem_alloc,
    .sem_free = sem_free,
    .sem_up = sem_up,
    .sem_down = sem_down,
    .mutex_alloc = mutex_alloc,
    .mutex_free = mutex_free,
    .mutex_lock = mutex_lock,
    .mutex_unlock = mutex_unlock,
    .tls_alloc = tls_alloc,
    .tls_free = tls_free,
    .tls_set = tls_set,
    .tls_get = tls_get,
    .time = enclave_nanos,
    .timer_alloc = timer_alloc,
    .timer_set_oneshot = timer_set_oneshot,
    .timer_free = timer_free,
    .print = print,
    .mem_alloc = malloc,
    .mem_free = free,
    .ioremap = lkl_ioremap,
    .iomem_access = lkl_iomem_access,
    .virtio_devices = lkl_virtio_devs,
    .gettid = _gettid,
    .jmp_buf_set = sgxlkl_jmp_buf_set,
    .jmp_buf_longjmp = sgxlkl_jmp_buf_longjmp,
};
