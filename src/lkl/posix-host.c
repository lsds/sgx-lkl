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

#include <pthread.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "syscall.h"
#include "atomic.h"
#include <poll.h>
#include <lkl_host.h>
#include "lkl/iomem.h"
#include "lkl/jmp_buf.h"

/* Let's see if the host has semaphore.h */
#include <unistd.h>

#ifdef _POSIX_SEMAPHORES
#include <semaphore.h>
/* TODO(pscollins): We don't support fork() for now, but maybe one day
 * we will? */
#define SHARE_SEM 0
#endif /* _POSIX_SEMAPHORES */

#define LKL_STDOUT_FILENO 1
#define NSEC_PER_SEC 1000000000L

static void panic(void) {
    // Even a simple print or abort(0) uses syscalls.
    // We cannot use syscalls in this case, since we might never
    // get rescheduled.
    a_crash();
}

static void print(const char *str, int len) {
    write(LKL_STDOUT_FILENO, str, len);
}

struct lkl_mutex {
    pthread_mutex_t mutex;
};

struct lkl_sem {
#ifdef _POSIX_SEMAPHORES
    sem_t sem;
#else
    pthread_mutex_t lock;
    int count;
    pthread_cond_t cond;
#endif /* _POSIX_SEMAPHORES */
};

struct lkl_tls_key {
        pthread_key_t key;
};

#define WARN_UNLESS(exp) do {                              \
        if (exp < 0)                                       \
            lkl_printf("%s: %s\n", #exp, strerror(errno)); \
    } while (0)

static int _warn_pthread(int ret, char *str_exp) {
    if (ret > 0)
        lkl_printf("%s: %s\n", str_exp, strerror(ret));

    return ret;
}


/* pthread_* functions use the reverse convention */
#define WARN_PTHREAD(exp) _warn_pthread(exp, #exp)

static struct lkl_sem *sem_alloc(int count) {
    struct lkl_sem *sem;

    sem = malloc(sizeof(*sem));
    if (!sem)
        return NULL;

#ifdef _POSIX_SEMAPHORES
    if (sem_init(&sem->sem, SHARE_SEM, count) < 0) {
        lkl_printf("sem_init: %s\n", strerror(errno));
        free(sem);
        return NULL;
    }
#else
    pthread_mutex_init(&sem->lock, NULL);
    sem->count = count;
    WARN_PTHREAD(pthread_cond_init(&sem->cond, NULL));
#endif /* _POSIX_SEMAPHORES */

    return sem;
}

static void sem_free(struct lkl_sem *sem) {
#ifdef _POSIX_SEMAPHORES
    WARN_UNLESS(sem_destroy(&sem->sem));
#else
    WARN_PTHREAD(pthread_cond_destroy(&sem->cond));
    WARN_PTHREAD(pthread_mutex_destroy(&sem->lock));
#endif /* _POSIX_SEMAPHORES */
    free(sem);
}

static void sem_up(struct lkl_sem *sem) {
#ifdef _POSIX_SEMAPHORES
    WARN_UNLESS(sem_post(&sem->sem));
#else
    WARN_PTHREAD(pthread_mutex_lock(&sem->lock));
    sem->count++;
    if (sem->count > 0)
        WARN_PTHREAD(pthread_cond_signal(&sem->cond));
    WARN_PTHREAD(pthread_mutex_unlock(&sem->lock));
#endif /* _POSIX_SEMAPHORES */
}

static void sem_down(struct lkl_sem *sem) {
    // Applications do not expect changes to the errno value by LKL. Keep track
    // of the current value and restore it at the end of sem_down.
    int curr_errno = errno;

#ifdef _POSIX_SEMAPHORES
    int err;

    do {
        err = sem_wait(&sem->sem);
    } while (err < 0 && errno == EINTR);
    if (err < 0 && errno != EINTR)
        lkl_printf("sem_wait: %s\n", strerror(errno));
#else
    WARN_PTHREAD(pthread_mutex_lock(&sem->lock));
    while (sem->count <= 0)
        WARN_PTHREAD(pthread_cond_wait(&sem->cond, &sem->lock));
    sem->count--;
    WARN_PTHREAD(pthread_mutex_unlock(&sem->lock));
#endif /* _POSIX_SEMAPHORES */

    // Restore errno.
    errno = curr_errno;
}

static struct lkl_mutex *mutex_alloc(int recursive) {
    struct lkl_mutex *_mutex = malloc(sizeof(struct lkl_mutex));
    pthread_mutex_t *mutex = NULL;
    pthread_mutexattr_t attr;

    if (!_mutex)
        return NULL;

    mutex = &_mutex->mutex;
    WARN_PTHREAD(pthread_mutexattr_init(&attr));

    /* PTHREAD_MUTEX_ERRORCHECK is *very* useful for debugging,
     * but has some overhead, so we provide an option to turn it
     * off. */
#ifdef DEBUG
    if (!recursive)
        WARN_PTHREAD(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK));
#endif /* DEBUG */

    if (recursive)
        WARN_PTHREAD(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE));

    WARN_PTHREAD(pthread_mutex_init(mutex, &attr));

    return _mutex;
}

static void mutex_lock(struct lkl_mutex *mutex) {
    WARN_PTHREAD(pthread_mutex_lock(&mutex->mutex));
}

static void mutex_unlock(struct lkl_mutex *_mutex) {
    pthread_mutex_t *mutex = &_mutex->mutex;
    WARN_PTHREAD(pthread_mutex_unlock(mutex));
}

static void mutex_free(struct lkl_mutex *_mutex) {
    pthread_mutex_t *mutex = &_mutex->mutex;
    WARN_PTHREAD(pthread_mutex_destroy(mutex));
    free(_mutex);
}

static lkl_thread_t thread_create(void (*fn)(void *), void *arg) {
    pthread_t thread;
    if (WARN_PTHREAD(pthread_create(&thread, NULL, (void* (*)(void *))fn, arg)))
        return 0;
    else
        return (lkl_thread_t) thread;
}

static void thread_detach(void) {
    WARN_PTHREAD(pthread_detach(pthread_self()));
}

static void thread_exit(void) {
    pthread_exit(NULL);
}

static int thread_join(lkl_thread_t tid) {
    if (WARN_PTHREAD(pthread_join((pthread_t)tid, NULL)))
        return -1;
    else
        return 0;
}

static lkl_thread_t thread_self(void) {
        return (lkl_thread_t)pthread_self();
}

static int thread_equal(lkl_thread_t a, lkl_thread_t b) {
        return pthread_equal(a, b);
}

static struct lkl_tls_key *tls_alloc(void (*destructor)(void *)) {
        struct lkl_tls_key *ret = malloc(sizeof(struct lkl_tls_key));

        if (WARN_PTHREAD(pthread_key_create(&ret->key, destructor))) {
                free(ret);
                return NULL;
        }
        return ret;
}

static void tls_free(struct lkl_tls_key *key) {
        WARN_PTHREAD(pthread_key_delete(key->key));
        free(key);
}

static int tls_set(struct lkl_tls_key *key, void *data) {
        if (WARN_PTHREAD(pthread_setspecific(key->key, data)))
                return -1;
        return 0;
}

static void *tls_get(struct lkl_tls_key *key) {
        return pthread_getspecific(key->key);
}

static unsigned long long time_ns(void) {
    struct timespec ts = {0};
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        panic();
    return 1e9*ts.tv_sec + ts.tv_nsec;
}

typedef struct sgx_lkl_timer {
    void (*callback_fn)(void*);
    void *callback_arg;
    unsigned long long delay_ns;
    unsigned long long next_delay_ns;
    pthread_t thread;
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    int armed;
} sgx_lkl_timer;

static void* timer_callback(void *_timer) {
    sgx_lkl_timer *timer = (sgx_lkl_timer*)_timer;
    int rc,res;

    struct timespec timeout;
    struct timespec now;
    if (timer == NULL || timer->callback_fn == NULL) {
        fprintf(stderr, "WARN: timer_callback() called with unitialised timer.\n");
        pthread_exit(NULL);
    }

    pthread_mutex_lock(&timer->mtx);
    do {
restart:
        if (timer->delay_ns <= 0) break;
        clock_gettime(CLOCK_REALTIME, &now);
        timeout.tv_sec = now.tv_sec + (timer->delay_ns / NSEC_PER_SEC);
        timeout.tv_nsec = now.tv_nsec + (timer->delay_ns % NSEC_PER_SEC);
        if (!timer->armed) {
            break;
        }
        rc = pthread_cond_timedwait(&timer->cv, &timer->mtx, &timeout);
        if (rc == ETIMEDOUT) {
            timer->callback_fn(timer->callback_arg);
            // If the callback function itself resets the timer,
            // timer->next_delay_ns will be non-zero.
            if (timer->armed && timer->next_delay_ns) {
                timer->delay_ns = timer->next_delay_ns;
                timer->next_delay_ns = 0;
                goto restart;
            }
        } else {
            /* Timer was stopped */
            if (!timer->armed) {
                break;
            }

            /* timer_set_oneshot was called while sleeping. */
            goto restart;

        }
        if (!timer->armed)
            break;

        rc = pthread_cond_wait(&timer->cv, &timer->mtx);
    } while (timer->armed);

    pthread_mutex_unlock(&timer->mtx);

    WARN_PTHREAD(pthread_cond_destroy(&timer->cv));
    WARN_PTHREAD(pthread_mutex_destroy(&timer->mtx));
    pthread_exit(NULL);
}

static void *timer_alloc(void (*fn)(void *), void *arg) {
    sgx_lkl_timer *timer = calloc(sizeof(*timer), 1);
    if (timer == NULL) {
        fprintf(stderr, "LKL host op: timer_alloc() failed, OOM\n");
        panic();
    }
    timer->callback_fn = fn;
    timer->callback_arg = arg;
    timer->armed = 0;
    timer->delay_ns = 0;
    timer->next_delay_ns = 0;
    return (void*)timer;
}

static int timer_set_oneshot(void *_timer, unsigned long ns) {
    sgx_lkl_timer *timer = (sgx_lkl_timer*)_timer;

    // Overwrite settings if timer was already armed
    int armed = a_swap(&(timer->armed), 1);
    if (armed == 1) {
        if (timer->thread == lthread_self()) {
            // timer_set_oneshot is executed as part of the current timer's
            // callback. Do not try to acquire the lock we are already holding.
            if (timer->next_delay_ns) {
                fprintf(stderr, "next_delay_ns already set.");
                panic();
            }
            timer->next_delay_ns = ns;
        } else {
            timer->delay_ns = ns;
            WARN_PTHREAD(pthread_mutex_lock(&timer->mtx));
            WARN_PTHREAD(pthread_cond_signal(&timer->cv));
            WARN_PTHREAD(pthread_mutex_unlock(&timer->mtx));
        }

        return 0;
    }

    int res = 0;
    timer->armed = 1;
    timer->delay_ns = ns;
    timer->next_delay_ns = 0;
    pthread_mutex_init(&timer->mtx,NULL);
    pthread_cond_init(&timer->cv,NULL);
    res = pthread_create(&(timer->thread), NULL, &timer_callback,
        (void*)timer);

    if (res != 0) {
        fprintf(stderr, "Error: pthread_create(timerfn) returned %d\n", res);
        panic();
    }

    return 0;
}

static void timer_free(void *_timer) {
    sgx_lkl_timer *timer = (sgx_lkl_timer*)_timer;
    if (timer == NULL) {
        fprintf(stderr, "WARN: timer_free() called with NULL\n");
        panic();
    }

    int res = 0;
    if (timer->armed) {
        WARN_PTHREAD(pthread_mutex_lock(&timer->mtx));
        timer->armed = 0;
        WARN_PTHREAD(pthread_cond_signal(&timer->cv));
        WARN_PTHREAD(pthread_mutex_unlock(&timer->mtx));

        a_barrier();
        void *exit_val = NULL;
        res = pthread_join(timer->thread, &exit_val);
        if (res != 0)
            lkl_printf("WARN: pthread_join(timer) returned %d\n",
                res);
    }
    free(_timer);
}

static long _gettid(void) {
    return (long)pthread_self();
}

struct lkl_host_operations sgxlkl_host_ops = {
    .panic = panic,
    .thread_create = thread_create,
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
    .time = time_ns,
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

