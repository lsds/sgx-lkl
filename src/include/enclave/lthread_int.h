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
 * lthread_int.c
 */

#ifndef LTHREAD_INT_H
#define LTHREAD_INT_H

#include <enclave/lthread.h>
#include <errno.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#define LT_MAX_EVENTS (1024)
#define MAX_STACK_SIZE (512 * 1024) /* 512k */

#define BIT(x) (1 << (x))
#define CLEARBIT(x) ~(1 << (x))
#define WAIT_LIMITLESS ~((uint64_t)0)
#define WAIT_TIMEOUT (WAIT_LIMITLESS - 1)

struct lthread;

struct lthread_sched;

int _lthread_sched_init(size_t stack_size);

int _lthread_resume(struct lthread* lt);

void _lthread_renice(struct lthread* lt);

void _lthread_yield(struct lthread* lt);

void _lthread_yield_cb(struct lthread* lt, void (*f)(void*), void* arg);

void _lthread_free(struct lthread* lt);

void _lthread_desched_sleep(struct lthread* lt);

int _save_exec_state(struct lthread* lt);

void print_timestamp(char*);

static inline uint64_t _lthread_timespec_to_usec(const struct timespec* ts)
{
    return (ts->tv_sec * 1000000) + ts->tv_nsec / 1000;
}

// TODO: should this be static?
static inline struct schedctx *__scheduler_self()
{
	struct schedctx *self;
	__asm__ __volatile__ ("mov %%gs:48,%0" : "=r" (self) );
	return self;
}


static inline struct lthread_sched*
lthread_get_sched()
{
    struct schedctx *c = __scheduler_self();
    return &c->sched;
}

#endif /* LTHREAD_INT_H */
