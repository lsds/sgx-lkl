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

#ifndef QUEUES_H
#define QUEUES_H

#include "mpmc_queue.h"
#include "atomic.h"

extern struct mpmcq __scheduler_queue;
extern struct mpmcq *__syscall_queue;
extern struct mpmcq *__return_queue;

void __initschedqueue(size_t maxlthreads);
void __initsyscallqueues(struct mpmcq *sq, struct mpmcq *rq);

struct lthread;

static inline void __scheduler_enqueue(struct lthread *lt)
{
    if (!lt) {a_crash();}
    for (;!mpmc_enqueue(&__scheduler_queue, lt);) a_spin();
}
#endif /* QUEUES_H */
