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

#include <lthread.h>
#include "hostqueues.h"

struct mpmcq __scheduler_queue;
struct mpmcq *__syscall_queue;
struct mpmcq *__return_queue;

static uint64_t roundup2(uint64_t s) {
    s--;
    s |= s >> 1;
    s |= s >> 2;
    s |= s >> 4;
    s |= s >> 8;
    s |= s >> 16;
    s |= s >> 32;
    s++;
    return s;
}

void __initschedqueue(size_t maxlthreads) {
    newmpmcq(&__scheduler_queue, roundup2(maxlthreads), 0);
}

void __initsyscallqueues(struct mpmcq *sq, struct mpmcq *rq) {
    __return_queue = rq;
    __syscall_queue = sq;
}
