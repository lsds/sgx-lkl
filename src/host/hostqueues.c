/*
 * Copyright 2016, 2017, 2018 Imperial College London (under GNU General Public License v3)
 * Copyright 2016, 2017 TU Dresden (under SCONE source code license)
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
