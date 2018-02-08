/*
 * Copyright 2016, 2017, 2018 Imperial College London (under GNU General Public License v3)
 * Copyright 2016, 2017 TU Dresden (under SCONE source code license)
 */

#include "hostmem.h"
#include "hostsyscallclient.h"
#include "hostsyscalls.h"
#include <sys/mman.h>
#include "atomic.h"

void arena_new(Arena *a, size_t sz) {
    a->mem = host_syscall_SYS_mmap(0, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    if (a->mem == MAP_FAILED)
        a_crash();
    a->size = sz;
}

syscall_t *arena_ensure(Arena *a, size_t sz, syscall_t *sc) {
    if (a->size < sz) {
        void *newmem;
        newmem = host_syscall_SYS_mremap(a->mem, a->size, sz, MREMAP_MAYMOVE, 0);
        if (newmem != MAP_FAILED) {
            a->mem = newmem;
            a->size = sz;
        } else {
            a_crash();
        }
        return getsyscallslot(NULL);
    }
    return sc;
}

void *arena_alloc(Arena *a, size_t sz) {
    if (sz == 0) {
        return NULL;
    }
    void *ret = (void*)(a->mem + a->allocated);
    a->allocated += sz;
    return ret;
}

void arena_free(Arena *a) {
    a->allocated = 0;
}

void arena_destroy(Arena *a) {
    if (a->mem != 0) {
        host_syscall_SYS_munmap(a->mem, a->size);
        a->mem = 0;
        a->size = 0;
    }
}

size_t deepsizeiovec(const struct iovec *dst) {
    return sizeof(*dst) + dst->iov_len;
}

int deepinitiovec(Arena *a, struct iovec *dst, const struct iovec *src) {
    dst->iov_len = src->iov_len;
    dst->iov_base = arena_alloc(a, src->iov_len);
    return 1;
}

void deepcopyiovec(struct iovec *dst, const struct iovec *src) {
    if (dst->iov_len != src->iov_len) {*(int *)NULL = 0;}
    memcpy(dst->iov_base, src->iov_base, src->iov_len);
    dst->iov_len = src->iov_len;
}
