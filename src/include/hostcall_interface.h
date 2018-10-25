/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */

#ifndef HOSTCALL_INTERFACE_H
#define HOSTCALL_INTERFACE_H
#include "enclave_config.h"

struct mpmcq *__syscall_queue;
struct mpmcq *__return_queue;

struct Arena
{
    uint8_t *mem;
    size_t size;
    size_t allocated;
};
typedef struct Arena Arena;

int hostsyscallclient_init(enclave_config_t *encl);
syscall_t *getsyscallslot(Arena **a);
size_t allocslot(struct lthread *lt);
void freeslot(size_t slotno);
void threadswitch(syscall_t *sc);
struct lthread *slottolthread(size_t s);

void arena_new(Arena *, size_t);
syscall_t *arena_ensure(Arena *, size_t, syscall_t *);
void *arena_alloc(Arena *, size_t);
void arena_free(Arena *);
void arena_destroy(Arena *);

size_t deepsizeiovec(const struct iovec *dst);
int deepinitiovec(struct Arena *a, struct iovec *dst, const struct iovec *src);
void deepcopyiovec(struct iovec *dst, const struct iovec *src);

#endif /* HOSTCALL_INTERFACE_H */

