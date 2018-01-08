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

#ifndef HOSTMEM_H
#define HOSTMEM_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include "enclave_config.h"
struct Arena
{
    uint8_t *mem;
    size_t size;
    size_t allocated;
};
typedef struct Arena Arena;

void arena_new(Arena *, size_t);
syscall_t *arena_ensure(Arena *, size_t, syscall_t *);
void *arena_alloc(Arena *, size_t);
void arena_free(Arena *);
void arena_destroy(Arena *);

size_t deepsizeiovec(const struct iovec *dst);
int deepinitiovec(struct Arena *a, struct iovec *dst, const struct iovec *src);
void deepcopyiovec(struct iovec *dst, const struct iovec *src);
#endif /* HOSTMEM_H */
