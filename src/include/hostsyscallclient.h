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

#ifndef HOSTSYSCALLCLIENT_H
#define HOSTSYSCALLCLIENT_H
#include "enclave_config.h"
#include <hostmem.h>
#include <lthread.h>

int hostsyscallclient_init(enclave_config_t *encl);
syscall_t *getsyscallslot(Arena **a);
size_t allocslot(struct lthread *lt);
void freeslot(size_t slotno);
void threadswitch(syscall_t *sc);
struct lthread *slottolthread(size_t s);

#endif /* HOSTSYSCALLCLIENT_H */

