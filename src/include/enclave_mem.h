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

#ifndef ENCLAVE_MEM_H
#define ENCLAVE_MEM_H

void enclave_mman_init(void *base, size_t num_pages);
void* enclave_mmap(void *addr, size_t length, int mmap_fixed);
int enclave_munmap(void *addr, size_t length);
void* enclave_mremap(void *old_addr, size_t old_length, void *new_addr, size_t new_length, int mremap_fixed);

#endif /* ENCLAVE_MEM_H */
