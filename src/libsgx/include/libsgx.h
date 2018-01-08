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

#ifndef LIBSGX_H
#define LIBSGX_H
#include <stdint.h>
#include "sgx.h"

#define PAGE_READ      0x1
#define PAGE_WRITE     0x2
#define PAGE_EXEC      0x4
#define PAGE_TCS       0x8
#define PAGE_NOEXTEND  0x10

#define ECREATE_NO_FIXED_ADDR (void*)-1

/* Initialize libsgx */
int   init_sgx();
/* Free EPC pages */
void  destroy_enclave();
void  execute_instructions();

/* SGX instructions wrappers */
uint64_t ecreate(size_t npages, int ssaSize, const void* sigstruct, void* baseaddr);
int      einit(uintptr_t base, void* sigstruct, void* einittoken); 
void     eenter(uint64_t tcs, uint64_t* rdi, uint64_t* rsi);
void     eresume(uint64_t tcs_id);
int      add_page(uint64_t base, uint64_t offset, uint64_t prot, const void* page);

/* High-level API */
void     enclave_sign(char* path, char* key, size_t heap, size_t stack, int tcs, int get_token);
uint64_t create_enclave(char* path, char* einit_path);
uint64_t create_enclave_mem(char* p, char* einit_path);
void     enter_enclave(int tcs_id, uint64_t call_id, void* arg, uint64_t* ret);
int      get_free_tcs_id();
int      get_tcs_num();

/* Debug functions */
uint64_t create_enclave_debug(char* path);
int      enter_enclave_debug(int tcs_id, uint64_t call_id, void* arg, uint64_t* ret);
#endif
