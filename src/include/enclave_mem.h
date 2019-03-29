/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */

#ifndef ENCLAVE_MEM_H
#define ENCLAVE_MEM_H

void enclave_mman_init(void *base, size_t num_pages);
void* enclave_mmap(void *addr, size_t length, int mmap_fixed);
int enclave_munmap(void *addr, size_t length);
void* enclave_mremap(void *old_addr, size_t old_length, void *new_addr, size_t new_length, int mremap_fixed);
int enclave_mmap_flags_supported(int flags, int fd);

#endif /* ENCLAVE_MEM_H */
