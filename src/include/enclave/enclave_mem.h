#ifndef ENCLAVE_MEM_H
#define ENCLAVE_MEM_H

#include <stddef.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <time.h>

void enclave_mman_init(const void* base, size_t num_pages, int _mmap_files);

void* enclave_mmap(
    void* addr,
    size_t length,
    int mmap_fixed,
    int prot,
    int zero_pages);

long enclave_munmap(void* addr, size_t length);

void* enclave_mremap(
    void* old_addr,
    size_t old_length,
    void* new_addr,
    size_t new_length,
    int mremap_fixed);

int enclave_mmap_files_flags_supported(int flags);

extern int mmap_files; // Allow MAP_PRIVATE or MAP_SHARED?

/**
 * Report memory usages (total and free bytes) in enclave
 */
void enclave_mem_info(size_t* total, size_t* free);

int enclave_mmap_flags_supported(int flags, int fd);

long syscall_SYS_munmap(void* addr, size_t length);

long syscall_SYS_mremap(
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    void* new_address);

long syscall_SYS_msync(void* addr, size_t length, int flags);

long syscall_SYS_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset);

int enclave_futex_wake(int* uaddr, int val);

#endif /* ENCLAVE_MEM_H */
