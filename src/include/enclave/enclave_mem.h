#ifndef ENCLAVE_MEM_H
#define ENCLAVE_MEM_H

#include <stddef.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <time.h>

#include "enclave/enclave_util.h"
#include "enclave/sgxlkl_t.h"

#ifndef PROT_NONE
#    define PROT_NONE 0x0
#endif
#ifndef PROT_READ
#    define PROT_READ 0x1
#endif
#ifndef PROT_WRITE
#    define PROT_WRITE 0x2
#endif
#ifndef PROT_EXEC
#    define PROT_EXEC 0x4
#endif

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

/**
 * Paranoid allocator.  Allocates on a separate page.
 */
static inline void* paranoid_alloc(size_t sz)
{
    // round up to page size:
    sz += 4096;
    sz %= 4096;
    void* ret =
        enclave_mmap(NULL, sz, /*fixed*/ 0, PROT_READ | PROT_WRITE, /*zero*/ 1);
    SGXLKL_ASSERT((intptr_t)ret > 0);

    return ret;
}

/**
 * Paranoid deallocate, marks the page as no-access and never reuses it.  This
 * should not be used in production because it will exhaust enclave memory
 * quite quickly, but can help tracking use-after-free bugs.
 */
static inline void paranoid_dealloc(void* p, size_t sz)
{
    // round up to page size:
    sz += 4096;
    sz %= 4096;
    int ret;
    sgxlkl_host_syscall_mprotect(&ret, p, sz, PROT_NONE);
}

#endif /* ENCLAVE_MEM_H */
