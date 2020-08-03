#include <linux/mman.h>
#include <lkl.h>
#include <lkl_host.h>
#include <sys/mman.h>

#include "enclave/enclave_mem.h"
#include "enclave/enclave_util.h"
#include "enclave/lthread_int.h"
#include "enclave/sgxlkl_t.h"

static long syscall_SYS_mprotect(void* addr, size_t len, int prot);

/**
 * Function used to implement the pread64 system call.
 * This is used in the mmap implementation, which cannot use `lkl_sys_pread64`
 * because doing a system call from within a system call is not allowed.
 */
static ssize_t (*pread_fn)(int fd, void* buf, size_t count, off_t offset);

/**
 * The LKL mmap function.  This is used as fallback from the mmap.
 */
static long (*mmap_fn)(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset);

/*
 * Returns 1 if we can mmap files using the given flags
 * returns 0 otherwise.
 */
int enclave_mmap_files_flags_supported(int flags)
{
    int supported_flags = 0;

    if (mmap_files == ENCLAVE_MMAP_FILES_SHARED)
        supported_flags = MAP_PRIVATE | MAP_SHARED;
    else if (mmap_files == ENCLAVE_MMAP_FILES_PRIVATE)
        supported_flags = MAP_PRIVATE;

    return supported_flags & flags;
}

long syscall_SYS_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    if ((flags & MAP_SHARED) && (flags & MAP_PRIVATE))
    {
        sgxlkl_warn("mmap() with MAP_SHARED and MAP_PRIVATE not supported\n");
        return -EINVAL;
    }
    // Anonymous mapping/allocation
    else if (fd == -1 && (flags & MAP_ANONYMOUS))
    {
        return (long)enclave_mmap(addr, length, flags & MAP_FIXED, prot, 1);
    }
    // File-backed mapping (if allowed)
    else if ((fd >= 0) && enclave_mmap_files_flags_supported(flags))
    {
        void* mem =
            enclave_mmap(addr, length, flags & MAP_FIXED, prot | PROT_WRITE, 0);

        if (mem > 0)
        {
            // Read file into memory
            size_t readb = 0;
            ssize_t ret = 0;
            while ((ret = pread_fn(
                        fd, ((char*)mem) + readb, length - readb, offset)) > 0)
            {
                readb += ret;
                offset += ret;
            };

            if (ret < 0)
            {
                enclave_munmap(addr, length);
                return -EBADF;
            }

            // Set requested page permissions
            if ((prot | PROT_WRITE) != prot)
                syscall_SYS_mprotect(mem, length, prot);
        }

        return (long)mem;
    }
    else
    {
        return -EINVAL;
    }
}

long syscall_SYS_mremap(
    void* old_addr,
    size_t old_length,
    size_t new_length,
    int flags,
    void* new_addr)
{
    return (long)enclave_mremap(
        old_addr, old_length, new_addr, new_length, flags & MREMAP_FIXED);
}

long syscall_SYS_munmap(void* addr, size_t length)
{
    // During thread teardown, libc unmaps the stack of the current thread
    // before doing an exit system call.  This works on a conventional system
    // because it's possible to do an exit system call without a stack.  With
    // LKL, the kernel and userspace share a stack and so any system call needs
    // a stack.  We work around this by deferring any attempt to unmap the
    // current stack.
    register void* rsp __asm__("rsp");
    if ((rsp > addr) && ((char*)rsp < ((char*)addr + length)))
    {
        struct lthread* lt = lthread_self();
        SGXLKL_ASSERT(lt->attr.stack == NULL);
        lt->attr.stack = addr;
        lt->attr.stack_size = length;
        return 0;
    }
    return enclave_munmap(addr, length);
}

long syscall_SYS_msync(void* addr, size_t length, int flags)
{
    return 0;
}

static long syscall_SYS_mprotect(void* addr, size_t len, int prot)
{
    long ret = 0;
    sgxlkl_host_syscall_mprotect((void*)&ret, addr, len, prot);
    return ret;
}

#if SGXLKL_ENABLE_SYSCALL_TRACING

/**
 * Wrapper for our `mmap` replacement that logs the arguments and result.
 */
static long syscall_SYS_mmap_log(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    long res = syscall_SYS_mmap(addr, length, prot, flags, fd, offset);
    __sgxlkl_log_syscall(
        SGXLKL_INTERNAL_SYSCALL,
        __lkl__NR_mmap,
        (long)res,
        6,
        (long)addr,
        (long)length,
        (long)prot,
        (long)flags,
        (long)fd,
        (long)offset);
    return res;
}

/**
 * Wrapper for our `mremap` replacement that logs the arguments and result.
 */
static long syscall_SYS_mremap_log(
    void* old_addr,
    size_t old_length,
    size_t new_length,
    int flags,
    void* new_addr)
{
    long res =
        syscall_SYS_mremap(old_addr, old_length, new_length, flags, new_addr);
    __sgxlkl_log_syscall(
        SGXLKL_INTERNAL_SYSCALL,
        __lkl__NR_mremap,
        (long)res,
        5,
        (long)old_addr,
        (long)old_length,
        (long)new_length,
        (long)flags,
        (long)new_addr);
    return res;
}

/**
 * Wrapper for our `munmap` replacement that logs the arguments and result.
 */
static long syscall_SYS_munmap_log(void* addr, size_t length)
{
    long res = syscall_SYS_munmap(addr, length);
    __sgxlkl_log_syscall(
        SGXLKL_INTERNAL_SYSCALL,
        __lkl__NR_munmap,
        res,
        2,
        (long)addr,
        (long)length);
    return res;
}

/**
 * Wrapper for our `msync` replacement that logs the arguments and result.
 */
static long syscall_SYS_msync_log(void* addr, size_t length, int flags)
{
    __sgxlkl_log_syscall(
        SGXLKL_INTERNAL_SYSCALL,
        __lkl__NR_msync,
        0,
        3,
        (long)addr,
        (long)length,
        (long)flags);
    return 0;
}

/**
 * Wrapper for our `mprotect` replacement that logs the arguments and result.
 */
static long syscall_SYS_mprotect_log(void* addr, size_t len, int prot)
{
    long res = syscall_SYS_mprotect(addr, len, prot);
    __sgxlkl_log_syscall(
        SGXLKL_INTERNAL_SYSCALL,
        __lkl__NR_mprotect,
        res,
        3,
        (long)addr,
        (long)len,
        (long)prot);
    return res;
}

#endif // SGXLKL_INTERNAL_SYSCALL

void syscall_register_mem_overrides(bool trace)
{
#if SGXLKL_ENABLE_SYSCALL_TRACING
    if (trace)
    {
        mmap_fn = (void*)lkl_replace_syscall(
            __lkl__NR_mmap, (lkl_syscall_handler_t)syscall_SYS_mmap_log);
        lkl_replace_syscall(
            __lkl__NR_munmap, (lkl_syscall_handler_t)syscall_SYS_munmap_log);
        lkl_replace_syscall(
            __lkl__NR_mremap, (lkl_syscall_handler_t)syscall_SYS_mremap_log);
        lkl_replace_syscall(
            __lkl__NR_msync, (lkl_syscall_handler_t)syscall_SYS_msync_log);
        lkl_replace_syscall(
            __lkl__NR_mprotect,
            (lkl_syscall_handler_t)syscall_SYS_mprotect_log);
    }
    else
#else
    (void)trace;
#endif
    {
        mmap_fn = (void*)lkl_replace_syscall(
            __lkl__NR_mmap, (lkl_syscall_handler_t)syscall_SYS_mmap);
        lkl_replace_syscall(
            __lkl__NR_munmap, (lkl_syscall_handler_t)syscall_SYS_munmap);
        lkl_replace_syscall(
            __lkl__NR_mremap, (lkl_syscall_handler_t)syscall_SYS_mremap);
        lkl_replace_syscall(
            __lkl__NR_msync, (lkl_syscall_handler_t)syscall_SYS_msync);
        lkl_replace_syscall(
            __lkl__NR_mprotect, (lkl_syscall_handler_t)syscall_SYS_mprotect);
    }
    // Get the function used for the pread64 system call so that we can read
    // data into memory in mmap.
    pread_fn = (void*)lkl_replace_syscall(__lkl__NR_pread64, NULL);
    lkl_replace_syscall(__lkl__NR_pread64, (lkl_syscall_handler_t)pread_fn);
}
