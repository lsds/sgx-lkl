#include <linux/mman.h>
#include <lkl.h>
#include <lkl_host.h>
#include <sys/mman.h>

#include "enclave/enclave_mem.h"
#include "enclave/enclave_util.h"
#include "enclave/lthread_int.h"
#include "enclave/sgxlkl_t.h"

static int syscall_SYS_mprotect(void* addr, size_t len, int prot);

/**
 * Function used to implement the pread64 system call.
 * This is used in the mmap implementation, which cannot use `lkl_sys_pread64`
 * because doing a system call from within a system call is not allowed.
 */
static ssize_t (*pread_fn)(int fd, void* buf, size_t count, off_t offset);

/**
 * The LKL mmap function.  This is used as fallback from the mmap.
 */
static void* (*mmap_fn)(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset);

/*
 * Returns 1 if syscall_SYS_mmap can be called with the specified flags,
 * returns 0 otherwise.
 */
int enclave_mmap_flags_supported(int flags, int fd)
{
    int supported_flags = -1;

    if (mmap_files == ENCLAVE_MMAP_FILES_SHARED)
        supported_flags = MAP_PRIVATE | MAP_SHARED;
    else if (mmap_files == ENCLAVE_MMAP_FILES_PRIVATE)
        supported_flags = MAP_PRIVATE;
    else
        supported_flags = 0;
    return (fd == -1 && (flags & MAP_ANONYMOUS)) || (supported_flags & flags);
}

void* syscall_SYS_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    void* mem;
    if ((flags & MAP_SHARED) && (flags & MAP_PRIVATE))
    {
        sgxlkl_warn("mmap() with MAP_SHARED and MAP_PRIVATE not supported\n");
        mem = (void*)-EINVAL;
    }
    // Anonymous mapping/allocation
    else if (fd == -1 && (flags & MAP_ANONYMOUS))
    {
        mem = enclave_mmap(addr, length, flags & MAP_FIXED, prot, 1);
        if ((intptr_t)mem < 0)
            return mem;
    }
    // File-backed mapping (if allowed)
    else if (fd >= 0 && enclave_mmap_flags_supported(flags, fd))
    {
        mem =
            enclave_mmap(addr, length, flags & MAP_FIXED, prot | PROT_WRITE, 0);
        if (mem > 0)
        {
            // Read file into memory
            size_t readb = 0, ret;
            while ((ret = pread_fn(
                        fd, ((char*)mem) + readb, length - readb, offset)) > 0)
            {
                readb += ret;
                offset += ret;
            }
            if (ret < 0)
            {
                enclave_munmap(addr, length);
                return (void*)-EBADF;
            }
            // Set requested page permissions
            if ((prot | PROT_WRITE) != prot)
                syscall_SYS_mprotect(mem, length, prot);
        }
    }
    else
    {
        mem = mmap_fn(addr, length, prot, MAP_PRIVATE, fd, offset);
    }
    return mem;
}

void* syscall_SYS_mremap(
    void* old_addr,
    size_t old_length,
    size_t new_length,
    int flags,
    void* new_addr)
{
    return enclave_mremap(
        old_addr, old_length, new_addr, new_length, flags & MREMAP_FIXED);
}

int syscall_SYS_munmap(void* addr, size_t length)
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
    enclave_munmap(addr, length);
    return 0;
}

int syscall_SYS_msync(void* addr, size_t length, int flags)
{
    return 0;
}

static int syscall_SYS_mprotect(void* addr, size_t len, int prot)
{
    int ret;
    sgxlkl_host_syscall_mprotect(&ret, addr, len, prot);
    return ret;
}

#if SGXLKL_ENABLE_SYSCALL_TRACING

/**
 * Wrapper for our `mmap` replacement that logs the arguments and result.
 */
static void* syscall_SYS_mmap_log(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    void* res = syscall_SYS_mmap(addr, length, prot, flags, fd, offset);
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
static void* syscall_SYS_mremap_log(
    void* old_addr,
    size_t old_length,
    size_t new_length,
    int flags,
    void* new_addr)
{
    void* res =
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
static int syscall_SYS_munmap_log(void* addr, size_t length)
{
    int res = syscall_SYS_munmap(addr, length);
    __sgxlkl_log_syscall(
        SGXLKL_INTERNAL_SYSCALL,
        __lkl__NR_munmap,
        res,
        2,
        (long)addr,
        (long)length);
    return 0;
}

/**
 * Wrapper for our `msync` replacement that logs the arguments and result.
 */
static int syscall_SYS_msync_log(void* addr, size_t length, int flags)
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
static int syscall_SYS_mprotect_log(void* addr, size_t len, int prot)
{
    int res = syscall_SYS_mprotect(addr, len, prot);
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
