#include <linux/mman.h>
#include <lkl.h>
#include <lkl_host.h>
#include <sys/mman.h>

#include "enclave/enclave_mem.h"
#include "enclave/enclave_util.h"
#include "enclave/lthread_int.h"
#include "enclave/sgxlkl_t.h"


/**
 * Function used to implement the pread64 system call.
 * This is used in the mmap implementation, which cannot use `lkl_sys_pread64`
 * because doing a system call from within a system call is not allowed.
 */
static ssize_t (*pread_fn)(int fd, void* buf, size_t count, off_t offset);

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
            while ((ret = pread(
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
                mprotect(mem, length, prot);
        }

        return (long)mem;
    }
    else
    {
        return -EINVAL;
    }
}

void syscall_register_mem_overrides()
{
    // Get the function used for the pread64 system call so that we can read
    // data into memory in mmap.
    pread_fn = (void*)lkl_replace_syscall(__lkl__NR_pread64, NULL);
    lkl_replace_syscall(__lkl__NR_pread64, (lkl_syscall_handler_t)pread_fn);
}
