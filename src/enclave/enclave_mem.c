#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#define _GNU_SOURCE

#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "shared/sgxlkl_enclave_config.h"

#include "enclave/bitops.h"
#include "enclave/lthread.h"
#include "enclave/enclave_mem.h"
#include "enclave/enclave_util.h"
#include "enclave/lthread_int.h"
#include "enclave/ticketlock.h"

static struct ticketlock mmaplock;

static void* mmap_bitmap;       // Memory allocation bitmap
static void* mmap_fresh_bitmap; // Zeroed pages bitmap (records if a page is
                                // guaranteed to be zeroed)
static void* mmap_base;         // First page that can be mmap'ed
static void* mmap_end;          // Last page that can be mmap'ed
static size_t mmap_num_pages;   // Total number of pages that can be mmap'ed

static int mmap_files; // Allow MAP_PRIVATE or MAP_SHARED?

static size_t used_pages =
    0; // Tracks the number of used pages for the mmap tracing

#if DEBUG
extern int sgxlkl_trace_mmap;
static size_t mmap_max_allocated = 0; // Maximum amount of memory used thus far
#endif

#define DIV_ROUNDUP(x, y) (((x) + ((y)-1)) / (y))

#define for_each_set_bit_in_region(bit, addr, size, start)                     \
    for ((bit) = find_next_bit((addr), (size), (start)); (bit) < (start + nr); \
         (bit) = find_next_bit((addr), (size), (bit) + 1))

static inline unsigned long bitmap_count_set_bits(
    unsigned long* map,
    unsigned long size,
    unsigned long start,
    unsigned long nr)
{
    unsigned bit;
    unsigned retval = 0;

    for_each_set_bit_in_region(bit, map, size, start) retval++;
    return (retval);
}

static inline unsigned long bitmap_find_next_zero_area(
    unsigned long* map,
    unsigned long size,
    unsigned long start,
    unsigned long nr)
{
    unsigned long index, end, i;
    for (;;)
    {
        index = find_next_zero_bit(map, size, start);

        end = index + nr;
        if (end > size)
        {
            return end;
        }
        i = find_next_bit(map, end, index);
        if (i < end)
        {
            start = i + 1;
            continue;
        }
        return index;
    }
}

static int in_mmap_range(void* addr, size_t size)
{
    return addr >= mmap_base && ((char*)addr + size) <= (char*)mmap_end;
}

static void* index_to_addr(size_t index)
{
    return (char*)mmap_end - (index * PAGE_SIZE);
}

static size_t addr_to_index(void* addr)
{
    return ((char*)mmap_end - (char*)addr) / PAGE_SIZE;
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
            if(pread(fd, mem, length, offset) < 0)
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

    return enclave_munmap(addr, length);
}

int syscall_SYS_msync(void* addr, size_t length, int flags)
{
    return 0;
}

void enclave_mem_info(size_t* total, size_t* free)
{
    *total = mmap_num_pages * PAGESIZE;
    *free = (mmap_num_pages - used_pages) * PAGESIZE;
}

/*
 * Initializes the enclave memory management.
 *
 * base specifies the base address of the enclave heap, and num_pages the
 * number of pages starting at the base address to manage.
 *
 * The mmap_bitmap is used to keep track of mapped/unmapped pages in the
 * range of base to base + num_pages * PAGE_SIZE. The bitmap occupies the
 * first few pages of enclave memory.
 *
 * The mmap_fresh_bitmap is used to keep track of yet untouched pages,
 * which are zero inside of the enclave. These pages therefore do not have
 * to be set to zero when mmap'ed, thus avoiding unnecessary paging.
 */
void enclave_mman_init(const void* base, size_t num_pages, int _mmap_files)
{
    // Don't use page at address 0x0.
    if (base == 0x0)
    {
        base = (char*)base + PAGE_SIZE;
        num_pages = num_pages - 1;
    }

    // Determine required size (in pages) for the bitmap.
    size_t bitmap_req_pages = DIV_ROUNDUP(num_pages, BITS_PER_BYTE * PAGE_SIZE);
    mmap_num_pages = num_pages - (2 * bitmap_req_pages);

    // Bitmaps are stored at the beginning of the enclave memory range
    mmap_bitmap = (void*)base;
    mmap_fresh_bitmap = (char*)mmap_bitmap + (bitmap_req_pages * PAGE_SIZE);

    // Base address for range of pages available to mmap calls
    mmap_base = (char*)mmap_bitmap + (2 * bitmap_req_pages * PAGE_SIZE);
    mmap_end = (char*)mmap_base + (mmap_num_pages - 1) * PAGE_SIZE;

    // Initialise mmap allocation bitmap
    bitmap_clear(mmap_bitmap, 0, mmap_num_pages);
    // Initialise mmap zeroed bitmap
    bitmap_set(mmap_fresh_bitmap, 0, mmap_num_pages);

    mmap_files = _mmap_files;
}

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

/*
 * Simple mmap implementation for the enclave
 *
 * addr - address at which to allocate the memory
 * length - size of memory to allocate (in bytes)
 * mmap_fixed - force fixed mmap mapping
 * prot - page protection to set on allocated memory
 * zero_pages - flag whether to zero allocated pages
 */
void* enclave_mmap(
    void* addr,
    size_t length,
    int mmap_fixed,
    int prot,
    int zero_pages)
{
    void* ret = 0;
    size_t pages = DIV_ROUNDUP(length, PAGE_SIZE);
    size_t replaced_pages = 0;
    size_t index_top = 0;

    // Make sure addr is page aligned and size is greater than 0
    if ((uintptr_t)addr % PAGE_SIZE != 0 || length == 0)
    {
        return (void*)-EINVAL;
    }

    // Obtain mmap lock to access mmap bitmaps
    ticket_lock(&mmaplock);

    // Fixed mmap allocation
    if (mmap_fixed)
    {
        if (!in_mmap_range(addr, length))
        {
            ret = (void*)-ENOMEM;
        }
        else
        {
            // Get index for last page since the bitmap is used in reverse
            index_top = addr_to_index(addr) - (pages - 1);

#if DEBUG
            if (sgxlkl_trace_mmap)
                replaced_pages = bitmap_count_set_bits(
                    mmap_bitmap, mmap_num_pages, index_top, pages);
#endif

            bitmap_set(mmap_bitmap, index_top, pages);
            ret = addr;
        }
    }
    // Allocation with address hint
    else if (addr != 0 && in_mmap_range(addr, length))
    {
        // Get index for last page since the bitmap is used in reverse
        index_top = addr_to_index(addr) - (pages - 1);

        // Address provided as a hint, check if range is available
        if (!bitmap_count_set_bits(
                mmap_bitmap, mmap_num_pages, index_top, pages))
        {
            bitmap_set(mmap_bitmap, index_top, pages);
            ret = addr;
        }
    }

    // Find next area with sufficient space
    if (ret == 0)
    {
        index_top =
            bitmap_find_next_zero_area(mmap_bitmap, mmap_num_pages, 0, pages);
        if (index_top + pages > mmap_num_pages)
        {
            ret = (void*)-ENOMEM;
        }
        else
        {
            bitmap_set(mmap_bitmap, index_top, pages);
            size_t index = index_top + (pages - 1);
            ret = index_to_addr(index);
        }
    }

    // Was there a successful allocation?
    if (ret >= 0)
    {
        int found_only_fresh_pages = 0;

        if (zero_pages)
        {
            // Are there allocated pages that are not fresh and need to be
            // zeroed?
            found_only_fresh_pages =
                (bitmap_count_set_bits(
                     mmap_fresh_bitmap, mmap_num_pages, index_top, pages) ==
                 pages);
        }

        // Allocated pages are no longer fresh
        bitmap_clear(mmap_fresh_bitmap, index_top, pages);

        // Release lock early
        ticket_unlock(&mmaplock);

        // Check if we need to zero the allocated pages
        if (zero_pages && !found_only_fresh_pages)
        {
            // Since there are pages that are not fresh, their page protection
            // may have changed
            if (prot != -1)
            {
                // Make pages writeable
                mprotect(ret, length, prot | PROT_WRITE);
            }

            // Set all allocated pages to zero
            memset(ret, 0, pages * PAGE_SIZE);

            // Restore the correct page permissions
            if (prot != -1 && ((prot | PROT_WRITE) != prot))
            {
                mprotect(ret, length, prot);
            }
        }

        // Do we need to set page permissions (if zeroing above did not already
        // set the correct page permissions)?
        if (prot != -1 && (!zero_pages || found_only_fresh_pages))
        {
            // Set requested page permission
            mprotect(ret, length, prot);
        }

        used_pages += pages - replaced_pages;
    }
    else
    {
        // Release lock
        ticket_unlock(&mmaplock);
    }

#if DEBUG
    if (sgxlkl_trace_mmap)
    {
        size_t requested = pages * PAGESIZE;
        size_t total = mmap_num_pages * PAGESIZE;
        size_t free = (mmap_num_pages - used_pages) * PAGESIZE;
        size_t used = total - free;
        if (mmap_max_allocated < used)
        {
            mmap_max_allocated = used;
        }
        char* mfixed = mmap_fixed ? " (MAP_FIXED)" : "";
        char* rv = ret < 0 ? " (FAILED)" : "";
        SGXLKL_TRACE_MMAP(
            "mmap stats: TOTAL: %8zuKB, USED: %8zuKB, MAX USED: %8zuKB, FREE: "
            "%8zuKB, ALLOCATED: %6zuKB (addr = %p, ret = %p) %s%s\n",
            total / 1024,
            used / 1024,
            mmap_max_allocated / 1024,
            free / 1024,
            requested / 1024,
            addr,
            ret,
            mfixed,
            rv);
    }
#endif

    return ret;
}

/*
 * munmap for enclave memory range
 */
int enclave_munmap(void* addr, size_t length)
{
    size_t pages = DIV_ROUNDUP(length, PAGE_SIZE);

    // Make sure addr is page aligned and size is greater than 0
    if ((uintptr_t)addr % PAGE_SIZE != 0 || length == 0 ||
        !in_mmap_range(addr, length))
    {
        return -EINVAL;
    }

    size_t index = addr_to_index(addr);
    size_t index_top = index - (pages - 1);

    ticket_lock(&mmaplock);

    // Only count pages that have been marked as mmapped before
    size_t occupied_pages =
        bitmap_count_set_bits(mmap_bitmap, mmap_num_pages, index_top, pages);
    used_pages -= occupied_pages;

    bitmap_clear(mmap_bitmap, index_top, pages);
    ticket_unlock(&mmaplock);

#if DEBUG
    if (sgxlkl_trace_mmap)
    {
        size_t requested = pages * PAGESIZE;
        size_t total = mmap_num_pages * PAGESIZE;
        size_t free = (mmap_num_pages - used_pages) * PAGESIZE;
        size_t used = total - free;
        SGXLKL_TRACE_MMAP(
            "munmap stats: TOTAL: %8zuKB, USED: %8zuKB, MAX USED: %8zuKB, "
            "FREE: %8zuKB,     FREED: %6zuKB (addr = %p)\n",
            total / 1024,
            used / 1024,
            mmap_max_allocated / 1024,
            free / 1024,
            requested / 1024,
            addr);
    }
#endif

    return 0;
}

/*
 * mremap for enclave memory range
 */
void* enclave_mremap(
    void* old_addr,
    size_t old_length,
    void* new_addr,
    size_t new_length,
    int mremap_fixed)
{
    // TODO: If possible, extend region without copying memory
    // TODO: Support for MREMAP_FIXED

    if (mremap_fixed)
    {
        errno = EINVAL;
        return MAP_FAILED;
    }

    void* ret = enclave_mmap(new_addr, new_length, 0, -1, 0);
    if (ret != MAP_FAILED)
    {
        memcpy(
            ret, old_addr, old_length > new_length ? new_length : old_length);
        enclave_munmap(old_addr, old_length);
    }

    return ret;
}
