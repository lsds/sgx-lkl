/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */

#include <errno.h>
#include <limits.h>
#include <string.h>
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/sysinfo.h>

#include "bitops.h"
#include "enclave_mem.h"
#include "sgx_hostcalls.h"
#include "ticketlock.h"
#include "sgxlkl_debug.h"

static struct ticketlock mmaplock;

static void* mmap_bitmap;
static void* mmap_base; // First page that can be mmap'ed.
static void* mmap_end;  // Last page that can be mmap'ed.
static size_t mmap_num_pages; // Total number of pages that can be mmap'ed.

static size_t used_pages = 0; // Tracks the number of used pages for the mmap tracing.

#if DEBUG
extern int sgxlkl_trace_mmap;
static size_t mmap_max_allocated = 0; // Maximum amount of memory used thus far.
#endif /* DEBUG */

#define DIV_ROUNDUP(x, y)   (((x)+((y)-1))/(y))

#define for_each_set_bit_in_region(bit, addr, size, start)   \
        for ((bit) = find_next_bit((addr), (size), (start)); \
             (bit) < (start + nr);                           \
             (bit) = find_next_bit((addr), (size), (bit) + 1))

static inline unsigned long bitmap_count_set_bits(unsigned long *map,
                                         unsigned long size,
                                         unsigned long start,
                                         unsigned long nr) {
    unsigned bit;
    unsigned retval = 0;

    for_each_set_bit_in_region(bit, map, size, start)
        retval++;
    return (retval);
}

static inline unsigned long bitmap_find_next_zero_area(unsigned long *map,
                                         unsigned long size,
                                         unsigned long start,
                                         unsigned long nr) {
    unsigned long index, end, i;
    for (;;) {
        index = find_next_zero_bit(map, size, start);

        end = index + nr;
        if (end > size) {
            return end;
        }
        i = find_next_bit(map, end, index);
        if (i < end) {
            start = i + 1;
            continue;
        }
        return index;
    }
}

static int in_mmap_range(void* addr, size_t size) {
    return addr >= mmap_base && ((char *)addr + size) <= (char *)mmap_end;
}

static void* index_to_addr(size_t index) {
    return (char *)mmap_end - (index * PAGE_SIZE);
}

static size_t addr_to_index(void* addr) {
    return ((char *)mmap_end - (char *)addr) / PAGE_SIZE;
}

void *syscall_SYS_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    void *mem;
    if ((flags & MAP_SHARED) && (flags & MAP_PRIVATE)) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    if (flags & MAP_ANON) {
        mem = enclave_mmap(addr, length, flags & MAP_FIXED);
        mprotect(mem, length , prot);
        if (mem == MAP_FAILED) {
            return mem;
        }
        if(prot & PROT_WRITE)
            memset(mem, 0, length);
    } else {
        //TODO: Do not allocate memory outside enclave for a system call that
        //can be invoked by applications!
        mem = host_syscall_SYS_mmap(addr, length, prot, flags, fd, offset);
    }
    return mem;
}

void *syscall_SYS_mremap(void *old_addr, size_t old_length, size_t new_length, int flags, void *new_addr) {
    if (!in_mmap_range(old_addr, 0)) {
        return host_syscall_SYS_mremap(old_addr, old_length, new_length, flags, new_addr);
    }
    return enclave_mremap(old_addr, old_length, new_addr, new_length, flags & MREMAP_FIXED);
}

int syscall_SYS_munmap(void *addr, size_t length) {
    if (in_mmap_range(addr, 0)) {
        enclave_munmap(addr, length);
        return 0;
    } else {
        return host_syscall_SYS_munmap(addr, length);
    }
}

int syscall_SYS_msync(void *addr, size_t length, int flags) {
    if (!in_mmap_range(addr, 0)) {
        return host_syscall_SYS_msync(addr, length, flags);
    }

    return 0;
}

int syscall_SYS_sysinfo(struct sysinfo *info) {
    size_t total = mmap_num_pages * PAGESIZE;
    size_t free = (mmap_num_pages - used_pages) * PAGESIZE;

    info->totalram = total;
    info->freeram = free;
    info->totalswap = 0;
    info->freeswap = 0;
    info->procs = 1;
    info->totalhigh = 0;
    info->freehigh = 0;
    info->mem_unit = 1;

    return 0;
}

/*
 * Initializes the enclave memory management.
 * 
 * base specifies the base address of the enclave heap, and num_pages th
 * enumber of pages starting at the base address to manage.
 * 
 * A bitmap is used to keep track of mapped/unmapped pages in the range of base
 * to base + num_pages*PAGE_SIZE. The bitmap occupies the first few pages of
 * enclave memory.
 */
void enclave_mman_init(void* base, size_t num_pages) {
    // Don't use page at address 0x0.
    if(base == 0x0) {
        base = (char *)base + PAGE_SIZE;
        num_pages = num_pages - 1;
    }

    // Determine required size (in pages) for the bitmap.
    size_t bitmap_req_pages = DIV_ROUNDUP(num_pages, BITS_PER_BYTE * PAGE_SIZE);
    mmap_num_pages = num_pages - bitmap_req_pages;
    // Bitmap is stored at the beginning of the enclave memory range.
    mmap_bitmap = base;
    // Base address for range of pages available to mmap calls.
    mmap_base = (char *)mmap_bitmap + (bitmap_req_pages * PAGE_SIZE);
    mmap_end = (char *)mmap_base + (mmap_num_pages - 1) * PAGE_SIZE;
    // Initialize bitmap
    bitmap_clear(mmap_bitmap, 0, mmap_num_pages);
}

/*
 * mmap for enclave memory range.
 */
void* enclave_mmap(void* addr, size_t length, int mmap_fixed) {
    void* ret = 0;
    size_t pages = DIV_ROUNDUP(length, PAGE_SIZE);
    size_t replaced_pages = 0;

    // Make sure addr is page aligned and size is greater than 0.
    if((uintptr_t) addr % PAGE_SIZE != 0 || length == 0) {
        errno = EINVAL;
        return MAP_FAILED;
    }

    ticket_lock(&mmaplock);
    if(mmap_fixed) {
        if(!in_mmap_range(addr, length)) {
            errno = ENOMEM;
            ret = MAP_FAILED;
        } else {
            // Get index for last page since the bitmap is used in reverse.
            size_t index_top = addr_to_index(addr) - (pages - 1);

#if DEBUG
            if(sgxlkl_trace_mmap)
                replaced_pages = bitmap_count_set_bits(mmap_bitmap, mmap_num_pages, index_top, pages);
#endif /* DEBUG */

            bitmap_set(mmap_bitmap, index_top, pages);
            ret = addr;
        }
    } else if(addr != 0 && in_mmap_range(addr, length)) {
        // Get index for last page since the bitmap is used in reverse.
        size_t index_top = addr_to_index(addr) - (pages - 1);
        // Address provided as a hint, check if range is available.
        if(!bitmap_count_set_bits(mmap_bitmap, mmap_num_pages, index_top, pages)) {
            bitmap_set(mmap_bitmap, index_top, pages);
            ret = addr;
        }
    }

    // Find next area with enough space.
    if(ret == 0) {
        size_t index_top = bitmap_find_next_zero_area(mmap_bitmap, mmap_num_pages, 0, pages);
        if(index_top + pages  > mmap_num_pages) {
            errno = ENOMEM;
            ret = MAP_FAILED;
        } else {
            bitmap_set(mmap_bitmap, index_top, pages);
            size_t index = index_top + (pages - 1);
            ret = index_to_addr(index);
        }
    }

    ticket_unlock(&mmaplock);

    if (ret != MAP_FAILED) {
        used_pages += pages - replaced_pages;
    }

#if DEBUG
    if(sgxlkl_trace_mmap) {
        size_t requested = pages * PAGESIZE;
        size_t total = mmap_num_pages * PAGESIZE;
        size_t free = (mmap_num_pages - used_pages) * PAGESIZE;
        size_t used = total - free;
        if (mmap_max_allocated < used) {
                mmap_max_allocated = used;
        }
        char *mfixed = mmap_fixed ? " (MAP_FIXED)" : "";
        char *rv = ret == MAP_FAILED ? " (FAILED)": "";
        SGXLKL_TRACE_MMAP("mmap stats: TOTAL: %8zuKB, USED: %8zuKB, MAX USED: %8zuKB, FREE: %8zuKB, ALLOCATED: %6zuKB (addr = %p, ret = %p) %s%s\n", total/1024, used/1024, mmap_max_allocated/1024, free/1024, requested/1024, addr, ret, mfixed, rv);
    }
#endif /* DEBUG */

    return ret;
}

/*
 * munmap for enclave memory range.
 */
int enclave_munmap(void* addr, size_t length) {
    size_t pages = DIV_ROUNDUP(length, PAGE_SIZE);

    // Make sure addr is page aligned and size is greater than 0.
    if((uintptr_t) addr % PAGE_SIZE != 0 || length == 0 || !in_mmap_range(addr, length)) {
        errno = EINVAL;
        return -1;
    }

    size_t index = addr_to_index(addr);
    size_t index_top = index - (pages - 1);

    ticket_lock(&mmaplock);

    // Only count pages that have been marked as mmapped before.
    size_t occupied_pages = bitmap_count_set_bits(mmap_bitmap, mmap_num_pages, index_top, pages);
    used_pages -= occupied_pages;

    bitmap_clear(mmap_bitmap, index_top, pages);
    ticket_unlock(&mmaplock);

#if DEBUG
    if(sgxlkl_trace_mmap) {
        size_t requested = pages * PAGESIZE;
        size_t total = mmap_num_pages * PAGESIZE;
        size_t free = (mmap_num_pages - used_pages) * PAGESIZE;
        size_t used = total - free;
        SGXLKL_TRACE_MMAP("munmap stats: TOTAL: %8zuKB, USED: %8zuKB, MAX USED: %8zuKB, FREE: %8zuKB,     FREED: %6zuKB (addr = %p)\n", total/1024, used/1024, mmap_max_allocated/1024, free/1024, requested/1024, addr);
    }
#endif /* DEBUG */

    return 0;
}

/*
 * mremap for enclave memory range.
 */
void* enclave_mremap(void* old_addr, size_t old_length, void* new_addr, size_t new_length, int mremap_fixed) {
    // TODO: If possible, extend region without copying memory
    // TODO: Support for MREMAP_FIXED
    if(mremap_fixed) {
        errno = EINVAL;
        return MAP_FAILED;
    }

    void *mem = enclave_mmap(new_addr, new_length, 0);
    if (mem != MAP_FAILED) {
        memcpy(mem, old_addr, old_length > new_length ? new_length : old_length);
        enclave_munmap(old_addr, old_length);
    }

    return mem;
}
