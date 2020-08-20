#ifndef _SGXLKL_USER_FUNCTBL_H
#define _SGXLKL_USER_FUNCTBL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef long time_t;

struct sgxlkl_user_timespec
{
    time_t tv_sec;
    long tv_nsec;
};

typedef int64_t off_t;

typedef struct sgxlkl_userargs
{
    /* Functions: ATTN: remove all but lkl_syscall() */
    long (*ua_lkl_syscall)(long no, long* params);
    void (*ua_sgxlkl_warn)(const char* msg, ...);
    void (*ua_sgxlkl_error)(const char* msg, ...);
    void (*ua_sgxlkl_fail)(const char* msg, ...);
    void* (*ua_enclave_mmap)(
        void* addr,
        size_t length,
        int mmap_fixed,
        int prot,
        int zero_pages);

    /* Arguments */
    int argc;
    char** argv;
    void* stack;
    const void* elf64_hdr;
    size_t num_ethreads;

    /* to be passed to init_clock_res() */
    struct sgxlkl_user_timespec clock_res[8];

    /* where in debug mode or not */
    bool sw_debug_mode;
}
sgxlkl_userargs_t;

extern sgxlkl_userargs_t* __sgxlkl_userargs;

#endif /* _SGXLKL_USER_FUNCTBL_H */
